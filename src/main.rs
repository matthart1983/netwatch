use anyhow::Result;
use netwatch::app;
use netwatch::config::NetwatchConfig;
use netwatch::ui::tty;
use ratatui::prelude::*;
use std::io;
use std::mem::ManuallyDrop;

// Replace glibc's `ptmalloc` (Linux) and the system allocator on other
// platforms with mimalloc. Long-running TUI daemons that spawn short
// per-tick threads pay a noticeable RSS tax to ptmalloc's per-thread
// arena retention; mimalloc returns memory to the OS more aggressively
// and shaves a meaningful chunk off our steady-state baseline.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match netwatch::cli::parse(&args)? {
        netwatch::cli::Command::Help => {
            print!("{}", netwatch::cli::help());
            return Ok(());
        }
        netwatch::cli::Command::Version => {
            println!("netwatch {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        netwatch::cli::Command::GenerateConfig => {
            NetwatchConfig::generate()?;
            println!(
                "Config written to {}",
                NetwatchConfig::path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            );
            return Ok(());
        }
        netwatch::cli::Command::Resolver(args) => {
            return netwatch::diagnose::remediation::resolver::command(&args)
        }
        netwatch::cli::Command::Diagnose(args) => {
            return netwatch::diagnose::episode::command(&args)
        }
        netwatch::cli::Command::Uptime(args) => return netwatch::uptime::command(&args),
        netwatch::cli::Command::GeoipUpdate { city } => {
            return netwatch::geoip_update::command(city)
        }
        netwatch::cli::Command::Doctor {
            json,
            check_capture,
            interface,
        } => return netwatch::runtime::capabilities::doctor(json, check_capture, interface),
        netwatch::cli::Command::CaptureChild { interface, mode } => {
            return netwatch::runtime::capabilities::capture_child(&interface, mode)
        }
        netwatch::cli::Command::Run(options) => options,
    };
    // Before anything is created or started. A config that is there but does
    // not load stops the TUI and the daemon here, naming the file and the
    // cause: the defaults would drop every setting in it, the sandbox mode
    // and `record_uptime` included.
    let api_key_flag = options.api_key.is_some();
    if api_key_flag {
        eprintln!("warning: {}", netwatch::cli::API_KEY_DEPRECATION);
    }
    let config = NetwatchConfig::load()?;
    // The TUI is about to hide stderr, and these are back in view when it
    // quits. A daemon's go to the journal. Nothing else here reports them twice:
    // `load` says nothing, however many times a session calls it.
    netwatch::config::print_warnings(&config.load_warnings);
    netwatch::config::print_warnings(&netwatch::collectors::egress::default_policy_warnings());
    let remote_url = options
        .remote
        .or_else(|| std::env::var("NETWATCH_REMOTE_URL").ok());
    let api_key = options
        .api_key
        .or_else(|| std::env::var("NETWATCH_API_KEY").ok());
    if remote_url.is_some() != api_key.is_some() {
        anyhow::bail!("remote streaming requires both URL and API key");
    }
    let remote_url = remote_url
        .map(|url| netwatch::remote::check_url(&url, options.insecure_remote))
        .transpose()?;
    let view = options.view;
    let demo = options.demo;
    let sandbox_mode = options
        .sandbox
        .unwrap_or_else(|| netwatch::sandbox::Mode::from_config(&config.sandbox));

    // Everything past this point can reach libpcap, so this is where Npcap has
    // to be resolved on Windows — after the flags that answer without it, so
    // `--version` and `--help` still work on a machine that has no Npcap at
    // all. See `platform::npcap` for why the default install needs help being
    // found, and `build.rs` for why we get to run at all before it loads.
    #[cfg(target_os = "windows")]
    if let Err(msg) = netwatch::platform::npcap::ensure_wpcap() {
        eprintln!("{msg}");
        std::process::exit(1);
    }

    let sandbox_paths = netwatch::sandbox::SandboxPaths::from_config(&config);
    if !matches!(sandbox_mode, netwatch::sandbox::Mode::Disabled) {
        sandbox_paths.prepare()?;
    } else if let Some(exports) = &sandbox_paths.cwd {
        // `prepare` makes it 0700 with the sandbox on; this does without it.
        netwatch::owner_only::create_dir_all(exports)?;
    }
    netwatch::sandbox::worker::install(sandbox_mode, sandbox_paths).map_err(anyhow::Error::msg)?;
    let _worker_session = netwatch::sandbox::worker::SessionGuard;
    netwatch::sandbox::worker::preflight().map_err(anyhow::Error::msg)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .on_thread_start(|| {
            assert!(
                netwatch::sandbox::worker::enter("tokio-blocking"),
                "blocking worker confinement failed"
            );
        })
        .build()?;

    let remote_publisher = match (remote_url, api_key) {
        (Some(url), Some(key)) => {
            let publisher =
                netwatch::remote::RemotePublisher::new(netwatch::remote::RemoteConfig {
                    url,
                    api_key: key,
                });
            publisher.start();
            Some(publisher)
        }
        (Some(_), None) => anyhow::bail!("--remote requires --api-key"),
        _ => None,
    };

    // File-only structured logging. Held until end of `main` so the
    // non-blocking writer's worker flushes queued records on shutdown.
    // Installed after CLI flag handling so `--version` / `--help` don't
    // touch the cache dir.
    let _log_guard = netwatch::logging::init();
    config.warn_removed_keys();
    config
        .load_warnings
        .iter()
        .for_each(netwatch::config::ConfigWarning::log);
    if api_key_flag {
        tracing::warn!(target: "netwatch::remote", "{}", netwatch::cli::API_KEY_DEPRECATION);
    }

    // Headless daemon mode: `netwatch daemon` (or `--daemon`/`--headless`).
    // Runs the same collectors as the TUI with no rendering, streams to the
    // remote backend, and flushes its durable queue on SIGTERM before exiting.
    if options.daemon {
        let metrics_addr = options
            .metrics_addr
            .or_else(|| std::env::var("NETWATCH_METRICS_ADDR").ok())
            .or_else(|| {
                options
                    .metrics
                    .then(|| netwatch::metrics::DEFAULT_METRICS_ADDR.to_string())
            });
        let metrics = metrics_addr.map(|addr| {
            let exporter = netwatch::metrics::MetricsExporter::new(addr);
            exporter.start();
            exporter
        });

        return runtime.block_on(app::run_headless(
            remote_publisher.as_ref(),
            metrics.as_ref(),
            sandbox_mode,
        ));
    }

    // `_tty` is declared after `_worker_session` and `runtime`, so during an
    // unwind it drops first and the shell is back before the workers' wait.
    tty::install_panic_hook();
    let _tty = tty::enter()?;
    // Never dropped: `Terminal`'s drop shows the cursor again, as
    // `tty::restore` already has, and panics in `eprintln!` if that write
    // fails, as every write does once the terminal has hung up.
    let mut terminal = ManuallyDrop::new(Terminal::new(CrosstermBackend::new(io::stdout()))?);

    let result = runtime.block_on(app::run(
        &mut terminal,
        remote_publisher.as_ref(),
        sandbox_mode,
        view,
        demo,
    ));

    tty::restore();

    // A background thread that dies can end the session with no more than
    // "Event channel closed"; the panic is what the user needs to see.
    match (result, tty::background_panic()) {
        (Err(error), Some(panic)) => {
            let log = netwatch::logging::log_dir()
                .map(|dir| format!("; log in {}", dir.display()))
                .unwrap_or_default();
            Err(error.context(format!("{panic}{log}")))
        }
        (result, _) => result,
    }
}
