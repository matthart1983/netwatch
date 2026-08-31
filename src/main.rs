use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use netwatch::app;
use netwatch::config::NetwatchConfig;
use ratatui::prelude::*;
use std::io;

// Replace glibc's `ptmalloc` (Linux) and the system allocator on other
// platforms with mimalloc. Long-running TUI daemons that spawn short
// per-tick threads pay a noticeable RSS tax to ptmalloc's per-thread
// arena retention; mimalloc returns memory to the OS more aggressively
// and shaves a meaningful chunk off our steady-state baseline.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    // Handle CLI flags before entering TUI mode
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("netwatch {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "netwatch {} — real-time network diagnostics in your terminal\n\n\
             USAGE:\n    netwatch [OPTIONS]\n    sudo netwatch              Full mode (health probes + packet capture)\n    netwatch daemon [OPTIONS]  Headless agent (no TUI); streams to --remote\n\n\
             OPTIONS:\n    --generate-config         Write a default config file and exit\n    \
             --remote <url>            Stream metrics to a NetWatch Core instance\n    \
             --api-key <key>           API key for remote streaming\n    \
             --lite                    Start in Lite view: one screen, fits 80×24\n    \
             --view <full|lite|dense>  Start in a specific view (dense: four boxes, 130×44)\n    \
             --no-sandbox              Disable the post-startup security sandbox\n    \
             --sandbox-strict          Refuse to start if the sandbox can't be enforced\n    \
             --metrics-addr <addr>     (daemon) Serve Prometheus /metrics + /healthz on addr\n    \
             --metrics                 (daemon) Serve metrics on the default 127.0.0.1:9464\n    \
             --egress-catalog          Print the drift-adjudication catalog and exit\n    \
             -h, --help                Print help\n    -V, --version             Print version\n\n\
             KEYS (in TUI):\n    1-7   Switch tabs    /     Filter    q   Quit\n    \
             V     Cycle view (full → lite → dense)\n    \
             L     Toggle Lite view\n    \
             Shift+R/F/E   Flight Recorder: arm / freeze / export",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    // Print the adjudication catalog and exit. Before pcap, like the other
    // flags that answer without touching the network — and because a user
    // should be able to audit what the tool considers "well known" without
    // running it as root.
    if args.iter().any(|a| a == "--egress-catalog") {
        print!("{}", netwatch::collectors::egress::catalog::render());
        return Ok(());
    }
    if args.iter().any(|a| a == "--generate-config") {
        let cfg = NetwatchConfig::default();
        cfg.save()?;
        match NetwatchConfig::path() {
            Some(path) => println!("Config written to {}", path.display()),
            None => println!("Config written (could not determine path)"),
        }
        return Ok(());
    }

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

    // Parse --remote and --api-key for optional metrics streaming. Fall back to
    // env vars so the daemon (e.g. under systemd) can take its endpoint and key
    // from an EnvironmentFile instead of argv — keeping the API key out of `ps`.
    let remote_url = args
        .windows(2)
        .find(|w| w[0] == "--remote")
        .map(|w| w[1].clone())
        .or_else(|| std::env::var("NETWATCH_REMOTE_URL").ok());
    let api_key = args
        .windows(2)
        .find(|w| w[0] == "--api-key")
        .map(|w| w[1].clone())
        .or_else(|| std::env::var("NETWATCH_API_KEY").ok());

    // Lite is opt-in at every terminal size — we never auto-select it, since
    // that would make the tabs unreachable on a small terminal with no
    // obvious way back.
    // Views are opt-in at every terminal size — we never auto-select one, since
    // that would make the tabs unreachable on a small terminal with no obvious
    // way back. `--view` is the general form; `--lite` predates it and stays.
    let view = args
        .iter()
        .position(|a| a == "--view")
        .and_then(|i| args.get(i + 1))
        .map(|name| netwatch::app::ViewMode::by_name(name))
        .or_else(|| {
            args.iter()
                .any(|a| a == "--lite")
                .then_some(netwatch::app::ViewMode::Lite)
        });

    let sandbox_mode = if args.iter().any(|a| a == "--no-sandbox") {
        netwatch::sandbox::Mode::Disabled
    } else if args.iter().any(|a| a == "--sandbox-strict") {
        netwatch::sandbox::Mode::Strict
    } else {
        // No CLI flag — honor the persistent setting from
        // ~/.config/netwatch/config.toml (Settings overlay → "Sandbox").
        // `load()` already falls back to defaults on missing/malformed.
        netwatch::sandbox::Mode::from_config(&NetwatchConfig::load().sandbox)
    };

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
        (Some(_), None) => {
            eprintln!("error: --remote requires --api-key");
            return Ok(());
        }
        _ => None,
    };

    // File-only structured logging. Held until end of `main` so the
    // non-blocking writer's worker flushes queued records on shutdown.
    // Installed after CLI flag handling so `--version` / `--help` don't
    // touch the cache dir.
    let _log_guard = netwatch::logging::init();

    // Headless daemon mode: `netwatch daemon` (or `--daemon`/`--headless`).
    // Runs the same collectors as the TUI with no rendering, streams to the
    // remote backend, and flushes its durable queue on SIGTERM before exiting.
    let daemon_mode = args
        .iter()
        .skip(1)
        .any(|a| a == "daemon" || a == "--daemon" || a == "--headless");
    if daemon_mode {
        // Optional Prometheus /metrics + /healthz endpoint (daemon only for now).
        // `--metrics-addr <addr>`, or `--metrics` for the default, or the
        // NETWATCH_METRICS_ADDR env var.
        let metrics_addr = args
            .windows(2)
            .find(|w| w[0] == "--metrics-addr")
            .map(|w| w[1].clone())
            .or_else(|| std::env::var("NETWATCH_METRICS_ADDR").ok())
            .or_else(|| {
                args.iter()
                    .any(|a| a == "--metrics")
                    .then(|| netwatch::metrics::DEFAULT_METRICS_ADDR.to_string())
            });
        let metrics = metrics_addr.map(|addr| {
            let exporter = netwatch::metrics::MetricsExporter::new(addr);
            exporter.start();
            exporter
        });

        if let Err(e) =
            app::run_headless(remote_publisher.as_ref(), metrics.as_ref(), sandbox_mode).await
        {
            eprintln!("Error: {e:?}");
        }
        return Ok(());
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = app::run(&mut terminal, remote_publisher.as_ref(), sandbox_mode, view).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Error: {e:?}");
    }

    Ok(())
}
