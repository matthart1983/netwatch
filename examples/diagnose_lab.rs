//! Headless lab driver: the real `App::tick` once a second, one line per tick.
//!
//! `diagnose_lab --seconds N [--seed FILE] [--stop-file FILE] [--jsonl]`
//!
//! `--stop-file` ends the run early, after the tick on which FILE first
//! exists, with the same shutdown as `--seconds`: a scenario that has seen
//! everything it asserts stops there and still gets its episode written.
//!
//! Run by `tests/diagnose/health_lab.py` inside its namespaces, never by hand
//! against a real home: it refuses to start unless every directory the App
//! writes resolves inside the temp home the lab created. See
//! `netwatch::diagnose::lab` for the line format and the seed file.
use anyhow::{bail, ensure, Context, Result};
use netwatch::{
    app::App,
    config::NetwatchConfig,
    diagnose::{lab, live::LiveSampler},
    runtime::bootstrap::{self, SessionKind},
};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

struct Options {
    seconds: u64,
    seed: Option<PathBuf>,
    stop_file: Option<PathBuf>,
    jsonl: bool,
}

fn parse() -> Result<Options> {
    let mut opts = Options {
        seconds: 0,
        seed: None,
        stop_file: None,
        jsonl: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seconds" => {
                opts.seconds = args.next().context("--seconds requires 1..3600")?.parse()?
            }
            "--seed" => opts.seed = Some(args.next().context("--seed requires a file")?.into()),
            "--stop-file" => {
                opts.stop_file = Some(args.next().context("--stop-file requires a file")?.into())
            }
            "--jsonl" => opts.jsonl = true,
            other => bail!("unknown option: {other}"),
        }
    }
    ensure!(
        (1..=3600).contains(&opts.seconds),
        "--seconds must be 1..3600"
    );
    Ok(opts)
}

fn main() -> Result<()> {
    let opts = parse()?;
    // Before anything resolves a path: the App loads baselines, the recovery
    // journal and the config as it is built.
    let home = lab::check_home(
        |name| std::env::var_os(name).map(PathBuf::from),
        &std::env::temp_dir(),
        &[
            ("cache", dirs::cache_dir()),
            ("config", dirs::config_dir()),
            ("state", dirs::state_dir().or_else(dirs::data_local_dir)),
        ],
    )
    .map_err(anyhow::Error::msg)?;
    eprintln!("lab home: {}", home.display());
    let seed = match &opts.seed {
        Some(path) => Some(
            lab::Seed::parse(&std::fs::read_to_string(path).context("reading the seed file")?)
                .map_err(anyhow::Error::msg)?,
        ),
        None => None,
    };
    // Missing, the file would load as the defaults, which here would run the
    // lab without episode recording and pass for the wrong reason.
    let path = NetwatchConfig::path().context("no config directory")?;
    ensure!(path.is_file(), "the lab writes {}", path.display());
    let config = NetwatchConfig::load_from(&path)?;

    let _session = netwatch::sandbox::worker::SessionGuard;
    let mode = netwatch::sandbox::Mode::from_config(&config.sandbox);
    let mut app = App::prepare_with_config(config);
    bootstrap::start(&mut app, SessionKind::Daemon, mode)?;
    bootstrap::prime_collectors(&mut app);

    // Before the first tick, not after it: tick 1's episode frame holds the
    // only baseline snapshot a recording keeps for this network, and replay
    // restores baselines from that alone. The gateway and resolver are read
    // as the App is built, and tick 1 computes this same fingerprint, so its
    // `set_network` changes nothing.
    if let Some(seed) = &seed {
        let network = &app.config_collector.config;
        let (Some(gateway), Some(resolver)) = (network.gateway.clone(), network.primary_dns())
        else {
            // Unseeded σ rules stay in Learning, and a scenario that expects
            // nothing to open would pass without judging anything.
            bail!("--seed: the gateway or resolver is not known, so nothing can be seeded");
        };
        app.diagnose
            .baselines
            .set_network(LiveSampler::fingerprint(&app));
        let seeded = seed.apply(&mut app.diagnose.baselines, &gateway, &resolver);
        eprintln!("seeded {}", seeded.join(", "));
    }

    let started = Instant::now();
    for t in 1..=opts.seconds {
        std::thread::sleep(
            (started + Duration::from_secs(t)).saturating_duration_since(Instant::now()),
        );
        app.tick();
        let snap = lab::snapshot(
            &app.diagnose.engine,
            &app.diagnose.baselines,
            &app.health_prober.status(),
            t,
            netwatch::diagnose::engine::format_ts(chrono::Local::now()),
        );
        if opts.jsonl {
            println!("{}", serde_json::to_string(&snap)?);
        } else {
            let issues: Vec<String> = snap
                .issues
                .iter()
                .map(|i| format!("{} {}", i.key, i.state))
                .collect();
            println!(
                "{t:>4}s {:<8} gw {:?} dns {:?} · {}",
                snap.verdict.chip,
                snap.probes.gateway_rtt_ms,
                snap.probes.dns_rtt_ms,
                if issues.is_empty() {
                    "no issues".to_string()
                } else {
                    issues.join(", ")
                }
            );
        }
        if opts.stop_file.as_ref().is_some_and(|f| f.exists()) {
            eprintln!("stop file seen after {t}s");
            break;
        }
    }
    // As the daemon stops: the recorder writes an episode still in progress.
    app.packet_collector.stop_capture();
    app.egress_profiler.persist_now();
    app.shutdown_diagnose();
    Ok(())
}
