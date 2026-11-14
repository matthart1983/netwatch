//! The false-alert soak: netwatch left running on an ordinary network, with
//! every tick recorded, and the accounting over what it recorded.
//!
//! ```sh
//! diagnose_quiet_soak record <dir> [--hours N] [--config FILE]
//! diagnose_quiet_soak report [--current-defaults] [--json] <dir>...
//! ```
//!
//! `record` keeps all its state under `<dir>` and touches nothing of the
//! user's netwatch. It can be stopped (Ctrl-C, SIGTERM) and started again on
//! the same directory: baselines carry over and the recordings add up.
//!
//! A rule is only tested while it has input. With the default config the
//! `target.*` rules have no target and the `path.*` rules have no trace, and
//! `report` shows them as never evaluated. `--config FILE` starts the soak
//! from a netwatch `config.toml` that sets `[[diagnose_targets]]` and
//! `[diagnose_probes] trace_refresh_secs`; it is copied in on the first run
//! and the copy is what later runs use. Run
//! `tests/soak/witness.py <dir>` beside it for the independent log `report`
//! judges opens against. See `tests/soak/README.md`.
use anyhow::{bail, ensure, Context, Result};
use netwatch::{
    app::App,
    config::NetwatchConfig,
    diagnose::soak::{self, HostInput},
    runtime::bootstrap::{self, SessionKind},
};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("record") => record(&args[1..]),
        Some("report") => report(&args[1..]),
        _ => bail!(
            "usage: diagnose_quiet_soak record <dir> [--hours N] [--config FILE]\n       \
             diagnose_quiet_soak report [--current-defaults] [--json] <dir>..."
        ),
    }
}

fn record(args: &[String]) -> Result<()> {
    let mut dir = None;
    let mut hours: Option<f64> = None;
    let mut config: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--hours" => {
                hours = Some(
                    it.next()
                        .context("--hours needs a number")?
                        .parse()
                        .context("--hours needs a number")?,
                )
            }
            "--config" => config = Some(PathBuf::from(it.next().context("--config needs a file")?)),
            other if dir.is_none() => dir = Some(PathBuf::from(other)),
            other => bail!("unexpected argument {other}"),
        }
    }
    let dir = dir.context("a soak directory is required")?;
    // Read before the environment moves, so a relative path means what the
    // caller meant.
    let config = config
        .map(|p| std::fs::read_to_string(&p).with_context(|| format!("{}", p.display())))
        .transpose()?;
    for (key, sub) in [
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
    ] {
        let p = dir.join(sub);
        std::fs::create_dir_all(&p)?;
        std::env::set_var(key, p);
    }

    let stop = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, stop.clone())?;
    }

    let own = NetwatchConfig::path().context("no config directory")?;
    if !own.exists() {
        if let Some(text) = &config {
            std::fs::create_dir_all(own.parent().context("config path has a parent")?)?;
            std::fs::write(&own, text)?;
        }
    } else if config.is_some() {
        eprintln!(
            "{} exists from an earlier run and is used; --config is ignored",
            own.display()
        );
    }
    let mut cfg = if own.exists() {
        NetwatchConfig::load().map_err(|e| anyhow::anyhow!("{}: {e}", own.display()))?
    } else {
        NetwatchConfig::default()
    };
    cfg.insights_enabled = false;
    cfg.diagnose_record_episodes = true;
    cfg.save()?;
    eprintln!(
        "{} target(s) · periodic trace {}",
        cfg.diagnose_targets.len(),
        cfg.diagnose_probes
            .trace_refresh_secs
            .map_or_else(|| "off".to_string(), |s| format!("every {s}s"))
    );
    let mut app = App::prepare_with_config(cfg);
    app.diagnose.soak = true;
    ensure!(
        app.diagnose.episode_dir.is_some(),
        "no state directory to record into"
    );
    bootstrap::start(
        &mut app,
        SessionKind::Daemon,
        netwatch::sandbox::Mode::from_config("on"),
    )?;
    bootstrap::prime_collectors(&mut app);

    let start = Instant::now();
    let limit = hours.map(|h| Duration::from_secs_f64(h * 3_600.0));
    let mut ticks: u64 = 0;
    let mut opens: u64 = 0;
    let mut was_open = std::collections::BTreeSet::new();
    eprintln!("recording into {} · stop with Ctrl-C", dir.display());
    while !stop.load(Ordering::Relaxed) && limit.is_none_or(|l| start.elapsed() < l) {
        app.tick();
        ticks += 1;
        let now_open: std::collections::BTreeSet<String> = app
            .diagnose
            .engine
            .primary()
            .into_iter()
            .map(netwatch::diagnose::episode::issue_key)
            .collect();
        for key in now_open.difference(&was_open) {
            opens += 1;
            eprintln!(
                "{} · opened {key}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
            );
        }
        was_open = now_open;
        if ticks.is_multiple_of(3_600) {
            eprintln!(
                "{:.1} h · {ticks} ticks · {opens} open(s) so far",
                start.elapsed().as_secs_f64() / 3_600.0
            );
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    // Writes the recording in progress, so a stop loses nothing.
    app.shutdown_diagnose();
    app.packet_collector.stop_capture();
    eprintln!(
        "stopped after {:.2} h · {ticks} ticks · {opens} open(s)",
        start.elapsed().as_secs_f64() / 3_600.0
    );
    Ok(())
}

fn host_label(dir: &Path) -> String {
    dir.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| dir.display().to_string())
}

fn report(args: &[String]) -> Result<()> {
    let mut current_defaults = false;
    let mut json = false;
    let mut dirs = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--current-defaults" => current_defaults = true,
            "--json" => json = true,
            other => dirs.push(PathBuf::from(other)),
        }
    }
    ensure!(!dirs.is_empty(), "at least one soak directory is required");
    let mut hosts = Vec::new();
    for dir in &dirs {
        ensure!(dir.is_dir(), "{} is not a directory", dir.display());
        let (host, errors) = HostInput::load(dir, &host_label(dir));
        for e in errors {
            eprintln!("skipped {e}");
        }
        hosts.push(host);
    }
    let report = soak::summarise(&hosts, current_defaults);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", report.text());
    }
    Ok(())
}
