//! Live workstation stability accounting, with isolated state. No injected faults.
use anyhow::{ensure, Context, Result};
use netwatch::{
    app::App,
    config::NetwatchConfig,
    runtime::bootstrap::{self, SessionKind},
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
fn bytes(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| {
            let p = e.path();
            if p.is_dir() {
                bytes(&p)
            } else {
                e.metadata().map(|m| m.len()).unwrap_or(0)
            }
        })
        .sum()
}
fn state_bytes(root: &Path) -> u64 {
    ["config", "state", "cache", "data"]
        .iter()
        .map(|dir| bytes(&root.join(dir).join("netwatch")))
        .sum()
}
fn main() -> Result<()> {
    let root = PathBuf::from(
        std::env::args()
            .nth(1)
            .context("new scratch directory required")?,
    );
    let seconds = std::env::args()
        .nth(2)
        .context("duration seconds required")?
        .parse::<u64>()?
        .clamp(60, 3600);
    ensure!(!root.exists(), "scratch directory must be new");
    for (key, dir) in [
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
    ] {
        let p = root.join(dir);
        std::fs::create_dir_all(&p)?;
        std::env::set_var(key, p);
    }
    let mut cfg = NetwatchConfig {
        insights_enabled: false,
        diagnose_record_episodes: true,
        ..Default::default()
    };
    cfg.save()?;
    let mut app = App::prepare_with_config(cfg);
    bootstrap::start(
        &mut app,
        SessionKind::Daemon,
        netwatch::sandbox::Mode::from_config("on"),
    )?;
    bootstrap::prime_collectors(&mut app);
    let start = Instant::now();
    let mut last = start;
    let mut sampled = 0.0;
    let mut ticks = 0;
    let mut max_tick: f64 = 0.0;
    let mut max_rss = 0;
    let mut max_threads = 0;
    let mut identities = BTreeSet::new();
    let mut max_ready = 0;
    while start.elapsed().as_secs() < seconds {
        let tick = Instant::now();
        app.tick();
        max_tick = max_tick.max(tick.elapsed().as_secs_f64());
        let now = Instant::now();
        let gap = now.duration_since(last).as_secs_f64();
        if gap <= 5.0 {
            sampled += gap;
        }
        last = now;
        ticks += 1;
        max_ready = max_ready.max(
            app.diagnose
                .engine
                .coverage()
                .rules
                .iter()
                .filter(|r| r.status == netwatch::diagnose::coverage::Availability::Available)
                .count(),
        );
        for i in app
            .diagnose
            .engine
            .issues()
            .iter()
            .filter(|i| i.state.is_open())
        {
            identities.insert(format!("{}|{}", i.rule, i.subject.label()));
        }
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(v) = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    if line.starts_with("VmRSS:") {
                        max_rss = max_rss.max(v);
                    }
                    if line.starts_with("Threads:") {
                        max_threads = max_threads.max(v);
                    }
                }
            }
        }
        if ticks % 60 == 0 {
            println!("{}s: {ticks} samples, {sampled:.1}s observed, RSS {max_rss} KiB, threads {max_threads}, state {} bytes",start.elapsed().as_secs(),state_bytes(&root));
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
    app.shutdown_diagnose();
    app.packet_collector.stop_capture();
    let summary = serde_json::json!({"wall_seconds":start.elapsed().as_secs_f64(),"monitored_seconds":sampled,"ticks":ticks,"longest_tick_seconds":max_tick,"max_rss_kib":max_rss,"max_threads":max_threads,"state_bytes":state_bytes(&root),"max_available_checks":max_ready,"observed_issue_keys":identities});
    std::fs::write(
        root.join("state/netwatch/soak-summary.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    println!("{summary}");
    ensure!(sampled > seconds as f64 * 0.9, "insufficient measured time");
    ensure!(max_tick < 5.0, "collector stalled app tick");
    ensure!(max_threads < 100, "unexpected worker growth");
    ensure!(state_bytes(&root) < 20_000_000, "unexpected state growth");
    Ok(())
}
