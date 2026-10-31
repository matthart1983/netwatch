//! Wall-clock smoke test against local HTTP services, using the real App loop.
//! cargo run --example diagnose_live_check -- /tmp/netwatch-live-check-unique
//! Takes about three minutes; writes recordings and an assertion summary.
use anyhow::{bail, ensure, Context, Result};
use netwatch::app::App;
use netwatch::config::NetwatchConfig;
use netwatch::diagnose::{
    episode, export,
    issue::{Severity, StepKind, VerifyOutcome},
    targets::TargetConfig,
};
use netwatch::runtime::bootstrap::{self, SessionKind};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

fn serve(
    listener: TcpListener,
    healthy: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
                    let mut request = [0; 4096];
                    if stream.read(&mut request).is_ok_and(|n| n > 0) {
                        let status = if healthy.load(Ordering::SeqCst) {
                            "200 OK"
                        } else {
                            "503 Service Unavailable"
                        };
                        let _ = write!(
                            stream,
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    })
}

fn main() -> Result<()> {
    let root = PathBuf::from(
        std::env::args()
            .nth(1)
            .context("supply a new scratch output directory")?,
    );
    ensure!(
        !root.exists(),
        "output directory must be new to isolate the test"
    );
    for (var, subdir) in [
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
    ] {
        let path = root.join(subdir);
        std::fs::create_dir_all(&path)?;
        std::env::set_var(var, path);
    }
    let unhealthy = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let http = TcpListener::bind("127.0.0.1:0")?;
    let http_port = http.local_addr()?.port();
    let reservation = TcpListener::bind("127.0.0.1:0")?;
    let stopped_port = reservation.local_addr()?.port();
    drop(reservation);
    let server = serve(http, unhealthy.clone(), stop.clone());
    let mut restarted = None;
    let target = |name: &str, port| TargetConfig {
        enabled: true,
        name: name.into(),
        host: "127.0.0.1".into(),
        port,
        tls: Some(false),
        http: true,
        path: "/private-health-secret".into(),
        expect_status: Some(200),
        interval_secs: 10,
    };
    let mut config = NetwatchConfig {
        refresh_rate_ms: 1000,
        insights_enabled: false,
        diagnose_record_episodes: true,
        diagnose_targets: vec![
            target("live-check-http", http_port),
            target("live-check-stopped", stopped_port),
        ],
        ..Default::default()
    };
    config.save()?;
    let mut app = App::prepare_with_config(config);
    bootstrap::start(
        &mut app,
        SessionKind::Daemon,
        netwatch::sandbox::Mode::from_config("on"),
    )?;
    bootstrap::prime_collectors(&mut app);
    let start = Instant::now();
    let mut repaired = false;
    let mut ids = Vec::new();
    let mut recovered = false;
    while start.elapsed() < Duration::from_secs(220) {
        app.tick();
        if start.elapsed().as_secs().is_multiple_of(20) {
            println!(
                "{}s: {}",
                start.elapsed().as_secs(),
                app.diagnose
                    .engine
                    .issues()
                    .iter()
                    .filter(|i| i.rule.starts_with("target."))
                    .map(|i| format!("{} {}", i.rule, i.state.label()))
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
        if !repaired {
            let issues: Vec<_> = app
                .diagnose
                .engine
                .issues()
                .iter()
                .filter(|i| i.rule.starts_with("target.") && i.state.is_open())
                .cloned()
                .collect();
            if issues.len() == 2 {
                for issue in &issues {
                    let expected = if issue.rule == "target.http_error" {
                        "service_error"
                    } else {
                        "service_down"
                    };
                    ensure!(
                        issue.top_cause().is_some_and(|c| c.id == expected),
                        "wrong cause: {issue:#?}"
                    );
                    ensure!(
                        issue.severity == Severity::Info,
                        "local service failure called a network fault"
                    );
                    if let Some(step) = issue
                        .remediation
                        .iter()
                        .position(|s| s.kind == StepKind::Instruct)
                    {
                        app.mark_diagnose_step_done(&issue.id, step)
                            .map_err(anyhow::Error::msg)?;
                    } else {
                        ensure!(
                            issue.rule == "target.http_error"
                                && issue
                                    .remediation
                                    .iter()
                                    .any(|s| s.kind == StepKind::Escalate),
                            "unexpected remediation workflow"
                        );
                    }
                    ids.push((
                        issue.id.clone(),
                        issue.top_cause().unwrap().key(&issue.rule),
                    ));
                }
                unhealthy.store(true, Ordering::SeqCst);
                restarted = Some(serve(
                    TcpListener::bind(("127.0.0.1", stopped_port))?,
                    Arc::new(AtomicBool::new(true)),
                    stop.clone(),
                ));
                repaired = true;
                println!("{}s: both faults correctly identified; recorded the manual service fix and restored both services", start.elapsed().as_secs());
            }
        } else if ids.iter().all(|(id, _)| {
            app.diagnose
                .engine
                .get(id)
                .is_some_and(|i| !i.state.is_open())
        }) {
            recovered = true;
            println!(
                "{}s: both incidents closed after the recovery holding window",
                start.elapsed().as_secs()
            );
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let mut checks = Vec::new();
    for (id, cause) in &ids {
        let issue = app.diagnose.engine.get(id).unwrap();
        checks.push(serde_json::json!({"id": id, "rule": issue.rule, "state": issue.state, "verification": issue.verification}));
        app.label_issue(id, cause).map_err(anyhow::Error::msg)?;
    }
    app.packet_collector.stop_capture();
    app.shutdown_diagnose();
    stop.store(true, Ordering::SeqCst);
    let _ = server.join();
    if let Some(server) = restarted {
        let _ = server.join();
    }
    let dir = app
        .diagnose
        .episode_dir
        .clone()
        .context("recording directory missing")?;
    let history = episode::history(&dir, 100);
    let mut replays = Vec::new();
    for entry in &history {
        let ep = episode::load(&entry.path)?;
        let replay = episode::replay(&ep);
        replays.push(serde_json::json!({"file": entry.path, "matches": replay.matches(), "divergences": replay.divergences}));
    }
    let key = export::install_key(&dir)?;
    let preview = export::build(&dir, &key, 1, chrono::Local::now());
    let exported = serde_json::to_string(&preview.bundle)?;
    let private = ![
        "127.0.0.1",
        "live-check-http",
        "live-check-stopped",
        "private-health-secret",
    ]
    .iter()
    .any(|s| exported.contains(s));
    let output_dir = root.join("cache/netwatch/exports");
    export::write(&preview.bundle, &output_dir.join("incident-export.json.gz"))
        .context("write redacted export")?;
    let summary = serde_json::json!({"repaired": repaired, "recovered": recovered, "checks": checks,
        "history_entries": history.len(), "replays": replays, "export_private": private,
        "labels": preview.bundle.episodes.iter().map(|e| e.labels.len()).sum::<usize>()});
    std::fs::write(
        output_dir.join("result.json"),
        serde_json::to_string_pretty(&summary)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    if !repaired || !recovered {
        bail!("fault or recovery was not observed; see {}", root.display());
    }
    for (id, _) in &ids {
        if app
            .diagnose
            .engine
            .get(id)
            .is_some_and(|i| i.rule == "target.http_error")
        {
            continue;
        }
        ensure!(
            app.diagnose
                .engine
                .get(id)
                .and_then(|i| i.verification.as_ref())
                .and_then(|v| v.outcome)
                == Some(VerifyOutcome::Recovered),
            "manual verification did not recover"
        );
    }
    ensure!(!history.is_empty(), "no incident history saved");
    ensure!(
        replays.iter().all(|r| r["matches"] == true),
        "live replay diverged; see result.json"
    );
    ensure!(private, "private values survived export");
    ensure!(
        preview
            .bundle
            .episodes
            .iter()
            .map(|e| e.labels.len())
            .sum::<usize>()
            >= 2,
        "answers not saved"
    );
    println!("PASS: live detection, manual verification, recovery, labels, history, replay and redacted export");
    Ok(())
}
