//! Verify native ICMP ping survives the sandbox.
//!
//! The v0.17.x sandbox sets NO_NEW_PRIVS via Landlock, which makes the
//! kernel ignore the setcap on /usr/bin/ping — so the subprocess
//! `Command::new("ping")` path returns EPERM under sandbox. The native
//! DGRAM ICMP path in `src/collectors/health.rs` should bypass this
//! because SOCK_DGRAM ICMP gates on `net.ipv4.ping_group_range`, not
//! on capabilities.
//!
//! Linux-only — macOS doesn't have Landlock; the no-op main on other
//! platforms keeps `cargo build --all-targets` happy in cross-platform CI.

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("ping_under_sandbox is Linux-only; no-op on this platform.");
}

#[cfg(target_os = "linux")]
fn main() {
    use netwatch::config::NetwatchConfig;
    use netwatch::sandbox::{self, Mode, SandboxPaths};

    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "192.168.0.54".to_string());

    println!("target = {target}");

    let cfg = NetwatchConfig::default();
    let paths = SandboxPaths::from_config(&cfg);
    let report = sandbox::apply(Mode::BestEffort, &paths);
    println!("sandbox summary = {}", report.summary());

    // Use the same internal path the health prober uses. Since
    // `run_ping` is `pub(crate)` (i.e., crate-private), call it via a
    // small shim. Easiest: reach in through HealthProber::probe.
    use netwatch::collectors::health::HealthProber;
    let prober = HealthProber::new();
    prober.probe(Some(&target), None);

    // Probe spawns a thread and updates the snapshot asynchronously.
    // Wait up to 5 s for it to land.
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let s = prober.status();
        if s.gateway_rtt_ms.is_some() {
            println!(
                "OK   gateway rtt = {:.2} ms, loss = {:.1}%",
                s.gateway_rtt_ms.unwrap(),
                s.gateway_loss_pct
            );
            return;
        }
    }

    let s = prober.status();
    eprintln!(
        "FAIL no rtt sample within 5 s (loss = {:.1}%) — ping likely blocked under sandbox",
        s.gateway_loss_pct
    );
    std::process::exit(1);
}
