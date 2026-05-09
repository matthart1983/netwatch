// Manual validation tool for the macOS PKTAP attribution path.
//
// Run with sudo and watch the output:
//
//     sudo cargo run --example pktap_probe
//
// Each line shows (direction, protocol, src→dst, pid, comm) for one captured
// frame. If you see PIDs and command names appearing, the kernel is delivering
// PKTAP-decorated frames and our header parser is reading them correctly. If
// the program prints "pktap unavailable" and exits, either you forgot sudo or
// PKTAP isn't supported on this host.
//
// The probe binary is intentionally minimal — it bypasses the in-app cache
// and prints raw events as they arrive, so you can confirm coverage of
// short-lived flows (e.g. `curl https://example.com` in another terminal).

// PKTAP is xnu-only; the rest of the example body is gated below so this
// file still compiles on Linux/Windows for `cargo test --all-targets`.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("pktap_probe is macOS-only — PKTAP is an xnu kernel feature.");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
use netwatch::platform::pktap;
#[cfg(target_os = "macos")]
use std::time::Duration;

#[cfg(target_os = "macos")]
fn main() {
    println!("Spawning PKTAP attributor (requires sudo)...");
    let handle = pktap::spawn();

    // Give the thread a moment to either start or fail fast.
    std::thread::sleep(Duration::from_millis(300));
    if let Some(err) = handle.startup_error() {
        eprintln!("error: {err}");
        // Tailor the hint to the failure class — a missing symbol won't be
        // fixed by sudo, but a "permission denied" or pcap_create failure
        // typically is.
        let hint = if err.contains("not found") || err.contains("Apple's libpcap") {
            "hint: this build is linked against a libpcap that doesn't expose Apple's PKTAP symbols"
        } else {
            "hint: re-run with sudo if this is a permission issue"
        };
        eprintln!("{hint}");
        std::process::exit(1);
    }

    println!("Attributor running. Generate traffic in another terminal — try");
    println!("  curl -s https://example.com >/dev/null");
    println!("Press Ctrl+C to stop.\n");

    use std::collections::HashSet;
    let mut printed: HashSet<String> = HashSet::new();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        for (key, attr) in handle.attributor.snapshot() {
            let line = format!(
                "{:?} {:?} {}:{} ↔ {}:{}  pid={} comm={}",
                attr.direction,
                key.protocol,
                key.addr_a.0,
                key.addr_a.1,
                key.addr_b.0,
                key.addr_b.1,
                attr.pid,
                attr.comm,
            );
            if printed.insert(line.clone()) {
                println!("{line}");
            }
        }
    }
}
