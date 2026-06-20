//! Live smoke for eBPF Phase 2 IPv6 attribution (`tcp_v6_connect`).
//!
//! Stronger than the `v6_connect_lands_in_attribution_cache` unit test: that
//! test connects from *itself* and asserts the cached pid is its own. Here a
//! *separate* process (`curl -6`) makes the IPv6 connection, and we assert
//! eBPF attributes the flow back to `curl` with curl's own pid — proving the
//! kprobe captures connects system-wide and names the right external process,
//! which is the actual netwatch use case.
//!
//! Self-contained: binds an IPv6 loopback listener (so no external IPv6 egress
//! is needed — the kprobe fires at connect-entry regardless of reachability),
//! spawns `curl` against it, then polls the attribution cache.
//!
//! Run under root/CAP_BPF:
//!   cargo build --features ebpf --example ebpf_v6_smoke
//!   sudo ./target/debug/examples/ebpf_v6_smoke

use netwatch::ebpf::conn_tracker::ConnTracker;
use netwatch_sdk::ebpf::Protocol;
use std::io::Read;
use std::net::{IpAddr, Ipv6Addr, TcpListener};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    // 1. Attach the BPF programs (needs root). Fail loudly here — unlike the
    //    unit test, a skip would defeat the point of a smoke.
    let tracker = match ConnTracker::new() {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "FAIL: ConnTracker::new failed ({e}) — run under sudo (needs CAP_BPF/CAP_PERFMON)"
            );
            std::process::exit(2);
        }
    };
    println!("ok: eBPF connect tracker attached");

    // 2. A throwaway IPv6 loopback listener so curl has somewhere to connect.
    let listener = TcpListener::bind("[::1]:0").expect("bind ::1 listener");
    let port = listener.local_addr().unwrap().port();
    // Accept-and-drain in the background so curl's request completes cleanly.
    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf);
                // minimal HTTP reply so curl exits 0
                use std::io::Write;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
        }
    });
    // Let the kprobe attach settle before generating the connect event.
    thread::sleep(Duration::from_millis(100));

    // 3. A *separate* process makes the IPv6 connection.
    let url = format!("http://[::1]:{port}/");
    println!("ok: spawning curl -6 {url}");
    let child = Command::new("curl")
        .args(["-6", "-sS", "--max-time", "5", "-o", "/dev/null", &url])
        .spawn()
        .expect("spawn curl (is curl installed?)");
    let curl_pid = child.id();
    let _ = child.wait_with_output();

    // 4. The connect kprobe keys the cache on (daddr, dport).
    let key = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut attr = None;
    while Instant::now() < deadline {
        if let Some(a) = tracker.attributor.lookup(Protocol::Tcp, key, port) {
            attr = Some(a);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let attr = match attr {
        Some(a) => a,
        None => {
            eprintln!(
                "FAIL: no eBPF attribution cached for the curl [::1]:{port} connect within 3s"
            );
            std::process::exit(1);
        }
    };

    println!(
        "ok: attributed [::1]:{port} -> pid={} comm={:?} (curl pid was {})",
        attr.pid, attr.comm, curl_pid
    );

    // 5. Assertions: the right *external* process, by name and pid.
    let mut failed = false;
    if !attr.comm.contains("curl") {
        eprintln!("FAIL: comm {:?} is not curl", attr.comm);
        failed = true;
    }
    if attr.pid != curl_pid {
        eprintln!(
            "FAIL: attributed pid {} != curl pid {} (tgid attribution regressed?)",
            attr.pid, curl_pid
        );
        failed = true;
    }

    if failed {
        std::process::exit(1);
    }
    println!("PASS: eBPF Phase 2 IPv6 attribution names the correct external process");
}
