//! Live smoke for eBPF Phase 2 **connected-UDP** IPv6 attribution
//! (`ip6_datagram_connect`) — the QUIC client pattern.
//!
//! Like `ebpf_v6_smoke.rs` but over UDP: a *separate* process connects a
//! UDP socket to a `[::1]` peer, and we assert eBPF attributes the flow back
//! to that process under `Protocol::Udp`. No real QUIC server is needed — the
//! kprobe fires on the UDP `connect()`, not on QUIC bytes — and no external
//! binary is needed: the example re-execs itself as the connecting child, so
//! attribution is genuinely cross-process.
//!
//! Run under root/CAP_BPF:
//!   cargo build --features ebpf --example ebpf_udp_v6_smoke
//!   sudo ./target/debug/examples/ebpf_udp_v6_smoke

use netwatch::ebpf::conn_tracker::ConnTracker;
use netwatch_sdk::ebpf::Protocol;
use std::env;
use std::net::{IpAddr, Ipv6Addr, UdpSocket};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "NETWATCH_UDP_SMOKE_CHILD_PORT";

fn main() {
    // Child role: connect a UDP socket to [::1]:<port> and exit. `connect()`
    // alone fires ip6_datagram_connect — we never send a datagram.
    if let Ok(port) = env::var(CHILD_ENV) {
        let port: u16 = port.parse().expect("child port");
        let sock = UdpSocket::bind("[::1]:0").expect("child bind ::1");
        sock.connect((Ipv6Addr::LOCALHOST, port))
            .expect("child connect ::1 udp");
        // Linger briefly so the parent's drain thread is guaranteed to see
        // the event before the socket (and process) tear down.
        thread::sleep(Duration::from_millis(200));
        return;
    }

    // Parent role: attach BPF, spawn the child, look up its attribution.
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

    // A bound UDP peer gives the child a fixed destination port to key on.
    let peer = UdpSocket::bind("[::1]:0").expect("bind ::1 udp peer");
    let port = peer.local_addr().unwrap().port();
    thread::sleep(Duration::from_millis(100)); // let the kprobe settle

    let exe = env::current_exe().expect("current_exe");
    println!(
        "ok: spawning child {} to connect UDP [::1]:{port}",
        exe.display()
    );
    let mut child = Command::new(&exe)
        .env(CHILD_ENV, port.to_string())
        .spawn()
        .expect("spawn child");
    let child_pid = child.id();

    let key = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut attr = None;
    while Instant::now() < deadline {
        if let Some(a) = tracker.attributor.lookup(Protocol::Udp, key, port) {
            attr = Some(a);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.wait();

    let attr = match attr {
        Some(a) => a,
        None => {
            eprintln!(
                "FAIL: no UDP attribution cached for the child [::1]:{port} connect within 3s"
            );
            std::process::exit(1);
        }
    };

    println!(
        "ok: attributed UDP [::1]:{port} -> pid={} comm={:?} (child pid was {})",
        attr.pid, attr.comm, child_pid
    );

    let mut failed = false;
    if attr.pid != child_pid {
        eprintln!(
            "FAIL: attributed pid {} != child pid {} (tgid attribution regressed?)",
            attr.pid, child_pid
        );
        failed = true;
    }
    // The same destination over TCP must NOT be attributed — proves the
    // protocol key actually discriminates UDP from TCP.
    if tracker
        .attributor
        .lookup(Protocol::Tcp, key, port)
        .is_some()
    {
        eprintln!("FAIL: UDP connect aliased into the TCP cache slot");
        failed = true;
    }

    if failed {
        std::process::exit(1);
    }
    println!("PASS: eBPF Phase 2 connected-UDP IPv6 attribution names the correct process");
}
