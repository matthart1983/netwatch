//! Live test of the consolidated Info column (refactor/packets-split).
//!
//! Captures a short window while generating a multi-protocol traffic mix, then
//! prints the `Proto` + `Info` each packet got — exercising the single DPI
//! path (`dpi::classify_once` → `describe_app_protocol`) on real wire bytes,
//! including protocols the old packet-layer parsers never recognized (SSH,
//! NTP as a structured proto, etc.).
//!
//! Run:  cargo run --example info_column_test            (capture on en0)
//!       cargo run --example info_column_test -- en0

use std::collections::BTreeSet;
use std::process::Command;
use std::thread;
use std::time::Duration;

use netwatch::collectors::packets::PacketCollector;

fn main() {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "en0".into());
    let mut collector = PacketCollector::new();
    collector.start_capture(
        &iface,
        Some("tcp port 443 or udp port 53 or udp port 123 or tcp port 22"),
    );
    thread::sleep(Duration::from_millis(700));
    if let Some(err) = collector.error.lock().unwrap().clone() {
        eprintln!("capture failed: {err}");
        std::process::exit(2);
    }
    println!("capturing on {iface}, generating traffic...\n");

    // TLS (443) — https fetch.
    let _ = Command::new("python3")
        .args([
            "-c",
            "import ssl,socket;\
             c=ssl.create_default_context();\
             s=c.wrap_socket(socket.create_connection(('example.com',443),timeout=5),server_hostname='example.com');\
             s.sendall(b'GET / HTTP/1.1\\r\\nHost: example.com\\r\\nConnection: close\\r\\n\\r\\n');\
             s.recv(2048); s.close()",
        ])
        .status();

    // DNS (53) — a couple of lookups.
    for host in ["www.rust-lang.org", "github.com"] {
        let _ = Command::new("dig")
            .args(["+timeout=2", "+tries=1", host])
            .output();
    }

    // NTP (123) — minimal client query to a public server.
    let _ = Command::new("python3")
        .args([
            "-c",
            "import socket;\
             s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3);\
             s.sendto(b'\\x1b'+47*b'\\0',('time.apple.com',123));\
             import contextlib;\
             \nwith contextlib.suppress(Exception): s.recvfrom(48)\ns.close()",
        ])
        .status();

    // SSH (22) — read the server identification banner.
    let _ = Command::new("python3")
        .args([
            "-c",
            "import socket,contextlib;\
             s=socket.create_connection(('github.com',22),timeout=5);\
             \nwith contextlib.suppress(Exception): print('  ssh banner:', s.recv(64).decode(errors='replace').strip())\ns.close()",
        ])
        .status();

    // Drain remaining packets.
    thread::sleep(Duration::from_millis(1200));
    collector.stop_capture();

    // Collect distinct (proto, info) rows for the protocols we expect, so the
    // output is a readable sample rather than every packet.
    let pkts = collector.get_packets();
    let mut by_proto: std::collections::BTreeMap<String, BTreeSet<String>> = Default::default();
    for p in pkts.iter() {
        if matches!(p.protocol.as_str(), "TCP" | "UDP" | "ARP") {
            continue;
        }
        by_proto
            .entry(p.protocol.clone())
            .or_default()
            .insert(p.info.clone());
    }

    println!("\n=== classified Info rows (up to 3 per protocol) ===");
    for (proto, infos) in &by_proto {
        for info in infos.iter().take(3) {
            println!("[{proto:<10}] {info}");
        }
    }
    println!("\n({} packets captured)", pkts.len());
}
