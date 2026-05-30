//! Live test of QUIC 1-RTT decryption (Phase 2c).
//!
//! Captures UDP/443 while headless Chrome (forced onto QUIC, writing its TLS
//! secrets to SSLKEYLOGFILE) loads an HTTP/3 site, then checks whether any
//! short-header packets were decrypted into `CapturedPacket.decrypted_plaintext`.
//!
//! Run:  cargo run --example quic_decrypt_test -- [host] [interface]

use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use netwatch::collectors::packets::PacketCollector;

const CHROME: &str = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

fn main() {
    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "www.google.com".into());
    let iface = std::env::args().nth(2).unwrap_or_else(|| "en0".into());
    let keylog = format!("/tmp/netwatch-quic-keylog-{}.txt", std::process::id());
    let _ = std::fs::remove_file(&keylog);
    std::fs::File::create(&keylog).expect("create keylog");

    let mut collector = PacketCollector::new();
    collector.configure_tls_keylog(Some(std::path::PathBuf::from(&keylog)));
    collector.start_capture(&iface, Some("udp port 443"));
    sleep(Duration::from_millis(700));
    if let Some(e) = collector.error.lock().unwrap().clone() {
        eprintln!("capture failed: {e}");
        std::process::exit(2);
    }
    println!("capturing udp/443 on {iface}; launching Chrome (forced QUIC) → {host}\n");

    let url = format!("https://{host}/");
    let user_dir = format!("/tmp/netwatch-chrome-{}", std::process::id());
    let status = Command::new(CHROME)
        .env("SSLKEYLOGFILE", &keylog)
        .args([
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            &format!("--user-data-dir={user_dir}"),
            &format!("--origin-to-force-quic-on={host}:443"),
            "--enable-quic",
            "--virtual-time-budget=8000",
            "--dump-dom",
            &url,
        ])
        .output();
    match &status {
        Ok(o) => println!(
            "  [chrome] exited ok={}, dom={} bytes",
            o.status.success(),
            o.stdout.len()
        ),
        Err(e) => {
            eprintln!("chrome launch failed: {e}");
            std::process::exit(2);
        }
    }

    sleep(Duration::from_millis(1500));
    collector.stop_capture();
    let keylog_lines = std::fs::read_to_string(&keylog)
        .map(|s| s.lines().count())
        .unwrap_or(0);
    let _ = std::fs::remove_file(&keylog);
    let _ = std::fs::remove_dir_all(&user_dir);

    let pkts = collector.get_packets();
    let total = pkts.len();
    let quic: usize = pkts
        .iter()
        .filter(|p| {
            p.protocol == "QUIC"
                || p.dst_port == Some(443) && p.protocol == "UDP"
                || p.src_port == Some(443) && p.protocol == "UDP"
        })
        .count();
    let decrypted: Vec<&netwatch::collectors::packets::CapturedPacket> = pkts
        .iter()
        .filter(|p| p.decrypted_plaintext.is_some())
        .collect();

    println!("\n=== RESULT ===");
    println!(
        "keylog lines: {keylog_lines} | packets: {total} | quic/udp443: {quic} | decrypted: {}",
        decrypted.len()
    );
    for p in decrypted.iter().take(8) {
        let pt = p.decrypted_plaintext.as_ref().unwrap();
        let preview: String = pt
            .iter()
            .take(48)
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!(
            "  {}:{} -> {}:{} [{}] {} bytes: {:?}",
            p.src_ip,
            p.src_port.unwrap_or(0),
            p.dst_ip,
            p.dst_port.unwrap_or(0),
            p.protocol,
            pt.len(),
            preview
        );
    }
    if decrypted.is_empty() {
        println!("\n❌ no QUIC 1-RTT packets decrypted (see notes: keylog timing, Chrome QUIC, version).");
    } else {
        println!(
            "\n✅ decrypted {} QUIC 1-RTT packet(s) end-to-end.",
            decrypted.len()
        );
    }
}
