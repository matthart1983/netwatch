//! Cross-platform smoke test for the native ICMP ping path.
//! Runs against the target IP (default 1.1.1.1) and prints rtt + loss.
//! Exits non-zero if loss is 100% — that's the macOS bug the v0.21.x
//! reply-offset fix was written for.

use netwatch::collectors::health::HealthProber;

fn main() {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "1.1.1.1".to_string());

    let prober = HealthProber::new();
    prober.probe(Some(&target), None);

    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let s = prober.status();
        if s.gateway_rtt_ms.is_some() || s.gateway_loss_pct < 100.0 {
            println!(
                "target={target} rtt={:?} ms, loss={:.1}%",
                s.gateway_rtt_ms, s.gateway_loss_pct
            );
            if s.gateway_loss_pct >= 100.0 {
                eprintln!("FAIL 100% loss — native ICMP path is broken on this OS");
                std::process::exit(1);
            }
            return;
        }
    }

    let s = prober.status();
    eprintln!("FAIL no rtt within 5 s; loss={:.1}%", s.gateway_loss_pct);
    std::process::exit(1);
}
