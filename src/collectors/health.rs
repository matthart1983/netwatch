use std::collections::VecDeque;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

const RTT_HISTORY_MAX: usize = 60;

pub struct HealthStatus {
    pub gateway_rtt_ms: Option<f64>,
    pub gateway_loss_pct: f64,
    pub dns_rtt_ms: Option<f64>,
    pub dns_loss_pct: f64,
    pub gateway_rtt_history: VecDeque<Option<f64>>,
    pub dns_rtt_history: VecDeque<Option<f64>>,
}

pub struct HealthProber {
    pub status: Arc<Mutex<HealthStatus>>,
}

impl HealthProber {
    pub fn new() -> Self {
        Self {
            status: Arc::new(Mutex::new(HealthStatus {
                gateway_rtt_ms: None,
                gateway_loss_pct: 100.0,
                dns_rtt_ms: None,
                dns_loss_pct: 100.0,
                gateway_rtt_history: VecDeque::new(),
                dns_rtt_history: VecDeque::new(),
            })),
        }
    }

    pub fn probe(&self, gateway: Option<&str>, dns_server: Option<&str>) {
        let status = Arc::clone(&self.status);
        let gw = gateway.map(|s| s.to_string());
        let dns = dns_server.map(|s| s.to_string());
        thread::spawn(move || {
            if let Some(gw) = gw.as_deref() {
                let (rtt, loss) = run_ping(gw);
                let mut s = status.lock().unwrap();
                s.gateway_rtt_ms = rtt;
                s.gateway_loss_pct = loss;
                s.gateway_rtt_history.push_back(rtt);
                if s.gateway_rtt_history.len() > RTT_HISTORY_MAX {
                    s.gateway_rtt_history.pop_front();
                }
                s.gateway_rtt_history.make_contiguous();
            }
            if let Some(dns) = dns.as_deref() {
                let (rtt, loss) = run_ping(dns);
                let mut s = status.lock().unwrap();
                s.dns_rtt_ms = rtt;
                s.dns_loss_pct = loss;
                s.dns_rtt_history.push_back(rtt);
                if s.dns_rtt_history.len() > RTT_HISTORY_MAX {
                    s.dns_rtt_history.pop_front();
                }
                s.dns_rtt_history.make_contiguous();
            }
        });
    }
}

fn run_ping(target: &str) -> (Option<f64>, f64) {
    #[cfg(target_os = "macos")]
    let args = ["-c", "3", "-t", "1", target];

    #[cfg(target_os = "linux")]
    let args = ["-c", "3", "-W", "1", target];

    #[cfg(target_os = "windows")]
    let args = ["-n", "3", "-w", "1000", target];

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let args = ["-c", "3", "-W", "1", target];

    let output = match Command::new("ping").args(args).output() {
        Ok(o) => o,
        Err(_) => return (None, 100.0),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let loss = parse_loss(&text);
    let rtt = parse_avg_rtt(&text);

    (rtt, loss)
}

fn parse_loss(output: &str) -> f64 {
    // "3 packets transmitted, 3 packets received, 0.0% packet loss"
    for line in output.lines() {
        if line.contains("packet loss") || line.contains("% loss") {
            for part in line.split_whitespace() {
                if part.ends_with('%') {
                    if let Ok(val) = part.trim_end_matches('%').parse::<f64>() {
                        return val;
                    }
                }
            }
            // Try comma-separated format
            for segment in line.split(',') {
                let trimmed = segment.trim();
                if trimmed.contains("% packet loss") || trimmed.contains("% loss") {
                    if let Some(pct_str) = trimmed.split('%').next() {
                        let pct_str = pct_str.trim();
                        if let Ok(val) = pct_str.parse::<f64>() {
                            return val;
                        }
                        // Handle "0.0% packet loss" - get last word before %
                        if let Some(last_word) = pct_str.split_whitespace().last() {
                            let cleaned = last_word.trim_start_matches('(');
                            if let Ok(val) = cleaned.parse::<f64>() {
                                return val;
                            }
                        }
                    }
                }
            }
        }
    }
    100.0
}

fn parse_avg_rtt(output: &str) -> Option<f64> {
    // "round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.567 ms"
    for line in output.lines() {
        if line.contains("min/avg/max") || line.contains("rtt min/avg/max") {
            if let Some(stats) = line.split('=').nth(1) {
                let stats = stats.trim();
                let parts: Vec<&str> = stats.split('/').collect();
                if parts.len() >= 2 {
                    return parts[1].trim().parse().ok();
                }
            }
        }
    }
    // Windows format: "Minimum = 1ms, Maximum = 3ms, Average = 2ms"
    for line in output.lines() {
        if line.contains("Average =") {
            if let Some(avg_part) = line.split("Average =").nth(1) {
                let avg_str = avg_part.trim().trim_end_matches("ms").trim();
                return avg_str.parse().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_loss tests ──────────────────────────────────────────────

    #[test]
    fn parse_loss_linux_zero() {
        let output = "\
PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=1.10 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=1.05 ms

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 1.050/1.126/1.230/0.075 ms";
        assert_eq!(parse_loss(output), 0.0);
    }

    #[test]
    fn parse_loss_linux_partial() {
        let output = "3 packets transmitted, 1 received, 66.7% packet loss, time 2003ms";
        assert_eq!(parse_loss(output), 66.7);
    }

    #[test]
    fn parse_loss_macos_format() {
        let output = "\
PING 192.168.1.1 (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=2.345 ms

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.567 ms";
        assert_eq!(parse_loss(output), 0.0);
    }

    #[test]
    fn parse_loss_windows_format() {
        let output = "\
Ping statistics for 192.168.1.1:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 3ms, Average = 2ms";
        assert_eq!(parse_loss(output), 0.0);
    }

    #[test]
    fn parse_loss_full_loss() {
        let output = "3 packets transmitted, 0 received, 100% packet loss, time 2003ms";
        assert_eq!(parse_loss(output), 100.0);
    }

    #[test]
    fn parse_loss_empty_input() {
        assert_eq!(parse_loss(""), 100.0);
    }

    #[test]
    fn parse_loss_gibberish() {
        assert_eq!(parse_loss("not a ping output at all"), 100.0);
    }

    // ── parse_avg_rtt tests ───────────────────────────────────────────

    #[test]
    fn parse_avg_rtt_linux() {
        let output = "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.111 ms";
        assert_eq!(parse_avg_rtt(output), Some(0.456));
    }

    #[test]
    fn parse_avg_rtt_macos() {
        let output = "round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.567 ms";
        assert_eq!(parse_avg_rtt(output), Some(2.345));
    }

    #[test]
    fn parse_avg_rtt_full_linux_output() {
        let output = "\
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=12.3 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=11.8 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=117 time=12.1 ms

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 11.800/12.066/12.300/0.205 ms";
        assert_eq!(parse_avg_rtt(output), Some(12.066));
    }

    #[test]
    fn parse_avg_rtt_windows() {
        let output = "\
Ping statistics for 192.168.1.1:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 3ms, Average = 2ms";
        assert_eq!(parse_avg_rtt(output), Some(2.0));
    }

    #[test]
    fn parse_avg_rtt_windows_large() {
        let output = "    Minimum = 10ms, Maximum = 50ms, Average = 25ms";
        assert_eq!(parse_avg_rtt(output), Some(25.0));
    }

    #[test]
    fn parse_avg_rtt_empty_input() {
        assert_eq!(parse_avg_rtt(""), None);
    }

    #[test]
    fn parse_avg_rtt_gibberish() {
        assert_eq!(parse_avg_rtt("this is not ping output"), None);
    }
}
