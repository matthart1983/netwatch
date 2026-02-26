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
                            if let Ok(val) = last_word.parse::<f64>() {
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
