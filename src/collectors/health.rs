use std::process::Command;

const RTT_HISTORY_MAX: usize = 60;

pub struct HealthStatus {
    pub gateway_rtt_ms: Option<f64>,
    pub gateway_loss_pct: f64,
    pub dns_rtt_ms: Option<f64>,
    pub dns_loss_pct: f64,
    pub gateway_rtt_history: Vec<Option<f64>>,
    pub dns_rtt_history: Vec<Option<f64>>,
}

pub struct HealthProber {
    pub status: HealthStatus,
}

impl HealthProber {
    pub fn new() -> Self {
        Self {
            status: HealthStatus {
                gateway_rtt_ms: None,
                gateway_loss_pct: 100.0,
                dns_rtt_ms: None,
                dns_loss_pct: 100.0,
                gateway_rtt_history: Vec::new(),
                dns_rtt_history: Vec::new(),
            },
        }
    }

    pub fn probe(&mut self, gateway: Option<&str>, dns_server: Option<&str>) {
        if let Some(gw) = gateway {
            let (rtt, loss) = run_ping(gw);
            self.status.gateway_rtt_ms = rtt;
            self.status.gateway_loss_pct = loss;
            self.status.gateway_rtt_history.push(rtt);
            if self.status.gateway_rtt_history.len() > RTT_HISTORY_MAX {
                self.status.gateway_rtt_history.remove(0);
            }
        }

        if let Some(dns) = dns_server {
            let (rtt, loss) = run_ping(dns);
            self.status.dns_rtt_ms = rtt;
            self.status.dns_loss_pct = loss;
            self.status.dns_rtt_history.push(rtt);
            if self.status.dns_rtt_history.len() > RTT_HISTORY_MAX {
                self.status.dns_rtt_history.remove(0);
            }
        }
    }
}

fn run_ping(target: &str) -> (Option<f64>, f64) {
    #[cfg(target_os = "macos")]
    let args = ["-c", "3", "-t", "1", target];

    #[cfg(target_os = "linux")]
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
    None
}
