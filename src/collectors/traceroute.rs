use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone)]
pub struct TracerouteHop {
    pub hop_number: u8,
    pub host: Option<String>,
    pub ip: Option<String>,
    pub rtt_ms: Vec<Option<f64>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TracerouteStatus {
    Idle,
    Running,
    Done,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct TracerouteResult {
    pub target: String,
    pub status: TracerouteStatus,
    pub hops: Vec<TracerouteHop>,
}

pub struct TracerouteRunner {
    pub result: Arc<Mutex<TracerouteResult>>,
}

impl TracerouteRunner {
    pub fn new() -> Self {
        Self {
            result: Arc::new(Mutex::new(TracerouteResult {
                target: String::new(),
                status: TracerouteStatus::Idle,
                hops: Vec::new(),
            })),
        }
    }

    pub fn run(&self, target: &str) {
        {
            let mut r = self.result.lock().unwrap();
            // Don't start if already running
            if r.status == TracerouteStatus::Running {
                return;
            }
            r.target = target.to_string();
            r.status = TracerouteStatus::Running;
            r.hops.clear();
        }

        let result = Arc::clone(&self.result);
        let target = target.to_string();
        thread::spawn(move || {
            match run_traceroute(&target) {
                Ok(hops) => {
                    let mut r = result.lock().unwrap();
                    r.hops = hops;
                    r.status = TracerouteStatus::Done;
                }
                Err(e) => {
                    let mut r = result.lock().unwrap();
                    r.status = TracerouteStatus::Error(e);
                }
            }
        });
    }

    pub fn clear(&self) {
        let mut r = self.result.lock().unwrap();
        r.target.clear();
        r.status = TracerouteStatus::Idle;
        r.hops.clear();
    }
}

fn run_traceroute(target: &str) -> Result<Vec<TracerouteHop>, String> {
    #[cfg(target_os = "windows")]
    let output = Command::new("tracert")
        .args(["-d", "-w", "1000", "-h", "30", target])
        .output()
        .map_err(|e| format!("Failed to run tracert: {}", e))?;

    #[cfg(not(target_os = "windows"))]
    let output = Command::new("traceroute")
        .args(["-n", "-q", "3", "-w", "1", "-m", "30", target])
        .output()
        .map_err(|e| format!("Failed to run traceroute: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            return Err(stderr.trim().to_string());
        }
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_traceroute_output(&text))
}

fn parse_traceroute_output(output: &str) -> Vec<TracerouteHop> {
    let mut hops = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Skip header lines (e.g., "traceroute to 8.8.8.8 ...")
        let first_token = trimmed.split_whitespace().next().unwrap_or("");
        let hop_number: u8 = match first_token.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let rest = &trimmed[first_token.len()..];
        let tokens: Vec<&str> = rest.split_whitespace().collect();

        if tokens.is_empty() {
            continue;
        }

        // All stars = no response
        if tokens.iter().all(|t| *t == "*") {
            hops.push(TracerouteHop {
                hop_number,
                host: None,
                ip: None,
                rtt_ms: vec![None; 3],
            });
            continue;
        }

        // With -n flag, output is: hop_number  IP  rtt1 ms  rtt2 ms  rtt3 ms
        // or:  hop_number  IP  rtt1 ms  *  rtt3 ms
        let mut ip: Option<String> = None;
        let mut host: Option<String> = None;
        let mut rtts: Vec<Option<f64>> = Vec::new();

        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i];

            if tok == "*" {
                rtts.push(None);
                i += 1;
            } else if tok == "ms" {
                // skip, already consumed the number before it
                i += 1;
            } else if let Ok(val) = tok.parse::<f64>() {
                rtts.push(Some(val));
                // Skip trailing "ms" if present
                if i + 1 < tokens.len() && tokens[i + 1] == "ms" {
                    i += 2;
                } else {
                    i += 1;
                }
            } else if ip.is_none() {
                // Could be IP or hostname
                // Check if it looks like an IP (contains dots or colons for IPv6)
                if tok.contains('.') || tok.contains(':') {
                    // Might be "IP" or "(IP)"
                    let cleaned = tok.trim_start_matches('(').trim_end_matches(')');
                    ip = Some(cleaned.to_string());
                } else {
                    host = Some(tok.to_string());
                }
                i += 1;
            } else if tok.starts_with('(') && tok.ends_with(')') {
                // Hostname resolution case: hostname (IP)
                let cleaned = tok.trim_start_matches('(').trim_end_matches(')');
                ip = Some(cleaned.to_string());
                i += 1;
            } else {
                i += 1;
            }
        }

        hops.push(TracerouteHop {
            hop_number,
            host,
            ip,
            rtt_ms: rtts,
        });
    }

    hops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_traceroute_basic() {
        let output = "\
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms  1.456 ms  1.789 ms
 2  10.0.0.1  5.123 ms  5.456 ms  5.789 ms
 3  * * *
 4  8.8.8.8  12.345 ms  12.456 ms  12.789 ms
";
        let hops = parse_traceroute_output(output);
        assert_eq!(hops.len(), 4);
        assert_eq!(hops[0].hop_number, 1);
        assert_eq!(hops[0].ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(hops[2].ip, None);
        assert!(hops[2].rtt_ms.iter().all(|r| r.is_none()));
        assert_eq!(hops[3].ip.as_deref(), Some("8.8.8.8"));
    }

    #[test]
    fn test_parse_traceroute_partial_stars() {
        let output = "\
traceroute to 1.1.1.1 (1.1.1.1), 30 hops max
 1  192.168.1.1  1.0 ms  *  1.5 ms
";
        let hops = parse_traceroute_output(output);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].rtt_ms.len(), 3);
        assert!(hops[0].rtt_ms[0].is_some());
        assert!(hops[0].rtt_ms[1].is_none());
        assert!(hops[0].rtt_ms[2].is_some());
    }
}
