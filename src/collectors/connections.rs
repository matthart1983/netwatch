use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
pub struct Connection {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    /// Kernel-measured smoothed RTT in microseconds (from eBPF tcp_probe).
    pub kernel_rtt_us: Option<f64>,
}

pub struct ConnectionCollector {
    pub connections: Arc<Mutex<Vec<Connection>>>,
    busy: Arc<AtomicBool>,
}

impl ConnectionCollector {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(Vec::new())),
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn update(&self) {
        if self.busy.load(Ordering::SeqCst) {
            return;
        }
        self.busy.store(true, Ordering::SeqCst);
        let connections = Arc::clone(&self.connections);
        let busy = Arc::clone(&self.busy);
        thread::spawn(move || {
            #[cfg(target_os = "macos")]
            let result = parse_lsof();
            #[cfg(target_os = "linux")]
            let result = parse_linux_connections();
            #[cfg(target_os = "windows")]
            let result = parse_windows_connections();
            #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
            let result: Vec<Connection> = Vec::new();
            *connections.lock().unwrap() = result;
            busy.store(false, Ordering::SeqCst);
        });
    }
}

const MAX_TRACKED_CONNECTIONS: usize = 2000;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct ConnectionKey {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub pid: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct TrackedConnection {
    pub key: ConnectionKey,
    pub process_name: Option<String>,
    pub state: String,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub is_active: bool,
}

pub struct ConnectionTimeline {
    pub tracked: Vec<TrackedConnection>,
    known_keys: HashMap<ConnectionKey, usize>,
}

impl ConnectionTimeline {
    pub fn new() -> Self {
        Self {
            tracked: Vec::new(),
            known_keys: HashMap::new(),
        }
    }

    pub fn update(&mut self, connections: &[Connection]) {
        let now = Instant::now();

        let mut current_keys: HashSet<ConnectionKey> = HashSet::new();

        for conn in connections {
            let key = ConnectionKey {
                protocol: conn.protocol.clone(),
                local_addr: conn.local_addr.clone(),
                remote_addr: conn.remote_addr.clone(),
                pid: conn.pid,
            };

            current_keys.insert(key.clone());

            if let Some(&idx) = self.known_keys.get(&key) {
                let tracked = &mut self.tracked[idx];
                tracked.last_seen = now;
                tracked.state = conn.state.clone();
                tracked.is_active = true;
            } else {
                let idx = self.tracked.len();
                self.tracked.push(TrackedConnection {
                    key: key.clone(),
                    process_name: conn.process_name.clone(),
                    state: conn.state.clone(),
                    first_seen: now,
                    last_seen: now,
                    is_active: true,
                });
                self.known_keys.insert(key, idx);
            }
        }

        for tracked in &mut self.tracked {
            if !current_keys.contains(&tracked.key) {
                tracked.is_active = false;
            }
        }

        // Evict oldest inactive connections if over limit
        if self.tracked.len() > MAX_TRACKED_CONNECTIONS {
            let mut inactive_indices: Vec<usize> = self.tracked.iter()
                .enumerate()
                .filter(|(_, t)| !t.is_active)
                .map(|(i, _)| i)
                .collect();
            inactive_indices.sort_by_key(|&i| self.tracked[i].first_seen);

            let to_remove = self.tracked.len() - MAX_TRACKED_CONNECTIONS;
            let remove_set: HashSet<usize> = inactive_indices.into_iter().take(to_remove).collect();

            if !remove_set.is_empty() {
                let removed_keys: Vec<ConnectionKey> = remove_set.iter()
                    .map(|&i| self.tracked[i].key.clone())
                    .collect();
                for key in &removed_keys {
                    self.known_keys.remove(key);
                }

                let mut new_tracked = Vec::new();
                let mut new_keys = HashMap::new();
                for (i, t) in self.tracked.drain(..).enumerate() {
                    if !remove_set.contains(&i) {
                        let new_idx = new_tracked.len();
                        new_keys.insert(t.key.clone(), new_idx);
                        new_tracked.push(t);
                    }
                }
                self.tracked = new_tracked;
                self.known_keys = new_keys;
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn parse_lsof() -> Vec<Connection> {
    let output = match Command::new("lsof")
        .args(["-i", "-n", "-P", "-F", "pcPtTn"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();

    let mut pid: Option<u32> = None;
    let mut process_name: Option<String> = None;
    let mut protocol = String::new();
    let mut state = String::new();
    let mut local_addr = String::new();
    let mut remote_addr = String::new();
    let mut has_network = false;

    // lsof -F field order per file descriptor is: f, t, P, n, TST=, TQR=, TQS=
    // The state (TST=) comes AFTER the network address (n), so we must defer
    // pushing the connection until the next file descriptor (f) or process (p)
    // boundary, or end-of-input.
    let flush = |connections: &mut Vec<Connection>,
                     has_network: &mut bool,
                     protocol: &str,
                     local_addr: &str,
                     remote_addr: &str,
                     state: &str,
                     pid: Option<u32>,
                     process_name: &Option<String>| {
        if *has_network {
            connections.push(Connection {
                protocol: protocol.to_string(),
                local_addr: local_addr.to_string(),
                remote_addr: remote_addr.to_string(),
                state: state.to_string(),
                pid,
                process_name: process_name.clone(),
                kernel_rtt_us: None,
            });
            *has_network = false;
        }
    };

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }

        let tag = line.as_bytes()[0];
        let value = &line[1..];

        match tag {
            b'p' => {
                flush(&mut connections, &mut has_network, &protocol, &local_addr, &remote_addr, &state, pid, &process_name);
                pid = value.parse().ok();
                process_name = None;
            }
            b'c' => {
                process_name = Some(value.to_string());
            }
            b'f' => {
                flush(&mut connections, &mut has_network, &protocol, &local_addr, &remote_addr, &state, pid, &process_name);
                protocol = String::new();
                state = String::new();
            }
            b'P' => {
                protocol = value.to_string();
            }
            b't' => {}
            b'T' => {
                if let Some(st) = value.strip_prefix("ST=") {
                    state = st.to_string();
                }
            }
            b'n' => {
                if let Some(arrow_pos) = value.find("->") {
                    local_addr = value[..arrow_pos].trim_matches(|c| c == '[' || c == ']').to_string();
                    remote_addr = value[arrow_pos + 2..].trim_matches(|c| c == '[' || c == ']').to_string();
                } else {
                    local_addr = value.to_string();
                    remote_addr = "*:*".to_string();
                };
                has_network = true;
            }
            _ => {}
        }
    }

    // Flush the last pending connection
    flush(&mut connections, &mut has_network, &protocol, &local_addr, &remote_addr, &state, pid, &process_name);

    connections
}

#[cfg(target_os = "linux")]
fn parse_linux_connections() -> Vec<Connection> {
    let mut connections = Vec::new();

    if let Ok(output) = Command::new("ss").args(["-tunap"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 6 {
                continue;
            }

            let protocol = cols[0].to_uppercase();
            let state = cols[1].to_string();
            let local_addr = cols[4].to_string();
            let remote_addr = cols[5].to_string();

            let (pid, process_name) = if cols.len() > 6 {
                parse_ss_process(cols[6])
            } else {
                (None, None)
            };

            connections.push(Connection {
                protocol,
                local_addr,
                remote_addr,
                state,
                pid,
                process_name,
                kernel_rtt_us: None,
            });
        }
    }

    connections
}

#[cfg(target_os = "linux")]
fn parse_ss_process(field: &str) -> (Option<u32>, Option<String>) {
    // Format: users:(("process",pid=1234,fd=3))
    let name = field
        .split('"')
        .nth(1)
        .map(|s| s.to_string());

    let pid = field
        .split("pid=")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.parse().ok());

    (pid, name)
}

#[cfg(target_os = "windows")]
fn resolve_pids(pids: &[u32]) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    if pids.is_empty() {
        return map;
    }

    let output = match Command::new("tasklist").args(["/FO", "CSV", "/NH"]).output() {
        Ok(o) => o,
        Err(_) => return map,
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let pid_set: HashSet<u32> = pids.iter().copied().collect();

    for line in text.lines() {
        // Format: "process.exe","1234","Console","1","12,345 K"
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 2 {
            continue;
        }
        let name = fields[0].trim_matches('"');
        let pid_str = fields[1].trim_matches('"');
        if let Ok(pid) = pid_str.parse::<u32>() {
            if pid_set.contains(&pid) {
                map.insert(pid, name.to_string());
            }
        }
    }

    map
}

#[cfg(target_os = "windows")]
fn parse_windows_connections() -> Vec<Connection> {
    let output = match Command::new("netstat").args(["-ano"]).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);

    struct RawConn {
        protocol: String,
        local_addr: String,
        remote_addr: String,
        state: String,
        pid: Option<u32>,
    }

    let mut raw_connections = Vec::new();
    let mut all_pids = HashSet::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("TCP") && !trimmed.starts_with("UDP") {
            continue;
        }

        let cols: Vec<&str> = trimmed.split_whitespace().collect();

        let (protocol, local_addr, remote_addr, state, pid) = if cols[0] == "UDP" {
            // UDP lines: Proto LocalAddr ForeignAddr PID (no state)
            if cols.len() < 4 {
                continue;
            }
            let pid: Option<u32> = cols[3].parse().ok();
            (cols[0].to_string(), cols[1].to_string(), cols[2].to_string(), String::new(), pid)
        } else {
            // TCP lines: Proto LocalAddr ForeignAddr State PID
            if cols.len() < 5 {
                continue;
            }
            let pid: Option<u32> = cols[4].parse().ok();
            (cols[0].to_string(), cols[1].to_string(), cols[2].to_string(), cols[3].to_string(), pid)
        };

        if let Some(p) = pid {
            all_pids.insert(p);
        }

        raw_connections.push(RawConn {
            protocol,
            local_addr,
            remote_addr,
            state,
            pid,
        });
    }

    let pid_names = resolve_pids(&all_pids.into_iter().collect::<Vec<_>>());

    raw_connections
        .into_iter()
        .map(|rc| Connection {
            protocol: rc.protocol,
            local_addr: rc.local_addr,
            remote_addr: rc.remote_addr,
            state: rc.state,
            process_name: rc.pid.and_then(|p| pid_names.get(&p).cloned()),
            pid: rc.pid,
        })
        .collect()
}

/// Export connections to JSON file
pub fn export_json(connections: &[Connection], path: &str) -> Result<usize, String> {
    use std::io::Write;
    let mut file = std::fs::File::create(path).map_err(|e| format!("Create error: {e}"))?;

    let entries: Vec<serde_json::Value> = connections.iter().map(|c| {
        serde_json::json!({
            "process": c.process_name.as_deref().unwrap_or("—"),
            "pid": c.pid,
            "protocol": c.protocol,
            "state": c.state,
            "local_address": c.local_addr,
            "remote_address": c.remote_addr,
        })
    }).collect();

    let json = serde_json::to_string_pretty(&entries).map_err(|e| format!("JSON error: {e}"))?;
    file.write_all(json.as_bytes()).map_err(|e| format!("Write error: {e}"))?;
    Ok(connections.len())
}

/// Export connections to CSV file
pub fn export_csv(connections: &[Connection], path: &str) -> Result<usize, String> {
    use std::io::Write;
    let mut file = std::fs::File::create(path).map_err(|e| format!("Create error: {e}"))?;

    writeln!(file, "process,pid,protocol,state,local_address,remote_address")
        .map_err(|e| format!("Write error: {e}"))?;

    for c in connections {
        writeln!(file, "{},{},{},{},{},{}",
            c.process_name.as_deref().unwrap_or("—"),
            c.pid.map(|p| p.to_string()).unwrap_or_else(|| "—".into()),
            c.protocol,
            c.state,
            c.local_addr,
            c.remote_addr,
        ).map_err(|e| format!("Write error: {e}"))?;
    }

    Ok(connections.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_conn(proto: &str, local: &str, remote: &str, state: &str, pid: u32) -> Connection {
        Connection {
            protocol: proto.into(),
            local_addr: local.into(),
            remote_addr: remote.into(),
            state: state.into(),
            pid: Some(pid),
            process_name: Some("test".into()),
            kernel_rtt_us: None,
        }
    }

    #[test]
    fn new_timeline_is_empty() {
        let tl = ConnectionTimeline::new();
        assert!(tl.tracked.is_empty());
    }

    #[test]
    fn update_adds_new_connections() {
        let mut tl = ConnectionTimeline::new();
        let conns = vec![
            make_conn("TCP", "127.0.0.1:8080", "10.0.0.1:443", "ESTABLISHED", 100),
            make_conn("UDP", "0.0.0.0:53", "*:*", "", 200),
        ];
        tl.update(&conns);
        assert_eq!(tl.tracked.len(), 2);
        assert!(tl.tracked.iter().all(|t| t.is_active));
    }

    #[test]
    fn update_marks_existing_connections_active() {
        let mut tl = ConnectionTimeline::new();
        let conns = vec![make_conn("TCP", "127.0.0.1:8080", "10.0.0.1:443", "ESTABLISHED", 100)];
        tl.update(&conns);
        tl.update(&conns);
        assert_eq!(tl.tracked.len(), 1);
        assert!(tl.tracked[0].is_active);
    }

    #[test]
    fn update_marks_disappeared_connections_inactive() {
        let mut tl = ConnectionTimeline::new();
        let conns = vec![make_conn("TCP", "127.0.0.1:8080", "10.0.0.1:443", "ESTABLISHED", 100)];
        tl.update(&conns);
        tl.update(&[]);
        assert_eq!(tl.tracked.len(), 1);
        assert!(!tl.tracked[0].is_active);
    }

    #[test]
    fn update_changes_state() {
        let mut tl = ConnectionTimeline::new();
        let c1 = vec![make_conn("TCP", "127.0.0.1:8080", "10.0.0.1:443", "ESTABLISHED", 100)];
        tl.update(&c1);
        assert_eq!(tl.tracked[0].state, "ESTABLISHED");

        let c2 = vec![make_conn("TCP", "127.0.0.1:8080", "10.0.0.1:443", "TIME_WAIT", 100)];
        tl.update(&c2);
        assert_eq!(tl.tracked[0].state, "TIME_WAIT");
    }

    #[test]
    fn connection_key_equality() {
        let k1 = ConnectionKey {
            protocol: "TCP".into(),
            local_addr: "127.0.0.1:80".into(),
            remote_addr: "10.0.0.1:443".into(),
            pid: Some(42),
        };
        let k2 = ConnectionKey {
            protocol: "TCP".into(),
            local_addr: "127.0.0.1:80".into(),
            remote_addr: "10.0.0.1:443".into(),
            pid: Some(42),
        };
        assert_eq!(k1, k2);

        let k3 = ConnectionKey {
            protocol: "UDP".into(),
            local_addr: "127.0.0.1:80".into(),
            remote_addr: "10.0.0.1:443".into(),
            pid: Some(42),
        };
        assert_ne!(k1, k3);
    }

    #[test]
    fn connection_key_deduplicates_in_timeline() {
        let mut tl = ConnectionTimeline::new();
        let conn = make_conn("TCP", "127.0.0.1:8080", "10.0.0.1:443", "ESTABLISHED", 100);
        tl.update(&[conn.clone(), conn.clone()]);
        assert_eq!(tl.tracked.len(), 1);
    }

    #[test]
    fn inactive_connection_becomes_active_on_reappearance() {
        let mut tl = ConnectionTimeline::new();
        let conns = vec![make_conn("TCP", "127.0.0.1:8080", "10.0.0.1:443", "ESTABLISHED", 100)];
        tl.update(&conns);
        tl.update(&[]);
        assert!(!tl.tracked[0].is_active);
        tl.update(&conns);
        assert!(tl.tracked[0].is_active);
    }

    #[test]
    fn eviction_removes_oldest_inactive_over_limit() {
        let mut tl = ConnectionTimeline::new();

        // Add MAX_TRACKED_CONNECTIONS active connections
        let conns: Vec<Connection> = (0..MAX_TRACKED_CONNECTIONS as u32)
            .map(|i| make_conn("TCP", &format!("127.0.0.1:{}", i), "10.0.0.1:443", "ESTABLISHED", i))
            .collect();
        tl.update(&conns);
        assert_eq!(tl.tracked.len(), MAX_TRACKED_CONNECTIONS);

        // Mark all as inactive, then add new ones to exceed the limit
        tl.update(&[]);
        let extra: Vec<Connection> = (0..10u32)
            .map(|i| make_conn("TCP", &format!("192.168.0.1:{}", i), "10.0.0.1:443", "ESTABLISHED", 50000 + i))
            .collect();
        tl.update(&extra);

        // Should have evicted enough inactive to get back to MAX_TRACKED_CONNECTIONS
        assert_eq!(tl.tracked.len(), MAX_TRACKED_CONNECTIONS);
        // All extra connections should still be present
        for i in 0..10u32 {
            let key = ConnectionKey {
                protocol: "TCP".into(),
                local_addr: format!("192.168.0.1:{}", i),
                remote_addr: "10.0.0.1:443".into(),
                pid: Some(50000 + i),
            };
            assert!(tl.known_keys.contains_key(&key));
        }
    }

    #[test]
    fn multiple_protocols_tracked_separately() {
        let mut tl = ConnectionTimeline::new();
        let conns = vec![
            make_conn("TCP", "127.0.0.1:80", "10.0.0.1:443", "ESTABLISHED", 100),
            make_conn("UDP", "127.0.0.1:80", "10.0.0.1:443", "", 100),
        ];
        tl.update(&conns);
        assert_eq!(tl.tracked.len(), 2);
    }

    #[test]
    fn export_json_creates_valid_file() {
        let dir = std::env::temp_dir().join("netwatch_test_export");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.json");

        let conns = vec![make_conn("TCP", "127.0.0.1:80", "10.0.0.1:443", "ESTABLISHED", 100)];
        let count = export_json(&conns, path.to_str().unwrap()).unwrap();
        assert_eq!(count, 1);

        let contents = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_csv_creates_valid_file() {
        let dir = std::env::temp_dir().join("netwatch_test_export_csv");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.csv");

        let conns = vec![
            make_conn("TCP", "127.0.0.1:80", "10.0.0.1:443", "ESTABLISHED", 100),
            make_conn("UDP", "0.0.0.0:53", "*:*", "", 200),
        ];
        let count = export_csv(&conns, path.to_str().unwrap()).unwrap();
        assert_eq!(count, 2);

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 data rows
        assert!(lines[0].contains("process,pid,protocol"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
