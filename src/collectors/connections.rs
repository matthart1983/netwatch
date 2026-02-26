use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct Connection {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

pub struct ConnectionCollector {
    pub connections: Arc<Mutex<Vec<Connection>>>,
}

impl ConnectionCollector {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn update(&self) {
        let connections = Arc::clone(&self.connections);
        thread::spawn(move || {
            #[cfg(target_os = "macos")]
            let result = parse_lsof();
            #[cfg(target_os = "linux")]
            let result = parse_linux_connections();
            #[cfg(target_os = "windows")]
            let result = parse_windows_connections();
            *connections.lock().unwrap() = result;
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
    let output = match Command::new("lsof").args(["-i", "-n", "-P"]).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();

    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        if cols.len() < 9 {
            continue;
        }

        let process_name = cols[0].to_string();
        let pid: Option<u32> = cols[1].parse().ok();
        let protocol = cols[7].to_string(); // NODE column: TCP or UDP

        let name_field = cols[8..].join(" ");

        let (local_addr, remote_addr, state) = parse_name_field(&name_field);

        connections.push(Connection {
            protocol,
            local_addr,
            remote_addr,
            state,
            pid,
            process_name: Some(process_name),
        });
    }

    connections
}

#[cfg(target_os = "macos")]
fn parse_name_field(name: &str) -> (String, String, String) {
    // Extract state from parentheses at end, e.g. "(ESTABLISHED)"
    let (addr_part, state) = if let Some(paren_start) = name.rfind('(') {
        let state = name[paren_start + 1..].trim_end_matches(')').to_string();
        (name[..paren_start].trim(), state)
    } else {
        (name.trim(), String::new())
    };

    // Split on "->" for local->remote
    if let Some(arrow_pos) = addr_part.find("->") {
        let local = addr_part[..arrow_pos].to_string();
        let remote = addr_part[arrow_pos + 2..].to_string();
        (local, remote, state)
    } else {
        (addr_part.to_string(), "*:*".to_string(), state)
    }
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
