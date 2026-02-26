use std::process::Command;

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
    pub connections: Vec<Connection>,
}

impl ConnectionCollector {
    pub fn new() -> Self {
        Self {
            connections: Vec::new(),
        }
    }

    pub fn update(&mut self) {
        #[cfg(target_os = "macos")]
        {
            self.connections = parse_lsof();
        }

        #[cfg(target_os = "linux")]
        {
            self.connections = parse_linux_connections();
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
