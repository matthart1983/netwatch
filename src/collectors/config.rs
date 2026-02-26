use std::process::Command;

pub struct NetworkConfig {
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    #[allow(dead_code)]
    pub hostname: String,
}

pub struct ConfigCollector {
    pub config: NetworkConfig,
}

impl ConfigCollector {
    pub fn new() -> Self {
        let hostname = nix::unistd::gethostname()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        Self {
            config: NetworkConfig {
                gateway: None,
                dns_servers: Vec::new(),
                hostname,
            },
        }
    }

    pub fn update(&mut self) {
        self.config.gateway = collect_gateway();
        self.config.dns_servers = collect_dns();
    }
}

#[cfg(target_os = "macos")]
fn collect_gateway() -> Option<String> {
    let output = Command::new("netstat").args(["-rn"]).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 2 && cols[0] == "default" {
            return Some(cols[1].to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn collect_gateway() -> Option<String> {
    let output = Command::new("ip").args(["route"]).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.starts_with("default via ") {
            return line.split_whitespace().nth(2).map(|s| s.to_string());
        }
    }
    None
}

fn collect_dns() -> Vec<String> {
    let mut servers = Vec::new();

    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver ") {
                if let Some(addr) = trimmed.split_whitespace().nth(1) {
                    servers.push(addr.to_string());
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    if servers.is_empty() {
        if let Ok(output) = Command::new("scutil").args(["--dns"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("nameserver[") {
                    if let Some(addr) = trimmed.split(':').nth(1) {
                        let addr = addr.trim().to_string();
                        if !servers.contains(&addr) {
                            servers.push(addr);
                        }
                    }
                }
            }
        }
    }

    servers
}
