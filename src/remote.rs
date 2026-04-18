use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::json;
use uuid::Uuid;

use crate::collectors::connections::ConnectionCollector;
use crate::collectors::health::HealthProber;
use crate::collectors::traffic::InterfaceTraffic;

pub struct RemoteConfig {
    pub url: String,
    pub api_key: String,
}

pub struct RemotePublisher {
    config: RemoteConfig,
    host_id: Uuid,
    snapshot_data: Arc<Mutex<Option<serde_json::Value>>>,
}

impl RemotePublisher {
    pub fn new(config: RemoteConfig) -> Self {
        Self {
            config,
            host_id: Uuid::new_v4(),
            snapshot_data: Arc::new(Mutex::new(None)),
        }
    }

    pub fn start(&self) {
        let url = self.config.url.trim_end_matches('/').to_string();
        let api_key = self.config.api_key.clone();
        let host_id = self.host_id;
        let data = self.snapshot_data.clone();

        thread::spawn(move || {
            let host_info = collect_host_info(host_id);

            loop {
                thread::sleep(Duration::from_secs(15));

                let snapshot = {
                    let lock = data.lock().unwrap();
                    lock.clone()
                };

                let Some(snapshot) = snapshot else { continue };

                let body = json!({
                    "agent_version": format!("netwatch-tui/{}", env!("CARGO_PKG_VERSION")),
                    "host": host_info,
                    "snapshots": [snapshot],
                });

                let endpoint = format!("{}/api/v1/ingest", url);
                let _ = ureq::post(&endpoint)
                    .set("Authorization", &format!("Bearer {}", api_key))
                    .set("Content-Type", "application/json")
                    .send_json(body);
            }
        });
    }

    pub fn update(
        &self,
        interfaces: &[InterfaceTraffic],
        health: &HealthProber,
        connections: &ConnectionCollector,
    ) {
        let ifaces: Vec<serde_json::Value> = interfaces
            .iter()
            .map(|i| {
                json!({
                    "name": i.name,
                    "is_up": true,
                    "rx_bytes": i.rx_bytes_total,
                    "tx_bytes": i.tx_bytes_total,
                    "rx_bytes_delta": (i.rx_rate as u64),
                    "tx_bytes_delta": (i.tx_rate as u64),
                    "rx_packets": i.rx_packets,
                    "tx_packets": i.tx_packets,
                    "rx_errors": i.rx_errors,
                    "tx_errors": i.tx_errors,
                    "rx_drops": i.rx_drops,
                    "tx_drops": i.tx_drops,
                })
            })
            .collect();

        let health_json = {
            let status = health.status.lock().unwrap();
            json!({
                "gateway_rtt_ms": status.gateway_rtt_ms,
                "gateway_loss_pct": status.gateway_loss_pct,
                "dns_rtt_ms": status.dns_rtt_ms,
                "dns_loss_pct": status.dns_loss_pct,
            })
        };

        let conn_count = connections
            .connections
            .lock()
            .map(|c| c.len() as u32)
            .unwrap_or(0);

        let tcp_states = collect_tcp_states(&connections);
        let system = collect_system_metrics();
        let disk_usage = collect_disk_usage();

        let snapshot = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "interfaces": ifaces,
            "health": health_json,
            "connection_count": conn_count,
            "system": system,
            "disk_usage": disk_usage,
            "tcp_time_wait": tcp_states.0,
            "tcp_close_wait": tcp_states.1,
        });

        *self.snapshot_data.lock().unwrap() = Some(snapshot);
    }
}

fn collect_host_info(host_id: Uuid) -> serde_json::Value {
    let hostname = run_cmd("hostname", &[]);
    let kernel = run_cmd("uname", &["-r"]);

    let (os, cpu_model, cpu_cores, memory_total) = if cfg!(target_os = "macos") {
        let os = Some("macOS".to_string());
        let cpu = run_cmd("sysctl", &["-n", "machdep.cpu.brand_string"]);
        let cores: Option<u32> = run_cmd("sysctl", &["-n", "hw.ncpu"]).and_then(|s| s.parse().ok());
        let mem: Option<u64> =
            run_cmd("sysctl", &["-n", "hw.memsize"]).and_then(|s| s.parse().ok());
        (os, cpu, cores, mem)
    } else {
        let os = std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| {
                    l.trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string()
                })
            });
        let cpu = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim().to_string())
        });
        let cores: Option<u32> = run_cmd("nproc", &[]).and_then(|s| s.parse().ok());
        let mem = std::fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u64>().ok())
                .map(|kb| kb * 1024)
        });
        (os, cpu, cores, mem)
    };

    json!({
        "host_id": host_id,
        "hostname": hostname,
        "os": os,
        "kernel": kernel,
        "cpu_model": cpu_model,
        "cpu_cores": cpu_cores,
        "memory_total_bytes": memory_total,
    })
}

fn collect_system_metrics() -> serde_json::Value {
    if cfg!(target_os = "macos") {
        collect_system_macos()
    } else {
        collect_system_linux()
    }
}

fn collect_system_macos() -> serde_json::Value {
    let load = run_cmd("sysctl", &["-n", "vm.loadavg"]).unwrap_or_default();
    let loads: Vec<f64> = load
        .trim_matches(|c: char| c == '{' || c == '}')
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();

    let mem_total: Option<u64> =
        run_cmd("sysctl", &["-n", "hw.memsize"]).and_then(|s| s.parse().ok());

    let vm_stat = run_cmd("vm_stat", &[]).unwrap_or_default();
    let page_size: u64 = 16384; // Apple Silicon default
    let mut free_pages: u64 = 0;
    let mut active_pages: u64 = 0;
    let mut inactive_pages: u64 = 0;
    let mut speculative_pages: u64 = 0;
    let mut wired_pages: u64 = 0;

    for line in vm_stat.lines() {
        let val = || -> Option<u64> {
            line.split(':')
                .nth(1)?
                .trim()
                .trim_end_matches('.')
                .parse()
                .ok()
        };
        if line.starts_with("Pages free") {
            free_pages = val().unwrap_or(0);
        }
        if line.starts_with("Pages active") {
            active_pages = val().unwrap_or(0);
        }
        if line.starts_with("Pages inactive") {
            inactive_pages = val().unwrap_or(0);
        }
        if line.starts_with("Pages speculative") {
            speculative_pages = val().unwrap_or(0);
        }
        if line.starts_with("Pages wired") {
            wired_pages = val().unwrap_or(0);
        }
    }

    let available = (free_pages + inactive_pages + speculative_pages) * page_size;
    let used = (active_pages + wired_pages) * page_size;

    let cpu_pct = run_cmd(
        "sh",
        &[
            "-c",
            "top -l 1 -n 0 2>/dev/null | grep 'CPU usage' | awk '{print $3}' | tr -d '%'",
        ],
    )
    .and_then(|s| s.parse::<f64>().ok());

    let swap = run_cmd("sysctl", &["-n", "vm.swapusage"]).unwrap_or_default();
    let swap_total: Option<u64> = swap
        .split_whitespace()
        .zip(swap.split_whitespace().skip(1))
        .find(|(_, v)| v.contains('M') || v.contains('G'))
        .and_then(|(_, v)| parse_size(v));
    let swap_used: Option<u64> = {
        let parts: Vec<&str> = swap.split("used =").collect();
        parts
            .get(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|v| parse_size(v))
    };

    json!({
        "cpu_usage_pct": cpu_pct,
        "memory_total_bytes": mem_total,
        "memory_used_bytes": used,
        "memory_available_bytes": available,
        "load_avg_1m": loads.first(),
        "load_avg_5m": loads.get(1),
        "load_avg_15m": loads.get(2),
        "swap_total_bytes": swap_total,
        "swap_used_bytes": swap_used,
    })
}

fn collect_system_linux() -> serde_json::Value {
    let loadavg = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let loads: Vec<f64> = loadavg
        .split_whitespace()
        .take(3)
        .filter_map(|s| s.parse().ok())
        .collect();

    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem_val = |key: &str| -> Option<u64> {
        meminfo
            .lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u64>().ok())
            .map(|kb| kb * 1024)
    };

    let mem_total = mem_val("MemTotal:");
    let mem_available = mem_val("MemAvailable:");
    let mem_used = match (mem_total, mem_available) {
        (Some(t), Some(a)) => Some(t - a),
        _ => None,
    };
    let swap_total = mem_val("SwapTotal:");
    let swap_free = mem_val("SwapFree:");
    let swap_used = match (swap_total, swap_free) {
        (Some(t), Some(f)) => Some(t - f),
        _ => None,
    };

    let stat = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    let cpu_pct = stat.lines().next().and_then(|line| {
        let vals: Vec<u64> = line
            .split_whitespace()
            .skip(1)
            .filter_map(|s| s.parse().ok())
            .collect();
        if vals.len() >= 4 {
            let total: u64 = vals.iter().sum();
            let idle = vals[3];
            if total > 0 {
                Some(((total - idle) as f64 / total as f64) * 100.0)
            } else {
                None
            }
        } else {
            None
        }
    });

    json!({
        "cpu_usage_pct": cpu_pct,
        "memory_total_bytes": mem_total,
        "memory_used_bytes": mem_used,
        "memory_available_bytes": mem_available,
        "load_avg_1m": loads.first(),
        "load_avg_5m": loads.get(1),
        "load_avg_15m": loads.get(2),
        "swap_total_bytes": swap_total,
        "swap_used_bytes": swap_used,
    })
}

fn collect_disk_usage() -> Vec<serde_json::Value> {
    let output = run_cmd("df", &["-k"]).unwrap_or_default();
    output
        .lines()
        .skip(1)
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                return None;
            }
            let device = parts[0];
            if device.starts_with("devfs") || device == "map" || device.starts_with("none") {
                return None;
            }
            let mount_hint = parts.last().unwrap_or(&"");
            if mount_hint.starts_with("/Volumes/")
                || mount_hint.starts_with("/System/Volumes/")
                || mount_hint.starts_with("/private/")
            {
                return None;
            }
            let total: u64 = parts[1].parse::<u64>().ok()? * 1024;
            let used: u64 = parts[2].parse::<u64>().ok()? * 1024;
            let available: u64 = parts[3].parse::<u64>().ok()? * 1024;
            let mount = if cfg!(target_os = "macos") && parts.len() >= 9 {
                parts[8..].join(" ")
            } else {
                parts.last()?.to_string()
            };
            if total == 0 {
                return None;
            }
            let pct = (used as f64 / total as f64) * 100.0;
            Some(json!({
                "mount_point": mount,
                "device": device,
                "total_bytes": total,
                "used_bytes": used,
                "available_bytes": available,
                "usage_pct": pct,
            }))
        })
        .collect()
}

fn collect_tcp_states(connections: &ConnectionCollector) -> (u32, u32) {
    let conns = connections.connections.lock().unwrap();
    let mut time_wait = 0u32;
    let mut close_wait = 0u32;
    for conn in conns.iter() {
        match conn.state.as_str() {
            "TIME_WAIT" | "TIME-WAIT" => time_wait += 1,
            "CLOSE_WAIT" | "CLOSE-WAIT" => close_wait += 1,
            _ => {}
        }
    }
    (time_wait, close_wait)
}

fn run_cmd(cmd: &str, args: &[&str]) -> Option<String> {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(v) = s.strip_suffix('M') {
        v.parse::<f64>().ok().map(|v| (v * 1024.0 * 1024.0) as u64)
    } else if let Some(v) = s.strip_suffix('G') {
        v.parse::<f64>()
            .ok()
            .map(|v| (v * 1024.0 * 1024.0 * 1024.0) as u64)
    } else {
        s.parse().ok()
    }
}
