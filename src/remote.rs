use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::json;
use uuid::Uuid;

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
            let hostname = hostname();
            let os = os_pretty_name();
            let kernel = kernel_version();

            loop {
                thread::sleep(Duration::from_secs(15));

                let snapshot = {
                    let lock = data.lock().unwrap();
                    lock.clone()
                };

                let Some(snapshot) = snapshot else { continue };

                let body = json!({
                    "agent_version": format!("netwatch-tui/{}", env!("CARGO_PKG_VERSION")),
                    "host": {
                        "host_id": host_id,
                        "hostname": hostname,
                        "os": os,
                        "kernel": kernel,
                    },
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

    pub fn update(&self, interfaces: &[InterfaceTraffic], health: &HealthProber, connection_count: usize) {
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
            let gw = &crate::collectors::config::ConfigCollector::new().config;
            json!({
                "gateway_ip": gw.gateway,
                "gateway_rtt_ms": status.gateway_rtt_ms,
                "gateway_loss_pct": status.gateway_loss_pct,
                "dns_ip": gw.dns_servers.first(),
                "dns_rtt_ms": status.dns_rtt_ms,
                "dns_loss_pct": status.dns_loss_pct,
            })
        };

        let snapshot = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "interfaces": ifaces,
            "health": health_json,
            "connection_count": connection_count,
        });

        *self.snapshot_data.lock().unwrap() = Some(snapshot);
    }
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn os_pretty_name() -> Option<String> {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
        })
}

fn kernel_version() -> Option<String> {
    std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}
