use super::{InterfaceInfo, InterfaceStats};
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    let mut stats = HashMap::new();
    let net_dir = Path::new("/sys/class/net");

    for entry in fs::read_dir(net_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let base = net_dir.join(&name).join("statistics");

        let read = |file: &str| -> u64 {
            fs::read_to_string(base.join(file))
                .unwrap_or_default()
                .trim()
                .parse()
                .unwrap_or(0)
        };

        stats.insert(
            name.clone(),
            InterfaceStats {
                name,
                rx_bytes: read("rx_bytes"),
                tx_bytes: read("tx_bytes"),
                rx_packets: read("rx_packets"),
                tx_packets: read("tx_packets"),
                rx_errors: read("rx_errors"),
                tx_errors: read("tx_errors"),
                rx_drops: read("rx_dropped"),
                tx_drops: read("tx_dropped"),
            },
        );
    }

    Ok(stats)
}

pub fn collect_interface_info() -> Result<Vec<InterfaceInfo>> {
    let mut interfaces = Vec::new();
    let net_dir = Path::new("/sys/class/net");

    for entry in fs::read_dir(net_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let base = net_dir.join(&name);

        let is_up = fs::read_to_string(base.join("operstate"))
            .unwrap_or_default()
            .trim()
            == "up";

        let mtu = fs::read_to_string(base.join("mtu"))
            .unwrap_or_default()
            .trim()
            .parse()
            .ok();

        let mac = fs::read_to_string(base.join("address"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| s != "00:00:00:00:00:00");

        // Get IP addresses from `ip addr show <name>` on Linux
        let (ipv4, ipv6) = get_ip_addresses(&name);

        interfaces.push(InterfaceInfo {
            name,
            ipv4,
            ipv6,
            mac,
            mtu,
            is_up,
        });
    }

    Ok(interfaces)
}

fn get_ip_addresses(iface: &str) -> (Option<String>, Option<String>) {
    let output = std::process::Command::new("ip")
        .args(["addr", "show", iface])
        .output();

    let Ok(output) = output else {
        return (None, None);
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut ipv4 = None;
    let mut ipv6 = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            ipv4 = trimmed
                .split_whitespace()
                .nth(1)
                .map(|s| s.split('/').next().unwrap_or(s).to_string());
        } else if trimmed.starts_with("inet6 ") && ipv6.is_none() {
            ipv6 = trimmed
                .split_whitespace()
                .nth(1)
                .map(|s| s.split('/').next().unwrap_or(s).to_string());
        }
    }

    (ipv4, ipv6)
}
