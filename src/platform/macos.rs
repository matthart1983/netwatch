use super::{InterfaceInfo, InterfaceStats};
use anyhow::Result;
use std::collections::HashMap;
use std::process::Command;

pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    let output = Command::new("netstat").args(["-ib"]).output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut stats: HashMap<String, InterfaceStats> = HashMap::new();

    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // netstat -ib columns: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
        if cols.len() < 11 {
            continue;
        }

        let name = cols[0].to_string();
        // Skip duplicate rows (netstat outputs one row per address per interface)
        // Keep the first row which has the link-level stats
        if stats.contains_key(&name) {
            continue;
        }

        let rx_packets = cols[4].parse().unwrap_or(0);
        let rx_errors = cols[5].parse().unwrap_or(0);
        let rx_bytes = cols[6].parse().unwrap_or(0);
        let tx_packets = cols[7].parse().unwrap_or(0);
        let tx_errors = cols[8].parse().unwrap_or(0);
        let tx_bytes = cols[9].parse().unwrap_or(0);

        stats.insert(
            name.clone(),
            InterfaceStats {
                name,
                rx_bytes,
                tx_bytes,
                rx_packets,
                tx_packets,
                rx_errors,
                tx_errors,
                rx_drops: 0,
                tx_drops: 0,
            },
        );
    }

    Ok(stats)
}

pub fn collect_interface_info() -> Result<Vec<InterfaceInfo>> {
    let output = Command::new("ifconfig").output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut interfaces = Vec::new();
    let mut current: Option<InterfaceInfo> = None;

    for line in text.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(':') {
            if let Some(iface) = current.take() {
                interfaces.push(iface);
            }
            let name = line.split(':').next().unwrap_or("").to_string();
            let is_up = line.contains("UP");
            let mtu = line
                .split_whitespace()
                .skip_while(|s| *s != "mtu")
                .nth(1)
                .and_then(|s| s.parse().ok());
            current = Some(InterfaceInfo {
                name,
                ipv4: None,
                ipv6: None,
                mac: None,
                mtu,
                is_up,
            });
        } else if let Some(ref mut iface) = current {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") {
                iface.ipv4 = trimmed
                    .split_whitespace()
                    .nth(1)
                    .map(|s| s.to_string());
            } else if trimmed.starts_with("inet6 ") {
                if iface.ipv6.is_none() {
                    iface.ipv6 = trimmed
                        .split_whitespace()
                        .nth(1)
                        .map(|s| s.split('%').next().unwrap_or(s).to_string());
                }
            } else if trimmed.starts_with("ether ") {
                iface.mac = trimmed
                    .split_whitespace()
                    .nth(1)
                    .map(|s| s.to_string());
            }
        }
    }

    if let Some(iface) = current.take() {
        interfaces.push(iface);
    }

    Ok(interfaces)
}
