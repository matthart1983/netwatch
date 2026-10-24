use super::{InterfaceInfo, InterfaceStats};
use anyhow::Result;
use std::collections::HashMap;
use std::process::Command;

mod iphlpapi;
pub mod tcp_table;

pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    // Try PowerShell Get-NetAdapterStatistics for per-interface stats
    if let Ok(stats) = collect_stats_powershell() {
        return Ok(stats);
    }

    // Fallback: parse netstat -e for aggregate stats
    collect_stats_netstat()
}

/// Run a PowerShell command and return its stdout as text.
///
/// Windows PowerShell writes to a pipe in the console's OEM code page — CP866
/// on a Russian install, CP936 on a Chinese one — so an adapter named
/// "Беспроводная сеть" reached us as mojibake and never matched the name the
/// interface list uses. Switching the output encoding first makes stdout
/// UTF-8 whatever the locale (no BOM is written to a redirected stream).
fn powershell(command: &str) -> Option<String> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {command}"),
        ])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn collect_stats_powershell() -> Result<HashMap<String, InterfaceStats>> {
    let Some(text) = powershell("Get-NetAdapterStatistics | ConvertTo-Json") else {
        anyhow::bail!("PowerShell Get-NetAdapterStatistics failed");
    };

    let mut stats = HashMap::new();

    // Output may be a single object or an array
    let json: serde_json::Value = serde_json::from_str(&text)?;

    let adapters = match &json {
        serde_json::Value::Array(arr) => arr.clone(),
        obj @ serde_json::Value::Object(_) => vec![obj.clone()],
        _ => return Ok(stats),
    };

    for adapter in &adapters {
        let name = adapter["Name"].as_str().unwrap_or_default().to_string();
        if name.is_empty() {
            continue;
        }

        stats.insert(
            name.clone(),
            InterfaceStats {
                name,
                rx_bytes: adapter["ReceivedBytes"].as_u64().unwrap_or(0),
                tx_bytes: adapter["SentBytes"].as_u64().unwrap_or(0),
                rx_packets: adapter["ReceivedUnicastPackets"].as_u64().unwrap_or(0),
                tx_packets: adapter["SentUnicastPackets"].as_u64().unwrap_or(0),
                rx_errors: adapter["ReceivedPacketErrors"].as_u64().unwrap_or(0),
                tx_errors: adapter["OutboundPacketErrors"].as_u64().unwrap_or(0),
                rx_drops: adapter["ReceivedDiscards"].as_u64().unwrap_or(0),
                tx_drops: adapter["OutboundDiscards"].as_u64().unwrap_or(0),
                signal_dbm: None,
                tx_retries: None,
            },
        );
    }

    Ok(stats)
}

fn collect_stats_netstat() -> Result<HashMap<String, InterfaceStats>> {
    let output = Command::new("netstat").args(["-e"]).output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut stats = HashMap::new();

    // netstat -e outputs aggregate stats in a table like:
    //                         Received            Sent
    // Bytes                 1234567             7654321
    // Unicast packets          1234                4321
    // ...Errors                   0                   0
    // ...Discards                 0                   0
    let mut rx_bytes = 0u64;
    let mut tx_bytes = 0u64;
    let mut rx_packets = 0u64;
    let mut tx_packets = 0u64;
    let mut rx_errors = 0u64;
    let mut tx_errors = 0u64;
    let mut rx_drops = 0u64;
    let mut tx_drops = 0u64;

    for line in text.lines() {
        let trimmed = line.trim();
        let cols: Vec<&str> = trimmed.split_whitespace().collect();

        if trimmed.starts_with("Bytes") && cols.len() >= 3 {
            rx_bytes = cols[1].parse().unwrap_or(0);
            tx_bytes = cols[2].parse().unwrap_or(0);
        } else if trimmed.starts_with("Unicast") && cols.len() >= 4 {
            rx_packets = cols[2].parse().unwrap_or(0);
            tx_packets = cols[3].parse().unwrap_or(0);
        } else if trimmed.starts_with("Errors") && cols.len() >= 3 {
            rx_errors = cols[1].parse().unwrap_or(0);
            tx_errors = cols[2].parse().unwrap_or(0);
        } else if trimmed.starts_with("Discards") && cols.len() >= 3 {
            rx_drops = cols[1].parse().unwrap_or(0);
            tx_drops = cols[2].parse().unwrap_or(0);
        }
    }

    stats.insert(
        "aggregate".to_string(),
        InterfaceStats {
            name: "aggregate".to_string(),
            rx_bytes,
            tx_bytes,
            rx_packets,
            tx_packets,
            rx_errors,
            tx_errors,
            rx_drops,
            tx_drops,
            signal_dbm: None,
            tx_retries: None,
        },
    );

    Ok(stats)
}

/// Interfaces from `GetAdaptersAddresses`, falling back to parsing ipconfig.
///
/// ipconfig's output is translated: on a Russian install the header reads
/// "Адаптер Ethernet Ethernet:" and the address line "IPv4-адрес", and it is
/// written in the console's OEM code page besides. The English-only parser
/// below then names the adapter after the whole mangled header, finds no
/// address, and every name it returns matches nothing in Get-NetAdapter — so
/// the dashboard shows no interfaces and capture cannot resolve an Npcap
/// device. The API reports the same friendly names in UTF-16 and numeric
/// status/type fields, in any display language, in a few milliseconds.
pub fn collect_interface_info() -> Result<Vec<InterfaceInfo>> {
    match iphlpapi::adapters() {
        Ok(info) => Ok(info),
        Err(_) => collect_interface_info_ipconfig(),
    }
}

fn collect_interface_info_ipconfig() -> Result<Vec<InterfaceInfo>> {
    let output = Command::new("ipconfig").args(["/all"]).output()?;
    let text = String::from_utf8_lossy(&output.stdout);

    let mtu_map = collect_mtu_map();

    let mut interfaces = Vec::new();
    let mut current: Option<InterfaceInfo> = None;

    for line in text.lines() {
        // Adapter header lines don't start with whitespace and end with ':'
        // e.g. "Ethernet adapter Ethernet:"
        // e.g. "Wireless LAN adapter Wi-Fi:"
        if !line.starts_with(' ') && !line.starts_with('\t') && line.ends_with(':') {
            if let Some(iface) = current.take() {
                interfaces.push(iface);
            }
            let is_wireless = if line.starts_with("Wireless LAN") {
                Some(true)
            } else if line.starts_with("Ethernet adapter") {
                Some(false)
            } else {
                None
            };
            // Extract the adapter name after "adapter " if present, else use the full line
            let name = if let Some(pos) = line.find("adapter ") {
                line[pos + 8..].trim_end_matches(':').trim().to_string()
            } else {
                line.trim_end_matches(':').trim().to_string()
            };
            let mtu = mtu_map.get(&name).copied();
            current = Some(InterfaceInfo {
                name,
                ipv4: None,
                ipv6: None,
                mac: None,
                mtu,
                is_up: true, // assume up; will set false if "Media disconnected"
                is_wireless,
            });
        } else if let Some(ref mut iface) = current {
            let trimmed = line.trim();

            if trimmed.contains("Media disconnected") {
                iface.is_up = false;
            } else if trimmed.contains("IPv4 Address") || trimmed.contains("IP Address") {
                // "IPv4 Address. . . . . . . . . . . : 192.168.1.100(Preferred)"
                if let Some(val) = extract_value(trimmed) {
                    // Strip "(Preferred)" or "(Tentative)" suffixes
                    let addr = val.split('(').next().unwrap_or(&val).trim().to_string();
                    if iface.ipv4.is_none() {
                        iface.ipv4 = Some(addr);
                    }
                }
            } else if trimmed.contains("IPv6 Address") || trimmed.contains("Link-local IPv6") {
                if let Some(val) = extract_value(trimmed) {
                    let addr = val.split('%').next().unwrap_or(&val);
                    let addr = addr.split('(').next().unwrap_or(addr).trim().to_string();
                    if iface.ipv6.is_none() {
                        iface.ipv6 = Some(addr);
                    }
                }
            } else if trimmed.contains("Physical Address") {
                if let Some(val) = extract_value(trimmed) {
                    // Windows uses '-' separators (e.g. "AA-BB-CC-DD-EE-FF"), convert to ':'
                    let mac = val.replace('-', ":");
                    iface.mac = Some(mac);
                }
            }
        }
    }

    if let Some(iface) = current.take() {
        interfaces.push(iface);
    }

    Ok(interfaces)
}

/// Parse "Key . . . . : Value" lines from ipconfig output
fn extract_value(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.splitn(2, ':').collect();
    if parts.len() == 2 {
        let val = parts[1].trim().to_string();
        if val.is_empty() {
            None
        } else {
            Some(val)
        }
    } else {
        None
    }
}

/// Collect MTU values from `netsh interface ipv4 show subinterfaces`
fn collect_mtu_map() -> HashMap<String, u32> {
    let mut map = HashMap::new();

    let output = Command::new("netsh")
        .args(["interface", "ipv4", "show", "subinterfaces"])
        .output();

    let Ok(output) = output else {
        return map;
    };

    let text = String::from_utf8_lossy(&output.stdout);

    // Output format:
    //    MTU  MediaSenseState   Bytes In  Bytes Out  Interface
    // ------  ---------------  ---------  ---------  -------------
    //   1500                1  123456789   98765432  Ethernet
    for line in text.lines() {
        let trimmed = line.trim();
        // Skip header and separator lines
        if trimmed.is_empty() || trimmed.starts_with("MTU") || trimmed.starts_with("---") {
            continue;
        }

        let cols: Vec<&str> = trimmed.splitn(5, char::is_whitespace).collect();
        if cols.len() < 5 {
            // Try splitting differently — the interface name is the last column
            // and columns are whitespace-separated with varying widths
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 5 {
                if let Ok(mtu) = parts[0].parse::<u32>() {
                    // Interface name is everything from index 4 onward
                    let iface_name = parts[4..].join(" ");
                    map.insert(iface_name, mtu);
                }
            }
            continue;
        }

        if let Ok(mtu) = cols[0].parse::<u32>() {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 5 {
                let iface_name = parts[4..].join(" ");
                map.insert(iface_name, mtu);
            }
        }
    }

    map
}

/// Friendly adapter name -> interface GUID, from `Get-NetAdapter`. The GUID is
/// what Npcap puts in its device name, so this is the one reliable bridge from
/// the names ipconfig shows to the device pcap opens (issue #51). Empty when
/// PowerShell is unavailable; the caller falls back to matching by address.
pub fn adapter_guids() -> HashMap<String, String> {
    powershell(
        "Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceGuid | ConvertTo-Json -Compress",
    )
    .map(|text| super::npcap_device::parse_adapter_guids(&text))
    .unwrap_or_default()
}

/// Friendly name of the adapter carrying the lowest-metric IPv4 default
/// route. `InterfaceAlias` is the same name ipconfig and Get-NetAdapter use.
pub fn default_route_interface() -> Option<String> {
    let alias = powershell(
        "(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
         | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } \
         | Select-Object -First 1).InterfaceAlias",
    )?;
    let alias = alias.trim().to_string();
    (!alias.is_empty()).then_some(alias)
}
