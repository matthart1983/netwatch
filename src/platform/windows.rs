use super::{ip_helper, InterfaceInfo, InterfaceStats};
use anyhow::Result;
use std::collections::HashMap;
use std::process::Command;

pub mod icmp;
mod iphlpapi;
pub mod tcp_table;

pub use iphlpapi::{default_gateway, dns_servers};

/// Per-interface counters from `GetIfTable2`, keyed by the names
/// [`collect_interface_info`] returns, plus any NIC with IP unbound under
/// its own name, as Get-NetAdapterStatistics reported it.
///
/// This runs every tick. It used to start PowerShell for
/// Get-NetAdapterStatistics each time, 300-800 ms of process start-up per
/// call, where the API answers in-process. PowerShell is kept only for when
/// the API call fails. `netstat -e` no longer follows it. Its one
/// machine-wide row matched no interface, and only an English install
/// printed the labels its parser looked for.
pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    if let Ok(stats) = iphlpapi::interface_stats() {
        return Ok(stats);
    }
    collect_stats_powershell()
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
    parse_adapter_statistics(&text)
}

/// Get-NetAdapterStatistics' JSON, one object or an array of them, as
/// `InterfaceStats`.
///
/// The counters go through the API path's mapping, multicast plus broadcast
/// being its non-unicast, so both paths count packets the same way. Both
/// key the same names, and a tick served from here that counted unicast
/// only would lower every packet series the API serves: Prometheus reads
/// that as a counter reset and counts the whole total again as new traffic.
fn parse_adapter_statistics(text: &str) -> Result<HashMap<String, InterfaceStats>> {
    let json: serde_json::Value = serde_json::from_str(text)?;
    let adapters = match &json {
        serde_json::Value::Array(arr) => arr.as_slice(),
        obj @ serde_json::Value::Object(_) => std::slice::from_ref(obj),
        _ => &[],
    };

    let mut stats = HashMap::new();
    for adapter in adapters {
        let name = adapter["Name"].as_str().unwrap_or_default().to_string();
        if name.is_empty() {
            continue;
        }
        let n = |key: &str| adapter[key].as_u64().unwrap_or(0);
        let counters = ip_helper::IfCounters {
            in_octets: n("ReceivedBytes"),
            in_ucast_pkts: n("ReceivedUnicastPackets"),
            in_nucast_pkts: n("ReceivedMulticastPackets")
                .saturating_add(n("ReceivedBroadcastPackets")),
            in_discards: n("ReceivedDiscards"),
            in_errors: n("ReceivedPacketErrors"),
            out_octets: n("SentBytes"),
            out_ucast_pkts: n("SentUnicastPackets"),
            out_nucast_pkts: n("SentMulticastPackets").saturating_add(n("SentBroadcastPackets")),
            out_discards: n("OutboundDiscards"),
            out_errors: n("OutboundPacketErrors"),
        };
        stats.insert(name.clone(), ip_helper::interface_stats(&name, &counters));
    }
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

// locale: fallback-only. GetAdaptersAddresses is tried first.
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

/// Collect MTU values from `netsh interface ipv4 show subinterfaces`, for the
/// ipconfig fallback only: the API path takes the MTU from the adapter record.
// locale: fallback-only. GetAdaptersAddresses is tried first.
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

/// Friendly adapter name -> interface GUID. The GUID is what Npcap puts in its
/// device name, so this is the one reliable bridge from the names the
/// interface list shows to the device pcap opens (issue #51).
///
/// `GetAdaptersAddresses` reports it as each adapter's `AdapterName`.
/// `Get-NetAdapter` is the fallback when that call fails; empty when
/// PowerShell is unavailable too, and the caller then matches by address.
pub fn adapter_guids() -> HashMap<String, String> {
    if let Ok(guids) = iphlpapi::adapter_guids() {
        return guids;
    }
    powershell(
        "Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceGuid | ConvertTo-Json -Compress",
    )
    .map(|text| super::npcap_device::parse_adapter_guids(&text))
    .unwrap_or_default()
}

/// Friendly name of the adapter carrying the best default route, from the
/// routing table: IPv4 first, lowest route plus interface metric, as
/// `ip_helper::default_routes` explains. Get-NetRoute is the fallback when
/// the API call fails.
pub fn default_route_interface() -> Option<String> {
    match iphlpapi::default_route_interface() {
        Ok(name) => name,
        Err(_) => default_route_interface_powershell(),
    }
}

/// The lowest-metric IPv4 default route's `InterfaceAlias`, which is the same
/// name ipconfig and Get-NetAdapter use.
fn default_route_interface_powershell() -> Option<String> {
    let alias = powershell(
        "(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
         | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } \
         | Select-Object -First 1).InterfaceAlias",
    )?;
    let alias = alias.trim().to_string();
    (!alias.is_empty()).then_some(alias)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fallback counts packets as the API path does, so a tick served
    /// by either moves no counter backwards.
    #[test]
    fn powershell_statistics_count_packets_like_the_api() {
        let text = r#"[
            {"Name": "Ethernet", "ReceivedBytes": 1000000, "SentBytes": 500000,
             "ReceivedUnicastPackets": 900, "ReceivedMulticastPackets": 60,
             "ReceivedBroadcastPackets": 40, "SentUnicastPackets": 450,
             "SentMulticastPackets": 30, "SentBroadcastPackets": 20,
             "ReceivedPacketErrors": 2, "OutboundPacketErrors": 4},
            {"Name": "", "ReceivedBytes": 1}
        ]"#;
        let stats = parse_adapter_statistics(text).unwrap();
        assert_eq!(stats.len(), 1);
        let ps = &stats["Ethernet"];
        let api = ip_helper::interface_stats(
            "Ethernet",
            &ip_helper::IfCounters {
                in_octets: 1_000_000,
                in_ucast_pkts: 900,
                in_nucast_pkts: 100,
                in_errors: 2,
                out_octets: 500_000,
                out_ucast_pkts: 450,
                out_nucast_pkts: 50,
                out_errors: 4,
                ..ip_helper::IfCounters::default()
            },
        );
        assert_eq!(ps.name, api.name);
        assert_eq!((ps.rx_bytes, ps.tx_bytes), (api.rx_bytes, api.tx_bytes));
        assert_eq!((ps.rx_packets, ps.tx_packets), (1000, 500));
        assert_eq!(
            (ps.rx_packets, ps.tx_packets),
            (api.rx_packets, api.tx_packets)
        );
        assert_eq!((ps.rx_errors, ps.tx_errors), (api.rx_errors, api.tx_errors));

        // A single adapter comes as one object rather than an array.
        let one = parse_adapter_statistics(r#"{"Name": "Wi-Fi", "SentBytes": 7}"#).unwrap();
        assert_eq!(one["Wi-Fi"].tx_bytes, 7);
        assert!(parse_adapter_statistics("null").unwrap().is_empty());
    }
}
