use super::{InterfaceInfo, InterfaceStats};
use anyhow::Result;
use std::collections::HashMap;
use std::process::Command;

pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    let output = Command::new("netstat").args(["-ibn"]).output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_netstat_output(&text))
}

fn parse_netstat_output(text: &str) -> HashMap<String, InterfaceStats> {
    let mut stats: HashMap<String, InterfaceStats> = HashMap::new();

    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // netstat -ibn columns: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
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
                signal_dbm: None,
                tx_retries: None,
            },
        );
    }

    stats
}

pub fn collect_interface_info() -> Result<Vec<InterfaceInfo>> {
    let output = Command::new("ifconfig").output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut interfaces = parse_ifconfig_output(&text);

    // Supplement with hardware-port info so we can distinguish Wi-Fi from
    // wired Ethernet (incl. USB-Ethernet adapters that share the `en` prefix).
    let wireless = collect_wireless_map();
    for iface in &mut interfaces {
        if let Some(&is_wireless) = wireless.get(&iface.name) {
            iface.is_wireless = Some(is_wireless);
        }
    }

    Ok(interfaces)
}

fn parse_ifconfig_output(text: &str) -> Vec<InterfaceInfo> {
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
                is_wireless: None,
            });
        } else if let Some(ref mut iface) = current {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") {
                iface.ipv4 = trimmed.split_whitespace().nth(1).map(|s| s.to_string());
            } else if trimmed.starts_with("inet6 ") {
                if iface.ipv6.is_none() {
                    iface.ipv6 = trimmed
                        .split_whitespace()
                        .nth(1)
                        .map(|s| s.split('%').next().unwrap_or(s).to_string());
                }
            } else if trimmed.starts_with("ether ") {
                iface.mac = trimmed.split_whitespace().nth(1).map(|s| s.to_string());
            } else if trimmed == "status: inactive" {
                // The UP flag is the admin state: an interface with its cable
                // pulled, or a radio with no network, keeps it. The media
                // status is what says the link is gone. Interfaces with no
                // media to report (lo0, utun) print no status line and stand
                // on the flag.
                iface.is_up = false;
            }
        }
    }

    if let Some(iface) = current.take() {
        interfaces.push(iface);
    }

    interfaces
}

/// Map BSD device name (e.g. `en0`, `en7`) to whether it's a Wi-Fi adapter.
/// Built from `networksetup -listallhardwareports`, whose output groups each
/// adapter as:
///
/// ```text
/// Hardware Port: Wi-Fi
/// Device: en0
/// Ethernet Address: aa:bb:cc:dd:ee:ff
/// ```
///
/// Anything labeled `Wi-Fi` (or with `AirPort` for older OSes) counts as
/// wireless; anything else with a Device line is treated as wired.
fn collect_wireless_map() -> HashMap<String, bool> {
    let mut map = HashMap::new();

    let Ok(output) = Command::new("networksetup")
        .arg("-listallhardwareports")
        .output()
    else {
        return map;
    };
    if !output.status.success() {
        return map;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    parse_hardware_ports(&text, &mut map);
    map
}

fn parse_hardware_ports(text: &str, map: &mut HashMap<String, bool>) {
    let mut current_port: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("Hardware Port:") {
            current_port = Some(val.trim().to_string());
        } else if let Some(val) = trimmed.strip_prefix("Device:") {
            let device = val.trim().to_string();
            if device.is_empty() {
                continue;
            }
            let is_wireless = current_port
                .as_deref()
                .map(|p| p.eq_ignore_ascii_case("Wi-Fi") || p.eq_ignore_ascii_case("AirPort"))
                .unwrap_or(false);
            map.insert(device, is_wireless);
        }
    }
}

/// Name of the interface carrying the default route, if any.
pub fn default_route_interface() -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    parse_route_get_interface(&String::from_utf8_lossy(&output.stdout))
}

fn parse_route_get_interface(text: &str) -> Option<String> {
    // `route -n get default` output includes a line like "  interface: en0"
    text.lines().find_map(|l| {
        l.trim()
            .strip_prefix("interface:")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const IFCONFIG_WITH_STATUS: &str = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:ff
\tinet 10.0.0.50 netmask 0xffffff00 broadcast 10.0.0.255
\tmedia: autoselect
\tstatus: active
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:00
\tmedia: autoselect (none)
\tstatus: inactive
en6: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:01
\tstatus: active
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet6 fe80::1%utun0 prefixlen 64 scopeid 0x10
";

    /// An unplugged cable leaves the UP flag set; `status: inactive` is what
    /// says the link is down.
    #[test]
    fn an_inactive_interface_is_down_whatever_its_up_flag_says() {
        let up: HashMap<String, bool> = parse_ifconfig_output(IFCONFIG_WITH_STATUS)
            .into_iter()
            .map(|i| (i.name, i.is_up))
            .collect();
        assert!(up["en0"]);
        assert!(!up["en5"], "UP flag set, media inactive");
        assert!(!up["en6"], "admin down, whatever the media says");
        assert!(up["lo0"], "no status line: the flag stands");
        assert!(up["utun0"]);
    }

    const NETSTAT_OUTPUT: &str = "\
Name       Mtu   Network       Address             Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0        16384 <Link#1>                         517138     0   83732104   517138     0   83732104     0
lo0        16384 127           127.0.0.1          517138     0   83732104   517138     0   83732104     0
lo0        16384 ::1/128       ::1                517138     0   83732104   517138     0   83732104     0
en0        1500  <Link#2>      aa:bb:cc:dd:ee:ff  1sobig     0 1234567890  2345678     0  987654321     0
en0        1500  10.0.0/24     10.0.0.50         9999999     0 1234567890  2345678     0  987654321     0
gif0*      1280  <Link#3>                              0     0          0        0     0          0     0
stf0*      1280  <Link#4>                              0     0          0        0     0          0     0
utun0      1380  <Link#5>                           12345    0    2345678    23456     0    3456789     0
utun0      1380  fe80::1%utun0 fe80::1             12345     0    2345678    23456     0    3456789     0";

    #[test]
    fn parse_netstat_basic_fields() {
        let stats = parse_netstat_output(NETSTAT_OUTPUT);

        // lo0's link-level row has no address so only 10 columns — parser
        // picks up the inet row (11 columns) instead
        let lo0 = stats.get("lo0").expect("lo0 should be present");
        assert_eq!(lo0.rx_packets, 517_138);
        assert_eq!(lo0.rx_errors, 0);
        assert_eq!(lo0.rx_bytes, 83_732_104);
        assert_eq!(lo0.tx_packets, 517_138);
        assert_eq!(lo0.tx_bytes, 83_732_104);
    }

    #[test]
    fn parse_netstat_deduplicates_interfaces() {
        let stats = parse_netstat_output(NETSTAT_OUTPUT);

        let en0 = stats.get("en0").expect("en0 should be present");
        assert_eq!(en0.rx_packets, 0, "first row has unparseable Ipkts");
        assert_eq!(en0.rx_bytes, 1_234_567_890);
        assert_eq!(en0.tx_bytes, 987_654_321);
        assert_ne!(en0.rx_packets, 9_999_999);
    }

    #[test]
    fn parse_netstat_skips_short_rows() {
        // empty address field collapses to 10 columns, below the 11-column threshold
        let stats = parse_netstat_output(NETSTAT_OUTPUT);

        assert!(!stats.contains_key("gif0*"));
        assert!(!stats.contains_key("stf0*"));
    }

    #[test]
    fn parse_netstat_unparseable_numbers_default_to_zero() {
        let stats = parse_netstat_output(NETSTAT_OUTPUT);

        let en0 = stats.get("en0").expect("en0 should be present");
        assert_eq!(en0.rx_packets, 0, "unparseable rx_packets should be 0");
        assert_eq!(en0.tx_packets, 2_345_678);
        assert_eq!(en0.rx_bytes, 1_234_567_890);
    }

    #[test]
    fn parse_netstat_empty_input() {
        let stats = parse_netstat_output("");
        assert!(stats.is_empty());
    }

    #[test]
    fn parse_netstat_header_only() {
        let stats = parse_netstat_output(
            "Name  Mtu  Network  Address  Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n",
        );
        assert!(stats.is_empty());
    }

    const IFCONFIG_OUTPUT: &str = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:ff
\tinet6 fe80::aabb:ccff:fedd:eeff%en0 prefixlen 64 secured scopeid 0x4
\tinet 10.0.0.50 netmask 0xffffff00 broadcast 10.0.0.255
en1: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
\tether 11:22:33:44:55:66";

    #[test]
    fn parse_ifconfig_interface_count() {
        let interfaces = parse_ifconfig_output(IFCONFIG_OUTPUT);
        assert_eq!(interfaces.len(), 3);
    }

    #[test]
    fn parse_ifconfig_up_flag() {
        let interfaces = parse_ifconfig_output(IFCONFIG_OUTPUT);

        let lo0 = interfaces.iter().find(|i| i.name == "lo0").unwrap();
        assert!(lo0.is_up);

        let en1 = interfaces.iter().find(|i| i.name == "en1").unwrap();
        assert!(!en1.is_up, "en1 lacks UP flag");
    }

    #[test]
    fn parse_ifconfig_addresses() {
        let interfaces = parse_ifconfig_output(IFCONFIG_OUTPUT);

        let en0 = interfaces.iter().find(|i| i.name == "en0").unwrap();
        assert_eq!(en0.ipv4.as_deref(), Some("10.0.0.50"));
        assert_eq!(en0.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        // %scope suffix stripped from fe80::aabb:ccff:fedd:eeff%en0
        assert_eq!(en0.ipv6.as_deref(), Some("fe80::aabb:ccff:fedd:eeff"));
    }

    #[test]
    fn parse_ifconfig_no_ip_addresses() {
        let interfaces = parse_ifconfig_output(IFCONFIG_OUTPUT);

        let en1 = interfaces.iter().find(|i| i.name == "en1").unwrap();
        assert_eq!(en1.ipv4, None);
        assert_eq!(en1.ipv6, None);
        assert_eq!(en1.mac.as_deref(), Some("11:22:33:44:55:66"));
    }

    #[test]
    fn parse_ifconfig_mtu() {
        let interfaces = parse_ifconfig_output(IFCONFIG_OUTPUT);

        let lo0 = interfaces.iter().find(|i| i.name == "lo0").unwrap();
        assert_eq!(lo0.mtu, Some(16_384));

        let en0 = interfaces.iter().find(|i| i.name == "en0").unwrap();
        assert_eq!(en0.mtu, Some(1_500));
    }

    #[test]
    fn parse_ifconfig_empty_input() {
        let interfaces = parse_ifconfig_output("");
        assert!(interfaces.is_empty());
    }

    const HARDWARE_PORTS_OUTPUT: &str = "\
Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: Ethernet Adapter (en7)
Device: en7
Ethernet Address: 11:22:33:44:55:66

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 36:d2:4a:74:9d:80

VLAN Configurations
===================
";

    #[test]
    fn parse_hardware_ports_flags_wifi_and_wired() {
        let mut map = HashMap::new();
        parse_hardware_ports(HARDWARE_PORTS_OUTPUT, &mut map);

        // The fix for issue #30: an `en*` USB-Ethernet adapter must not be
        // classified as Wi-Fi just because it shares the `en` prefix.
        assert_eq!(map.get("en0"), Some(&true), "en0 = Wi-Fi");
        assert_eq!(map.get("en7"), Some(&false), "en7 = wired USB-Ethernet");
        assert_eq!(map.get("bridge0"), Some(&false), "bridge0 = wired");
    }

    #[test]
    fn parse_hardware_ports_ignores_orphan_devices() {
        // "Device:" line with no preceding "Hardware Port:" — should still
        // record an entry (defaulting to non-wireless) without panicking.
        let text = "Device: en9\nEthernet Address: 00:11:22:33:44:55\n";
        let mut map = HashMap::new();
        parse_hardware_ports(text, &mut map);
        assert_eq!(map.get("en9"), Some(&false));
    }

    #[test]
    fn parse_hardware_ports_airport_legacy_label() {
        // Pre-Wi-Fi-rename macOS used "AirPort" as the hardware port label.
        let text = "Hardware Port: AirPort\nDevice: en1\n";
        let mut map = HashMap::new();
        parse_hardware_ports(text, &mut map);
        assert_eq!(map.get("en1"), Some(&true));
    }

    #[test]
    fn parse_route_get_interface_typical() {
        let out = "\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
";
        assert_eq!(parse_route_get_interface(out).as_deref(), Some("en0"));
    }

    #[test]
    fn parse_route_get_interface_none_when_absent() {
        assert_eq!(parse_route_get_interface(""), None);
        assert_eq!(
            parse_route_get_interface("route: writing to routing socket: not in table\n"),
            None
        );
    }
}
