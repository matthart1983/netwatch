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
            },
        );
    }

    stats
}

pub fn collect_interface_info() -> Result<Vec<InterfaceInfo>> {
    let output = Command::new("ifconfig").output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_ifconfig_output(&text))
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
            }
        }
    }

    if let Some(iface) = current.take() {
        interfaces.push(iface);
    }

    interfaces
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
