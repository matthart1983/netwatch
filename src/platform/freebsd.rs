//! FreeBSD platform backend.
//!
//! FreeBSD is BSD-derived like macOS, so this leans on the same base-system
//! tools (`netstat`, `ifconfig`, `route`, `getifaddrs`) rather than inventing
//! new ones. It is adapted from, not shared with, `macos.rs` — that module is
//! `#[cfg(target_os = "macos")]`'d out entirely on this target, so nothing in
//! it is importable here.
//!
//! **Nothing in this file has been run against a real FreeBSD host** (this
//! was written without one available). Every parser below is written
//! defensively (column-count/shape checks, no indexing past a verified
//! length) and flags its specific uncertainty in a comment. The new
//! `vmactions/freebsd-vm` CI job is what proves these right or wrong — check
//! its `cargo test` output first if interfaces/connections look wrong on a
//! real BSD box.

use super::{InterfaceInfo, InterfaceStats};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::process::Command;

pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    let output = Command::new("netstat").args(["-ibn"]).output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_netstat_output(&text))
}

/// UNVERIFIED column layout. Written from documented FreeBSD `netstat -ibn`
/// output: `Name Mtu Network Address Ipkts Ierrs Idrop Ibytes Opkts Oerrs
/// Obytes Coll` — FreeBSD carries an `Idrop` column macOS's `-ibn` lacks
/// (see [`super::IFACE_DROPS_COUNTED`]'s doc comment, which already singles
/// out macOS as the one platform with no drop column — implying every other
/// platform, FreeBSD included, is expected to have one). If a live dump
/// disagrees, recheck this column count/offset table first.
fn parse_netstat_output(text: &str) -> HashMap<String, InterfaceStats> {
    let mut stats: HashMap<String, InterfaceStats> = HashMap::new();

    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 12 {
            continue;
        }

        let name = cols[0].to_string();
        // Skip duplicate rows (netstat outputs one row per address per
        // interface) — keep the first row, which has the link-level stats.
        if stats.contains_key(&name) {
            continue;
        }

        let rx_packets = cols[4].parse().unwrap_or(0);
        let rx_errors = cols[5].parse().unwrap_or(0);
        let rx_drops = cols[6].parse().unwrap_or(0);
        let rx_bytes = cols[7].parse().unwrap_or(0);
        let tx_packets = cols[8].parse().unwrap_or(0);
        let tx_errors = cols[9].parse().unwrap_or(0);
        let tx_bytes = cols[10].parse().unwrap_or(0);

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
                rx_drops,
                tx_drops: 0,
                signal_dbm: None,
                tx_retries: None,
            },
        );
    }

    stats
}

pub fn collect_interface_info() -> Result<Vec<InterfaceInfo>> {
    // The kernel's own IFF_UP is the authority on "up"; the ifconfig text is
    // only trusted for addresses, MTU and media. A failed or empty ifconfig
    // must not blank the dashboard — every panel that lists "up" interfaces
    // filters on `is_up` — so fall back to bare entries from getifaddrs.
    let up = up_interfaces_from_getifaddrs();
    let mut interfaces = match Command::new("ifconfig").output() {
        Ok(output) => parse_ifconfig_output(&String::from_utf8_lossy(&output.stdout)),
        Err(_) => Vec::new(),
    };
    if interfaces.is_empty() {
        interfaces = up
            .names
            .iter()
            .map(|name| InterfaceInfo {
                name: name.clone(),
                ipv4: None,
                ipv6: None,
                mac: None,
                mtu: None,
                is_up: false,
                is_wireless: None,
            })
            .collect();
    }
    for iface in &mut interfaces {
        if up.up.contains(&iface.name) {
            iface.is_up = true;
        }
    }
    Ok(interfaces)
}

struct GetifaddrsFlags {
    /// Every interface name the kernel reports, in first-seen order.
    names: Vec<String>,
    /// The subset with `IFF_UP` set.
    up: HashSet<String>,
}

fn up_interfaces_from_getifaddrs() -> GetifaddrsFlags {
    use std::ffi::CStr;

    let mut out = GetifaddrsFlags {
        names: Vec::new(),
        up: HashSet::new(),
    };
    let mut ifap: *mut nix::libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `ifap` with an owned list we free below;
    // every pointer is null-checked before it is read.
    if unsafe { nix::libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
        return out;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        let entry = unsafe { &*cur };
        cur = entry.ifa_next;
        if entry.ifa_name.is_null() {
            continue;
        }
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        if (entry.ifa_flags as u32) & (nix::libc::IFF_UP as u32) != 0 {
            out.up.insert(name.clone());
        }
        if !out.names.contains(&name) {
            out.names.push(name);
        }
    }
    // SAFETY: `ifap` came from a successful `getifaddrs` and is freed once.
    unsafe { nix::libc::freeifaddrs(ifap) };
    out
}

/// True when the `<...>` flag list on an `ifconfig` header line contains the
/// exact `UP` token. A substring test would also match `LOWER_UP`, so a link
/// that is administratively down but has carrier would read as up.
fn header_flags_contain_up(line: &str) -> bool {
    line.split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .is_some_and(|(flags, _)| flags.split(',').any(|f| f == "UP"))
}

/// Adapted from macOS's ifconfig parser — same tab-indented continuation
/// lines, same `inet`/`inet6`/`ether` prefixes. Two differences handled:
///
/// - FreeBSD inserts `metric 0` between the flags and `mtu`
///   (`flags=...<...> metric 0 mtu 1500`). Harmless here: the `mtu` token is
///   found by searching for the literal word, not a fixed position, so an
///   extra token ahead of it doesn't shift anything.
/// - There is no `networksetup` equivalent on FreeBSD, so Wi-Fi detection
///   reads the interface's own `media:` line instead of a second command.
///
/// UNVERIFIED: the exact `media:` wording for an 802.11 interface (`media:
/// IEEE 802.11 Wireless Ethernet ...`) is from documentation, not a live
/// wlan device, and the CI runner (QEMU) almost certainly has no wireless
/// hardware, so this path may go entirely untested there too — worth a
/// manual check against real FreeBSD wlan hardware if anyone has it.
fn parse_ifconfig_output(text: &str) -> Vec<InterfaceInfo> {
    let mut interfaces = Vec::new();
    let mut current: Option<InterfaceInfo> = None;

    for line in text.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(':') {
            if let Some(iface) = current.take() {
                interfaces.push(iface);
            }
            let name = line.split(':').next().unwrap_or("").to_string();
            let is_up = header_flags_contain_up(line);
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
            } else if let Some(media) = trimmed.strip_prefix("media:") {
                iface.is_wireless = Some(media.to_ascii_uppercase().contains("802.11"));
            }
        }
    }

    if let Some(iface) = current.take() {
        interfaces.push(iface);
    }

    interfaces
}

/// Name of the interface carrying the default route, if any.
///
/// Same `route(8)` shape as macOS (shared BSD ancestry): `route -n get
/// default` prints an `interface: <name>` line. Logic duplicated rather than
/// imported — `macos.rs` isn't compiled on this target.
pub fn default_route_interface() -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    parse_route_get_interface(&String::from_utf8_lossy(&output.stdout))
}

fn parse_route_get_interface(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        l.trim()
            .strip_prefix("interface:")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

/// `ifi_baudrate` from `getifaddrs`'s `AF_LINK` entry — ported from
/// `platform::mod`'s `#[cfg(target_os = "macos")]` block, since FreeBSD's
/// `<net/if.h>` defines the same `struct if_data` with the same field,
/// exposed the same way through `nix::libc`.
pub fn link_speed_bps(iface: &str) -> Option<u64> {
    use std::ffi::CStr;

    let mut ifap: *mut nix::libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `ifap` with an owned list we free below;
    // every pointer is null-checked before it is read.
    if unsafe { nix::libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
        return None;
    }
    let mut speed = None;
    let mut cur = ifap;
    while !cur.is_null() {
        let entry = unsafe { &*cur };
        cur = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_data.is_null() {
            continue;
        }
        // Only the AF_LINK entry carries `if_data`; the AF_INET ones don't.
        if i32::from(unsafe { (*entry.ifa_addr).sa_family }) != nix::libc::AF_LINK {
            continue;
        }
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        if name.to_string_lossy() != iface {
            continue;
        }
        let data = unsafe { &*(entry.ifa_data as *const nix::libc::if_data) };
        if data.ifi_baudrate > 0 {
            speed = Some(u64::from(data.ifi_baudrate));
        }
        break;
    }
    // SAFETY: `ifap` came from a successful `getifaddrs` and is freed once.
    unsafe { nix::libc::freeifaddrs(ifap) };
    speed
}

#[cfg(test)]
mod tests {
    use super::*;

    // Representative but UNVERIFIED sample data — see module doc comment.
    const NETSTAT_OUTPUT: &str = "\
Name   Mtu   Network       Address            Ipkts Ierrs Idrop     Ibytes Opkts Oerrs     Obytes  Coll
lo0    16384 <Link#1>                         517138     0     0   83732104 517138     0   83732104     0
lo0    16384 127           127.0.0.1          517138     0     0   83732104 517138     0   83732104     0
em0     1500 <Link#2>      aa:bb:cc:dd:ee:ff 1234567     0     5  987654321 234567     2  876543210     0";

    #[test]
    fn parse_netstat_basic_fields() {
        let stats = parse_netstat_output(NETSTAT_OUTPUT);
        let lo0 = stats.get("lo0").expect("lo0 should be present");
        assert_eq!(lo0.rx_packets, 517_138);
        assert_eq!(lo0.rx_bytes, 83_732_104);
        assert_eq!(lo0.tx_bytes, 83_732_104);
    }

    #[test]
    fn parse_netstat_reads_the_idrop_column() {
        let stats = parse_netstat_output(NETSTAT_OUTPUT);
        let em0 = stats.get("em0").expect("em0 should be present");
        assert_eq!(
            em0.rx_drops, 5,
            "FreeBSD's netstat -ibn carries an extra Idrop column macOS's lacks"
        );
        assert_eq!(em0.tx_errors, 2);
        assert_eq!(em0.rx_bytes, 987_654_321);
    }

    #[test]
    fn parse_netstat_deduplicates_interfaces() {
        let stats = parse_netstat_output(NETSTAT_OUTPUT);
        // lo0 appears twice; the second (identical) row must not overwrite.
        assert_eq!(stats.len(), 2);
    }

    #[test]
    fn parse_netstat_empty_input() {
        assert!(parse_netstat_output("").is_empty());
    }

    #[test]
    fn parse_netstat_header_only() {
        let stats = parse_netstat_output(
            "Name  Mtu  Network  Address  Ipkts Ierrs Idrop Ibytes Opkts Oerrs Obytes Coll\n",
        );
        assert!(stats.is_empty());
    }

    const IFCONFIG_OUTPUT: &str = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
em0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
\tether aa:bb:cc:dd:ee:ff
\tinet6 fe80::aabb:ccff:fedd:eeff%em0 prefixlen 64 scopeid 0x2
\tinet 10.0.0.50 netmask 0xffffff00 broadcast 10.0.0.255
\tmedia: Ethernet autoselect (1000baseT <full-duplex>)
\tstatus: active
wlan0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
\tether 11:22:33:44:55:66
\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
\tmedia: IEEE 802.11 Wireless Ethernet MCS mode 11ng <hostap>
\tstatus: running
em1: flags=8822<BROADCAST,SIMPLEX,MULTICAST> metric 0 mtu 1500
\tether 22:33:44:55:66:77";

    #[test]
    fn parse_ifconfig_interface_count() {
        assert_eq!(parse_ifconfig_output(IFCONFIG_OUTPUT).len(), 4);
    }

    #[test]
    fn parse_ifconfig_up_flag() {
        let ifaces = parse_ifconfig_output(IFCONFIG_OUTPUT);
        assert!(ifaces.iter().find(|i| i.name == "lo0").unwrap().is_up);
        assert!(
            !ifaces.iter().find(|i| i.name == "em1").unwrap().is_up,
            "em1 lacks UP flag"
        );
    }

    #[test]
    fn up_flag_is_an_exact_token_not_a_substring() {
        assert!(header_flags_contain_up(
            "vtnet0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500"
        ));
        assert!(!header_flags_contain_up(
            "em1: flags=1008802<BROADCAST,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500"
        ));
        assert!(!header_flags_contain_up("em1: no flags here"));
    }

    /// Runs the real `ifconfig`/`netstat`/`getifaddrs` on the host. Every
    /// FreeBSD box has `lo0` up, so it must come back up, and every interface
    /// that carries counters must also have an info entry — the dashboard
    /// joins the two by name.
    #[test]
    fn live_info_marks_loopback_up_and_joins_stats_by_name() {
        let info = collect_interface_info().expect("interface info");
        let lo0 = info.iter().find(|i| i.name == "lo0").expect("lo0 in info");
        assert!(lo0.is_up, "lo0 must be up: {info:?}");
        let stats = collect_interface_stats().expect("interface stats");
        for name in stats.keys() {
            assert!(
                info.iter().any(|i| &i.name == name),
                "{name} has counters but no info entry: {info:?}"
            );
        }
    }

    #[test]
    fn parse_ifconfig_metric_does_not_shift_mtu() {
        let ifaces = parse_ifconfig_output(IFCONFIG_OUTPUT);
        assert_eq!(
            ifaces.iter().find(|i| i.name == "lo0").unwrap().mtu,
            Some(16_384)
        );
        assert_eq!(
            ifaces.iter().find(|i| i.name == "em0").unwrap().mtu,
            Some(1_500)
        );
    }

    #[test]
    fn parse_ifconfig_addresses() {
        let ifaces = parse_ifconfig_output(IFCONFIG_OUTPUT);
        let em0 = ifaces.iter().find(|i| i.name == "em0").unwrap();
        assert_eq!(em0.ipv4.as_deref(), Some("10.0.0.50"));
        assert_eq!(em0.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(em0.ipv6.as_deref(), Some("fe80::aabb:ccff:fedd:eeff"));
    }

    #[test]
    fn parse_ifconfig_media_line_detects_wireless() {
        let ifaces = parse_ifconfig_output(IFCONFIG_OUTPUT);
        assert_eq!(
            ifaces.iter().find(|i| i.name == "em0").unwrap().is_wireless,
            Some(false)
        );
        assert_eq!(
            ifaces
                .iter()
                .find(|i| i.name == "wlan0")
                .unwrap()
                .is_wireless,
            Some(true)
        );
        assert_eq!(
            ifaces.iter().find(|i| i.name == "lo0").unwrap().is_wireless,
            None,
            "no media line on loopback — stay None rather than guess"
        );
        assert_eq!(
            ifaces.iter().find(|i| i.name == "em1").unwrap().is_wireless,
            None,
            "no media line printed (link down) — stay None rather than guess"
        );
    }

    #[test]
    fn parse_ifconfig_empty_input() {
        assert!(parse_ifconfig_output("").is_empty());
    }

    #[test]
    fn parse_route_get_interface_typical() {
        let out = "\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: em0
      flags: <UP,GATEWAY,DONE,STATIC>
";
        assert_eq!(parse_route_get_interface(out).as_deref(), Some("em0"));
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
