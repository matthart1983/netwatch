use std::process::Command;

pub struct NetworkConfig {
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    #[allow(dead_code)]
    pub hostname: String,
}

impl NetworkConfig {
    /// DNS server to use for the Health widget probe.
    ///
    /// Skips IPv6 link-local addresses (`fe80::/10`) because they require a
    /// zone identifier (`%en0`) that `IpAddr::parse` rejects, so the ICMP
    /// probe can't actually reach them — leaving the widget stuck at 100%
    /// loss even when the host's *other* DNS server is healthy. macOS in
    /// particular surfaces an IPv6 RA-discovered link-local nameserver
    /// ahead of the routable IPv4 one in `/etc/resolv.conf`.
    pub fn primary_dns(&self) -> Option<String> {
        self.dns_servers
            .iter()
            .find(|s| !is_link_local(s))
            .or_else(|| self.dns_servers.first())
            .cloned()
    }
}

fn is_link_local(addr: &str) -> bool {
    let lower = addr.trim().to_ascii_lowercase();
    lower.starts_with("fe80:") || lower.starts_with("fe80::")
}

pub struct ConfigCollector {
    pub config: NetworkConfig,
}

impl Default for ConfigCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigCollector {
    pub fn new() -> Self {
        #[cfg(unix)]
        let hostname = nix::unistd::gethostname()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        #[cfg(windows)]
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        Self {
            config: NetworkConfig {
                gateway: None,
                dns_servers: Vec::new(),
                // Topology draws it, and `sethostname` accepts any bytes.
                hostname: crate::ui::sanitize::display_owned(hostname),
            },
        }
    }

    pub fn update(&mut self) {
        self.config.gateway = collect_gateway();
        self.config.dns_servers = collect_dns();
    }
}

// FreeBSD's `netstat -rn` has the same shape: a row starting with `default`
// whose second column is the gateway, with the IPv4 `Internet:` section
// printed before the IPv6 `Internet6:` one — shared BSD routing-table
// output, same as macOS.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
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

/// The next hop of the best default route, from IP Helper's routing table.
/// `route print` is the fallback for when that call fails.
#[cfg(target_os = "windows")]
fn collect_gateway() -> Option<String> {
    match crate::platform::windows::default_gateway() {
        Ok(gateway) => gateway,
        Err(_) => {
            let output = Command::new("route")
                .args(["print", "0.0.0.0"])
                .output()
                .ok()?;
            parse_route_print_gateway(&String::from_utf8_lossy(&output.stdout))
        }
    }
}

/// The gateway from `route print 0.0.0.0`'s active routes, whose columns are
/// destination, netmask, gateway, interface and metric.
///
/// The table is not sorted by metric, so the lowest-metric default row wins
/// rather than the first. A VPN's on-link default prints "On-link" (or its
/// translation) in the gateway column, which is no address to probe, so such
/// a row is skipped. The persistent-routes section has four columns and is
/// skipped too: a persistent route is not necessarily active.
#[cfg(any(target_os = "windows", test))]
fn parse_route_print_gateway(text: &str) -> Option<String> {
    text.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 5 || cols[0] != "0.0.0.0" || cols[1] != "0.0.0.0" {
                return None;
            }
            let gateway: std::net::Ipv4Addr = cols[2].parse().ok()?;
            Some((cols[4].parse::<u32>().unwrap_or(u32::MAX), gateway))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, gateway)| gateway.to_string())
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "windows"
)))]
fn collect_gateway() -> Option<String> {
    None
}

fn collect_dns() -> Vec<String> {
    let mut servers = Vec::new();

    #[cfg(unix)]
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
                    // Format: `nameserver[0] : 192.168.1.1` or
                    // `nameserver[0] : fe80::1%en0`. Splitting on every `:`
                    // shreds IPv6 — split once on the first `:` after the
                    // closing bracket instead.
                    if let Some(rest) = trimmed.split_once(':').map(|(_, v)| v) {
                        let addr = rest.trim().to_string();
                        if !addr.is_empty() && !servers.contains(&addr) {
                            servers.push(addr);
                        }
                    }
                }
            }
        }
    }

    // Windows: from `GetAdaptersAddresses`, the default-route adapter's
    // servers first. ipconfig only when that call fails: its labels are
    // translated ("Serveurs DNS", "DNS-серверы"), so the parse below finds
    // servers on English Windows only.
    #[cfg(target_os = "windows")]
    if servers.is_empty() {
        servers = match crate::platform::windows::dns_servers() {
            Ok(servers) => servers,
            Err(_) => Command::new("ipconfig")
                .args(["/all"])
                .output()
                .map(|output| parse_ipconfig_dns(&String::from_utf8_lossy(&output.stdout)))
                .unwrap_or_default(),
        };
    }

    servers
}

/// DNS servers from English `ipconfig /all` output, each once.
///
/// The first server follows the label ("DNS Servers . . . : 192.168.1.1"),
/// and each further one sits alone on the next line. An IPv6 server contains
/// colons itself, so the value is what follows the label's " : ", not the
/// last colon, and continuation lines are recognised by parsing as an
/// address rather than by lacking a colon. A link-local server keeps its
/// zone index ("%12") and any other loses it, and Windows' fec0
/// placeholders go, as on the API path (`ip_helper::dns_server_text`).
// locale: fallback-only. GetAdaptersAddresses is tried first.
#[cfg(any(target_os = "windows", test))]
fn parse_ipconfig_dns(text: &str) -> Vec<String> {
    let mut servers = Vec::new();
    let mut in_dns = false;
    for line in text.lines() {
        let trimmed = line.trim();
        let labelled = trimmed
            .split_once(" : ")
            .or_else(|| trimmed.strip_suffix(" :").map(|label| (label, "")));
        let value = match labelled {
            Some((label, value)) => {
                in_dns = label.starts_with("DNS Server");
                value
            }
            None => trimmed,
        };
        if !in_dns {
            continue;
        }
        let (addr, zone) = value.split_once('%').unwrap_or((value, ""));
        match addr.trim().parse::<std::net::IpAddr>() {
            Ok(ip) => {
                let zone = zone.trim().parse().unwrap_or(0);
                if let Some(text) = crate::platform::ip_helper::dns_server_text(ip, zone) {
                    if !servers.contains(&text) {
                        servers.push(text);
                    }
                }
            }
            // A line that is not an address, such as the blank line before
            // the next adapter, ends the list.
            Err(_) => in_dns = false,
        }
    }
    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dns: &[&str]) -> NetworkConfig {
        NetworkConfig {
            gateway: None,
            dns_servers: dns.iter().map(|s| s.to_string()).collect(),
            hostname: "test".into(),
        }
    }

    #[test]
    fn primary_dns_prefers_routable_over_ipv6_link_local() {
        // Issue #31: macOS lists the IPv6 RA-discovered link-local
        // nameserver first, but ICMP can't reach it without a zone ID,
        // so the Health widget sat at 100% loss. We must pick the
        // routable IPv4 fallback.
        let c = cfg(&["fe80::96ea:eaff:fe05:f074", "192.168.15.1"]);
        assert_eq!(c.primary_dns().as_deref(), Some("192.168.15.1"));
    }

    #[test]
    fn primary_dns_skips_link_local_with_zone_id() {
        let c = cfg(&["fe80::1%en0", "1.1.1.1"]);
        assert_eq!(c.primary_dns().as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn primary_dns_keeps_first_when_no_routable_option() {
        let c = cfg(&["fe80::1", "fe80::2"]);
        assert_eq!(c.primary_dns().as_deref(), Some("fe80::1"));
    }

    #[test]
    fn primary_dns_keeps_global_ipv6() {
        // 2001:: is global, not link-local — keep it.
        let c = cfg(&["2001:4860:4860::8888", "192.168.1.1"]);
        assert_eq!(c.primary_dns().as_deref(), Some("2001:4860:4860::8888"));
    }

    #[test]
    fn primary_dns_empty_returns_none() {
        let c = cfg(&[]);
        assert!(c.primary_dns().is_none());
    }

    #[test]
    fn primary_dns_single_routable() {
        let c = cfg(&["192.168.1.1"]);
        assert_eq!(c.primary_dns().as_deref(), Some("192.168.1.1"));
    }

    /// English `ipconfig /all` from a dual-stack host, trimmed to the lines
    /// that matter, with an IPv6 server first and the Windows placeholders
    /// on the second adapter.
    const IPCONFIG_ALL: &str = "\
Windows IP Configuration

   Host Name . . . . . . . . . . . . : desk
   Primary Dns Suffix  . . . . . . . :
   DNS Suffix Search List. . . . . . : lan

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : lan
   IPv4 Address. . . . . . . . . . . : 192.168.1.20(Preferred)
   Default Gateway . . . . . . . . . : fe80::1%12
                                       192.168.1.1
   DNS Servers . . . . . . . . . . . : 2001:db8::53%12
                                       192.168.1.1
                                       1.1.1.1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Ethernet adapter vEthernet (WSL):

   Default Gateway . . . . . . . . . :
                                       172.29.0.1
   DNS Servers . . . . . . . . . . . : fec0:0:0:ffff::1%1
                                       fec0:0:0:ffff::2%1
                                       192.168.1.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
";

    #[test]
    fn ipconfig_dns_keeps_ipv6_servers_and_continuation_lines() {
        // The old parser split on the last ':' and kept "53%12" for the
        // first server and "1%1" for the placeholder, skipped continuation
        // lines with a colon in them, and took the second adapter's gateway
        // continuation, 172.29.0.1, for a DNS server.
        assert_eq!(
            parse_ipconfig_dns(IPCONFIG_ALL),
            ["2001:db8::53", "192.168.1.1", "1.1.1.1"]
        );
        let ipconfig = parse_ipconfig_dns(IPCONFIG_ALL);
        for server in &ipconfig {
            assert!(server.parse::<std::net::IpAddr>().is_ok(), "{server}");
        }
        let c = cfg(&ipconfig.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(c.primary_dns().as_deref(), Some("2001:db8::53"));
    }

    /// A link-local resolver keeps the zone ipconfig prints, so Health
    /// passes it over for the routable one and Diagnose leaves it out, as
    /// on the API path.
    #[test]
    fn ipconfig_dns_keeps_a_link_local_servers_zone() {
        let text = "\
   DNS Servers . . . . . . . . . . . : fe80::1%12
                                       192.168.1.1
";
        let servers = parse_ipconfig_dns(text);
        assert_eq!(servers, ["fe80::1%12", "192.168.1.1"]);
        let c = cfg(&servers.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(c.primary_dns().as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn ipconfig_dns_empty_without_servers() {
        assert!(parse_ipconfig_dns("").is_empty());
        assert!(parse_ipconfig_dns("   DNS Servers . . . . . . . . . . . :\n").is_empty());
        // A translated label is not recognised; that is why the API path
        // exists.
        assert!(
            parse_ipconfig_dns("   Serveurs DNS. . . . . . . . . . : 192.168.1.1\n").is_empty()
        );
    }

    #[test]
    fn route_print_gateway_is_the_lowest_metric_address() {
        let text = "\
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         On-link        10.8.0.2      5
          0.0.0.0          0.0.0.0      10.0.0.1      10.0.0.50     55
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.20     35
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      172.16.0.1       1
===========================================================================
";
        assert_eq!(
            parse_route_print_gateway(text).as_deref(),
            Some("192.168.1.1")
        );
        assert_eq!(parse_route_print_gateway("Active Routes:\nNone\n"), None);
    }

    #[test]
    fn is_link_local_matches_fe80_prefix() {
        assert!(is_link_local("fe80::1"));
        assert!(is_link_local("fe80::96ea:eaff:fe05:f074"));
        assert!(is_link_local("fe80::1%en0"));
        assert!(is_link_local("FE80::1")); // case-insensitive
        assert!(!is_link_local("192.168.1.1"));
        assert!(!is_link_local("2001:4860:4860::8888"));
        assert!(!is_link_local("fec0::1")); // deprecated site-local, not link-local
    }
}
