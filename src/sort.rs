use std::cmp::Ordering;
use std::net::IpAddr;

// to add a new sortable column:
// 1. add a SortColumn to the tab's COLUMNS array in its ui module
// 2. add its comparator arm in the tab's sort function

#[derive(Debug, Clone, Copy)]
pub struct SortColumn {
    pub name: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct TabSortState {
    pub column: usize,
    pub ascending: bool,
}

// -- comparator helpers used by per-tab sort functions --

/// Compare two "host:port" address strings by parsed IP octets, then port.
/// Handles IPv4 ("1.2.3.4:80"), IPv6 ("[::1]:80"), and wildcard ("*:*").
pub fn cmp_ip_addr(a: &str, b: &str) -> Ordering {
    fn parse_host_port(s: &str) -> (Option<IpAddr>, u16) {
        if s == "*:*" || s.is_empty() {
            return (None, 0);
        }
        // IPv6 bracket notation: [::1]:port
        if let Some(bracket_end) = s.rfind("]:") {
            let ip_str = &s[1..bracket_end];
            let port_str = &s[bracket_end + 2..];
            let ip = ip_str.parse::<IpAddr>().ok();
            let port = port_str.parse::<u16>().unwrap_or(0);
            return (ip, port);
        }
        // IPv4 or plain: host:port (split on last colon)
        if let Some(colon) = s.rfind(':') {
            let host = &s[..colon];
            let port_str = &s[colon + 1..];
            let ip = if host == "*" {
                None
            } else {
                host.parse::<IpAddr>().ok()
            };
            let port = if port_str == "*" {
                0
            } else {
                port_str.parse::<u16>().unwrap_or(0)
            };
            return (ip, port);
        }
        (s.parse::<IpAddr>().ok(), 0)
    }

    let (ip_a, port_a) = parse_host_port(a);
    let (ip_b, port_b) = parse_host_port(b);

    // None (wildcard/unparseable) sorts before any real IP
    let ip_ord = match (ip_a, ip_b) {
        (None, None) => a.cmp(b),
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(IpAddr::V4(a4)), Some(IpAddr::V4(b4))) => a4.octets().cmp(&b4.octets()),
        (Some(IpAddr::V6(a6)), Some(IpAddr::V6(b6))) => a6.octets().cmp(&b6.octets()),
        // IPv4 sorts before IPv6
        (Some(IpAddr::V4(_)), Some(IpAddr::V6(_))) => Ordering::Less,
        (Some(IpAddr::V6(_)), Some(IpAddr::V4(_))) => Ordering::Greater,
    };
    ip_ord.then_with(|| port_a.cmp(&port_b))
}

/// Compare two bare IP address strings (no port) by parsed octets.
/// For interface addresses that aren't in host:port format.
pub fn cmp_ip(a: &str, b: &str) -> Ordering {
    let ip_a = a.parse::<IpAddr>().ok();
    let ip_b = b.parse::<IpAddr>().ok();
    match (ip_a, ip_b) {
        (None, None) => a.cmp(b),
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(IpAddr::V4(a4)), Some(IpAddr::V4(b4))) => a4.octets().cmp(&b4.octets()),
        (Some(IpAddr::V6(a6)), Some(IpAddr::V6(b6))) => a6.octets().cmp(&b6.octets()),
        (Some(IpAddr::V4(_)), Some(IpAddr::V6(_))) => Ordering::Less,
        (Some(IpAddr::V6(_)), Some(IpAddr::V4(_))) => Ordering::Greater,
    }
}

/// Case-insensitive string comparison with case as tiebreaker.
/// Uses char-level lowering to avoid allocating two Strings per call.
pub fn cmp_case_insensitive(a: &str, b: &str) -> Ordering {
    let lower_ord = a
        .chars()
        .flat_map(char::to_lowercase)
        .cmp(b.chars().flat_map(char::to_lowercase));
    lower_ord.then_with(|| a.cmp(b))
}

/// Compare two f64 values with total ordering (NaN sorts after infinity).
pub fn cmp_f64(a: f64, b: f64) -> Ordering {
    a.total_cmp(&b)
}

/// Apply sort direction: if descending, reverse the ordering.
pub fn apply_direction(ord: Ordering, ascending: bool) -> Ordering {
    if ascending {
        ord
    } else {
        ord.reverse()
    }
}
