use std::cmp::Ordering;
use std::net::IpAddr;

// to add a new sortable column:
// 1. add a SortColumn to the tab's COLUMNS array in its ui module
// 2. add its comparator arm in the tab's sort function

#[derive(Debug, Clone, Copy)]
pub struct SortColumn {
    pub name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TabSortState {
    pub column: usize,
    pub ascending: bool,
}

// -- comparator helpers used by per-tab sort functions --

/// A "host:port" address string as [`cmp_ip_addr`] orders it, for a sort that
/// parses each address once rather than twice per comparison.
///
/// The variants are in sort order: wildcard or unparseable addresses before
/// any real IP, and IPv4 before IPv6.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpSortKey<'a> {
    Unparsed(&'a str, u16),
    V4([u8; 4], u16),
    V6([u8; 16], u16),
}

/// Handles IPv4 ("1.2.3.4:80"), IPv6 ("[::1]:80"), and wildcard ("*:*").
pub fn ip_sort_key(s: &str) -> IpSortKey<'_> {
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

    match parse_host_port(s) {
        (None, port) => IpSortKey::Unparsed(s, port),
        (Some(IpAddr::V4(ip)), port) => IpSortKey::V4(ip.octets(), port),
        (Some(IpAddr::V6(ip)), port) => IpSortKey::V6(ip.octets(), port),
    }
}

/// Compare two "host:port" address strings by parsed IP octets, then port.
pub fn cmp_ip_addr(a: &str, b: &str) -> Ordering {
    ip_sort_key(a).cmp(&ip_sort_key(b))
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

/// A string as [`cmp_case_insensitive`] orders it, for a sort that lowers each
/// string once rather than on every comparison. The lowered text is built from
/// `char::to_lowercase`, as that comparison is, because `str::to_lowercase`
/// also treats a word-final sigma specially and would order some names apart.
pub fn case_insensitive_key(s: &str) -> (String, &str) {
    (s.chars().flat_map(char::to_lowercase).collect(), s)
}

/// Compare two f64 values with total ordering (NaN sorts after infinity).
pub fn cmp_f64(a: f64, b: f64) -> Ordering {
    a.total_cmp(&b)
}

/// An f64 as [`cmp_f64`] orders it, for use in a sort key.
#[derive(Debug, Clone, Copy)]
pub struct TotalF64(pub f64);

impl PartialEq for TotalF64 {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for TotalF64 {}

impl PartialOrd for TotalF64 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TotalF64 {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_f64(self.0, other.0)
    }
}

/// Apply sort direction: if descending, reverse the ordering.
pub fn apply_direction(ord: Ordering, ascending: bool) -> Ordering {
    if ascending {
        ord
    } else {
        ord.reverse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keys are what a cached sort compares in place of these functions,
    /// so a pair must come out the same either way.
    #[test]
    fn sort_keys_order_as_their_comparators_do() {
        let addrs = [
            "",
            "*:*",
            "*:443",
            "0.0.0.0:*",
            "1.2.3.4",
            "1.2.3.4:80",
            "1.2.3.4:443",
            "1.2.3.5:80",
            "10.0.0.1:80",
            "[::]:*",
            "[::1]:80",
            "[::1]:443",
            "[2001:db8::1]:80",
            "::1",
            "example.com:80",
            "example.com:443",
            "not an address",
        ];
        for a in addrs {
            for b in addrs {
                assert_eq!(
                    ip_sort_key(a).cmp(&ip_sort_key(b)),
                    cmp_ip_addr(a, b),
                    "{a} vs {b}"
                );
            }
        }

        // `Σ` lowers to `σ` a character at a time and to `ς` at a word's end
        // through `str::to_lowercase`, and `ß` and `İ` change length.
        let names = [
            "", "curl", "Curl", "CURL", "curl2", "ΑΣ", "ας", "ασ", "ß", "SS", "İ", "i",
        ];
        for a in names {
            for b in names {
                assert_eq!(
                    case_insensitive_key(a).cmp(&case_insensitive_key(b)),
                    cmp_case_insensitive(a, b),
                    "{a} vs {b}"
                );
            }
        }

        let rates = [
            f64::NEG_INFINITY,
            -1.0,
            -0.0,
            0.0,
            1.5,
            f64::INFINITY,
            f64::NAN,
        ];
        for a in rates {
            for b in rates {
                assert_eq!(TotalF64(a).cmp(&TotalF64(b)), cmp_f64(a, b), "{a} vs {b}");
            }
        }
    }
}
