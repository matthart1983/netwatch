//! Rows of the Windows TCP and UDP tables (`GetExtendedTcpTable`,
//! `GetExtendedUdpTable`), decoded into the endpoints and state names the
//! connection collector uses on every platform. Platform-neutral so the
//! decoding is unit-tested on every host; only the calls that fill the rows
//! (`platform::windows::tcp_table`) are Windows-only.
//!
//! netstat printed these same tables as text, in the display language:
//! German Windows reports an established connection as `HERGESTELLT` and a
//! listener as `ABHÖREN`, and even English prints `LISTENING`, which no
//! filter, counter or colour in netwatch matched. The API gives the state as
//! a number, so the name is netwatch's own whatever the language.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// `MIB_TCPROW_OWNER_PID`, field for field. A copy of the windows-sys struct
/// rather than the struct itself, so tests can build rows on any host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tcp4Row {
    pub state: u32,
    pub local_addr: u32,
    pub local_port: u32,
    pub remote_addr: u32,
    pub remote_port: u32,
    pub owning_pid: u32,
}

/// `MIB_TCP6ROW_OWNER_PID` without its scope ids. Packet capture keys a flow
/// on the bare address, and a `%12` suffix would also stop the collector's
/// address parsers reading the endpoint, so the scope is not carried.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tcp6Row {
    pub local_addr: [u8; 16],
    pub local_port: u32,
    pub remote_addr: [u8; 16],
    pub remote_port: u32,
    pub state: u32,
    pub owning_pid: u32,
}

/// `MIB_UDPROW_OWNER_PID`. A UDP socket has no peer in this table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Udp4Row {
    pub local_addr: u32,
    pub local_port: u32,
    pub owning_pid: u32,
}

/// `MIB_UDP6ROW_OWNER_PID`, scope id dropped as in [`Tcp6Row`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Udp6Row {
    pub local_addr: [u8; 16],
    pub local_port: u32,
    pub owning_pid: u32,
}

/// One decoded socket, before the collector names its process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    /// `TCP` or `UDP`, as every other platform's collector spells it.
    pub protocol: &'static str,
    pub local_addr: String,
    pub remote_addr: String,
    /// Empty for UDP, which has no state on any platform.
    pub state: String,
    pub pid: Option<u32>,
}

/// The name for a `MIB_TCP_STATE` value, from the vocabulary the Linux
/// collector produces (`ss` names, with `ESTAB` widened to `ESTABLISHED`).
/// The state filter, the colours and the TIME_WAIT/CLOSE_WAIT counters behind
/// the Prometheus metrics match these, and the JSON and CSV exports carry
/// them.
///
/// A closed socket is `CLOSED`, as lsof names it. `ss` calls it `UNCONN`,
/// the word it also uses for an unconnected UDP socket, and the views that
/// leave closed sockets out look for `CLOSED`.
pub fn tcp_state_name(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",      // MIB_TCP_STATE_CLOSED
        2 => "LISTEN",      // MIB_TCP_STATE_LISTEN
        3 => "SYN-SENT",    // MIB_TCP_STATE_SYN_SENT
        4 => "SYN-RECV",    // MIB_TCP_STATE_SYN_RCVD
        5 => "ESTABLISHED", // MIB_TCP_STATE_ESTAB
        6 => "FIN-WAIT-1",  // MIB_TCP_STATE_FIN_WAIT1
        7 => "FIN-WAIT-2",  // MIB_TCP_STATE_FIN_WAIT2
        8 => "CLOSE-WAIT",  // MIB_TCP_STATE_CLOSE_WAIT
        9 => "CLOSING",     // MIB_TCP_STATE_CLOSING
        10 => "LAST-ACK",   // MIB_TCP_STATE_LAST_ACK
        11 => "TIME-WAIT",  // MIB_TCP_STATE_TIME_WAIT
        // MIB_TCP_STATE_DELETE_TCB: the connection is gone and Windows is
        // freeing its control block. No other platform has a name for that
        // moment, and a Windows-only one would match no filter.
        12 => "CLOSED",
        _ => "UNKNOWN",
    }
}

/// English netstat's state column, in `MIB_TCP_STATE` order (1 to 12). Only
/// the netstat fallback reads text; a translated name has no entry here and
/// is kept as netstat printed it.
const NETSTAT_STATES: [&str; 12] = [
    "CLOSED",
    "LISTENING",
    "SYN_SENT",
    "SYN_RECEIVED",
    "ESTABLISHED",
    "FIN_WAIT_1",
    "FIN_WAIT_2",
    "CLOSE_WAIT",
    "CLOSING",
    "LAST_ACK",
    "TIME_WAIT",
    "DELETE_TCB",
];

/// The [`tcp_state_name`] for one of English netstat's state names.
pub fn netstat_state_name(text: &str) -> Option<&'static str> {
    let index = NETSTAT_STATES.iter().position(|s| *s == text)?;
    Some(tcp_state_name(index as u32 + 1))
}

/// The port in a row's port DWORD. Only the low 16 bits are the port, in
/// network byte order, which on little-endian Windows makes them the DWORD's
/// first two bytes in memory. The high 16 bits are not guaranteed to be zero.
pub fn port(dword: u32) -> u16 {
    let bytes = dword.to_le_bytes();
    u16::from_be_bytes([bytes[0], bytes[1]])
}

/// An IPv4 address DWORD, held in network byte order: its bytes in memory
/// are the address's octets in order.
pub fn ipv4(dword: u32) -> Ipv4Addr {
    Ipv4Addr::from(dword.to_le_bytes())
}

/// `1.2.3.4:443` or `[2001:db8::1]:443`: the form `ss` and netstat print, so
/// the collector's address parsers and every view read it as they read the
/// Linux rows. An IPv4-mapped address keeps its `::ffff:` form, which the
/// stream-key join already folds back to IPv4.
fn endpoint(ip: IpAddr, port: u16) -> String {
    SocketAddr::new(ip, port).to_string()
}

/// A listener's peer, which the table leaves as the unspecified address and
/// port 0, becomes `*:*`: the "no peer" every view and address parser in
/// netwatch already recognises, and what lsof shows for the same socket.
fn peer(ip: IpAddr, port: u16) -> String {
    if ip.is_unspecified() && port == 0 {
        "*:*".to_string()
    } else {
        endpoint(ip, port)
    }
}

/// PID 0 is the System Idle process, which owns no socket. Windows records it
/// for a connection whose process has already let go, as every TIME_WAIT row
/// is. Such a row is reported as having no owner, so it reads "unattributed"
/// rather than naming a process.
pub fn owner(pid: u32) -> Option<u32> {
    (pid != 0).then_some(pid)
}

impl From<&Tcp4Row> for Socket {
    fn from(row: &Tcp4Row) -> Self {
        Socket {
            protocol: "TCP",
            local_addr: endpoint(ipv4(row.local_addr).into(), port(row.local_port)),
            remote_addr: peer(ipv4(row.remote_addr).into(), port(row.remote_port)),
            state: tcp_state_name(row.state).to_string(),
            pid: owner(row.owning_pid),
        }
    }
}

impl From<&Tcp6Row> for Socket {
    fn from(row: &Tcp6Row) -> Self {
        Socket {
            protocol: "TCP",
            local_addr: endpoint(Ipv6Addr::from(row.local_addr).into(), port(row.local_port)),
            remote_addr: peer(
                Ipv6Addr::from(row.remote_addr).into(),
                port(row.remote_port),
            ),
            state: tcp_state_name(row.state).to_string(),
            pid: owner(row.owning_pid),
        }
    }
}

impl From<&Udp4Row> for Socket {
    fn from(row: &Udp4Row) -> Self {
        Socket {
            protocol: "UDP",
            local_addr: endpoint(ipv4(row.local_addr).into(), port(row.local_port)),
            remote_addr: "*:*".to_string(),
            state: String::new(),
            pid: owner(row.owning_pid),
        }
    }
}

impl From<&Udp6Row> for Socket {
    fn from(row: &Udp6Row) -> Self {
        Socket {
            protocol: "UDP",
            local_addr: endpoint(Ipv6Addr::from(row.local_addr).into(), port(row.local_port)),
            remote_addr: "*:*".to_string(),
            state: String::new(),
            pid: owner(row.owning_pid),
        }
    }
}

/// A process image name from the NUL-terminated UTF-16 buffer a Toolhelp32
/// snapshot fills (`PROCESSENTRY32W::szExeFile`). Windows file names need not
/// be valid UTF-16; a lone surrogate becomes U+FFFD rather than losing the
/// whole name.
pub fn image_name(units: &[u16]) -> String {
    let len = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..len])
}

/// How many rows can be read from a table: the count its header claims,
/// capped at what fits in the `filled` bytes after the header, where rows
/// start at `rows_at` and are `row_size` bytes each. The count and the size
/// come from the same call and should agree; this is what keeps a slice
/// built from them inside the buffer if they ever do not.
pub fn rows_that_fit(filled: usize, rows_at: usize, row_size: usize, claimed: usize) -> usize {
    if row_size == 0 {
        return 0;
    }
    claimed.min(filled.saturating_sub(rows_at) / row_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A port DWORD as Windows fills it: the port in network order in the
    /// first two bytes, then whatever the high half holds.
    fn port_dword(port: u16, high: u16) -> u32 {
        let [a, b] = port.to_be_bytes();
        let [c, d] = high.to_le_bytes();
        u32::from_le_bytes([a, b, c, d])
    }

    fn addr_dword(octets: [u8; 4]) -> u32 {
        u32::from_le_bytes(octets)
    }

    #[test]
    fn ports_are_read_in_network_order() {
        // What an x86 load of the DWORD yields for port 80: 0x5000.
        assert_eq!(port(0x0000_5000), 80);
        assert_eq!(port(port_dword(443, 0)), 443);
        assert_eq!(port(port_dword(49_152, 0)), 49_152);
        assert_eq!(port(port_dword(65_535, 0)), 65_535);
    }

    #[test]
    fn the_high_half_of_a_port_dword_is_ignored() {
        assert_eq!(port(port_dword(8080, 0xBEEF)), 8080);
        assert_eq!(port(0xFFFF_5000), 80);
    }

    #[test]
    fn ipv4_addresses_are_read_in_network_order() {
        // An x86 load of 127.0.0.1 yields 0x0100007F, as /proc/net/tcp shows.
        assert_eq!(ipv4(0x0100_007F), Ipv4Addr::LOCALHOST);
        assert_eq!(
            ipv4(addr_dword([192, 168, 1, 20])),
            Ipv4Addr::new(192, 168, 1, 20)
        );
    }

    #[test]
    fn an_established_ipv4_row_decodes_to_the_collector_format() {
        let row = Tcp4Row {
            state: 5,
            local_addr: addr_dword([192, 168, 1, 20]),
            local_port: port_dword(50_123, 0x1234),
            remote_addr: addr_dword([93, 184, 216, 34]),
            remote_port: port_dword(443, 0),
            owning_pid: 4242,
        };
        assert_eq!(
            Socket::from(&row),
            Socket {
                protocol: "TCP",
                local_addr: "192.168.1.20:50123".into(),
                remote_addr: "93.184.216.34:443".into(),
                state: "ESTABLISHED".into(),
                pid: Some(4242),
            }
        );
    }

    #[test]
    fn a_listener_has_no_peer() {
        let v4 = Tcp4Row {
            state: 2,
            local_addr: 0,
            local_port: port_dword(445, 0),
            remote_addr: 0,
            remote_port: 0,
            owning_pid: 4,
        };
        let s = Socket::from(&v4);
        assert_eq!(s.local_addr, "0.0.0.0:445");
        assert_eq!(s.remote_addr, "*:*");
        assert_eq!(s.state, "LISTEN");

        let v6 = Tcp6Row {
            state: 2,
            local_port: port_dword(445, 0),
            owning_pid: 4,
            ..Default::default()
        };
        let s = Socket::from(&v6);
        assert_eq!(s.local_addr, "[::]:445");
        assert_eq!(s.remote_addr, "*:*");
    }

    /// Port 0 on a real address, or a real port on the unspecified address,
    /// is still a peer.
    #[test]
    fn only_the_all_zero_peer_is_a_wildcard() {
        let row = Tcp4Row {
            state: 3,
            local_addr: addr_dword([10, 0, 0, 2]),
            local_port: port_dword(50_000, 0),
            remote_addr: addr_dword([10, 0, 0, 1]),
            remote_port: 0,
            owning_pid: 7,
        };
        assert_eq!(Socket::from(&row).remote_addr, "10.0.0.1:0");
    }

    #[test]
    fn ipv6_rows_are_bracketed_and_compressed() {
        let mut remote = [0u8; 16];
        remote[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        remote[15] = 1;
        let row = Tcp6Row {
            local_addr: Ipv6Addr::LOCALHOST.octets(),
            local_port: port_dword(51_000, 0),
            remote_addr: remote,
            remote_port: port_dword(443, 0),
            state: 5,
            owning_pid: 99,
        };
        let s = Socket::from(&row);
        assert_eq!(s.local_addr, "[::1]:51000");
        assert_eq!(s.remote_addr, "[2001:db8::1]:443");
        assert_eq!(s.state, "ESTABLISHED");
    }

    /// What the collector's own parser makes of the strings this produces is
    /// the point of the format, so check it reads them back.
    #[test]
    fn decoded_endpoints_parse_back_to_the_same_address() {
        let row = Tcp6Row {
            local_addr: Ipv6Addr::LOCALHOST.octets(),
            local_port: port_dword(51_000, 0),
            remote_addr: Ipv6Addr::LOCALHOST.octets(),
            remote_port: port_dword(8080, 0),
            state: 5,
            owning_pid: 1,
        };
        let s = Socket::from(&row);
        let parsed: SocketAddr = s.remote_addr.parse().unwrap();
        assert_eq!(parsed, SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 8080));
    }

    #[test]
    fn a_v4_mapped_address_keeps_the_form_the_join_folds() {
        let row = Udp6Row {
            local_addr: Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets(),
            local_port: port_dword(5353, 0),
            owning_pid: 10,
        };
        assert_eq!(Socket::from(&row).local_addr, "[::ffff:127.0.0.1]:5353");
    }

    #[test]
    fn udp_rows_have_no_peer_and_no_state() {
        let row = Udp4Row {
            local_addr: 0,
            local_port: port_dword(53, 0),
            owning_pid: 1880,
        };
        assert_eq!(
            Socket::from(&row),
            Socket {
                protocol: "UDP",
                local_addr: "0.0.0.0:53".into(),
                remote_addr: "*:*".into(),
                state: String::new(),
                pid: Some(1880),
            }
        );
        let v6 = Udp6Row {
            local_port: port_dword(5353, 0),
            owning_pid: 1880,
            ..Default::default()
        };
        assert_eq!(Socket::from(&v6).local_addr, "[::]:5353");
    }

    #[test]
    fn pid_zero_is_no_owner() {
        let row = Tcp4Row {
            state: 11,
            local_addr: addr_dword([127, 0, 0, 1]),
            local_port: port_dword(50_000, 0),
            remote_addr: addr_dword([127, 0, 0, 1]),
            remote_port: port_dword(8080, 0),
            owning_pid: 0,
        };
        let s = Socket::from(&row);
        assert_eq!(s.state, "TIME-WAIT");
        assert_eq!(s.pid, None);
        assert_eq!(owner(4), Some(4), "System (pid 4) does own sockets");
    }

    #[test]
    fn every_tcp_state_has_its_name() {
        let names: Vec<_> = (0..=13).map(tcp_state_name).collect();
        assert_eq!(
            names,
            [
                "UNKNOWN",
                "CLOSED",
                "LISTEN",
                "SYN-SENT",
                "SYN-RECV",
                "ESTABLISHED",
                "FIN-WAIT-1",
                "FIN-WAIT-2",
                "CLOSE-WAIT",
                "CLOSING",
                "LAST-ACK",
                "TIME-WAIT",
                "CLOSED",
                "UNKNOWN",
            ]
        );
        // MIB_TCP_STATE_RESERVED, and anything a later Windows adds.
        assert_eq!(tcp_state_name(100), "UNKNOWN");
    }

    /// The names are only useful if the views know them. This is the set
    /// that used to fail on Windows: `LISTENING` matched no filter, and a
    /// translated name matched nothing at all.
    #[test]
    fn the_views_and_counters_know_every_state_name() {
        use crate::app::ConnectionStateFilter;
        use crate::ui::widgets::state_label;

        assert!(ConnectionStateFilter::Established.matches(tcp_state_name(5)));
        assert!(ConnectionStateFilter::Listen.matches(tcp_state_name(2)));
        assert!(ConnectionStateFilter::TimeWait.matches(tcp_state_name(11)));
        let labels: Vec<_> = (1..=12).map(|s| state_label(tcp_state_name(s))).collect();
        assert_eq!(
            labels,
            [
                "closed",
                "listen",
                "syn-sent",
                "syn-recv",
                "estab",
                "fin-wait-1",
                "fin-wait-2",
                "close-wait",
                "closing",
                "last-ack",
                "time-wait",
                "closed",
            ]
        );
    }

    #[test]
    fn english_netstat_names_map_to_the_same_states() {
        assert_eq!(netstat_state_name("LISTENING"), Some("LISTEN"));
        assert_eq!(netstat_state_name("ESTABLISHED"), Some("ESTABLISHED"));
        assert_eq!(netstat_state_name("SYN_RECEIVED"), Some("SYN-RECV"));
        assert_eq!(netstat_state_name("TIME_WAIT"), Some("TIME-WAIT"));
        assert_eq!(netstat_state_name("CLOSE_WAIT"), Some("CLOSE-WAIT"));
        assert_eq!(netstat_state_name("DELETE_TCB"), Some("CLOSED"));
        for (i, name) in NETSTAT_STATES.iter().enumerate() {
            assert_eq!(netstat_state_name(name), Some(tcp_state_name(i as u32 + 1)));
        }
        // German Windows; only the API can name these.
        assert_eq!(netstat_state_name("HERGESTELLT"), None);
        assert_eq!(netstat_state_name("ABHÖREN"), None);
    }

    fn wide(s: &str, len: usize) -> Vec<u16> {
        let mut units: Vec<u16> = s.encode_utf16().collect();
        units.resize(len, 0);
        units
    }

    #[test]
    fn image_names_stop_at_the_nul() {
        let mut buf = wide("chrome.exe", 260);
        // Whatever a longer earlier name left behind the terminator.
        buf[11..15].copy_from_slice(&[b'x' as u16; 4]);
        assert_eq!(image_name(&buf), "chrome.exe");
        assert_eq!(image_name(&wide("Блокнот.exe", 260)), "Блокнот.exe");
        assert_eq!(image_name(&wide("", 260)), "");
        // No terminator at all: the whole buffer, not a read past it.
        assert_eq!(image_name(&wide("svchost.exe", 11)), "svchost.exe");
        assert_eq!(image_name(&[0xD800, b'a' as u16, 0]), "\u{FFFD}a");
    }

    #[test]
    fn rows_are_capped_at_the_buffer() {
        // 4-byte header, 24-byte rows (MIB_TCPROW_OWNER_PID).
        assert_eq!(rows_that_fit(4 + 24 * 3, 4, 24, 3), 3);
        assert_eq!(rows_that_fit(4 + 24 * 3, 4, 24, 1), 1);
        assert_eq!(rows_that_fit(4 + 24 * 3, 4, 24, 1_000_000), 3);
        assert_eq!(rows_that_fit(4 + 24 * 3 - 1, 4, 24, 3), 2);
        assert_eq!(rows_that_fit(2, 4, 24, 3), 0);
        assert_eq!(rows_that_fit(100, 4, 0, 3), 0);
        assert_eq!(rows_that_fit(4, 4, 24, 0), 0);
    }
}
