//! Display-formatting helpers: MAC / IPv6 rendering, TCP flag strings,
//! IP-protocol and ICMP type names, port labels, the ARP summary and the hex
//! and ASCII dumps, plus the one canonical spelling addresses are compared in.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv6Addr};

use super::{TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_FLAG_URG};

pub(crate) fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// An IPv6 address from a packet header, in RFC 5952's canonical form
/// (`2001:db8::1`, as `Ipv6Addr` displays it). `ss`, `lsof`, IP Helper and
/// the `/proc/net` fallback all print that form, and stream keys are built
/// from these strings on both sides, so writing every group out
/// (`2001:db8:0:0:0:0:0:1`) left IPv6 connections without their stream, DPI
/// label or JA4.
///
/// A v4-mapped address stays IPv6 here (`::ffff:192.0.2.1`), because a packet
/// carrying one on the wire is an IPv6 packet. Sockets describe their IPv4
/// peers that way, but their packets travel as IPv4, which is why
/// [`parse_ip`] maps it to IPv4 for the connection side.
pub(crate) fn format_ipv6(bytes: &[u8; 16]) -> String {
    Ipv6Addr::from(*bytes).to_string()
}

/// An address read from any of the places netwatch meets one: a connection
/// table row, a packet, or a display filter the user typed. Everything that
/// compares addresses from two of those goes through here, so they agree
/// however each source spells it:
///
/// - brackets go, including the stray closing one macOS `lsof` prints
///   (`fe80::1]`), and so does a `%zone`, which no packet carries;
/// - a v4-mapped address (`::ffff:192.0.2.1`, how `ss` shows a dual-stack
///   socket's IPv4 peer) becomes the IPv4 address its packets carry;
/// - a link-local address loses the scope macOS embeds in its second group
///   (`fe80:16::1`), which is never on the wire either: RFC 4291 requires
///   those bits to be zero.
///
/// `None` for anything that is not an address: a host name, a wildcard, a
/// fragment such as `192.168.`.
pub(crate) fn parse_ip(text: &str) -> Option<IpAddr> {
    let text = text.trim_start_matches('[').trim_end_matches(']');
    let text = text.split_once('%').map_or(text, |(addr, _zone)| addr);
    match text.parse::<IpAddr>().ok()?.to_canonical() {
        IpAddr::V6(v6) if v6.is_unicast_link_local() => {
            let mut groups = v6.segments();
            groups[1..4].fill(0);
            Some(IpAddr::V6(Ipv6Addr::from(groups)))
        }
        ip => Some(ip),
    }
}

/// [`parse_ip`], spelled as packet decoding spells addresses: dotted IPv4 and
/// RFC 5952 IPv6. Two spellings of one address give the same string, so the
/// result can key a map or be compared with `==`.
pub(crate) fn canonical_ip(text: &str) -> Option<String> {
    parse_ip(text).map(|ip| ip.to_string())
}

/// One end of a conversation as people read and paste it: `host:port`, with
/// an IPv6 address in brackets (`[2001:db8::20]:53`) as RFC 5952 section 6
/// asks and the connection table prints. Compressed IPv6 has no fixed group
/// count, so an unbracketed port reads as one more group, and
/// `2001:db8::20:53` is itself the address of a different host. A host name
/// or an IPv4 address is written as is.
pub(crate) fn format_endpoint(host: &str, port: impl std::fmt::Display) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Offset-prefixed hex, sixteen bytes to the line.
///
/// Written into one buffer. Every captured packet used to carry this dump
/// and [`ascii_dump`], built with a `format!` per byte, which was most of the
/// capture thread's decode time and about five times the frame's size in memory.
/// Only the selected packet's dump is ever drawn, so the Packets tab builds
/// it from the frame when it draws one.
pub fn hex_dump(raw: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    // Six characters of offset and gap, three per byte.
    let mut out = String::with_capacity(raw.len().div_ceil(16) * (6 + 16 * 3));
    for (i, chunk) in raw.chunks(16).enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let _ = write!(out, "{:04x}  ", i * 16);
        for (j, &b) in chunk.iter().enumerate() {
            if j > 0 {
                out.push(' ');
            }
            out.push(char::from(DIGITS[usize::from(b >> 4)]));
            out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
        }
    }
    out
}

/// The same bytes as printable characters, aligned with [`hex_dump`].
pub fn ascii_dump(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len().div_ceil(16) * (6 + 16 + 1));
    for (i, chunk) in raw.chunks(16).enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let _ = write!(out, "{:04x}  ", i * 16);
        out.extend(chunk.iter().map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '.'
            }
        }));
    }
    out
}

pub(crate) fn tcp_flags(flags: u8) -> String {
    let mut s = Vec::new();
    if flags & TCP_FLAG_FIN != 0 {
        s.push("FIN");
    }
    if flags & TCP_FLAG_SYN != 0 {
        s.push("SYN");
    }
    if flags & TCP_FLAG_RST != 0 {
        s.push("RST");
    }
    if flags & TCP_FLAG_PSH != 0 {
        s.push("PSH");
    }
    if flags & TCP_FLAG_ACK != 0 {
        s.push("ACK");
    }
    if flags & TCP_FLAG_URG != 0 {
        s.push("URG");
    }
    if s.is_empty() {
        "NONE".into()
    } else {
        s.join(",")
    }
}

pub(crate) fn ip_protocol_name(proto: u8) -> String {
    match proto {
        1 => "ICMP".into(),
        2 => "IGMP".into(),
        6 => "TCP".into(),
        17 => "UDP".into(),
        41 => "IPv6-encap".into(),
        47 => "GRE".into(),
        58 => "ICMPv6".into(),
        89 => "OSPF".into(),
        132 => "SCTP".into(),
        _ => format!("Proto({})", proto),
    }
}

pub fn port_label(port: u16) -> &'static str {
    match port {
        20 => "FTP-Data",
        21 => "FTP",
        22 => "SSH",
        25 => "SMTP",
        53 => "DNS",
        67 => "DHCP-S",
        68 => "DHCP-C",
        80 => "HTTP",
        110 => "POP3",
        123 => "NTP",
        143 => "IMAP",
        443 => "HTTPS",
        465 => "SMTPS",
        587 => "Submission",
        993 => "IMAPS",
        995 => "POP3S",
        1900 => "SSDP",
        1883 => "MQTT",
        3306 => "MySQL",
        3389 => "RDP",
        5222 => "XMPP",
        5353 => "mDNS",
        5432 => "PostgreSQL",
        6379 => "Redis",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        27017 => "MongoDB",
        _ => "—",
    }
}

pub(crate) fn icmp_type_name(icmp_type: u8, code: u8) -> String {
    match icmp_type {
        0 => "Echo Reply".into(),
        3 => {
            let reason = match code {
                0 => "Network Unreachable",
                1 => "Host Unreachable",
                2 => "Protocol Unreachable",
                3 => "Port Unreachable",
                4 => "Fragmentation Needed",
                13 => "Administratively Prohibited",
                _ => "Unreachable",
            };
            format!("Dest Unreachable: {}", reason)
        }
        4 => "Source Quench".into(),
        5 => {
            let redir = match code {
                0 => "for Network",
                1 => "for Host",
                _ => "",
            };
            format!("Redirect {}", redir)
        }
        8 => "Echo Request".into(),
        9 => "Router Advertisement".into(),
        10 => "Router Solicitation".into(),
        11 => {
            let reason = if code == 0 {
                "TTL Exceeded"
            } else {
                "Fragment Reassembly Exceeded"
            };
            format!("Time Exceeded: {}", reason)
        }
        _ => format!("Type {} Code {}", icmp_type, code),
    }
}

pub(crate) fn icmpv6_type_name(icmp_type: u8) -> String {
    match icmp_type {
        1 => "Dest Unreachable".into(),
        2 => "Packet Too Big".into(),
        3 => "Time Exceeded".into(),
        128 => "Echo Request".into(),
        129 => "Echo Reply".into(),
        133 => "Router Solicitation".into(),
        134 => "Router Advertisement".into(),
        135 => "Neighbor Solicitation".into(),
        136 => "Neighbor Advertisement".into(),
        _ => format!("Type {}", icmp_type),
    }
}

pub(crate) fn parse_arp(data: &[u8], details: &mut Vec<String>) -> String {
    if data.len() < 28 {
        details.push("ARP: (truncated)".into());
        return "ARP (truncated)".into();
    }
    let op = u16::from_be_bytes([data[6], data[7]]);
    let sender_mac = format_mac(&data[8..14]);
    let sender_ip = format!("{}.{}.{}.{}", data[14], data[15], data[16], data[17]);
    let target_mac = format_mac(&data[18..24]);
    let target_ip = format!("{}.{}.{}.{}", data[24], data[25], data[26], data[27]);

    let info = match op {
        1 => {
            details.push(format!(
                "ARP: Request — Who has {}? Tell {} ({})",
                target_ip, sender_ip, sender_mac
            ));
            format!("Who has {}? Tell {}", target_ip, sender_ip)
        }
        2 => {
            details.push(format!("ARP: Reply — {} is at {}", sender_ip, sender_mac));
            format!("{} is at {}", sender_ip, sender_mac)
        }
        _ => {
            details.push(format!(
                "ARP: op={}, {} ({}) → {} ({})",
                op, sender_ip, sender_mac, target_ip, target_mac
            ));
            format!("ARP op={}", op)
        }
    };
    info
}
