//! Display-formatting helpers: MAC / IPv6 rendering, TCP flag strings,
//! IP-protocol and ICMP type names, port labels, and the ARP summary.

use super::{TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_FLAG_URG};

pub(crate) fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub(crate) fn format_ipv6(bytes: &[u8]) -> String {
    bytes
        .chunks(2)
        .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
        .collect::<Vec<_>>()
        .join(":")
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
