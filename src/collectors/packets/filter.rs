//! Packet display-filter mini-language: `FilterExpr`, its tokenizer/parser,
//! and `matches_packet`. Drives which captured packets are visible on the
//! Packets tab (list, detail pane, and scroll/selection).

use super::CapturedPacket;

// ── Display filters ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum FilterExpr {
    Protocol(String),
    SrcIp(String),
    DstIp(String),
    Ip(String),
    Port(u16),
    Stream(u32),
    Contains(String),
    /// `app:tls`, `app:quic`, `app:dns`, `app:http`, `app:ssh` — matches
    /// the L7 protocol tag carried on `pkt.app_protocol`. Distinct from
    /// `Protocol` which matches the L4 string in `pkt.protocol`.
    AppProto(String),
    /// `sni:hostname` — substring match against TLS or QUIC SNI.
    Sni(String),
    /// `host:hostname` — substring match against HTTP Host header.
    Host(String),
    /// `ech:true` / `ech:false` — matches the ECH (Encrypted ClientHello)
    /// presence flag on TLS or QUIC. `true` selects connections where the
    /// observer cannot see the inner SNI; `false` selects vanilla TLS/QUIC
    /// connections only (non-TLS/QUIC packets never match either way).
    Ech(bool),
    /// `ja4:<value>` — substring match against the TLS JA4 fingerprint.
    /// Lets the user pivot from "I saw a suspicious JA4 in the details
    /// panel" to "show me every other connection with the same JA4"
    /// — the core threat-hunting move JA4 enables.
    Ja4(String),
    /// `decrypted:true` / `decrypted:false` — matches whether netwatch
    /// recovered TLS 1.3 application-data plaintext for this packet
    /// (configured SSLKEYLOGFILE + cooperating client). `true` is the
    /// quickest way to see exactly what decryption produced without
    /// scrolling past undecryptable QUIC/TLS-1.2/keyless flows.
    Decrypted(bool),
    Not(Box<FilterExpr>),
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
}

pub fn parse_filter(input: &str) -> Option<FilterExpr> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    let tokens = tokenize(input);
    if tokens.is_empty() {
        return None;
    }
    let (expr, rest) = parse_or(&tokens, 0)?;
    if rest.is_empty() {
        Some(expr)
    } else {
        None
    }
}

const MAX_FILTER_DEPTH: usize = 32;

fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if ch == '!' {
            tokens.push("!".to_string());
            chars.next();
            continue;
        }
        if ch == '=' {
            chars.next();
            if chars.peek() == Some(&'=') {
                chars.next();
            }
            tokens.push("==".to_string());
            continue;
        }
        if ch == '"' || ch == '\'' {
            chars.next();
            let mut s = String::new();
            while let Some(&c) = chars.peek() {
                if c == ch {
                    chars.next();
                    break;
                }
                s.push(c);
                chars.next();
            }
            tokens.push(format!("\"{s}\""));
            continue;
        }
        let mut word = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() || c == '=' || c == '!' {
                break;
            }
            word.push(c);
            chars.next();
        }
        tokens.push(word);
    }
    tokens
}

fn parse_or(tokens: &[String], depth: usize) -> Option<(FilterExpr, &[String])> {
    if depth > MAX_FILTER_DEPTH {
        return None;
    }
    let (mut left, mut rest) = parse_and(tokens, depth + 1)?;
    while !rest.is_empty() && rest[0].eq_ignore_ascii_case("or") {
        let (right, r) = parse_and(&rest[1..], depth + 1)?;
        left = FilterExpr::Or(Box::new(left), Box::new(right));
        rest = r;
    }
    Some((left, rest))
}

fn parse_and(tokens: &[String], depth: usize) -> Option<(FilterExpr, &[String])> {
    if depth > MAX_FILTER_DEPTH {
        return None;
    }
    let (mut left, mut rest) = parse_not(tokens, depth + 1)?;
    while !rest.is_empty() && rest[0].eq_ignore_ascii_case("and") {
        let (right, r) = parse_not(&rest[1..], depth + 1)?;
        left = FilterExpr::And(Box::new(left), Box::new(right));
        rest = r;
    }
    Some((left, rest))
}

fn parse_not(tokens: &[String], depth: usize) -> Option<(FilterExpr, &[String])> {
    if depth > MAX_FILTER_DEPTH {
        return None;
    }
    if tokens.is_empty() {
        return None;
    }
    if tokens[0] == "!" || tokens[0].eq_ignore_ascii_case("not") {
        let (expr, rest) = parse_not(&tokens[1..], depth + 1)?;
        return Some((FilterExpr::Not(Box::new(expr)), rest));
    }
    parse_atom(tokens)
}

fn parse_atom(tokens: &[String]) -> Option<(FilterExpr, &[String])> {
    if tokens.is_empty() {
        return None;
    }

    // ip.src == x
    if tokens[0].eq_ignore_ascii_case("ip.src") && tokens.len() >= 3 && tokens[1] == "==" {
        return Some((FilterExpr::SrcIp(tokens[2].to_lowercase()), &tokens[3..]));
    }
    // ip.dst == x
    if tokens[0].eq_ignore_ascii_case("ip.dst") && tokens.len() >= 3 && tokens[1] == "==" {
        return Some((FilterExpr::DstIp(tokens[2].to_lowercase()), &tokens[3..]));
    }
    // port [==] N
    if tokens[0].eq_ignore_ascii_case("port") && tokens.len() >= 2 {
        if tokens[1] == "==" && tokens.len() >= 3 {
            if let Ok(p) = tokens[2].parse::<u16>() {
                return Some((FilterExpr::Port(p), &tokens[3..]));
            }
        }
        if let Ok(p) = tokens[1].parse::<u16>() {
            return Some((FilterExpr::Port(p), &tokens[2..]));
        }
    }
    // stream N
    if tokens[0].eq_ignore_ascii_case("stream") && tokens.len() >= 2 {
        if let Ok(n) = tokens[1].parse::<u32>() {
            return Some((FilterExpr::Stream(n), &tokens[2..]));
        }
    }
    // contains "x"
    if tokens[0].eq_ignore_ascii_case("contains") && tokens.len() >= 2 {
        let val = tokens[1].trim_matches('"').to_lowercase();
        return Some((FilterExpr::Contains(val), &tokens[2..]));
    }

    let word = &tokens[0];

    // DPI-aware prefixes: `app:`, `sni:`, `host:`. Single-token form
    // because the tokenizer doesn't split on `:`. Reuses the same
    // shape used by the Connections tab filter chips.
    if let Some(val) = word.strip_prefix("app:") {
        return Some((
            FilterExpr::AppProto(val.trim_matches('"').to_lowercase()),
            &tokens[1..],
        ));
    }
    if let Some(val) = word.strip_prefix("sni:") {
        return Some((
            FilterExpr::Sni(val.trim_matches('"').to_lowercase()),
            &tokens[1..],
        ));
    }
    if let Some(val) = word.strip_prefix("host:") {
        return Some((
            FilterExpr::Host(val.trim_matches('"').to_lowercase()),
            &tokens[1..],
        ));
    }
    if let Some(val) = word.strip_prefix("ech:") {
        let want = match val.trim_matches('"').to_lowercase().as_str() {
            "true" => true,
            "false" => false,
            // Reject anything else; binary flag, no aliases. Bad input
            // fails the whole filter parse, matching how `port:abc`-style
            // typos would otherwise become invisible bare-word matches.
            _ => return None,
        };
        return Some((FilterExpr::Ech(want), &tokens[1..]));
    }
    if let Some(val) = word.strip_prefix("decrypted:") {
        let want = match val.trim_matches('"').to_lowercase().as_str() {
            "true" => true,
            "false" => false,
            // Binary flag, no aliases — reject typos rather than silently
            // degrading to a bare-word match (mirrors `ech:`).
            _ => return None,
        };
        return Some((FilterExpr::Decrypted(want), &tokens[1..]));
    }
    if let Some(val) = word.strip_prefix("ja4:") {
        return Some((
            FilterExpr::Ja4(val.trim_matches('"').to_lowercase()),
            &tokens[1..],
        ));
    }

    // Bare IP address (contains a dot and digits)
    if word.contains('.') && word.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Some((FilterExpr::Ip(word.to_string()), &tokens[1..]));
    }

    // Known protocol names
    let protocols = [
        "tcp", "udp", "dns", "mdns", "tls", "http", "arp", "icmp", "icmpv6", "dhcp", "ntp", "ssdp",
        "quic", "ssh", "https", "smtp", "ftp", "imap", "pop3",
    ];
    if protocols.iter().any(|p| word.eq_ignore_ascii_case(p)) {
        return Some((FilterExpr::Protocol(word.to_uppercase()), &tokens[1..]));
    }

    // Bare word → text search
    let val = word.trim_matches('"').to_lowercase();
    Some((FilterExpr::Contains(val), &tokens[1..]))
}

pub fn matches_packet(expr: &FilterExpr, pkt: &CapturedPacket) -> bool {
    match expr {
        FilterExpr::Protocol(p) => pkt.protocol.eq_ignore_ascii_case(p),
        FilterExpr::SrcIp(ip) => pkt.src_ip.contains(ip.as_str()),
        FilterExpr::DstIp(ip) => pkt.dst_ip.contains(ip.as_str()),
        FilterExpr::Ip(ip) => pkt.src_ip.contains(ip.as_str()) || pkt.dst_ip.contains(ip.as_str()),
        FilterExpr::Port(p) => pkt.src_port == Some(*p) || pkt.dst_port == Some(*p),
        FilterExpr::Stream(n) => pkt.stream_index == Some(*n),
        FilterExpr::Contains(s) => {
            pkt.info.to_lowercase().contains(s)
                || pkt.src_ip.to_lowercase().contains(s)
                || pkt.dst_ip.to_lowercase().contains(s)
                || pkt.protocol.to_lowercase().contains(s)
                || pkt.payload_text.to_lowercase().contains(s)
                || pkt
                    .src_host
                    .as_ref()
                    .is_some_and(|h| h.to_lowercase().contains(s))
                || pkt
                    .dst_host
                    .as_ref()
                    .is_some_and(|h| h.to_lowercase().contains(s))
                // Also search recovered TLS plaintext so `contains "GET /"`
                // finds decrypted requests/responses, not just cleartext.
                || pkt.decrypted_plaintext.as_ref().is_some_and(|pt| {
                    String::from_utf8_lossy(pt).to_lowercase().contains(s)
                })
        }
        FilterExpr::AppProto(tag) => match &pkt.app_protocol {
            Some(crate::dpi::AppProtocol::Tls { .. }) => "tls" == tag.as_str(),
            Some(crate::dpi::AppProtocol::Quic { .. }) => "quic" == tag.as_str(),
            Some(crate::dpi::AppProtocol::Http { .. }) => "http" == tag.as_str(),
            Some(crate::dpi::AppProtocol::Dns { .. }) => "dns" == tag.as_str(),
            Some(crate::dpi::AppProtocol::Ssh { .. }) => "ssh" == tag.as_str(),
            Some(crate::dpi::AppProtocol::Mqtt { .. }) => "mqtt" == tag.as_str(),
            Some(crate::dpi::AppProtocol::Stun { .. }) => "stun" == tag.as_str(),
            Some(crate::dpi::AppProtocol::BitTorrent { .. }) => "bittorrent" == tag.as_str(),
            Some(crate::dpi::AppProtocol::NetBios { .. }) => "netbios" == tag.as_str(),
            Some(crate::dpi::AppProtocol::Snmp { .. }) => "snmp" == tag.as_str(),
            Some(crate::dpi::AppProtocol::Ssdp { .. }) => "ssdp" == tag.as_str(),
            Some(crate::dpi::AppProtocol::Ftp { .. }) => "ftp" == tag.as_str(),
            Some(crate::dpi::AppProtocol::Llmnr { .. }) => "llmnr" == tag.as_str(),
            None => false,
        },
        FilterExpr::Sni(needle) => match &pkt.app_protocol {
            Some(crate::dpi::AppProtocol::Tls { sni: Some(h), .. }) => {
                h.to_lowercase().contains(needle.as_str())
            }
            Some(crate::dpi::AppProtocol::Quic { sni: Some(h), .. }) => {
                h.to_lowercase().contains(needle.as_str())
            }
            _ => false,
        },
        FilterExpr::Host(needle) => match &pkt.app_protocol {
            Some(crate::dpi::AppProtocol::Http { host: Some(h), .. }) => {
                h.to_lowercase().contains(needle.as_str())
            }
            _ => false,
        },
        FilterExpr::Ech(want) => match &pkt.app_protocol {
            Some(crate::dpi::AppProtocol::Tls { ech, .. }) => ech == want,
            Some(crate::dpi::AppProtocol::Quic { ech, .. }) => ech == want,
            _ => false,
        },
        FilterExpr::Ja4(needle) => match &pkt.app_protocol {
            Some(crate::dpi::AppProtocol::Tls { ja4: Some(j), .. }) => {
                j.to_lowercase().contains(needle.as_str())
            }
            Some(crate::dpi::AppProtocol::Quic { ja4: Some(j), .. }) => {
                j.to_lowercase().contains(needle.as_str())
            }
            _ => false,
        },
        FilterExpr::Decrypted(want) => pkt.decrypted_plaintext.is_some() == *want,
        FilterExpr::Not(inner) => !matches_packet(inner, pkt),
        FilterExpr::And(a, b) => matches_packet(a, pkt) && matches_packet(b, pkt),
        FilterExpr::Or(a, b) => matches_packet(a, pkt) || matches_packet(b, pkt),
    }
}
