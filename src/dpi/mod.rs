//! Deep packet inspection — application-layer protocol classification.
//!
//! Each classifier looks at the first N bytes of an application-layer
//! payload (post-TCP/UDP) and decides whether the flow is its protocol.
//! Classifiers run once per stream — the result is cached on the
//! `Stream` record in `collectors::packets` for the flow's lifetime.
//!
//! Adding a new classifier:
//! 1. Drop a new file under `src/dpi/` with a struct implementing
//!    `Classifier::classify`.
//! 2. Add it to `classify_once` in priority order — cheap pattern-match
//!    classifiers first, parser-based ones later.

pub mod bittorrent;
pub mod dhcp;
pub mod dns;
pub mod ftp;
pub mod http;
pub mod http3;
pub mod ja4;
pub mod ja4_db;
pub mod llmnr;
pub mod mqtt;
pub mod netbios;
pub mod ntp;
pub mod quic;
pub mod snmp;
pub mod ssdp;
pub mod ssh;
pub mod stun;
pub mod tls;
pub mod tls_decrypt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppProtocol {
    /// TLS handshake observed; SNI / ALPN extracted when present.
    /// `ech` is true when the ClientHello carries an `encrypted_client_hello`
    /// extension (type 0xfe0d). When true, `sni` is the *outer* SNI — the
    /// real destination is hidden from the network. We can't distinguish
    /// real ECH from GREASE-ECH (RFC 8744) without the server's keys; both
    /// look identical on the wire and both mean the observer can't see the
    /// inner SNI, so the flag is honest either way.
    Tls {
        sni: Option<String>,
        alpn: Option<String>,
        #[serde(default)]
        ech: bool,
        /// JA4 fingerprint (Foxio spec) of the ClientHello. `None` when
        /// the ClientHello was malformed enough that fingerprinting
        /// couldn't run; otherwise always Some(_).
        #[serde(default)]
        ja4: Option<String>,
    },
    /// HTTP/1.x request line + `Host:` header. Requests also carry the
    /// request-target (`path`); responses carry the `status` code.
    Http {
        method: String,
        host: Option<String>,
        /// Request-target from the request line (e.g. `/index.html`). `None`
        /// on responses or when only the server side was observed.
        #[serde(default)]
        path: Option<String>,
        /// Response status code (e.g. `404`). `None` on requests.
        #[serde(default)]
        status: Option<u16>,
    },
    /// DNS query or response — first question's qname + qtype, plus the
    /// header RCODE on responses.
    Dns {
        qname: String,
        qtype: u16,
        /// Response code from the DNS header (`0`=NOERROR, `3`=NXDOMAIN,
        /// …). `Some` only when the QR bit marks this a response; `None`
        /// for queries.
        #[serde(default)]
        rcode: Option<u8>,
    },
    /// SSH server / client banner line, e.g. `SSH-2.0-OpenSSH_9.0`.
    Ssh { version: String },
    /// QUIC Initial packet detected; SNI extracted across reassembled
    /// CRYPTO frames in `collectors::packets`. `ech` mirrors the TLS
    /// variant — true when the reassembled ClientHello carried an
    /// `encrypted_client_hello` extension, in which case `sni` is the
    /// outer SNI.
    Quic {
        sni: Option<String>,
        #[serde(default)]
        ech: bool,
        /// JA4Q fingerprint (Foxio spec, `q` protocol prefix) of the
        /// reassembled QUIC ClientHello. `None` when reassembly /
        /// decryption fell short of producing a parseable ClientHello.
        #[serde(default)]
        ja4: Option<String>,
    },
    /// MQTT control packet. Variant carries CONNECT client-id when seen.
    Mqtt { client_id: Option<String> },
    /// STUN binding request / response (RFC 5389) — message method + class.
    Stun { message_type: String },
    /// BitTorrent peer-wire handshake (BEP 3). Info hash hex if extracted.
    BitTorrent { info_hash: Option<String> },
    /// NetBIOS name service / datagram / session traffic.
    NetBios { service: String },
    /// SNMP message — version (1/2c/3) and community string when readable.
    Snmp {
        version: String,
        community: Option<String>,
    },
    /// SSDP control message — `NOTIFY` or `M-SEARCH` with optional ST/NT.
    Ssdp {
        method: String,
        target: Option<String>,
    },
    /// FTP control channel command (USER / PASS / RETR / STOR / ...).
    Ftp { command: String },
    /// LLMNR query (RFC 4795) — wire-format-identical to DNS but on port
    /// 5355. Carries qname + qtype like the DNS variant.
    Llmnr { qname: String, qtype: u16 },
    /// DHCP / BOOTP message, identified by its BOOTP op code (1 = request,
    /// 2 = reply). Port-gated to 67/68.
    Dhcp { op: u8 },
    /// NTP message — protocol `version` and `mode` from the leap/version/mode
    /// byte (RFC 5905). Port-gated to 123.
    Ntp { version: u8, mode: u8 },
}

impl AppProtocol {
    /// The lowercase name display filters match (`tls`, `quic`, …) and the
    /// flow log writes.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Tls { .. } => "tls",
            Self::Quic { .. } => "quic",
            Self::Http { .. } => "http",
            Self::Dns { .. } => "dns",
            Self::Ssh { .. } => "ssh",
            Self::Mqtt { .. } => "mqtt",
            Self::Stun { .. } => "stun",
            Self::BitTorrent { .. } => "bittorrent",
            Self::NetBios { .. } => "netbios",
            Self::Snmp { .. } => "snmp",
            Self::Ssdp { .. } => "ssdp",
            Self::Ftp { .. } => "ftp",
            Self::Llmnr { .. } => "llmnr",
            Self::Dhcp { .. } => "dhcp",
            Self::Ntp { .. } => "ntp",
        }
    }
}

pub trait Classifier {
    /// `Some(protocol)` when this classifier recognizes the payload,
    /// `None` to fall through to the next classifier.
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol>;
}

/// Run all classifiers in priority order, returning the first match.
/// Cheap pattern-match classifiers go first; parser-based ones last.
///
/// Port hints disambiguate protocols that are wire-format-identical
/// (LLMNR vs. DNS, SSDP vs. HTTP) or strongly port-locked (SNMP, MQTT,
/// NetBIOS) — pass either side's port and we'll match accordingly.
pub fn classify_once(
    payload: &[u8],
    is_tcp: bool,
    src_port: u16,
    dst_port: u16,
) -> Option<AppProtocol> {
    if payload.len() < 4 {
        return None;
    }
    let any_port = |p: u16| src_port == p || dst_port == p;
    let any_port_in = |range: std::ops::RangeInclusive<u16>| {
        range.contains(&src_port) || range.contains(&dst_port)
    };

    if is_tcp {
        // BitTorrent handshake: cheap magic-byte check.
        if let Some(p) = bittorrent::BitTorrentClassifier.classify(payload, is_tcp) {
            return Some(p);
        }
        if let Some(p) = ssh::SshClassifier.classify(payload, is_tcp) {
            return Some(p);
        }
        // FTP control channel: port 21 is canonical. Skip the heavy
        // banner scan on other ports so HTTP/SMTP/IMAP traffic isn't
        // mistaken for FTP responses ("220 ...").
        if any_port(21) {
            if let Some(p) = ftp::FtpClassifier.classify(payload, is_tcp) {
                return Some(p);
            }
        }
        if let Some(p) = http::HttpClassifier.classify(payload, is_tcp) {
            return Some(p);
        }
        if let Some(p) = tls::TlsClassifier.classify(payload, is_tcp) {
            return Some(p);
        }
        // MQTT control packets travel over TCP, typically on 1883/8883.
        if any_port(1883) || any_port(8883) {
            if let Some(p) = mqtt::MqttClassifier.classify(payload, is_tcp) {
                return Some(p);
            }
        }
        // NetBIOS session service over TCP/139 (CIFS sessions).
        if any_port(139) {
            if let Some(p) = netbios::NetBiosClassifier.classify(payload, is_tcp) {
                return Some(p);
            }
        }
    }

    if !is_tcp {
        if let Some(p) = quic::QuicClassifier.classify(payload, is_tcp) {
            return Some(p);
        }
        // DHCP/BOOTP on UDP 67/68 and NTP on 123 — strictly port-gated,
        // so a cheap op-byte read is enough to label them.
        if any_port(67) || any_port(68) {
            if let Some(p) = dhcp::DhcpClassifier.classify(payload, is_tcp) {
                return Some(p);
            }
        }
        if any_port(123) {
            if let Some(p) = ntp::NtpClassifier.classify(payload, is_tcp) {
                return Some(p);
            }
        }
        // SSDP on UDP/1900 (HTTP-like text payload). Check before DNS
        // because its `M-SEARCH * HTTP/1.1` looks like nothing else.
        if any_port(1900) {
            if let Some(p) = ssdp::SsdpClassifier.classify(payload, is_tcp) {
                return Some(p);
            }
        }
        // LLMNR on UDP/5355 — wire-identical to DNS. Disambiguate by port
        // so the LLMNR variant gets used.
        if any_port(5355) {
            if let Some(p) = llmnr::LlmnrClassifier.classify(payload, is_tcp) {
                return Some(p);
            }
        }
        // SNMP on UDP/161 (queries) and 162 (traps).
        if any_port(161) || any_port(162) {
            if let Some(p) = snmp::SnmpClassifier.classify(payload, is_tcp) {
                return Some(p);
            }
        }
        // NetBIOS name service (UDP/137) and datagram service (UDP/138).
        if any_port_in(137..=138) {
            if let Some(p) = netbios::NetBiosClassifier.classify(payload, is_tcp) {
                return Some(p);
            }
        }
        // STUN on 3478 traditionally; many WebRTC stacks use ephemeral
        // ports, but the magic cookie at offset 4 is unambiguous. Run
        // the classifier on every UDP flow that has at least 20 bytes.
        if let Some(p) = stun::StunClassifier.classify(payload, is_tcp) {
            return Some(p);
        }
        // DNS (and mDNS, port 5353). Wire-format check is what gates it
        // so we can leave the port filter loose.
        if let Some(p) = dns::DnsClassifier.classify(payload, is_tcp) {
            return Some(p);
        }
    }

    None
}

#[cfg(test)]
mod fuzz_tests {
    use super::*;

    /// Tiny deterministic xorshift PRNG — keeps the fuzz corpus
    /// reproducible and pulls in no `rand`/`proptest` dependency.
    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn byte(&mut self) -> u8 {
            (self.next() & 0xFF) as u8
        }
    }

    /// Backs the "safely parses hostile traffic" claim: throw a large
    /// corpus of random and adversarially-shaped byte buffers at every DPI
    /// classifier and assert the parsers never panic (overflow, slice OOB,
    /// utf8, etc.). The test passing *is* the assertion — any panic in a
    /// classifier surfaces here instead of in production capture.
    #[test]
    fn classifiers_never_panic_on_hostile_input() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        // A few real protocol prefixes to seed structured mutation — a
        // valid-looking header followed by garbage is the nastiest case
        // for a length-trusting parser.
        let seeds: &[&[u8]] = &[
            &[0x16, 0x03, 0x01],                   // TLS handshake record
            &[0x47, 0x45, 0x54, 0x20],             // "GET "
            b"HTTP/1.1 200 OK\r\n",                // HTTP response line
            &[0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01], // DNS-ish header
            &[0x13, b'B', b'i', b't'],             // BitTorrent length prefix
            b"SSH-2.0-",                           // SSH banner
        ];

        for iter in 0..20_000u32 {
            let len = (rng.next() % 2048) as usize;
            let mut buf = Vec::with_capacity(len);
            // Optionally prepend a structured seed so we exercise the
            // "valid prefix, hostile tail" path, not just pure noise.
            if iter % 3 == 0 {
                let seed = seeds[(iter as usize / 3) % seeds.len()];
                buf.extend_from_slice(seed);
            }
            while buf.len() < len {
                buf.push(rng.byte());
            }

            let sp = (rng.next() & 0xFFFF) as u16;
            let dp = (rng.next() & 0xFFFF) as u16;
            // Both transports, and a couple of canonical ports to unlock
            // the port-gated classifiers (FTP/SNMP/NetBIOS/DNS/…).
            let _ = classify_once(&buf, true, sp, dp);
            let _ = classify_once(&buf, false, sp, dp);
            let _ = classify_once(&buf, false, 53, dp);
            let _ = classify_once(&buf, true, 21, dp);
        }
    }
}
