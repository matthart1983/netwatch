//! DNS classifier — extracts the first question's qname + qtype.
//!
//! Matches both queries and responses since they share the same header
//! shape and the question section comes first in both. Works for plain
//! DNS-over-UDP (port 53), mDNS (5353), LLMNR (5355) — all use the
//! same wire format. DNS-over-TCP and DoH / DoT are not handled here;
//! the TLS classifier covers DoT/DoH at the TLS layer.
//!
//! Wire format (RFC 1035):
//! ```text
//! Header (12 bytes): id(2) flags(2) qd(2) an(2) ns(2) ar(2)
//! Question:          qname (labels, null-terminated) qtype(2) qclass(2)
//! Label:             length(1) bytes(length)
//! ```
//!
//! Limits:
//! - We deliberately reject compression pointers (`0xC0`+ prefix) in
//!   the qname. They're legal in *responses* but our use case is "what
//!   was being looked up," which is the question-section qname — and
//!   that should never compress. Rejecting pointers also keeps the
//!   parser linear-time with no recursion.
//! - We cap qname at 253 bytes (RFC 1035 max).

use super::{AppProtocol, Classifier};
use crate::ui::sanitize::display_owned;

const MAX_QNAME_LEN: usize = 253;
const HEADER_LEN: usize = 12;

pub struct DnsClassifier;

impl Classifier for DnsClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if is_tcp {
            return None; // DNS-over-TCP exists; skip for now.
        }
        if payload.len() < HEADER_LEN + 1 + 4 {
            return None; // minimum: header + root qname(1) + qtype+qclass(4)
        }
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        if qdcount == 0 {
            return None;
        }

        // Header flags: QR is the high bit of byte 2; RCODE is the low
        // nibble of byte 3 (RFC 1035 §4.1.1). We surface the response code
        // only on responses (QR=1); queries report `None`.
        let is_response = payload[2] & 0x80 != 0;
        let rcode = if is_response {
            Some(payload[3] & 0x0F)
        } else {
            None
        };

        // Parse the first question's qname starting right after the
        // 12-byte header. Refuse compression pointers — see module
        // doc. Reject malformed lengths (would walk past the buffer).
        let mut pos = HEADER_LEN;
        let mut name = String::new();
        loop {
            if pos >= payload.len() {
                return None;
            }
            let len = payload[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            // High two bits set → compression pointer (0xC0+). Refuse.
            if len & 0xC0 != 0 {
                return None;
            }
            if pos + 1 + len > payload.len() {
                return None;
            }
            if name.len() + len + 1 > MAX_QNAME_LEN {
                return None;
            }
            // Label bytes must be ASCII-ish. We don't strictly validate
            // hostnames here — utf8 conversion will fail for binary
            // junk and we'll bail.
            let label = std::str::from_utf8(&payload[pos + 1..pos + 1 + len]).ok()?;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(label);
            pos += 1 + len;
        }

        if pos + 4 > payload.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        // Skip qclass; not surfaced.

        // Drop trailing dot if present; root queries show as empty.
        if name.is_empty() {
            return None;
        }
        Some(AppProtocol::Dns {
            qname: display_owned(name),
            qtype,
            rcode,
        })
    }
}

/// A DNS message as the flow log needs it: the question, and for a response
/// the answer records it can use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub txid: u16,
    pub is_response: bool,
    pub qname: String,
    pub qtype: u16,
    /// `Some` on a response only.
    pub rcode: Option<u8>,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    /// The record's owner name.
    pub name: String,
    pub ttl: u32,
    pub data: DnsRecordData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordData {
    Addr(std::net::IpAddr),
    Cname(String),
}

/// Answer records kept from one message; the rest are skipped.
const MAX_ANSWERS: usize = 64;
/// Compression pointers followed while reading one name. A well-formed name
/// needs few; a loop needs this many to be stopped.
const MAX_POINTER_HOPS: usize = 16;

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;

/// Parse a whole DNS message over UDP: header, the first question, and the
/// A, AAAA and CNAME records of the answer section. `None` for anything that
/// is not a DNS message with one readable question. Names are made safe to
/// print, like [`DnsClassifier`]'s.
pub fn parse_message(payload: &[u8]) -> Option<DnsMessage> {
    if payload.len() < HEADER_LEN {
        return None;
    }
    let u16_at = |at: usize| -> Option<u16> {
        Some(u16::from_be_bytes([
            *payload.get(at)?,
            *payload.get(at + 1)?,
        ]))
    };
    let txid = u16_at(0)?;
    let is_response = payload[2] & 0x80 != 0;
    let rcode = is_response.then_some(payload[3] & 0x0F);
    if u16_at(4)? == 0 {
        return None;
    }
    let qdcount = u16_at(4)? as usize;
    let ancount = u16_at(6)? as usize;

    let (qname, mut pos) = read_name(payload, HEADER_LEN)?;
    if qname.is_empty() {
        return None;
    }
    let qtype = u16_at(pos)?;
    pos += 4;
    // Any further questions are skipped, not read: one is the norm.
    for _ in 1..qdcount {
        pos = skip_name(payload, pos)? + 4;
    }

    let mut answers = Vec::new();
    if is_response {
        for _ in 0..ancount {
            let Some((name, after)) = read_name(payload, pos) else {
                break;
            };
            let (Some(rtype), Some(ttl_hi), Some(ttl_lo), Some(rdlen)) = (
                u16_at(after),
                u16_at(after + 4),
                u16_at(after + 6),
                u16_at(after + 8),
            ) else {
                break;
            };
            let rdata = after + 10;
            let end = rdata + rdlen as usize;
            if end > payload.len() {
                break;
            }
            let ttl = (u32::from(ttl_hi) << 16) | u32::from(ttl_lo);
            let data = match (rtype, rdlen) {
                (TYPE_A, 4) => {
                    let b: [u8; 4] = payload[rdata..end].try_into().ok()?;
                    Some(DnsRecordData::Addr(std::net::Ipv4Addr::from(b).into()))
                }
                (TYPE_AAAA, 16) => {
                    let b: [u8; 16] = payload[rdata..end].try_into().ok()?;
                    Some(DnsRecordData::Addr(std::net::Ipv6Addr::from(b).into()))
                }
                (TYPE_CNAME, _) => read_name(payload, rdata).map(|(n, _)| DnsRecordData::Cname(n)),
                _ => None,
            };
            if let Some(data) = data {
                if answers.len() < MAX_ANSWERS {
                    answers.push(DnsAnswer { name, ttl, data });
                }
            }
            pos = end;
        }
    }
    Some(DnsMessage {
        txid,
        is_response,
        qname,
        qtype,
        rcode,
        answers,
    })
}

/// Read the name at `start`, following compression pointers, and return it
/// with the position just past it in the record (not past a pointer's
/// target). Lowercased, as names compare case-insensitively.
fn read_name(payload: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut after = None;
    let mut hops = 0;
    loop {
        let len = *payload.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        match len & 0xC0 {
            0xC0 => {
                let low = *payload.get(pos + 1)? as usize;
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return None;
                }
                after.get_or_insert(pos + 2);
                pos = ((len & 0x3F) << 8) | low;
            }
            0x00 => {
                let label = payload.get(pos + 1..pos + 1 + len)?;
                if name.len() + len + 1 > MAX_QNAME_LEN {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
                pos += 1 + len;
            }
            // 0x40 and 0x80 are reserved label types.
            _ => return None,
        }
    }
    Some((display_owned(name), after.unwrap_or(pos)))
}

/// The position just past the name at `start`, without reading it.
fn skip_name(payload: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    loop {
        let len = *payload.get(pos)? as usize;
        match len {
            0 => return Some(pos + 1),
            l if l & 0xC0 == 0xC0 => return Some(pos + 2),
            l if l & 0xC0 == 0 => pos += 1 + l,
            _ => return None,
        }
    }
}

/// The usual name of a query type, and `TYPE<n>` (RFC 3597) for the rest.
pub fn qtype_label(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

/// Short label for a DNS RCODE (RFC 1035 §4.1.1 + common extensions).
pub fn rcode_label(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        other => format!("RCODE{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard DNS query for `example.com` type A. Hand-built per
    /// RFC 1035: id=0xABCD, flags=RD (0x0100), qdcount=1.
    #[rustfmt::skip]
    const QUERY_EXAMPLE_COM_A: &[u8] = &[
        // Header
        0xAB, 0xCD, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // qname: 7 "example" 3 "com" 0
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        // qtype = A (0x0001), qclass = IN (0x0001)
        0x00, 0x01, 0x00, 0x01,
    ];

    /// A response for `www.example.com` A: a CNAME to `edge.example.net`,
    /// then that name's A and AAAA records, owner names compressed.
    fn cname_response() -> Vec<u8> {
        let mut m = vec![
            0x12, 0x34, 0x81, 0x80, // id, QR RD RA, NOERROR
            0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // qd 1, an 4
        ];
        // question at 12: www.example.com A IN
        m.extend_from_slice(b"\x03www\x07example\x03com\x00");
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // CNAME: owner -> 12, ttl 300, rdata edge.example.net
        m.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C]);
        let rdata = b"\x04edge\x07example\x03net\x00";
        m.extend_from_slice(&[0x00, rdata.len() as u8]);
        let target = m.len() as u8;
        m.extend_from_slice(rdata);
        // A for edge.example.net (pointer to the CNAME target), ttl 60
        m.extend_from_slice(&[0xC0, target, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C]);
        m.extend_from_slice(&[0x00, 0x04, 93, 184, 215, 14]);
        // AAAA
        m.extend_from_slice(&[0xC0, target, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C]);
        m.extend_from_slice(&[0x00, 0x10]);
        m.extend_from_slice(&[0x26, 0x06, 0x28, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // An MX the parser skips
        m.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x0F, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C]);
        m.extend_from_slice(&[0x00, 0x04, 0x00, 0x0A, 0xC0, 0x0C]);
        m
    }

    #[test]
    fn parse_message_reads_cname_a_and_aaaa_answers() {
        let msg = parse_message(&cname_response()).unwrap();
        assert_eq!(msg.txid, 0x1234);
        assert!(msg.is_response);
        assert_eq!(msg.qname, "www.example.com");
        assert_eq!(msg.qtype, 1);
        assert_eq!(msg.rcode, Some(0));
        assert_eq!(msg.answers.len(), 3, "{:?}", msg.answers);
        assert_eq!(msg.answers[0].name, "www.example.com");
        assert_eq!(msg.answers[0].ttl, 300);
        assert_eq!(
            msg.answers[0].data,
            DnsRecordData::Cname("edge.example.net".into())
        );
        assert_eq!(msg.answers[1].name, "edge.example.net");
        assert_eq!(
            msg.answers[1].data,
            DnsRecordData::Addr("93.184.215.14".parse().unwrap())
        );
        assert_eq!(
            msg.answers[2].data,
            DnsRecordData::Addr("2606:2800::1".parse().unwrap())
        );
    }

    #[test]
    fn parse_message_reads_a_query_and_lowercases() {
        let mut q = QUERY_EXAMPLE_COM_A.to_vec();
        q[13] = b'E';
        let msg = parse_message(&q).unwrap();
        assert!(!msg.is_response);
        assert_eq!(msg.qname, "example.com");
        assert_eq!(msg.rcode, None);
        assert!(msg.answers.is_empty());
        assert_eq!(qtype_label(msg.qtype), "A");
        assert_eq!(qtype_label(65), "HTTPS");
        assert_eq!(qtype_label(999), "TYPE999");
    }

    /// Hostile input ends in `None` or in fewer answers, never a panic or a
    /// hang: pointer loops, pointers past the end, truncation at every byte.
    #[test]
    fn parse_message_survives_hostile_input() {
        let good = cname_response();
        for cut in 0..good.len() {
            let _ = parse_message(&good[..cut]);
        }
        // A question name that points at itself.
        let mut looped = QUERY_EXAMPLE_COM_A[..12].to_vec();
        looped.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(parse_message(&looped), None);
        // A pointer past the end.
        let mut far = QUERY_EXAMPLE_COM_A[..12].to_vec();
        far.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(parse_message(&far), None);
        // An answer count far beyond the records present.
        let mut many = good.clone();
        many[7] = 0xFF;
        assert_eq!(parse_message(&many).unwrap().answers.len(), 3);
        // A reserved label type.
        let mut reserved = QUERY_EXAMPLE_COM_A.to_vec();
        reserved[12] = 0x40;
        assert_eq!(parse_message(&reserved), None);
    }

    #[test]
    fn extracts_qname_and_qtype() {
        let result = DnsClassifier.classify(QUERY_EXAMPLE_COM_A, false);
        match result {
            Some(AppProtocol::Dns {
                qname,
                qtype,
                rcode,
            }) => {
                assert_eq!(qname, "example.com");
                assert_eq!(qtype, 1); // A
                assert_eq!(rcode, None, "queries carry no rcode");
            }
            other => panic!("expected Dns{{..}}, got {:?}", other),
        }
    }

    #[test]
    fn extracts_rcode_from_response() {
        // Same question, but flags = response (QR=1) with RCODE=3 (NXDOMAIN):
        // byte 2 = 0x81 (QR + RD), byte 3 = 0x83 (RA + NXDOMAIN).
        #[rustfmt::skip]
        let response: &[u8] = &[
            0xAB, 0xCD, 0x81, 0x83,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        match DnsClassifier.classify(response, false) {
            Some(AppProtocol::Dns {
                qname,
                rcode: Some(rc),
                ..
            }) => {
                assert_eq!(qname, "example.com");
                assert_eq!(rc, 3); // NXDOMAIN
                assert_eq!(rcode_label(rc), "NXDOMAIN");
            }
            other => panic!("expected Dns response with rcode, got {:?}", other),
        }
    }

    #[test]
    fn rejects_tcp_path() {
        assert!(DnsClassifier.classify(QUERY_EXAMPLE_COM_A, true).is_none());
    }

    /// A label is any 63 bytes the sender likes, so a query for an
    /// attacker's name can carry an escape sequence into every view that
    /// shows DNS.
    #[test]
    fn qname_control_characters_are_replaced() {
        let mut payload = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["\x1b]52;c;AAAA\x07", "evil\u{202E}moc", "example"] {
            payload.push(label.len() as u8);
            payload.extend_from_slice(label.as_bytes());
        }
        payload.extend_from_slice(&[0, 0, 1, 0, 1]);
        match DnsClassifier.classify(&payload, false) {
            Some(AppProtocol::Dns { qname, .. }) => {
                assert_eq!(qname, "·]52;c;AAAA·.evil·moc.example");
            }
            other => panic!("expected Dns{{..}}, got {:?}", other),
        }
    }

    #[test]
    fn rejects_compression_pointer_in_qname() {
        // Header (qdcount=1), then a label whose length byte starts
        // with 0xC0 (compression pointer marker). Our parser refuses
        // this in the question section.
        #[rustfmt::skip]
        let payload: &[u8] = &[
            0xAB, 0xCD, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x0C, // pointer back to header — illegal here
            0x00, 0x01, 0x00, 0x01,
        ];
        assert!(DnsClassifier.classify(payload, false).is_none());
    }

    #[test]
    fn rejects_zero_qdcount() {
        // Same shape but qdcount=0 → no question to classify.
        #[rustfmt::skip]
        let payload: &[u8] = &[
            0xAB, 0xCD, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        assert!(DnsClassifier.classify(payload, false).is_none());
    }

    #[test]
    fn rejects_truncated_payload() {
        // Header + label-length byte but no label bytes.
        let payload: &[u8] = &[
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
        ];
        assert!(DnsClassifier.classify(payload, false).is_none());
    }

    #[test]
    fn rejects_non_utf8_labels() {
        // Header + label of length 3 containing high-bit bytes — fails
        // utf8 parsing and we bail. (Real DNS labels are ASCII-only.)
        #[rustfmt::skip]
        let payload: &[u8] = &[
            0xAB, 0xCD, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0xff, 0xfe, 0xfd,
            0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        assert!(DnsClassifier.classify(payload, false).is_none());
    }
}
