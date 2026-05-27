//! TLS classifier — extracts SNI hostname + ALPN protocol from the
//! first TLS record on a TCP flow, and flags Encrypted ClientHello (ECH)
//! presence when the ClientHello carries the `encrypted_client_hello`
//! extension.
//!
//! Coverage: TLS 1.0–1.3 ClientHello with the standard SNI extension
//! (RFC 6066). TLS 1.3 with ECH (draft-ietf-tls-esni, ext type 0xfe0d)
//! is detected and surfaced as a flag; the reported SNI in that case is
//! the *outer* SNI (typically `cloudflare-ech.com` or similar). Real ECH
//! and GREASE-ECH (RFC 8744) are indistinguishable on the wire without
//! the server's keys, so we flag presence rather than claiming to know
//! which is which — the user-relevant signal is the same either way:
//! the network observer doesn't see the inner SNI.
//!
//! Limits:
//! - Server-side Hellos (ServerHello, EncryptedExtensions) are ignored;
//!   we classify from the client direction only. If we miss the client
//!   side because capture started mid-flow, the connection stays
//!   classified as plain TCP.
//! - ClientHellos fragmented across multiple TCP segments are missed
//!   on the first segment. <1% of real traffic; acceptable for v1.

use tls_parser::{
    parse_tls_extensions, parse_tls_message_handshake, parse_tls_plaintext, TlsExtension,
    TlsMessage, TlsMessageHandshake,
};

use super::{AppProtocol, Classifier};

/// IANA TLS ExtensionType code point for `encrypted_client_hello`
/// (draft-ietf-tls-esni). tls-parser 0.12 doesn't have a typed variant
/// for this, so real ECH extensions arrive as `TlsExtension::Unknown`
/// with this type code.
const ECH_EXTENSION_TYPE: u16 = 0xfe0d;

/// `true` when the extension list contains an `encrypted_client_hello`
/// extension. Used by both the TLS classifier and any downstream caller
/// (e.g. QUIC ECH detection if added) that has already parsed
/// extensions out of a handshake.
pub fn has_ech(exts: &[TlsExtension]) -> bool {
    exts.iter()
        .any(|e| matches!(e, TlsExtension::Unknown(t, _) if t.0 == ECH_EXTENSION_TYPE))
}

/// Fields extracted from a bare TLS 1.3 ClientHello in a single
/// extension-walk. Used by `dpi::quic` to read both SNI and ECH-presence
/// out of a QUIC Initial's reassembled CRYPTO frames without parsing
/// the extension list twice.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HandshakeMetadata {
    pub sni: Option<String>,
    pub ech: bool,
}

/// Walk a bare TLS 1.3 handshake (no TLS record wrapper) and extract
/// the SNI hostname and `encrypted_client_hello` flag. Returns all
/// defaults (None / false) if the bytes aren't a parseable ClientHello.
pub fn extract_handshake_metadata(handshake_bytes: &[u8]) -> HandshakeMetadata {
    let Ok((_, msg)) = parse_tls_message_handshake(handshake_bytes) else {
        return HandshakeMetadata::default();
    };
    let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg else {
        return HandshakeMetadata::default();
    };
    let Some(ext_data) = ch.ext else {
        return HandshakeMetadata::default();
    };
    let Ok((_, exts)) = parse_tls_extensions(ext_data) else {
        return HandshakeMetadata::default();
    };
    let mut meta = HandshakeMetadata::default();
    meta.ech = has_ech(&exts);
    for ext in &exts {
        if let TlsExtension::SNI(entries) = ext {
            meta.sni = entries
                .first()
                .and_then(|(_, host)| std::str::from_utf8(host).ok())
                .map(|s| s.to_string());
            break;
        }
    }
    meta
}

pub struct TlsClassifier;

impl Classifier for TlsClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if !is_tcp {
            return None;
        }
        // Quick reject before invoking the parser: TLS records always
        // start with content_type = 0x16 (handshake) followed by major
        // protocol version 0x03.
        if payload.len() < 5 || payload[0] != 0x16 || payload[1] != 0x03 {
            return None;
        }

        let (_, record) = parse_tls_plaintext(payload).ok()?;
        for msg in record.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
                let mut sni: Option<String> = None;
                let mut alpn: Option<String> = None;
                let mut ech = false;
                if let Some(ext_data) = ch.ext {
                    if let Ok((_, exts)) = parse_tls_extensions(ext_data) {
                        ech = has_ech(&exts);
                        for ext in &exts {
                            match ext {
                                TlsExtension::SNI(entries) => {
                                    sni = entries
                                        .first()
                                        .and_then(|(_, host)| std::str::from_utf8(host).ok())
                                        .map(|s| s.to_string());
                                }
                                TlsExtension::ALPN(protos) => {
                                    alpn = protos
                                        .first()
                                        .and_then(|p| std::str::from_utf8(p).ok())
                                        .map(|s| s.to_string());
                                }
                                _ => {}
                            }
                        }
                    }
                }
                return Some(AppProtocol::Tls { sni, alpn, ech });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real TLS 1.3 ClientHello captured from Python's default `ssl`
    /// stack initiating a handshake with `server_hostname='example.com'`.
    /// 517 bytes including standard padding to a power of two. No ALPN
    /// (Python's default context doesn't enable it).
    #[rustfmt::skip]
    const CLIENT_HELLO_EXAMPLE_COM: &[u8] = &[
        0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0xc9,
        0x32, 0x78, 0xb0, 0xa0, 0x6d, 0xef, 0xa6, 0x5c, 0xef, 0xc5, 0x06, 0x3f,
        0x0d, 0xd4, 0x88, 0x43, 0x26, 0x9c, 0xb7, 0xc2, 0x54, 0x79, 0xe7, 0x10,
        0x1e, 0xba, 0x5e, 0x55, 0xb0, 0x7f, 0xac, 0x20, 0x43, 0x0e, 0x44, 0x62,
        0x97, 0xf6, 0xb4, 0xa7, 0x7a, 0x4b, 0xd8, 0x10, 0xa2, 0xac, 0x1a, 0x41,
        0x4b, 0x2b, 0x03, 0xa2, 0x79, 0x49, 0x8e, 0x19, 0x4d, 0x92, 0x75, 0x87,
        0x6e, 0x0e, 0xa8, 0xc6, 0x00, 0x24, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01,
        0xc0, 0x2c, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8,
        0xc0, 0x24, 0xc0, 0x28, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x9f, 0x00, 0x9e,
        0x00, 0x6b, 0x00, 0x67, 0x00, 0xff, 0x01, 0x00, 0x01, 0x8f, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
        0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00,
        0x01, 0x02, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17,
        0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02,
        0x01, 0x03, 0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00,
        0x00, 0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28, 0x04, 0x03,
        0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a,
        0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
        0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03, 0x02, 0x04, 0x02, 0x05, 0x02,
        0x06, 0x02, 0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00,
        0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00,
        0x1d, 0x00, 0x20, 0x64, 0x99, 0x98, 0x0a, 0x63, 0xef, 0x56, 0x83, 0x6e,
        0xae, 0xb3, 0xa8, 0x6b, 0x64, 0xe4, 0xc2, 0xd8, 0x5e, 0x22, 0x29, 0xc0,
        0x57, 0x46, 0xb1, 0x6b, 0x23, 0x66, 0x42, 0xfa, 0x41, 0xd9, 0x1c, 0x00,
        0x15, 0x00, 0xe2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    #[test]
    fn extracts_sni_from_clienthello() {
        let result = TlsClassifier.classify(CLIENT_HELLO_EXAMPLE_COM, true);
        match result {
            Some(AppProtocol::Tls { sni, alpn, ech }) => {
                assert_eq!(sni.as_deref(), Some("example.com"));
                // No ALPN in this particular fixture (Python ssl default).
                assert!(alpn.is_none(), "didn't expect ALPN in this fixture");
                // Vanilla Python ssl does not send the ECH extension.
                assert!(!ech, "vanilla fixture should not be flagged as ECH");
            }
            other => panic!("expected Tls{{..}}, got {:?}", other),
        }
    }

    #[test]
    fn rejects_non_tls_payload() {
        assert!(TlsClassifier
            .classify(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", true)
            .is_none());
        // UDP path: never claims TLS.
        assert!(TlsClassifier
            .classify(CLIENT_HELLO_EXAMPLE_COM, false)
            .is_none());
        // Too short to be a TLS record header.
        assert!(TlsClassifier.classify(&[0x16, 0x03], true).is_none());
    }

    #[test]
    fn handles_empty_payload() {
        assert!(TlsClassifier.classify(&[], true).is_none());
    }

    #[test]
    fn has_ech_detects_encrypted_client_hello() {
        use tls_parser::TlsExtensionType;
        let exts = vec![
            TlsExtension::SNI(vec![]),
            TlsExtension::Unknown(TlsExtensionType(ECH_EXTENSION_TYPE), &[]),
        ];
        assert!(has_ech(&exts));
    }

    #[test]
    fn has_ech_ignores_unrelated_unknown_extensions() {
        use tls_parser::TlsExtensionType;
        // Some arbitrary other Unknown extension type code — must not
        // false-positive as ECH.
        let exts = vec![TlsExtension::Unknown(TlsExtensionType(0x1234), &[])];
        assert!(!has_ech(&exts));
    }

    #[test]
    fn has_ech_returns_false_on_empty() {
        assert!(!has_ech(&[]));
    }

    /// Synthetic ClientHello: takes the example.com fixture and appends
    /// a 4-byte ECH extension (type 0xfe0d, length 0) with the three
    /// length fields fixed up: extensions list length (+4), handshake
    /// length (+4), and TLS record length (+4).
    ///
    /// Field offsets derived by walking the fixture structure:
    /// - Bytes 3..=4    = TLS record length    (0x0200 = 512)
    /// - Bytes 6..=8    = handshake length     (0x0001fc = 508)
    /// - Bytes 116..=117 = extensions length   (0x018f = 399)
    ///   (session_id at 44..=75, ciphers at 78..=113, then 1-byte
    ///   compression-list length + 1-byte method.)
    fn build_ech_fixture() -> Vec<u8> {
        assert_eq!(
            &CLIENT_HELLO_EXAMPLE_COM[116..=117],
            &[0x01, 0x8f],
            "fixture changed; re-derive extensions_length offset"
        );

        let mut bytes = CLIENT_HELLO_EXAMPLE_COM.to_vec();
        // Bump TLS record length: 0x0200 -> 0x0204
        bytes[3] = 0x02;
        bytes[4] = 0x04;
        // Bump handshake length: 0x0001fc -> 0x000200
        bytes[6] = 0x00;
        bytes[7] = 0x02;
        bytes[8] = 0x00;
        // Bump extensions length: 0x018f -> 0x0193
        bytes[116] = 0x01;
        bytes[117] = 0x93;
        // Append an empty ECH extension: type 0xfe0d, length 0x0000.
        bytes.extend_from_slice(&[0xfe, 0x0d, 0x00, 0x00]);
        bytes
    }

    #[test]
    fn extract_metadata_strips_record_header_and_finds_sni() {
        // Skip the 5-byte TLS record header (content_type + version + len)
        // to get the bare handshake bytes that the QUIC path feeds in.
        let handshake = &CLIENT_HELLO_EXAMPLE_COM[5..];
        let meta = extract_handshake_metadata(handshake);
        assert_eq!(meta.sni.as_deref(), Some("example.com"));
        assert!(!meta.ech, "vanilla fixture has no ECH");
    }

    #[test]
    fn extract_metadata_finds_ech_when_present() {
        let fixture = build_ech_fixture();
        let meta = extract_handshake_metadata(&fixture[5..]);
        assert_eq!(meta.sni.as_deref(), Some("example.com"));
        assert!(meta.ech, "augmented fixture should carry ECH flag");
    }

    #[test]
    fn extract_metadata_returns_defaults_on_garbage() {
        let meta = extract_handshake_metadata(&[0xff; 16]);
        assert_eq!(meta, HandshakeMetadata::default());
    }

    #[test]
    fn detects_ech_in_clienthello_pipeline() {
        let fixture = build_ech_fixture();
        let result = TlsClassifier.classify(&fixture, true);
        match result {
            Some(AppProtocol::Tls { sni, ech, .. }) => {
                assert_eq!(
                    sni.as_deref(),
                    Some("example.com"),
                    "ECH-augmented fixture should still expose its (outer) SNI"
                );
                assert!(ech, "expected ECH extension to be detected");
            }
            other => panic!("expected Tls{{..}}, got {:?}", other),
        }
    }
}
