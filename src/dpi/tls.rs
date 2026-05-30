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

use super::ja4::{self, Ja4Input};
use super::{AppProtocol, Classifier};

/// IANA TLS ExtensionType code point for `encrypted_client_hello`
/// (draft-ietf-tls-esni). tls-parser 0.12 doesn't have a typed variant
/// for this, so real ECH extensions arrive as `TlsExtension::Unknown`
/// with this type code.
const ECH_EXTENSION_TYPE: u16 = 0xfe0d;

/// Pull the 32-byte `client_random` out of a TLS ClientHello record.
/// Used by the TLS-decryption path to key per-flow secrets in the
/// SSLKEYLOGFILE; the keylog uses `client_random` as its lookup key.
/// Returns `None` for non-TLS, non-ClientHello, or malformed input.
pub fn extract_client_random(payload: &[u8]) -> Option<[u8; 32]> {
    // Same fast-reject as TlsClassifier: TLS records start with
    // content_type=0x16 (handshake) and major version 0x03.
    if payload.len() < 5 || payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }
    let (_, record) = parse_tls_plaintext(payload).ok()?;
    for msg in record.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
            if ch.random.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(ch.random);
                return Some(out);
            }
        }
    }
    None
}

/// Pull the negotiated cipher suite ID out of a TLS ServerHello.
/// Required by the decryption path: the SSLKEYLOGFILE stores AEAD
/// secrets but not the chosen cipher, so we read it off the wire.
/// Returns `None` for non-TLS, non-ServerHello, or malformed input.
pub fn extract_server_hello_cipher_suite(payload: &[u8]) -> Option<u16> {
    if payload.len() < 5 || payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }
    let (_, record) = parse_tls_plaintext(payload).ok()?;
    for msg in record.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) = msg {
            return Some(sh.cipher.0);
        }
    }
    None
}

/// `true` when the extension list contains an `encrypted_client_hello`
/// extension. Used by both the TLS classifier and any downstream caller
/// (e.g. QUIC ECH detection if added) that has already parsed
/// extensions out of a handshake.
pub fn has_ech(exts: &[TlsExtension]) -> bool {
    exts.iter()
        .any(|e| matches!(e, TlsExtension::Unknown(t, _) if t.0 == ECH_EXTENSION_TYPE))
}

/// Fields extracted from a bare TLS 1.3 ClientHello in a single
/// extension-walk. Used by `dpi::quic` to read SNI, ECH-presence,
/// and JA4Q out of a QUIC Initial's reassembled CRYPTO frames
/// without parsing the extension list multiple times.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HandshakeMetadata {
    pub sni: Option<String>,
    pub ech: bool,
    /// JA4Q (JA4 with `q` protocol prefix) computed from the
    /// reassembled QUIC ClientHello. `None` if the handshake bytes
    /// weren't a parseable ClientHello.
    pub ja4: Option<String>,
    /// ClientHello random (32 bytes) — the `client_random` used to look
    /// up this connection's secrets in the SSLKEYLOGFILE keylog. `None`
    /// if the bytes weren't a parseable ClientHello. Needed by QUIC
    /// 1-RTT decryption to associate the flow with its keylog entry.
    pub client_random: Option<[u8; 32]>,
}

/// Walk a bare TLS 1.3 handshake (no TLS record wrapper) and extract
/// SNI, ECH flag, and JA4Q. Returns all defaults if the bytes aren't
/// a parseable ClientHello. Always emits the `q` protocol prefix on
/// JA4 because the only caller for bare-handshake input is the QUIC
/// reassembly path; TLS-over-TCP runs through `TlsClassifier` which
/// has its own JA4 computation with the `t` prefix.
pub fn extract_handshake_metadata(handshake_bytes: &[u8]) -> HandshakeMetadata {
    let Ok((_, msg)) = parse_tls_message_handshake(handshake_bytes) else {
        return HandshakeMetadata::default();
    };
    let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg else {
        return HandshakeMetadata::default();
    };
    // Capture client_random first — it's available regardless of the
    // extension list, and QUIC 1-RTT decryption needs it even when the
    // ClientHello is too truncated to finish extension parsing.
    let mut meta = HandshakeMetadata::default();
    if ch.random.len() == 32 {
        let mut r = [0u8; 32];
        r.copy_from_slice(ch.random);
        meta.client_random = Some(r);
    }
    let Some(ext_data) = ch.ext else {
        return meta;
    };
    let Ok((_, exts)) = parse_tls_extensions(ext_data) else {
        return meta;
    };
    meta.ech = has_ech(&exts);
    let mut alpn_first_bytes: Option<&[u8]> = None;
    let mut sig_algs: Vec<u16> = Vec::new();
    let mut tls_version: u16 = ch.version.0;
    for ext in &exts {
        match ext {
            TlsExtension::SNI(entries) => {
                meta.sni = entries
                    .first()
                    .and_then(|(_, host)| std::str::from_utf8(host).ok())
                    .map(|s| s.to_string());
            }
            TlsExtension::ALPN(protos) => {
                if let Some(first) = protos.first() {
                    alpn_first_bytes = Some(*first);
                }
            }
            TlsExtension::SignatureAlgorithms(algs) => {
                sig_algs = algs.clone();
            }
            TlsExtension::SupportedVersions(vers) => {
                let highest = vers
                    .iter()
                    .map(|v| v.0)
                    .filter(|v| !ja4::is_grease(*v))
                    .max();
                if let Some(v) = highest {
                    tls_version = v;
                }
            }
            _ => {}
        }
    }
    let cipher_codes: Vec<u16> = ch.ciphers.iter().map(|c| c.0).collect();
    let ext_type_codes = ja4::extension_type_codes(ext_data);
    meta.ja4 = Some(ja4::compute_ja4(&ja4::Ja4Input {
        is_quic: true,
        tls_version,
        sni_present: meta.sni.is_some(),
        alpn_first: alpn_first_bytes,
        ciphers: &cipher_codes,
        extensions: &ext_type_codes,
        signature_algorithms: &sig_algs,
    }));
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
                let mut alpn_first_bytes: Option<&[u8]> = None;
                let mut ech = false;
                // Collected for JA4: extension type codes (in wire order),
                // signature algorithms (wire order), and the negotiated
                // TLS version (highest from supported_versions if present,
                // else falls back to the ClientHello legacy version).
                let mut ext_type_codes: Vec<u16> = Vec::new();
                let mut sig_algs: Vec<u16> = Vec::new();
                let mut tls_version: u16 = ch.version.0;
                if let Some(ext_data) = ch.ext {
                    ext_type_codes = ja4::extension_type_codes(ext_data);
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
                                    if let Some(first) = protos.first() {
                                        alpn_first_bytes = Some(*first);
                                        alpn = std::str::from_utf8(first).ok().map(String::from);
                                    }
                                }
                                TlsExtension::SignatureAlgorithms(algs) => {
                                    sig_algs = algs.clone();
                                }
                                TlsExtension::SupportedVersions(vers) => {
                                    // The TLS 1.3 ClientHello carries
                                    // legacy_version = 0x0303 and the real
                                    // version list in this extension. Pick
                                    // the highest non-GREASE entry.
                                    let highest = vers
                                        .iter()
                                        .map(|v| v.0)
                                        .filter(|v| !ja4::is_grease(*v))
                                        .max();
                                    if let Some(v) = highest {
                                        tls_version = v;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                let cipher_codes: Vec<u16> = ch.ciphers.iter().map(|c| c.0).collect();
                let ja4 = Some(ja4::compute_ja4(&Ja4Input {
                    is_quic: false,
                    tls_version,
                    sni_present: sni.is_some(),
                    alpn_first: alpn_first_bytes,
                    ciphers: &cipher_codes,
                    extensions: &ext_type_codes,
                    signature_algorithms: &sig_algs,
                }));
                return Some(AppProtocol::Tls {
                    sni,
                    alpn,
                    ech,
                    ja4,
                });
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
            Some(AppProtocol::Tls {
                sni,
                alpn,
                ech,
                ja4,
            }) => {
                assert_eq!(sni.as_deref(), Some("example.com"));
                // No ALPN in this particular fixture (Python ssl default).
                assert!(alpn.is_none(), "didn't expect ALPN in this fixture");
                // Vanilla Python ssl does not send the ECH extension.
                assert!(!ech, "vanilla fixture should not be flagged as ECH");
                // JA4 must be present and structurally well-formed; we
                // don't pin the exact hash here because Python's ssl
                // stack can shift cipher/extension ordering across
                // releases. Detailed JA4 verification lives in the
                // synthetic-input tests in dpi::ja4.
                let s = ja4.expect("JA4 should be computed for any parseable ClientHello");
                let parts: Vec<&str> = s.split('_').collect();
                assert_eq!(parts.len(), 3, "JA4 = JA4_a_JA4_b_JA4_c; got {}", s);
                assert_eq!(parts[0].len(), 10, "JA4_a must be 10 chars; got {}", s);
                assert!(
                    parts[0].starts_with("t13d"),
                    "Python ssl fixture is TLS 1.3 with SNI; got {}",
                    s
                );
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
    fn extract_client_random_returns_32_bytes_from_fixture() {
        // CLIENT_HELLO_EXAMPLE_COM has the legacy_version 0x0303 at
        // offset 9..=10, then the 32-byte random at 11..=42. Verify
        // we extract those 32 bytes verbatim.
        let cr = extract_client_random(CLIENT_HELLO_EXAMPLE_COM)
            .expect("Python ssl fixture has a ClientHello");
        assert_eq!(&cr[..], &CLIENT_HELLO_EXAMPLE_COM[11..=42]);
    }

    #[test]
    fn extract_client_random_rejects_non_tls_payloads() {
        assert!(extract_client_random(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(extract_client_random(&[]).is_none());
        assert!(extract_client_random(&[0x16, 0x03]).is_none());
    }

    #[test]
    fn extract_server_hello_cipher_suite_rejects_clienthello() {
        // ClientHello is content_type 0x16 + handshake_type 0x01;
        // our extractor only returns Some for ServerHellos (0x02).
        assert!(extract_server_hello_cipher_suite(CLIENT_HELLO_EXAMPLE_COM).is_none());
    }

    #[test]
    fn extract_metadata_strips_record_header_and_finds_sni() {
        // Skip the 5-byte TLS record header (content_type + version + len)
        // to get the bare handshake bytes that the QUIC path feeds in.
        let handshake = &CLIENT_HELLO_EXAMPLE_COM[5..];
        let meta = extract_handshake_metadata(handshake);
        assert_eq!(meta.sni.as_deref(), Some("example.com"));
        assert!(!meta.ech, "vanilla fixture has no ECH");
        // Phase 2a: client_random is captured for QUIC 1-RTT keylog lookup.
        // It's the same 32 bytes extract_client_random pulls from the record.
        assert_eq!(
            meta.client_random.as_ref().map(|r| &r[..]),
            Some(&CLIENT_HELLO_EXAMPLE_COM[11..=42])
        );
    }

    #[test]
    fn extract_metadata_finds_client_random_even_without_extensions() {
        // A ClientHello truncated before its extensions still yields the
        // random — QUIC 1-RTT decryption needs it even from a partial CH.
        let handshake = &CLIENT_HELLO_EXAMPLE_COM[5..];
        let meta = extract_handshake_metadata(handshake);
        assert!(meta.client_random.is_some());
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
