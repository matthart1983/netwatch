//! QUIC classifier — detects QUIC v1 Initial packets and attempts SNI
//! extraction by undoing header protection and AEAD-decrypting the
//! payload per RFC 9001.
//!
//! ## Pipeline
//! 1. Parse the long header (type, version, DCID, SCID, token, length).
//! 2. Reject anything that isn't a v1 Initial packet.
//! 3. Derive the client Initial keys from the DCID via HKDF +
//!    the v1 Initial salt (`38762cf7…`).
//! 4. Remove header protection on the first byte's low 4 bits and the
//!    packet-number bytes using AES-128-ECB-derived mask.
//! 5. AEAD-decrypt (AES-128-GCM) with `nonce = iv XOR pn` and
//!    `aad = unprotected header`.
//! 6. Walk decrypted frames, accumulate CRYPTO frame data at the right
//!    offsets to reassemble the TLS 1.3 ClientHello.
//! 7. Run `tls-parser` on the reassembled ClientHello, extract SNI.
//!
//! ## Returns
//! - `AppProtocol::Quic { sni: Some(host) }` on full pipeline success.
//! - `AppProtocol::Quic { sni: None }` when we can identify the packet
//!   as QUIC v1 Initial but anything downstream fails (key derivation,
//!   AEAD auth, malformed frames, multi-packet ClientHello not yet
//!   handled). The UI still gets a `QUIC` tag.
//!
//! ## Not handled
//! - **Multi-packet ClientHellos** — uncommon (CHs fit in one Initial
//!   for most browsers because Initials are padded to 1200 bytes). We
//!   could implement reassembly across packets but it requires
//!   buffering Initials across the flow.
//! - **QUIC v2** (RFC 9369) — different salt + label prefix; flagged
//!   but not decrypted.

use ring::aead::{self, quic};
use ring::hkdf;

use super::{tls, AppProtocol, Classifier};

/// RFC 9001 §5.2 — Initial salt for QUIC v1.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// RFC 9369 §3.3.3 — Initial salt for QUIC v2.
const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

const VERSION_V1: u32 = 0x0000_0001;
const VERSION_V2: u32 = 0x6b33_43cf;

const SAMPLE_LEN: usize = 16;

#[derive(Clone, Copy)]
pub(crate) enum QuicVersion {
    V1,
    V2,
}

impl QuicVersion {
    fn salt(self) -> &'static [u8; 20] {
        match self {
            QuicVersion::V1 => &INITIAL_SALT_V1,
            QuicVersion::V2 => &INITIAL_SALT_V2,
        }
    }
    fn key_label(self) -> &'static [u8] {
        match self {
            QuicVersion::V1 => b"quic key",
            QuicVersion::V2 => b"quicv2 key",
        }
    }
    fn iv_label(self) -> &'static [u8] {
        match self {
            QuicVersion::V1 => b"quic iv",
            QuicVersion::V2 => b"quicv2 iv",
        }
    }
    fn hp_label(self) -> &'static [u8] {
        match self {
            QuicVersion::V1 => b"quic hp",
            QuicVersion::V2 => b"quicv2 hp",
        }
    }
}

pub struct QuicClassifier;

impl Classifier for QuicClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if is_tcp {
            return None;
        }
        let header = parse_long_header(payload)?;
        if !header.is_initial() {
            return None;
        }
        // Surface what went wrong with SNI extraction at trace level
        // so users can debug "why is this just QUIC and not QUIC
        // host.com" via the file log. Levels: trace = single line per
        // Initial we touch; debug = stage-by-stage outcome.
        let result = try_extract_handshake_metadata(payload, &header);
        let (sni, ech, ja4) = match &result {
            Ok(meta) if meta.sni.is_some() => {
                tracing::trace!(
                    target: "netwatch::dpi::quic",
                    version = ?header.version_kind.map(version_label),
                    host = ?meta.sni,
                    ech = meta.ech,
                    ja4 = ?meta.ja4,
                    "SNI extracted"
                );
                (meta.sni.clone(), meta.ech, meta.ja4.clone())
            }
            Ok(meta) => {
                tracing::trace!(
                    target: "netwatch::dpi::quic",
                    version = ?header.version_kind.map(version_label),
                    ech = meta.ech,
                    ja4 = ?meta.ja4,
                    "Initial decrypted but ClientHello has no SNI extension"
                );
                (None, meta.ech, meta.ja4.clone())
            }
            Err(reason) => {
                tracing::trace!(
                    target: "netwatch::dpi::quic",
                    version = ?header.version_kind.map(version_label),
                    reason = %reason,
                    "SNI extraction failed; emitting bare QUIC tag"
                );
                (None, false, None)
            }
        };
        Some(AppProtocol::Quic { sni, ech, ja4 })
    }
}

fn version_label(v: QuicVersion) -> &'static str {
    match v {
        QuicVersion::V1 => "v1",
        QuicVersion::V2 => "v2",
    }
}

/// A minimally parsed long header. References slices into the original
/// packet so we can pass the exact protected header bytes to AEAD as
/// AAD after we unprotect them.
struct LongHeader {
    /// QUIC version when recognized (v1 or v2). Other versions are
    /// rejected at parse time.
    version_kind: Option<QuicVersion>,
    /// True iff the packet-type bits identify this as an Initial *for
    /// the recognized version*. The bit mapping changed between v1 and
    /// v2 (RFC 9369 §3.2).
    type_initial: bool,
    dcid_offset: usize,
    dcid_len: usize,
    /// Offset where the packet-number bytes start (right after the
    /// `Length` varint).
    pn_offset: usize,
    /// Value of the `Length` varint (pn + protected payload bytes).
    pn_plus_payload_len: usize,
}

impl LongHeader {
    fn is_initial(&self) -> bool {
        self.type_initial && self.version_kind.is_some()
    }
}

fn parse_long_header(buf: &[u8]) -> Option<LongHeader> {
    // Need at least: 1 (flags) + 4 (version) + 1 (dcid_len) = 6.
    if buf.len() < 6 {
        return None;
    }
    let flags = buf[0];
    // Long header form + fixed bit set: `1 1 _ _ _ _ _ _` → byte & 0xC0 == 0xC0.
    if flags & 0xC0 != 0xC0 {
        return None;
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    // Packet-type bits (5–4) identify Initial differently per version:
    //  v1: type 00 → Initial
    //  v2: type 01 → Initial
    let type_bits = (flags >> 4) & 0x03;
    let (version_kind, type_initial) = match version {
        VERSION_V1 => (Some(QuicVersion::V1), type_bits == 0b00),
        VERSION_V2 => (Some(QuicVersion::V2), type_bits == 0b01),
        _ => (None, false),
    };
    let dcid_len = buf[5] as usize;
    let dcid_offset = 6;
    if buf.len() < dcid_offset + dcid_len + 1 {
        return None;
    }
    let scid_len_offset = dcid_offset + dcid_len;
    let scid_len = buf[scid_len_offset] as usize;
    let scid_offset = scid_len_offset + 1;
    if buf.len() < scid_offset + scid_len {
        return None;
    }
    let after_scid = scid_offset + scid_len;
    let (token_len, token_len_size) = read_varint(&buf[after_scid..])?;
    let token_offset = after_scid + token_len_size;
    let after_token = token_offset + token_len as usize;
    if buf.len() < after_token {
        return None;
    }
    let (pn_plus_payload_len, length_size) = read_varint(&buf[after_token..])?;
    let pn_offset = after_token + length_size;
    if buf.len() < pn_offset + (pn_plus_payload_len as usize) {
        return None;
    }
    let _ = version; // captured by version_kind; not retained on the struct
    Some(LongHeader {
        version_kind,
        type_initial,
        dcid_offset,
        dcid_len,
        pn_offset,
        pn_plus_payload_len: pn_plus_payload_len as usize,
    })
}

/// Read a QUIC variable-length integer (RFC 9000 §16) — 2-bit length
/// prefix tells us 1/2/4/8 byte width.
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut val = (first & 0x3F) as u64;
    for &b in &buf[1..len] {
        val = (val << 8) | (b as u64);
    }
    Some((val, len))
}

/// HKDF-Expand-Label per TLS 1.3 / RFC 8446 §7.1, reused by QUIC.
fn hkdf_expand_label(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) -> Result<(), ()> {
    let out_len = out.len() as u16;
    let mut label_full = Vec::with_capacity(6 + label.len());
    label_full.extend_from_slice(b"tls13 ");
    label_full.extend_from_slice(label);
    let mut info = Vec::with_capacity(2 + 1 + label_full.len() + 1);
    info.extend_from_slice(&out_len.to_be_bytes());
    info.push(label_full.len() as u8);
    info.extend_from_slice(&label_full);
    info.push(0); // empty context

    struct DynLen(usize);
    impl hkdf::KeyType for DynLen {
        fn len(&self) -> usize {
            self.0
        }
    }
    let len = DynLen(out.len());
    let info_components: [&[u8]; 1] = [&info];
    let okm = prk.expand(&info_components, len).map_err(|_| ())?;
    okm.fill(out).map_err(|_| ())
}

struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn derive_initial_keys(dcid: &[u8], version: QuicVersion) -> Result<InitialKeys, ()> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, version.salt());
    let initial_secret = salt.extract(dcid);
    let mut client_initial_secret = [0u8; 32];
    hkdf_expand_label(&initial_secret, b"client in", &mut client_initial_secret)?;
    let client_prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client_initial_secret);
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    hkdf_expand_label(&client_prk, version.key_label(), &mut key)?;
    hkdf_expand_label(&client_prk, version.iv_label(), &mut iv)?;
    hkdf_expand_label(&client_prk, version.hp_label(), &mut hp)?;
    Ok(InitialKeys { key, iv, hp })
}

/// AEAD + header-protection material for QUIC 1-RTT (and Handshake) packets,
/// derived from a TLS traffic secret. Unlike Initial keys (from DCID + a
/// fixed salt), the secret here is the `*_TRAFFIC_SECRET_0` the cooperating
/// client wrote to `SSLKEYLOGFILE`. `key`/`hp` are 16 bytes for AES-128-GCM,
/// 32 for AES-256-GCM and ChaCha20-Poly1305.
// Wired into the short-header decrypt path in Phase 2c; for now only the
// derivation + its RFC 9001 §A.5 KAT exercise it.
#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct OneRttKeys {
    pub key: Vec<u8>,
    pub iv: [u8; 12],
    pub hp: Vec<u8>,
}

/// Derive 1-RTT keys from a traffic secret per RFC 9001 §5.1, using the
/// QUIC HKDF labels (`"quic key"`/`"quic iv"`/`"quic hp"`, or the `quicv2`
/// variants). The HKDF hash and key length come from the negotiated cipher
/// suite. Validated against the RFC 9001 §A.5 ChaCha20 test vector.
#[allow(clippy::result_unit_err, dead_code)] // wired in Phase 2c
pub(crate) fn derive_1rtt_keys(
    secret: &[u8],
    suite: crate::dpi::tls_decrypt::CipherSuite,
    version: QuicVersion,
) -> Result<OneRttKeys, ()> {
    let prk = hkdf::Prk::new_less_safe(suite.hkdf_alg(), secret);
    let klen = suite.key_len();
    let mut key = vec![0u8; klen];
    let mut iv = [0u8; 12];
    let mut hp = vec![0u8; klen];
    hkdf_expand_label(&prk, version.key_label(), &mut key)?;
    hkdf_expand_label(&prk, version.iv_label(), &mut iv)?;
    hkdf_expand_label(&prk, version.hp_label(), &mut hp)?;
    Ok(OneRttKeys { key, iv, hp })
}

/// Header-protection mask for a 1-RTT packet, selecting the cipher per the
/// negotiated suite (AES-128/256 ECB or ChaCha20). `sample` is 16 bytes.
#[allow(clippy::result_unit_err)]
fn one_rtt_hp_mask(
    suite: crate::dpi::tls_decrypt::CipherSuite,
    hp_key: &[u8],
    sample: &[u8; SAMPLE_LEN],
) -> Result<[u8; 5], ()> {
    use crate::dpi::tls_decrypt::CipherSuite::*;
    let key = match suite {
        Aes128GcmSha256 => quic::HeaderProtectionKey::new(&quic::AES_128, hp_key),
        Aes256GcmSha384 => quic::HeaderProtectionKey::new(&quic::AES_256, hp_key),
        Chacha20Poly1305Sha256 => quic::HeaderProtectionKey::new(&quic::CHACHA20, hp_key),
    }
    .map_err(|_| ())?;
    key.new_mask(sample).map_err(|_| ())
}

/// Reconstruct the full packet number from a truncated on-wire value, per
/// RFC 9000 §A.3, given the largest packet number already processed in this
/// packet-number space.
fn decode_packet_number(largest_pn: u64, truncated: u64, pn_len: usize) -> u64 {
    let pn_nbits = pn_len * 8;
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;
    let expected = largest_pn.wrapping_add(1);
    let candidate = (expected & !pn_mask) | truncated;
    if candidate.wrapping_add(pn_hwin) <= expected && candidate < (1u64 << 62) - pn_win {
        candidate + pn_win
    } else if candidate > expected.wrapping_add(pn_hwin) && candidate >= pn_win {
        candidate - pn_win
    } else {
        candidate
    }
}

/// Decrypt a QUIC 1-RTT (short-header) packet. `dcid_len` is the connection's
/// Destination Connection ID length — known from the handshake, *not* on the
/// wire for short headers. `secret` is this direction's `*_TRAFFIC_SECRET_0`
/// from the keylog; `largest_pn` is the largest pn already seen in this
/// direction (for truncated-pn reconstruction). Returns the decrypted frame
/// payload (QUIC frames), or `Err` if not a short header / auth fails.
///
/// Validated against the RFC 9001 §A.5 ChaCha20 short-header vector.
#[allow(clippy::result_unit_err, dead_code)] // wired into the capture path in Phase 2c-ii
pub(crate) fn decrypt_1rtt_packet(
    packet: &[u8],
    dcid_len: usize,
    secret: &[u8],
    suite: crate::dpi::tls_decrypt::CipherSuite,
    version: QuicVersion,
    largest_pn: u64,
) -> Result<Vec<u8>, ()> {
    // Short header: fixed bit 0x40 set, long-header bit 0x80 clear.
    if packet.is_empty() || packet[0] & 0x80 != 0 {
        return Err(());
    }
    let pn_offset = 1 + dcid_len;
    let keys = derive_1rtt_keys(secret, suite, version)?;
    let mut buf = packet.to_vec();

    // Header protection: sample 16 bytes starting 4 after the pn field.
    let sample_offset = pn_offset + 4;
    if buf.len() < sample_offset + SAMPLE_LEN {
        return Err(());
    }
    let sample: [u8; SAMPLE_LEN] = buf[sample_offset..sample_offset + SAMPLE_LEN]
        .try_into()
        .map_err(|_| ())?;
    let mask = one_rtt_hp_mask(suite, &keys.hp, &sample)?;
    // Short header masks the low 5 bits of byte 0 (long header masks 4).
    buf[0] ^= mask[0] & 0x1f;
    let pn_len = ((buf[0] & 0x03) as usize) + 1;
    if buf.len() < pn_offset + pn_len {
        return Err(());
    }
    let mut truncated: u64 = 0;
    for i in 0..pn_len {
        buf[pn_offset + i] ^= mask[1 + i];
        truncated = (truncated << 8) | buf[pn_offset + i] as u64;
    }
    let pn = decode_packet_number(largest_pn, truncated, pn_len);

    // AEAD: nonce = iv XOR (pn right-aligned), AAD = unprotected header.
    let mut nonce_bytes = keys.iv;
    let pn_be = pn.to_be_bytes();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= pn_be[i];
    }
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let header_end = pn_offset + pn_len;
    let aad = aead::Aad::from(buf[..header_end].to_vec());
    let mut ciphertext = buf[header_end..].to_vec();
    let tag_len = suite.aead_alg().tag_len();
    if ciphertext.len() < tag_len {
        return Err(());
    }
    let opening =
        aead::LessSafeKey::new(aead::UnboundKey::new(suite.aead_alg(), &keys.key).map_err(|_| ())?);
    opening
        .open_in_place(nonce, aad, &mut ciphertext)
        .map_err(|_| ())?;
    ciphertext.truncate(ciphertext.len() - tag_len);
    Ok(ciphertext)
}

/// Remove header protection on a full Initial packet. Mutates `buf` so
/// that the first byte's low 4 bits and the packet-number bytes are
/// their unprotected values. Returns the packet number (as a u64) and
/// the packet-number length in bytes.
#[allow(clippy::result_unit_err)]
fn unprotect_header(
    buf: &mut [u8],
    header: &LongHeader,
    hp_key: &[u8; 16],
) -> Result<(u64, usize), ()> {
    // Sample is 16 bytes starting 4 bytes after the start of the pn
    // field (RFC 9001 §5.4.2).
    let sample_offset = header.pn_offset + 4;
    if buf.len() < sample_offset + SAMPLE_LEN {
        return Err(());
    }
    let sample: [u8; SAMPLE_LEN] = buf[sample_offset..sample_offset + SAMPLE_LEN]
        .try_into()
        .map_err(|_| ())?;
    let hp_key = quic::HeaderProtectionKey::new(&quic::AES_128, hp_key).map_err(|_| ())?;
    let mask = hp_key.new_mask(&sample).map_err(|_| ())?;

    // Long header: XOR mask[0] into low 4 bits of byte 0.
    buf[0] ^= mask[0] & 0x0f;
    let pn_len = ((buf[0] & 0x03) as usize) + 1;
    if buf.len() < header.pn_offset + pn_len {
        return Err(());
    }
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        buf[header.pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | buf[header.pn_offset + i] as u64;
    }
    Ok((pn, pn_len))
}

fn decrypt_payload(
    buf: &mut Vec<u8>,
    header: &LongHeader,
    keys: &InitialKeys,
    pn: u64,
    pn_len: usize,
) -> Result<Vec<u8>, ()> {
    // Nonce = IV XOR PN (right-aligned).
    let mut nonce_bytes = keys.iv;
    let pn_bytes = pn.to_be_bytes(); // 8 bytes
    for i in 0..8 {
        nonce_bytes[4 + i] ^= pn_bytes[i];
    }
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    // AAD is the unprotected header from byte 0 through the last pn byte.
    let header_end = header.pn_offset + pn_len;
    let header_bytes: Vec<u8> = buf[..header_end].to_vec();
    let aad = aead::Aad::from(header_bytes);

    // Ciphertext spans from end of header to end of (pn + payload). The
    // last 16 bytes are the auth tag.
    let payload_start = header_end;
    let payload_end = header.pn_offset + header.pn_plus_payload_len;
    if buf.len() < payload_end {
        return Err(());
    }
    let mut ciphertext = buf[payload_start..payload_end].to_vec();
    let opening = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &keys.key).map_err(|_| ())?,
    );
    opening
        .open_in_place(nonce, aad, &mut ciphertext)
        .map_err(|_| ())?;
    // open_in_place truncates the tag in-place by returning a slice
    // shorter than input; we explicitly resize.
    let plain_len = ciphertext.len() - aead::AES_128_GCM.tag_len();
    ciphertext.truncate(plain_len);
    Ok(ciphertext)
}

/// Walk the decrypted Initial payload and accumulate CRYPTO-frame data
/// at its declared offset into a byte buffer. Single-packet CHs land
/// at offset 0 and produce a contiguous block; multi-packet ones leave
/// gaps and we'll return what we have (the SNI is usually in the first
/// fragment).
fn reassemble_crypto(plaintext: &[u8]) -> Result<Vec<u8>, ()> {
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0;
    while pos < plaintext.len() {
        let (frame_type, n) = read_varint(&plaintext[pos..]).ok_or(())?;
        pos += n;
        match frame_type {
            0x00 => continue, // PADDING — skip 1 byte (already advanced)
            0x01 => continue, // PING — single-byte frame
            0x06 => {
                // CRYPTO frame: offset(varint) length(varint) data
                let (offset, no) = read_varint(&plaintext[pos..]).ok_or(())?;
                pos += no;
                let (length, nl) = read_varint(&plaintext[pos..]).ok_or(())?;
                pos += nl;
                let length = length as usize;
                if pos + length > plaintext.len() {
                    return Err(());
                }
                let end = (offset as usize) + length;
                if out.len() < end {
                    out.resize(end, 0);
                }
                out[offset as usize..end].copy_from_slice(&plaintext[pos..pos + length]);
                pos += length;
            }
            0x02 | 0x03 => {
                // ACK frames — variable shape; bail rather than skip
                // wrong byte count. ClientHello packets typically
                // don't carry ACKs, so this rarely matters.
                return Err(());
            }
            _ => {
                // Unknown frame type — refuse rather than risk
                // misalignment.
                return Err(());
            }
        }
    }
    if out.is_empty() {
        Err(())
    } else {
        Ok(out)
    }
}

/// Decode one Initial packet into a human-readable frame breakdown.
/// Returns lines like `"CRYPTO offset=0 len=1100"` or
/// `"PADDING bytes=200"`. Used by the Packets tab's detail pane to
/// surface the decrypted QUIC frame structure that rustnet/wireshark
/// can't show without similar header-protection removal.
pub fn decode_initial_frame_summary(payload: &[u8]) -> Option<Vec<String>> {
    let header = parse_long_header(payload)?;
    if !header.is_initial() {
        return None;
    }
    if header.dcid_len == 0 || header.dcid_len > 20 {
        return None;
    }
    let version = header.version_kind?;
    let dcid = &payload[header.dcid_offset..header.dcid_offset + header.dcid_len];
    let keys = derive_initial_keys(dcid, version).ok()?;
    let mut buf: Vec<u8> = payload.to_vec();
    let (pn, pn_len) = unprotect_header(&mut buf, &header, &keys.hp).ok()?;
    let plaintext = decrypt_payload(&mut buf, &header, &keys, pn, pn_len).ok()?;
    Some(frame_summary_lines(&plaintext, pn, version))
}

fn frame_summary_lines(plaintext: &[u8], pn: u64, version: QuicVersion) -> Vec<String> {
    let mut out = vec![format!(
        "Initial v{}  pn={}  payload={} bytes",
        match version {
            QuicVersion::V1 => "1",
            QuicVersion::V2 => "2",
        },
        pn,
        plaintext.len()
    )];
    let mut padding_run: usize = 0;
    let mut pos = 0;
    while pos < plaintext.len() {
        let Some((frame_type, n)) = read_varint(&plaintext[pos..]) else {
            out.push(format!("(truncated at offset {})", pos));
            break;
        };
        pos += n;
        match frame_type {
            0x00 => {
                padding_run += 1;
                continue;
            }
            other => {
                if padding_run > 0 {
                    out.push(format!("PADDING bytes={}", padding_run));
                    padding_run = 0;
                }
                match other {
                    0x01 => out.push("PING".into()),
                    0x06 => {
                        let Some((offset, no)) = read_varint(&plaintext[pos..]) else {
                            break;
                        };
                        pos += no;
                        let Some((length, nl)) = read_varint(&plaintext[pos..]) else {
                            break;
                        };
                        pos += nl;
                        out.push(format!("CRYPTO offset={} len={}", offset, length));
                        pos += length as usize;
                    }
                    0x02 | 0x03 => {
                        out.push(format!("ACK type=0x{:02x} (frame body skipped)", other));
                        break; // ACK has variable shape; stop here
                    }
                    _ => {
                        out.push(format!(
                            "frame type=0x{:02x} (unknown shape, stopping)",
                            other
                        ));
                        break;
                    }
                }
            }
        }
    }
    if padding_run > 0 {
        out.push(format!("PADDING bytes={}", padding_run));
    }
    out
}

/// Stateless cross-packet helper: decrypt one Initial packet and
/// return the CRYPTO-frame fragments it carries (offset, data) so the
/// caller can merge them into a per-stream buffer across multiple
/// Initials. Returns `None` if this isn't a recognized v1/v2 Initial
/// or decryption/auth fails.
///
/// Used by the Stream tracker to reassemble Chrome-class ClientHellos
/// that overflow a single Initial — those land their SNI extension in
/// fragment 2+, which single-packet classification can't see.
pub fn extract_initial_crypto_frames(payload: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let header = parse_long_header(payload)?;
    if !header.is_initial() {
        return None;
    }
    if header.dcid_len == 0 || header.dcid_len > 20 {
        return None;
    }
    let version = header.version_kind?;
    let dcid = &payload[header.dcid_offset..header.dcid_offset + header.dcid_len];
    let keys = derive_initial_keys(dcid, version).ok()?;
    let mut buf: Vec<u8> = payload.to_vec();
    let (pn, pn_len) = unprotect_header(&mut buf, &header, &keys.hp).ok()?;
    let plaintext = decrypt_payload(&mut buf, &header, &keys, pn, pn_len).ok()?;
    crypto_frame_fragments(&plaintext)
}

/// Same walk as `reassemble_crypto` but returns raw (offset, data)
/// fragments instead of an offset-indexed buffer, so the caller can
/// merge them into a longer-lived per-stream buffer.
fn crypto_frame_fragments(plaintext: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut pos = 0;
    while pos < plaintext.len() {
        let (frame_type, n) = read_varint(&plaintext[pos..])?;
        pos += n;
        match frame_type {
            0x00 | 0x01 => continue, // PADDING / PING
            0x06 => {
                let (offset, no) = read_varint(&plaintext[pos..])?;
                pos += no;
                let (length, nl) = read_varint(&plaintext[pos..])?;
                pos += nl;
                let length = length as usize;
                if pos + length > plaintext.len() {
                    return None;
                }
                out.push((offset, plaintext[pos..pos + length].to_vec()));
                pos += length;
            }
            // Unknown / variable-shape frames (ACK 0x02/0x03 in particular):
            // bail rather than risk misalignment, but only after we've
            // captured any CRYPTO frames seen so far.
            _ => break,
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn try_extract_handshake_metadata(
    payload: &[u8],
    header: &LongHeader,
) -> Result<tls::HandshakeMetadata, &'static str> {
    if header.dcid_len == 0 || header.dcid_len > 20 {
        return Err("invalid dcid length");
    }
    let version = header.version_kind.ok_or("unknown quic version")?;
    let dcid = &payload[header.dcid_offset..header.dcid_offset + header.dcid_len];
    let keys = derive_initial_keys(dcid, version).map_err(|_| "key derivation failed")?;

    let mut buf: Vec<u8> = payload.to_vec();
    let (pn, pn_len) =
        unprotect_header(&mut buf, header, &keys.hp).map_err(|_| "header unprotect failed")?;
    let plaintext = decrypt_payload(&mut buf, header, &keys, pn, pn_len)
        .map_err(|_| "aead decrypt failed (auth tag or short buffer)")?;
    let crypto = reassemble_crypto(&plaintext).map_err(|_| "crypto-frame reassembly failed")?;
    Ok(tls::extract_handshake_metadata(&crypto))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_quic_v1_initial() {
        let mut payload = vec![0xC0, 0x00, 0x00, 0x00, 0x01];
        payload.extend(std::iter::repeat(0u8).take(64));
        // Even if SNI extraction fails on this synthetic packet, the
        // detection returns Some(Quic { sni: None }).
        match QuicClassifier.classify(&payload, false) {
            Some(AppProtocol::Quic { .. }) => {}
            other => panic!("expected Quic{{..}}, got {:?}", other),
        }
    }

    #[test]
    fn rejects_tcp() {
        let payload = vec![
            0xC0, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(QuicClassifier.classify(&payload, true).is_none());
    }

    #[test]
    fn rejects_non_initial_byte() {
        let payload = vec![
            0x40, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(QuicClassifier.classify(&payload, false).is_none());
    }

    #[test]
    fn varint_round_trip() {
        assert_eq!(read_varint(&[0x25]), Some((37, 1)));
        assert_eq!(read_varint(&[0x40, 0x25]), Some((37, 2)));
        assert_eq!(read_varint(&[0x80, 0x00, 0x00, 0x25]), Some((37, 4)));
    }

    /// Test vector from RFC 9001 Appendix A.2: client Initial.
    /// DCID = 0x8394c8f03e515708. Decrypts to a known CRYPTO frame
    /// containing a ClientHello whose SNI is `example.com`. This is the
    /// canonical end-to-end test for the entire pipeline.
    #[test]
    fn rfc9001_appendix_a2_extracts_sni() {
        // The full Initial packet from RFC 9001 Appendix A.2.
        // (Protected — un-decryptable without going through our pipeline.)
        // Source: <https://datatracker.ietf.org/doc/html/rfc9001#name-client-initial>
        let hex = "\
c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11\
d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399\
1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c\
8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212\
30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5\
457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208\
4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec\
4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3\
485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db\
059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c\
7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8\
9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556\
be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74\
68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a\
c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00\
f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632\
291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964\
25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd\
14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff\
ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198\
e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd\
c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73\
203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f\
cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e\
fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade\
a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047\
90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2\
162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4\
40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0\
6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e\
8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0\
be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400\
54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab\
760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9\
f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4\
056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064\
7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241\
e221af44860018ab0856972e194cd934";
        let packet = hex_to_bytes(hex);
        let result = QuicClassifier.classify(&packet, false);
        match result {
            Some(AppProtocol::Quic {
                sni: Some(host), ..
            }) => {
                assert_eq!(host, "example.com");
            }
            other => panic!(
                "expected Quic{{ sni: Some(\"example.com\") }}, got {:?}",
                other
            ),
        }
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9001 §A.5 — derive 1-RTT key/iv/hp from the ChaCha20-Poly1305
    /// application secret and check against the published values. This pins
    /// the QUIC HKDF labels ("quic key"/"quic iv"/"quic hp") and the
    /// suite's hash, independent of any packet decryption.
    #[test]
    fn derive_1rtt_keys_matches_rfc9001_a5_chacha20() {
        let secret =
            hex_to_bytes("9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b");
        let keys = derive_1rtt_keys(
            &secret,
            crate::dpi::tls_decrypt::CipherSuite::Chacha20Poly1305Sha256,
            QuicVersion::V1,
        )
        .expect("derive");
        assert_eq!(
            keys.key,
            hex_to_bytes("c6d98ff3441c3fe1b2182094f69caa2e d4b716b65488960a7a984979fb23e1c8")
        );
        assert_eq!(keys.iv.to_vec(), hex_to_bytes("e0459b3474bdd0e44a41c144"));
        assert_eq!(
            keys.hp,
            hex_to_bytes("25a282b9e82f06f21f488917a4fc8f1b 73573685608597d0efcb076b0ab7a7a4")
        );
    }

    /// RFC 9001 §A.5 — full short-header decrypt: protected packet + the
    /// server application secret → unprotected header `4200bff4` and payload
    /// plaintext `01` (a single PING frame). Empty DCID, pn 654360564.
    #[test]
    fn decrypt_1rtt_packet_matches_rfc9001_a5() {
        let packet = hex_to_bytes("4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
        let secret =
            hex_to_bytes("9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b");
        // largest_pn = 654360563 so reconstruction yields the example's
        // full pn 654360564 (= 0x2700bff4) from the 3-byte truncated 0x00bff4.
        let plaintext = decrypt_1rtt_packet(
            &packet,
            0, // empty Destination Connection ID
            &secret,
            crate::dpi::tls_decrypt::CipherSuite::Chacha20Poly1305Sha256,
            QuicVersion::V1,
            654360563,
        )
        .expect("RFC 9001 A.5 packet must decrypt");
        assert_eq!(plaintext, hex_to_bytes("01"));
    }

    #[test]
    fn decode_packet_number_reconstructs_rfc9000_a3() {
        // RFC 9000 §A.3 worked example: largest=0xa82f30ea, truncated=0x9b32,
        // pn_len=2 → 0xa82f9b32.
        assert_eq!(decode_packet_number(0xa82f30ea, 0x9b32, 2), 0xa82f9b32);
    }
}
