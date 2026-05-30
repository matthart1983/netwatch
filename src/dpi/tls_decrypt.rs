//! Passive TLS 1.3 Application-Data decryption via NSS SSLKEYLOGFILE.
//!
//! When a cooperating client process (Chrome, Firefox, Node, curl with
//! the right env var, etc.) is launched with `SSLKEYLOGFILE=/path/to/keylog`,
//! it appends one line per TLS connection containing the master secrets.
//! We read that file, index secrets by `client_random`, and use them
//! to derive per-record AEAD keys for any TLS 1.3 connection we
//! observe. Same trick Wireshark uses.
//!
//! ## What's in scope (Phase 1)
//!
//! - TLS 1.3 only — `CLIENT_TRAFFIC_SECRET_0` / `SERVER_TRAFFIC_SECRET_0`.
//! - Cipher suites: TLS_AES_128_GCM_SHA256 (0x1301),
//!   TLS_AES_256_GCM_SHA384 (0x1302),
//!   TLS_CHACHA20_POLY1305_SHA256 (0x1303).
//! - Application Data records (TLS content_type 23). Handshake records
//!   that arrive after the ServerHello (EncryptedExtensions, Certificate,
//!   etc.) are NOT decrypted here — they use the *handshake* secrets,
//!   not the application ones.
//!
//! ## What's not in scope (deferred to later phases)
//!
//! - TLS 1.2 (different key schedule + AEAD modes).
//! - QUIC application-data decryption (different secret labels, same
//!   AEAD primitives — Phase 2).
//! - 0-RTT (`EARLY_TRAFFIC_SECRET`).
//! - KeyUpdate post-handshake re-keying (Phase 2 polish).
//! - Active interception. netwatch stays read-only.
//!
//! ## Security posture
//!
//! Decryption only works for connections whose client cooperatively
//! exported its secrets. Production traffic, malware, third-party
//! services — none of those will be decryptable. This is a developer
//! debugging affordance, not an interception tool.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use ring::aead;
use ring::hkdf;

/// TLS 1.3 cipher suite IDs we support.
/// Other suites parse as unknown and decryption fails fast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

impl CipherSuite {
    pub fn from_wire(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    pub(crate) fn hkdf_alg(self) -> hkdf::Algorithm {
        match self {
            Self::Aes128GcmSha256 => hkdf::HKDF_SHA256,
            Self::Aes256GcmSha384 => hkdf::HKDF_SHA384,
            Self::Chacha20Poly1305Sha256 => hkdf::HKDF_SHA256,
        }
    }

    pub(crate) fn aead_alg(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128GcmSha256 => &aead::AES_128_GCM,
            Self::Aes256GcmSha384 => &aead::AES_256_GCM,
            Self::Chacha20Poly1305Sha256 => &aead::CHACHA20_POLY1305,
        }
    }

    pub(crate) fn key_len(self) -> usize {
        self.aead_alg().key_len()
    }
}

/// One row of the keylog. The label decides which secret slot it
/// populates in the per-connection `Secrets` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeylogLabel {
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ClientApplicationTrafficSecret0,
    ServerApplicationTrafficSecret0,
    EarlyTrafficSecret,
    ExporterSecret,
    /// TLS 1.2 only (not used in Phase 1, parsed so we don't choke on
    /// mixed keylogs).
    ClientRandom,
}

impl KeylogLabel {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => Some(Self::ClientHandshakeTrafficSecret),
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => Some(Self::ServerHandshakeTrafficSecret),
            "CLIENT_TRAFFIC_SECRET_0" => Some(Self::ClientApplicationTrafficSecret0),
            "SERVER_TRAFFIC_SECRET_0" => Some(Self::ServerApplicationTrafficSecret0),
            "EARLY_TRAFFIC_SECRET" => Some(Self::EarlyTrafficSecret),
            "EXPORTER_SECRET" => Some(Self::ExporterSecret),
            "CLIENT_RANDOM" => Some(Self::ClientRandom),
            _ => None,
        }
    }
}

/// All known secrets for one TLS connection, indexed by `client_random`.
#[derive(Default, Debug, Clone)]
pub struct Secrets {
    pub client_application: Option<Vec<u8>>,
    pub server_application: Option<Vec<u8>>,
    pub client_handshake: Option<Vec<u8>>,
    pub server_handshake: Option<Vec<u8>>,
}

/// In-memory keylog index: `client_random` (32 bytes) → Secrets.
/// Backed by a RwLock so a background watcher can append while
/// readers query.
#[derive(Default, Debug)]
pub struct KeylogStore {
    inner: RwLock<HashMap<[u8; 32], Secrets>>,
}

impl KeylogStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Ingest one line of the SSLKEYLOGFILE. Returns `true` if the
    /// line was recognized and stored, `false` for blanks, comments,
    /// or unknown labels.
    pub fn ingest_line(&self, line: &str) -> bool {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return false;
        }
        let mut parts = line.split_whitespace();
        let Some(label_str) = parts.next() else {
            return false;
        };
        let Some(client_random_hex) = parts.next() else {
            return false;
        };
        let Some(secret_hex) = parts.next() else {
            return false;
        };
        let Some(label) = KeylogLabel::parse(label_str) else {
            return false;
        };
        let Some(client_random) = parse_client_random(client_random_hex) else {
            return false;
        };
        let Some(secret) = decode_hex(secret_hex) else {
            return false;
        };
        let mut w = self.inner.write().unwrap();
        let entry = w.entry(client_random).or_default();
        match label {
            KeylogLabel::ClientApplicationTrafficSecret0 => entry.client_application = Some(secret),
            KeylogLabel::ServerApplicationTrafficSecret0 => entry.server_application = Some(secret),
            KeylogLabel::ClientHandshakeTrafficSecret => entry.client_handshake = Some(secret),
            KeylogLabel::ServerHandshakeTrafficSecret => entry.server_handshake = Some(secret),
            // The remaining variants are recognized but not yet stored
            // — Phase 1 only needs the application-data secrets. We
            // accept them so we don't log noise for normal keylog
            // files that contain them.
            _ => {}
        }
        tracing::trace!(
            target: "netwatch::dpi::tls_decrypt",
            label = ?label,
            cr_prefix = %format!("{:02x}{:02x}{:02x}{:02x}", client_random[0], client_random[1], client_random[2], client_random[3]),
            "ingested keylog line"
        );
        true
    }

    pub fn lookup(&self, client_random: &[u8; 32]) -> Option<Secrets> {
        self.inner.read().unwrap().get(client_random).cloned()
    }
}

/// Background watcher that tails `path` (the configured SSLKEYLOGFILE)
/// and feeds new lines into `store`. Polls every ~100ms — keylog files
/// are append-only and tiny, so frequent polling is cheap and avoids a
/// notify dependency. The tight interval shrinks the window in which a
/// flow's first application-data records arrive before its secret has
/// been ingested (the capture loop also tolerates that race via
/// sequence resync). Survives file-not-yet-existing (waits for the
/// client process to create it) and file truncation (resets offset).
///
/// The returned `WatcherHandle` stops the background thread when dropped.
pub fn spawn_keylog_watcher(path: PathBuf, store: Arc<KeylogStore>) -> WatcherHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = Arc::clone(&stop);
    let handle = thread::Builder::new()
        .name("netwatch-keylog-watcher".into())
        .spawn(move || keylog_loop(path, store, stop_for_thread))
        .expect("failed to spawn keylog watcher thread");
    WatcherHandle {
        stop,
        join: Some(handle),
    }
}

/// Owns the watcher thread lifecycle. Dropping the handle signals the
/// thread to stop and joins it.
pub struct WatcherHandle {
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl Drop for WatcherHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn keylog_loop(path: PathBuf, store: Arc<KeylogStore>, stop: Arc<AtomicBool>) {
    let mut last_offset: u64 = 0;
    let mut leftover = String::new();
    while !stop.load(Ordering::SeqCst) {
        // Open every iteration so we tolerate file recreation/rotation.
        if let Ok(mut f) = File::open(&path) {
            if let Ok(meta) = f.metadata() {
                let cur = meta.len();
                if cur < last_offset {
                    // File was truncated or replaced — restart from 0.
                    last_offset = 0;
                    leftover.clear();
                    tracing::debug!(
                        target: "netwatch::dpi::tls_decrypt",
                        path = %path.display(),
                        "keylog file shrank; resetting offset"
                    );
                }
                if cur > last_offset {
                    let _ = f.seek(SeekFrom::Start(last_offset));
                    let mut chunk = String::new();
                    if f.read_to_string(&mut chunk).is_ok() {
                        leftover.push_str(&chunk);
                        // Drain complete lines; keep any trailing
                        // partial line in `leftover` for the next poll.
                        let mut consumed = 0;
                        for line in leftover.split_inclusive('\n') {
                            if line.ends_with('\n') {
                                let _ = store.ingest_line(line);
                                consumed += line.len();
                            }
                        }
                        let remainder = leftover[consumed..].to_string();
                        leftover = remainder;
                        last_offset = cur;
                    }
                }
            }
        }
        // Sleep in small slices so a shutdown signal doesn't have to
        // wait the full ~100ms poll interval.
        for _ in 0..4 {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

fn parse_client_random(hex: &str) -> Option<[u8; 32]> {
    let bytes = decode_hex(hex)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Per-direction record state. Sequence number increments per Application
/// Data record decrypted. TLS 1.3 §5.3: nonce = static iv XOR
/// (sequence_number left-padded to iv length).
pub struct DirectionKeys {
    aead: aead::LessSafeKey,
    iv: [u8; 12],
    next_seq: u64,
}

/// HKDF-Expand-Label per RFC 8446 §7.1. `Length` is implicit in
/// `output.len()`.
fn hkdf_expand_label(
    alg: hkdf::Algorithm,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    output: &mut [u8],
) {
    // HkdfLabel = uint16 length || opaque label<7..255> || opaque context<0..255>
    //   label    = "tls13 " + label
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    info.extend_from_slice(&(output.len() as u16).to_be_bytes());
    let full_label_len = (6 + label.len()) as u8;
    info.push(full_label_len);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let prk = hkdf::Prk::new_less_safe(alg, secret);
    let info_slices = [info.as_slice()];
    let okm = prk.expand(&info_slices, OkmLen(output.len())).unwrap();
    okm.fill(output).unwrap();
}

/// Adapter so we can ask ring's HKDF for an arbitrary-length OKM.
/// ring's `KeyType` trait expects a concrete length; we provide one
/// at runtime by wrapping a `usize`.
#[derive(Clone, Copy)]
struct OkmLen(usize);
impl hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl DirectionKeys {
    /// Derive AEAD key + IV from a TLS 1.3 traffic secret per
    /// RFC 8446 §7.3.
    pub fn from_traffic_secret(suite: CipherSuite, secret: &[u8]) -> Self {
        let hkdf_alg = suite.hkdf_alg();
        let mut key = vec![0u8; suite.key_len()];
        hkdf_expand_label(hkdf_alg, secret, b"key", &[], &mut key);
        let mut iv = [0u8; 12];
        hkdf_expand_label(hkdf_alg, secret, b"iv", &[], &mut iv);
        let unbound = aead::UnboundKey::new(suite.aead_alg(), &key).unwrap();
        Self {
            aead: aead::LessSafeKey::new(unbound),
            iv,
            next_seq: 0,
        }
    }

    /// Decrypt one TLS 1.3 record's encrypted payload. `aad` is the
    /// 5-byte TLS record header (type, version, length). `ciphertext`
    /// is the encrypted payload INCLUDING the AEAD auth tag. Returns
    /// the inner plaintext (with the trailing content-type byte and
    /// zero padding stripped per RFC 8446 §5.2).
    pub fn decrypt_record(
        &mut self,
        aad: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<TlsInnerPlaintext, DecryptError> {
        if ciphertext.len() < self.aead.algorithm().tag_len() {
            return Err(DecryptError::ShortCiphertext);
        }
        let nonce_bytes = self.nonce_for(self.next_seq);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        self.aead
            .open_in_place(nonce, aead::Aad::from(aad), ciphertext)
            .map_err(|_| DecryptError::AeadAuthFailed)?;
        // open_in_place leaves the auth tag bytes at the end of the
        // buffer; trim them so callers don't see them.
        let plain_len = ciphertext.len() - self.aead.algorithm().tag_len();
        ciphertext.truncate(plain_len);
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(DecryptError::SeqOverflow)?;
        strip_inner_plaintext(ciphertext)
    }

    fn nonce_for(&self, seq: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq_be = seq.to_be_bytes();
        // XOR sequence number into the rightmost 8 bytes.
        for i in 0..8 {
            nonce[4 + i] ^= seq_be[i];
        }
        nonce
    }

    /// Like [`decrypt_record`](Self::decrypt_record) but tolerant of up
    /// to `max_skip` records we never observed: tries the expected
    /// `next_seq` first, then successive sequence numbers, and uses
    /// whichever authenticates. On success, advances `next_seq` past
    /// the matched record so the skipped sequence numbers are accounted
    /// for and subsequent records stay in sync.
    ///
    /// `record_ciphertext` is the encrypted payload INCLUDING the AEAD
    /// tag (it is not mutated; trials run on copies). `aad` is the
    /// 5-byte record header. Returns `AeadAuthFailed` if nothing in the
    /// `[next_seq, next_seq + max_skip]` window authenticates — which is
    /// the expected outcome for a record encrypted under a *different*
    /// key (e.g. a handshake-secret record carried with outer type
    /// 0x17), leaving `next_seq` untouched.
    ///
    /// The search is forward-only: a record whose true sequence is
    /// *below* `next_seq` (i.e. arriving late / replayed) will not
    /// match. With `max_skip == 0` this is equivalent to a
    /// non-destructive `decrypt_record`.
    ///
    /// This recovers the steady-state sequence when the keylog secret
    /// landed only after the first application-data records had already
    /// flowed — the watcher-ingest race — and resynchronizes after a
    /// record we couldn't reassemble (e.g. one spanning TCP segments).
    pub fn decrypt_record_resync(
        &mut self,
        aad: &[u8],
        record_ciphertext: &[u8],
        max_skip: u64,
    ) -> Result<TlsInnerPlaintext, DecryptError> {
        let tag_len = self.aead.algorithm().tag_len();
        if record_ciphertext.len() < tag_len {
            return Err(DecryptError::ShortCiphertext);
        }
        let start = self.next_seq;
        let end = start.saturating_add(max_skip);
        let mut seq = start;
        loop {
            let mut buf = record_ciphertext.to_vec();
            let nonce = aead::Nonce::assume_unique_for_key(self.nonce_for(seq));
            if self
                .aead
                .open_in_place(nonce, aead::Aad::from(aad), &mut buf)
                .is_ok()
            {
                buf.truncate(buf.len() - tag_len);
                self.next_seq = seq.checked_add(1).ok_or(DecryptError::SeqOverflow)?;
                return strip_inner_plaintext(&buf);
            }
            if seq >= end {
                return Err(DecryptError::AeadAuthFailed);
            }
            seq = seq.checked_add(1).ok_or(DecryptError::SeqOverflow)?;
        }
    }
}

/// RFC 8446 §5.2 TLSInnerPlaintext after AEAD decrypt:
///   content + content_type (1 byte) + zeros padding
/// Strip trailing zeros to find the content-type byte; everything
/// before it is the actual application data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInnerPlaintext {
    pub content: Vec<u8>,
    /// 23 = application_data, 22 = handshake, 21 = alert.
    pub content_type: u8,
}

fn strip_inner_plaintext(buf: &[u8]) -> Result<TlsInnerPlaintext, DecryptError> {
    let last_nonzero = buf
        .iter()
        .rposition(|&b| b != 0)
        .ok_or(DecryptError::AllZeroPlaintext)?;
    let content_type = buf[last_nonzero];
    let content = buf[..last_nonzero].to_vec();
    Ok(TlsInnerPlaintext {
        content,
        content_type,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecryptError {
    ShortCiphertext,
    AeadAuthFailed,
    SeqOverflow,
    AllZeroPlaintext,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── keylog parsing ──────────────────────────────────────────

    #[test]
    fn ingest_line_accepts_valid_traffic_secret() {
        let store = KeylogStore::default();
        // Real-ish line: label + 64-hex client_random + 64-hex SHA-256 secret.
        let cr = "00".repeat(32);
        let secret = "11".repeat(32);
        let line = format!("CLIENT_TRAFFIC_SECRET_0 {cr} {secret}");
        assert!(store.ingest_line(&line));
        let secrets = store.lookup(&[0u8; 32]).expect("should be indexed");
        assert_eq!(secrets.client_application, Some(vec![0x11; 32]));
    }

    #[test]
    fn ingest_line_rejects_blank_and_comments() {
        let store = KeylogStore::default();
        assert!(!store.ingest_line(""));
        assert!(!store.ingest_line("   "));
        assert!(!store.ingest_line("# this is a comment"));
    }

    #[test]
    fn ingest_line_rejects_unknown_label() {
        let store = KeylogStore::default();
        let line = format!("BOGUS_LABEL {} {}", "00".repeat(32), "11".repeat(32));
        assert!(!store.ingest_line(&line));
    }

    #[test]
    fn ingest_line_rejects_wrong_client_random_length() {
        let store = KeylogStore::default();
        // 31 bytes of hex instead of 32.
        let line = format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}",
            "00".repeat(31),
            "11".repeat(32)
        );
        assert!(!store.ingest_line(&line));
    }

    #[test]
    fn ingest_line_accepts_all_known_labels() {
        let store = KeylogStore::default();
        let cr = "ab".repeat(32);
        for label in [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
            "EARLY_TRAFFIC_SECRET",
            "EXPORTER_SECRET",
            "CLIENT_RANDOM",
        ] {
            let line = format!("{label} {cr} {}", "cd".repeat(32));
            assert!(store.ingest_line(&line), "expected to accept {label}");
        }
    }

    #[test]
    fn multiple_lines_for_same_connection_merge() {
        let store = KeylogStore::default();
        let cr = "ff".repeat(32);
        store.ingest_line(&format!("CLIENT_TRAFFIC_SECRET_0 {cr} {}", "11".repeat(32)));
        store.ingest_line(&format!("SERVER_TRAFFIC_SECRET_0 {cr} {}", "22".repeat(32)));
        let s = store.lookup(&[0xFF; 32]).unwrap();
        assert_eq!(s.client_application, Some(vec![0x11; 32]));
        assert_eq!(s.server_application, Some(vec![0x22; 32]));
    }

    // ── HKDF-Expand-Label vector (RFC 8448 §3 / IETF interop) ───

    /// RFC 8448 §3 "{client} send Application Data" derives the
    /// client-application traffic key from the secret. Verifying
    /// against the published vector catches HkdfLabel framing bugs.
    ///
    /// secret: 0x9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5
    /// key (16 bytes): 0x17422dda596ed5d9acd890e3c63f5051
    /// iv  (12 bytes): 0x5b78923dee08579033e523d9
    #[test]
    fn hkdf_expand_label_matches_rfc8448_application_key_iv() {
        let secret: [u8; 32] = [
            0x9e, 0x40, 0x64, 0x6c, 0xe7, 0x9a, 0x7f, 0x9d, 0xc0, 0x5a, 0xf8, 0x88, 0x9b, 0xce,
            0x65, 0x52, 0x87, 0x5a, 0xfa, 0x0b, 0x06, 0xdf, 0x00, 0x87, 0xf7, 0x92, 0xeb, 0xb7,
            0xc1, 0x75, 0x04, 0xa5,
        ];
        let mut key = [0u8; 16];
        hkdf_expand_label(hkdf::HKDF_SHA256, &secret, b"key", &[], &mut key);
        assert_eq!(
            key,
            [
                0x17, 0x42, 0x2d, 0xda, 0x59, 0x6e, 0xd5, 0xd9, 0xac, 0xd8, 0x90, 0xe3, 0xc6, 0x3f,
                0x50, 0x51,
            ]
        );

        let mut iv = [0u8; 12];
        hkdf_expand_label(hkdf::HKDF_SHA256, &secret, b"iv", &[], &mut iv);
        assert_eq!(
            iv,
            [0x5b, 0x78, 0x92, 0x3d, 0xee, 0x08, 0x57, 0x90, 0x33, 0xe5, 0x23, 0xd9]
        );
    }

    // ── full record decrypt (RFC 8448 §3 known-answer) ──────────

    /// End-to-end decrypt of the real "{client} send application_data"
    /// record from the RFC 8448 §3 Simple 1-RTT Handshake trace. This
    /// exercises the whole pipeline — `from_traffic_secret` (HKDF key +
    /// iv derivation) → nonce construction (seq 0) → AEAD open →
    /// inner-plaintext stripping — against published ground truth from
    /// an independent implementation. If this passes, decryption of a
    /// live TLS 1.3 flow with matching keylog secrets is correct.
    ///
    /// secret = client_application_traffic_secret_0
    /// suite  = TLS_AES_128_GCM_SHA256 (16-byte key, SHA-256)
    /// expected plaintext = 0x00 0x01 .. 0x31 (50 bytes), type 0x17.
    #[test]
    fn decrypt_record_matches_rfc8448_client_application_data() {
        let secret: [u8; 32] = [
            0x9e, 0x40, 0x64, 0x6c, 0xe7, 0x9a, 0x7f, 0x9d, 0xc0, 0x5a, 0xf8, 0x88, 0x9b, 0xce,
            0x65, 0x52, 0x87, 0x5a, 0xfa, 0x0b, 0x06, 0xdf, 0x00, 0x87, 0xf7, 0x92, 0xeb, 0xb7,
            0xc1, 0x75, 0x04, 0xa5,
        ];
        // Complete TLS record from RFC 8448: 5-byte header + 67-byte
        // ciphertext-with-tag.
        let record: [u8; 72] = [
            0x17, 0x03, 0x03, 0x00, 0x43, // header (aad)
            0xa2, 0x3f, 0x70, 0x54, 0xb6, 0x2c, 0x94, 0xd0, 0xaf, 0xfa, 0xfe, 0x82, 0x28, 0xba,
            0x55, 0xcb, 0xef, 0xac, 0xea, 0x42, 0xf9, 0x14, 0xaa, 0x66, 0xbc, 0xab, 0x3f, 0x2b,
            0x98, 0x19, 0xa8, 0xa5, 0xb4, 0x6b, 0x39, 0x5b, 0xd5, 0x4a, 0x9a, 0x20, 0x44, 0x1e,
            0x2b, 0x62, 0x97, 0x4e, 0x1f, 0x5a, 0x62, 0x92, 0xa2, 0x97, 0x70, 0x14, 0xbd, 0x1e,
            0x3d, 0xea, 0xe6, 0x3a, 0xee, 0xbb, 0x21, 0x69, 0x49, 0x15, 0xe4,
        ];
        let aad = &record[..5];
        let mut ciphertext = record[5..].to_vec();

        let mut keys = DirectionKeys::from_traffic_secret(CipherSuite::Aes128GcmSha256, &secret);
        let inner = keys
            .decrypt_record(aad, &mut ciphertext)
            .expect("RFC 8448 record must decrypt and authenticate");

        let expected: Vec<u8> = (0x00u8..=0x31).collect();
        assert_eq!(inner.content, expected, "recovered plaintext mismatch");
        assert_eq!(inner.content_type, 0x17, "expected application_data");
        // Sequence advanced for the next record on this direction.
        assert_eq!(keys.next_seq, 1);
    }

    /// A tampered ciphertext (one flipped byte) must fail the AEAD auth
    /// tag check rather than returning garbage plaintext.
    #[test]
    fn decrypt_record_rejects_tampered_ciphertext() {
        let secret: [u8; 32] = [
            0x9e, 0x40, 0x64, 0x6c, 0xe7, 0x9a, 0x7f, 0x9d, 0xc0, 0x5a, 0xf8, 0x88, 0x9b, 0xce,
            0x65, 0x52, 0x87, 0x5a, 0xfa, 0x0b, 0x06, 0xdf, 0x00, 0x87, 0xf7, 0x92, 0xeb, 0xb7,
            0xc1, 0x75, 0x04, 0xa5,
        ];
        let aad = [0x17, 0x03, 0x03, 0x00, 0x43];
        let mut ciphertext = vec![
            0xa2, 0x3f, 0x70, 0x54, 0xb6, 0x2c, 0x94, 0xd0, 0xaf, 0xfa, 0xfe, 0x82, 0x28, 0xba,
            0x55, 0xcb, 0xef, 0xac, 0xea, 0x42, 0xf9, 0x14, 0xaa, 0x66, 0xbc, 0xab, 0x3f, 0x2b,
            0x98, 0x19, 0xa8, 0xa5, 0xb4, 0x6b, 0x39, 0x5b, 0xd5, 0x4a, 0x9a, 0x20, 0x44, 0x1e,
            0x2b, 0x62, 0x97, 0x4e, 0x1f, 0x5a, 0x62, 0x92, 0xa2, 0x97, 0x70, 0x14, 0xbd, 0x1e,
            0x3d, 0xea, 0xe6, 0x3a, 0xee, 0xbb, 0x21, 0x69, 0x49, 0x15, 0xe4,
        ];
        ciphertext[0] ^= 0x01; // flip one bit of the first ciphertext byte
        let mut keys = DirectionKeys::from_traffic_secret(CipherSuite::Aes128GcmSha256, &secret);
        assert_eq!(
            keys.decrypt_record(&aad, &mut ciphertext),
            Err(DecryptError::AeadAuthFailed)
        );
    }

    /// Wrong sequence number (decrypting record 0 as if it were record
    /// 1) changes the nonce and must fail authentication — guards the
    /// per-direction `next_seq` counter against silent corruption.
    #[test]
    fn decrypt_record_wrong_sequence_fails_auth() {
        let secret: [u8; 32] = [
            0x9e, 0x40, 0x64, 0x6c, 0xe7, 0x9a, 0x7f, 0x9d, 0xc0, 0x5a, 0xf8, 0x88, 0x9b, 0xce,
            0x65, 0x52, 0x87, 0x5a, 0xfa, 0x0b, 0x06, 0xdf, 0x00, 0x87, 0xf7, 0x92, 0xeb, 0xb7,
            0xc1, 0x75, 0x04, 0xa5,
        ];
        let aad = [0x17, 0x03, 0x03, 0x00, 0x43];
        let mut ciphertext = vec![
            0xa2, 0x3f, 0x70, 0x54, 0xb6, 0x2c, 0x94, 0xd0, 0xaf, 0xfa, 0xfe, 0x82, 0x28, 0xba,
            0x55, 0xcb, 0xef, 0xac, 0xea, 0x42, 0xf9, 0x14, 0xaa, 0x66, 0xbc, 0xab, 0x3f, 0x2b,
            0x98, 0x19, 0xa8, 0xa5, 0xb4, 0x6b, 0x39, 0x5b, 0xd5, 0x4a, 0x9a, 0x20, 0x44, 0x1e,
            0x2b, 0x62, 0x97, 0x4e, 0x1f, 0x5a, 0x62, 0x92, 0xa2, 0x97, 0x70, 0x14, 0xbd, 0x1e,
            0x3d, 0xea, 0xe6, 0x3a, 0xee, 0xbb, 0x21, 0x69, 0x49, 0x15, 0xe4,
        ];
        let mut keys = DirectionKeys::from_traffic_secret(CipherSuite::Aes128GcmSha256, &secret);
        keys.next_seq = 1; // pretend we already consumed record 0
        assert_eq!(
            keys.decrypt_record(&aad, &mut ciphertext),
            Err(DecryptError::AeadAuthFailed)
        );
    }

    // ── sequence resync (watcher-race recovery) ─────────────────

    /// The RFC 8448 client traffic secret, reused so resync tests run
    /// against real key/iv derivation.
    const RFC8448_CLIENT_SECRET: [u8; 32] = [
        0x9e, 0x40, 0x64, 0x6c, 0xe7, 0x9a, 0x7f, 0x9d, 0xc0, 0x5a, 0xf8, 0x88, 0x9b, 0xce, 0x65,
        0x52, 0x87, 0x5a, 0xfa, 0x0b, 0x06, 0xdf, 0x00, 0x87, 0xf7, 0x92, 0xeb, 0xb7, 0xc1, 0x75,
        0x04, 0xa5,
    ];

    /// Seal `plaintext` (+ inner content_type) into a TLS 1.3 record
    /// ciphertext at sequence `seq`, using the same key schedule the
    /// decrypter derives. Returns (aad, ciphertext_with_tag).
    fn seal_record(seq: u64, plaintext: &[u8], content_type: u8) -> (Vec<u8>, Vec<u8>) {
        let mut keys = DirectionKeys::from_traffic_secret(
            CipherSuite::Aes128GcmSha256,
            &RFC8448_CLIENT_SECRET,
        );
        let mut buf = plaintext.to_vec();
        buf.push(content_type);
        let total = buf.len() + keys.aead.algorithm().tag_len();
        let aad = vec![0x17, 0x03, 0x03, (total >> 8) as u8, (total & 0xff) as u8];
        let nonce = aead::Nonce::assume_unique_for_key(keys.nonce_for(seq));
        keys.aead
            .seal_in_place_append_tag(nonce, aead::Aad::from(&aad), &mut buf)
            .unwrap();
        (aad, buf)
    }

    #[test]
    fn resync_decrypts_at_expected_sequence() {
        let (aad, ct) = seal_record(0, b"hello", 0x17);
        let mut keys = DirectionKeys::from_traffic_secret(
            CipherSuite::Aes128GcmSha256,
            &RFC8448_CLIENT_SECRET,
        );
        let inner = keys.decrypt_record_resync(&aad, &ct, 16).unwrap();
        assert_eq!(inner.content, b"hello");
        assert_eq!(inner.content_type, 0x17);
        assert_eq!(keys.next_seq, 1);
    }

    #[test]
    fn resync_recovers_when_secrets_arrived_late() {
        // The record we observe is sequence 5 — the first four records
        // flowed before the keylog secret was ingested. Decrypter starts
        // at next_seq=0 and must search forward to find it.
        let (aad, ct) = seal_record(5, b"GET / HTTP/1.1", 0x17);
        let mut keys = DirectionKeys::from_traffic_secret(
            CipherSuite::Aes128GcmSha256,
            &RFC8448_CLIENT_SECRET,
        );
        let inner = keys
            .decrypt_record_resync(&aad, &ct, 16)
            .expect("forward search within window must find seq 5");
        assert_eq!(inner.content, b"GET / HTTP/1.1");
        // next_seq advances past the matched record so the rest stay in sync.
        assert_eq!(keys.next_seq, 6);
    }

    #[test]
    fn resync_stops_at_window_edge() {
        // Record is sequence 20 but the window only reaches seq 16.
        let (aad, ct) = seal_record(20, b"late", 0x17);
        let mut keys = DirectionKeys::from_traffic_secret(
            CipherSuite::Aes128GcmSha256,
            &RFC8448_CLIENT_SECRET,
        );
        assert_eq!(
            keys.decrypt_record_resync(&aad, &ct, 16),
            Err(DecryptError::AeadAuthFailed)
        );
        // A failed search must not advance the sequence counter.
        assert_eq!(keys.next_seq, 0);
    }

    #[test]
    fn resync_does_not_search_backwards() {
        // Record is sequence 0 but we're already expecting seq 3 — a late
        // or replayed record must not authenticate.
        let (aad, ct) = seal_record(0, b"stale", 0x17);
        let mut keys = DirectionKeys::from_traffic_secret(
            CipherSuite::Aes128GcmSha256,
            &RFC8448_CLIENT_SECRET,
        );
        keys.next_seq = 3;
        assert_eq!(
            keys.decrypt_record_resync(&aad, &ct, 16),
            Err(DecryptError::AeadAuthFailed)
        );
        assert_eq!(keys.next_seq, 3);
    }

    #[test]
    fn resync_window_zero_matches_strict_decrypt() {
        // max_skip=0 only tries the exact next_seq: a seq-2 record fails
        // when we expect seq 0, just like the strict path.
        let (aad, ct) = seal_record(2, b"x", 0x17);
        let mut keys = DirectionKeys::from_traffic_secret(
            CipherSuite::Aes128GcmSha256,
            &RFC8448_CLIENT_SECRET,
        );
        assert_eq!(
            keys.decrypt_record_resync(&aad, &ct, 0),
            Err(DecryptError::AeadAuthFailed)
        );
    }

    // ── strip_inner_plaintext ───────────────────────────────────

    #[test]
    fn strip_inner_plaintext_finds_content_type_past_padding() {
        // application_data (0x17), 3 bytes padding.
        let buf = b"GET / HTTP/2\r\n\x17\x00\x00\x00";
        let r = strip_inner_plaintext(buf).unwrap();
        assert_eq!(r.content_type, 0x17);
        assert_eq!(r.content, b"GET / HTTP/2\r\n");
    }

    #[test]
    fn strip_inner_plaintext_no_padding() {
        let buf = b"hello\x17";
        let r = strip_inner_plaintext(buf).unwrap();
        assert_eq!(r.content_type, 0x17);
        assert_eq!(r.content, b"hello");
    }

    #[test]
    fn strip_inner_plaintext_rejects_all_zero() {
        assert_eq!(
            strip_inner_plaintext(&[0u8; 16]),
            Err(DecryptError::AllZeroPlaintext)
        );
    }

    // ── nonce computation ───────────────────────────────────────

    #[test]
    fn nonce_xors_sequence_number_into_iv() {
        // Synthetic IV + seq=5 → last byte of IV XORed with 0x05.
        let dk = DirectionKeys {
            aead: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_128_GCM, &[0u8; 16]).unwrap(),
            ),
            iv: [0xAA; 12],
            next_seq: 0,
        };
        let n = dk.nonce_for(5);
        let mut expected = [0xAA; 12];
        expected[11] = 0xAA ^ 5;
        assert_eq!(n, expected);
    }

    #[test]
    fn cipher_suite_from_wire_known_and_unknown() {
        assert_eq!(
            CipherSuite::from_wire(0x1301),
            Some(CipherSuite::Aes128GcmSha256)
        );
        assert_eq!(
            CipherSuite::from_wire(0x1302),
            Some(CipherSuite::Aes256GcmSha384)
        );
        assert_eq!(
            CipherSuite::from_wire(0x1303),
            Some(CipherSuite::Chacha20Poly1305Sha256)
        );
        assert_eq!(CipherSuite::from_wire(0x1304), None); // AES-CCM not in scope
        assert_eq!(CipherSuite::from_wire(0xFFFF), None);
    }
}
