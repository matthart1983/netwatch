//! Passive TLS 1.3 and TLS 1.2 Application-Data decryption via NSS
//! SSLKEYLOGFILE.
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
//! - Post-handshake **KeyUpdate** (RFC 8446 §4.6.3): an observed KeyUpdate
//!   derives generation N+1 ("traffic upd") and resets the record sequence, so
//!   long-lived sessions keep decrypting after a re-key.
//!
//! ## TLS 1.2 (also in scope)
//!
//! - Master secret from the `CLIENT_RANDOM` keylog line; key block via the
//!   TLS 1.2 PRF (RFC 5246 §5). AEAD suites only: AES-128/256-GCM
//!   (RFC 5288) and ChaCha20-Poly1305 (RFC 7905). Legacy CBC
//!   mac-then-encrypt suites are out of scope. See the TLS 1.2 section
//!   lower in this file ([`Tls12Suite`], [`Tls12DirectionKeys`]).
//!
//! ## What's not in scope (deferred to later phases)
//!
//! - TLS 1.2 CBC (mac-then-encrypt) suites.
//! - QUIC application-data decryption (different secret labels, same
//!   AEAD primitives — Phase 2).
//! - 0-RTT (`EARLY_TRAFFIC_SECRET`).
//! - KeyUpdate recovery when the KeyUpdate record itself is *missed* (a capture
//!   gap): we advance on observed KeyUpdates, but don't yet fall back to keylog
//!   `*_TRAFFIC_SECRET_<N>` generations to re-sync after a missed one.
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
use ring::hmac;

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
    /// TLS 1.2 master secret (48 bytes) from a `CLIENT_RANDOM` keylog
    /// line. `None` for TLS 1.3 connections (which log traffic secrets
    /// instead). Its presence is what routes a flow to the TLS 1.2
    /// decrypt path in `try_decrypt_tls_record`.
    pub master_secret: Option<Vec<u8>>,
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
            // TLS 1.2: the CLIENT_RANDOM line carries the 48-byte master
            // secret. Routes the flow to the TLS 1.2 decrypt path.
            KeylogLabel::ClientRandom => entry.master_secret = Some(secret),
            // The remaining variants are recognized but not yet stored
            // (EARLY_TRAFFIC_SECRET, EXPORTER_SECRET). We accept them so
            // we don't log noise for normal keylog files that contain them.
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
    /// Cipher suite and the current `application_traffic_secret_N`, retained so
    /// a TLS 1.3 KeyUpdate (RFC 8446 §4.6.3) can derive generation N+1.
    suite: CipherSuite,
    traffic_secret: Vec<u8>,
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
        let (aead, iv) = Self::derive_aead(suite, secret);
        Self {
            aead,
            iv,
            next_seq: 0,
            suite,
            traffic_secret: secret.to_vec(),
        }
    }

    /// Derive the AEAD key and IV from a traffic secret (RFC 8446 §7.3).
    fn derive_aead(suite: CipherSuite, secret: &[u8]) -> (aead::LessSafeKey, [u8; 12]) {
        let hkdf_alg = suite.hkdf_alg();
        let mut key = vec![0u8; suite.key_len()];
        hkdf_expand_label(hkdf_alg, secret, b"key", &[], &mut key);
        let mut iv = [0u8; 12];
        hkdf_expand_label(hkdf_alg, secret, b"iv", &[], &mut iv);
        let unbound = aead::UnboundKey::new(suite.aead_alg(), &key).unwrap();
        (aead::LessSafeKey::new(unbound), iv)
    }

    /// Advance to the next key generation after a TLS 1.3 KeyUpdate
    /// (RFC 8446 §4.6.3): `application_traffic_secret_{N+1} =
    /// HKDF-Expand-Label(secret_N, "traffic upd", "", Hash.length)`. Re-derives
    /// the AEAD key/IV and resets the record sequence to 0 (RFC 8446 §5.3), so
    /// records sent under the new key keep decrypting.
    pub fn advance_generation(&mut self) {
        let mut next = vec![0u8; self.traffic_secret.len()];
        hkdf_expand_label(
            self.suite.hkdf_alg(),
            &self.traffic_secret,
            b"traffic upd",
            &[],
            &mut next,
        );
        let (aead, iv) = Self::derive_aead(self.suite, &next);
        self.aead = aead;
        self.iv = iv;
        self.next_seq = 0;
        self.traffic_secret = next;
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

// ────────────────────────────────────────────────────────────────────────
// TLS 1.2 Application-Data decryption.
//
// TLS 1.2 differs from the 1.3 path above in three ways, all handled here:
//
//   1. Key schedule. 1.3 derives per-direction keys straight from the keylog
//      traffic secrets via HKDF-Expand-Label. 1.2 instead runs the PRF
//      (HMAC-based P_hash, RFC 5246 §5) over the 48-byte *master secret* with
//      label "key expansion" and seed `server_random || client_random` to
//      produce a key block, which is sliced into the per-direction write keys
//      and fixed IVs. So 1.2 needs the master secret (CLIENT_RANDOM keylog
//      line) plus the server_random read off the ServerHello.
//
//   2. Nonce. 1.2-GCM (RFC 5288) prepends an 8-byte *explicit* nonce to each
//      record; the AEAD nonce is `fixed_iv(4) || explicit(8)`. 1.2-ChaCha
//      (RFC 7905) has no explicit nonce and builds it like 1.3:
//      `fixed_iv(12) XOR seq`.
//
//   3. AAD. 1.2 authenticates `seq(8) || type(1) || version(2) ||
//      plaintext_len(2)` (RFC 5246 §6.2.3.3), where plaintext_len excludes the
//      explicit nonce and tag — not the 5-byte record header 1.3 uses. And
//      there is no inner content-type byte: the outer record type is the real
//      type, so no `strip_inner_plaintext` step.
// ────────────────────────────────────────────────────────────────────────

/// AEAD TLS 1.2 cipher suites we can decrypt. Legacy CBC mac-then-encrypt
/// suites are intentionally excluded — only AEAD (GCM / ChaCha20-Poly1305)
/// suites are modelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12Suite {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Tls12Suite {
    pub fn from_wire(id: u16) -> Option<Self> {
        match id {
            // ECDHE / DHE / static-RSA, AES-128-GCM, SHA-256 PRF.
            0xc02b | 0xc02f | 0x009c | 0x009e => Some(Self::Aes128Gcm),
            // ECDHE / DHE / static-RSA, AES-256-GCM, SHA-384 PRF.
            0xc02c | 0xc030 | 0x009d | 0x009f => Some(Self::Aes256Gcm),
            // ECDHE ChaCha20-Poly1305, SHA-256 PRF (RFC 7905).
            0xcca8 | 0xcca9 => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }

    fn aead_alg(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128Gcm => &aead::AES_128_GCM,
            Self::Aes256Gcm => &aead::AES_256_GCM,
            Self::Chacha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }

    fn prf_hmac(self) -> hmac::Algorithm {
        match self {
            Self::Aes128Gcm | Self::Chacha20Poly1305 => hmac::HMAC_SHA256,
            Self::Aes256Gcm => hmac::HMAC_SHA384,
        }
    }

    fn key_len(self) -> usize {
        self.aead_alg().key_len()
    }

    /// Implicit ("fixed") IV from the key block: 4 bytes for GCM (the rest of
    /// the 12-byte nonce is the explicit per-record nonce), 12 for ChaCha.
    fn fixed_iv_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 4,
            Self::Chacha20Poly1305 => 12,
        }
    }

    /// Explicit per-record nonce length carried on the wire ahead of the
    /// ciphertext: 8 for GCM, 0 for ChaCha20-Poly1305.
    fn record_iv_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 8,
            Self::Chacha20Poly1305 => 0,
        }
    }

    fn key_block_len(self) -> usize {
        // 2 * (mac_key_len + enc_key_len + fixed_iv_len); mac_key_len = 0 for AEAD.
        2 * (self.key_len() + self.fixed_iv_len())
    }
}

/// TLS 1.2 PRF `P_hash` (RFC 5246 §5): expand `secret` over `seed` to
/// `out_len` bytes using the suite's HMAC.
fn p_hash(alg: hmac::Algorithm, secret: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let key = hmac::Key::new(alg, secret);
    // A(1) = HMAC(secret, seed); A(i) = HMAC(secret, A(i-1)).
    let mut a = hmac::sign(&key, seed).as_ref().to_vec();
    let mut out = Vec::with_capacity(out_len);
    while out.len() < out_len {
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(&a);
        ctx.update(seed);
        out.extend_from_slice(ctx.sign().as_ref());
        a = hmac::sign(&key, &a).as_ref().to_vec();
    }
    out.truncate(out_len);
    out
}

/// TLS 1.2 PRF (RFC 5246 §5): `PRF(secret, label, seed) = P_hash(secret,
/// label || seed)`.
fn tls12_prf(
    alg: hmac::Algorithm,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);
    p_hash(alg, secret, &label_seed, out_len)
}

/// Per-direction TLS 1.2 AEAD state: the write key, the fixed IV, and the
/// record sequence number (only the AAD — and, for ChaCha, the nonce —
/// depend on it).
pub struct Tls12DirectionKeys {
    aead: aead::LessSafeKey,
    suite: Tls12Suite,
    fixed_iv: Vec<u8>,
    next_seq: u64,
}

impl Tls12DirectionKeys {
    /// Derive both directions' keys from the master secret. Returns
    /// `(client_write, server_write)`. Per RFC 5246 §6.3 the key block is
    /// `client_write_key || server_write_key || client_write_IV ||
    /// server_write_IV` (MAC keys are empty for AEAD suites).
    pub fn derive(
        suite: Tls12Suite,
        master_secret: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> (Self, Self) {
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(server_random);
        seed.extend_from_slice(client_random);
        let key_block = tls12_prf(
            suite.prf_hmac(),
            master_secret,
            b"key expansion",
            &seed,
            suite.key_block_len(),
        );

        let k = suite.key_len();
        let iv = suite.fixed_iv_len();
        let client_key = &key_block[0..k];
        let server_key = &key_block[k..2 * k];
        let client_iv = &key_block[2 * k..2 * k + iv];
        let server_iv = &key_block[2 * k + iv..2 * k + 2 * iv];

        let mk = |key: &[u8], fixed_iv: &[u8]| {
            let unbound = aead::UnboundKey::new(suite.aead_alg(), key).unwrap();
            Self {
                aead: aead::LessSafeKey::new(unbound),
                suite,
                fixed_iv: fixed_iv.to_vec(),
                next_seq: 0,
            }
        };
        (mk(client_key, client_iv), mk(server_key, server_iv))
    }

    /// Build the 12-byte AEAD nonce for a record at sequence `seq`.
    /// GCM (RFC 5288): `fixed_iv(4) || explicit_nonce(8)`. ChaCha (RFC 7905):
    /// `fixed_iv(12) XOR seq` (seq right-aligned), so no explicit nonce.
    fn nonce_for(&self, seq: u64, explicit_nonce: &[u8]) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        match self.suite {
            Tls12Suite::Aes128Gcm | Tls12Suite::Aes256Gcm => {
                nonce[..4].copy_from_slice(&self.fixed_iv);
                nonce[4..].copy_from_slice(explicit_nonce);
            }
            Tls12Suite::Chacha20Poly1305 => {
                nonce.copy_from_slice(&self.fixed_iv);
                let seq_be = seq.to_be_bytes();
                for i in 0..8 {
                    nonce[4 + i] ^= seq_be[i];
                }
            }
        }
        nonce
    }

    /// TLS 1.2 AAD (RFC 5246 §6.2.3.3): `seq(8) || type(1) || version(2) ||
    /// plaintext_len(2)`.
    fn aad(seq: u64, content_type: u8, version: [u8; 2], plaintext_len: usize) -> [u8; 13] {
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8] = content_type;
        aad[9] = version[0];
        aad[10] = version[1];
        aad[11..].copy_from_slice(&(plaintext_len as u16).to_be_bytes());
        aad
    }

    /// Decrypt one TLS 1.2 record's payload (the bytes after the 5-byte record
    /// header). `content_type` and `version` come from that header.
    ///
    /// Like the 1.3 [`DirectionKeys::decrypt_record_resync`], this tries
    /// sequence numbers in `[next_seq, next_seq + max_skip]` and uses whichever
    /// authenticates, so a flow whose master secret arrived late (the keylog
    /// watcher race) or that skipped an unreassembled record re-locks onto the
    /// correct sequence. Returns the cleartext (no inner content-type byte in
    /// TLS 1.2) on success.
    pub fn decrypt_record_resync(
        &mut self,
        content_type: u8,
        version: [u8; 2],
        record_payload: &[u8],
        max_skip: u64,
    ) -> Result<Vec<u8>, DecryptError> {
        let tag_len = self.aead.algorithm().tag_len();
        let rec_iv = self.suite.record_iv_len();
        if record_payload.len() < rec_iv + tag_len {
            return Err(DecryptError::ShortCiphertext);
        }
        let explicit_nonce = &record_payload[..rec_iv];
        let ct_and_tag = &record_payload[rec_iv..];
        let plaintext_len = ct_and_tag.len() - tag_len;

        let start = self.next_seq;
        let end = start.saturating_add(max_skip);
        let mut seq = start;
        loop {
            let nonce_bytes = self.nonce_for(seq, explicit_nonce);
            let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
            let aad = Self::aad(seq, content_type, version, plaintext_len);
            let mut buf = ct_and_tag.to_vec();
            if self
                .aead
                .open_in_place(nonce, aead::Aad::from(&aad), &mut buf)
                .is_ok()
            {
                buf.truncate(plaintext_len);
                self.next_seq = seq.checked_add(1).ok_or(DecryptError::SeqOverflow)?;
                return Ok(buf);
            }
            if seq >= end {
                return Err(DecryptError::AeadAuthFailed);
            }
            seq = seq.checked_add(1).ok_or(DecryptError::SeqOverflow)?;
        }
    }
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
            suite: CipherSuite::Aes128GcmSha256,
            traffic_secret: vec![0u8; 32],
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

    #[test]
    fn key_update_advances_to_next_generation() {
        let suite = CipherSuite::Aes128GcmSha256;
        // Generation-1 traffic secret per RFC 8446 §4.6.3.
        let mut gen1 = vec![0u8; RFC8448_CLIENT_SECRET.len()];
        hkdf_expand_label(
            suite.hkdf_alg(),
            &RFC8448_CLIENT_SECRET,
            b"traffic upd",
            &[],
            &mut gen1,
        );

        // Seal an application-data record at seq 0 under the gen-1 keys.
        let plaintext = b"post-keyupdate application data".to_vec();
        let (aad, sealed) = {
            let mut k = DirectionKeys::from_traffic_secret(suite, &gen1);
            let mut buf = plaintext.clone();
            buf.push(0x17); // inner content_type = application_data
            let total = buf.len() + k.aead.algorithm().tag_len();
            let aad = vec![0x17, 0x03, 0x03, (total >> 8) as u8, (total & 0xff) as u8];
            let nonce = aead::Nonce::assume_unique_for_key(k.nonce_for(0));
            k.aead
                .seal_in_place_append_tag(nonce, aead::Aad::from(&aad), &mut buf)
                .unwrap();
            (aad, buf)
        };

        // A receiver on gen-0 that observes a KeyUpdate must decrypt the gen-1
        // record after advancing — and the sequence resets to 0.
        let mut keys = DirectionKeys::from_traffic_secret(suite, &RFC8448_CLIENT_SECRET);
        keys.next_seq = 7; // several gen-0 records had already flowed
        keys.advance_generation();
        assert_eq!(
            keys.next_seq, 0,
            "sequence resets on key change (RFC 8446 §5.3)"
        );

        let mut ct = sealed.clone();
        let inner = keys
            .decrypt_record(&aad, &mut ct)
            .expect("gen-1 record must decrypt after KeyUpdate advance");
        assert_eq!(inner.content, plaintext);
        assert_eq!(inner.content_type, 0x17);
    }

    // ── TLS 1.2 ─────────────────────────────────────────────────

    /// TLS 1.2 master secret stored from a CLIENT_RANDOM keylog line —
    /// this is what routes a flow to the 1.2 decrypt path.
    #[test]
    fn ingest_line_stores_tls12_master_secret() {
        let store = KeylogStore::default();
        let cr = "ab".repeat(32);
        // The master secret is 48 bytes (96 hex chars).
        let ms = "cd".repeat(48);
        assert!(store.ingest_line(&format!("CLIENT_RANDOM {cr} {ms}")));
        let s = store.lookup(&[0xab; 32]).unwrap();
        assert_eq!(s.master_secret, Some(vec![0xcd; 48]));
        // And it does not populate the 1.3 traffic-secret slots.
        assert!(s.client_application.is_none());
    }

    /// Independent known-answer for the TLS 1.2 PRF (P_SHA256), inputs from
    /// the IETF TLS WG test vector (Michael D'Errico, 2010):
    ///   secret = 9bbe436ba940f017b17652849a71db35
    ///   label  = "test label"
    ///   seed   = a0ba9f936cda311827a6f796ffd5198c
    /// The expected prefix below was cross-checked against an independent
    /// Python stdlib `hmac`/`hashlib` implementation of the RFC 5246 PRF (a
    /// different HMAC than ring's), so this catches a PRF that is
    /// self-consistent but non-interoperable — something the round-trip
    /// tests below, which use the PRF on both sides, cannot.
    #[test]
    fn tls12_prf_sha256_matches_ietf_vector() {
        let secret = [
            0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71,
            0xdb, 0x35,
        ];
        let seed = [
            0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18, 0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5,
            0x19, 0x8c,
        ];
        let out = tls12_prf(hmac::HMAC_SHA256, &secret, b"test label", &seed, 100);
        assert_eq!(out.len(), 100);
        assert_eq!(
            &out[..16],
            &[
                0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b, 0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c,
                0xd4, 0x53,
            ]
        );
    }

    /// Seal `plaintext` as a TLS 1.2 application_data record's payload (the
    /// bytes after the 5-byte header) under the *client* write keys at
    /// sequence `seq`, using the same derivation the decrypter uses. For GCM
    /// this prepends the 8-byte explicit nonce; for ChaCha there is none.
    fn seal_tls12_client(
        suite: Tls12Suite,
        master: &[u8],
        cr: &[u8; 32],
        sr: &[u8; 32],
        seq: u64,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let (dir, _server) = Tls12DirectionKeys::derive(suite, master, cr, sr);
        let rec_iv = suite.record_iv_len();
        let explicit = seq.to_be_bytes();
        let nonce_bytes = dir.nonce_for(seq, &explicit[..rec_iv]);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let aad = Tls12DirectionKeys::aad(seq, 0x17, [0x03, 0x03], plaintext.len());
        let mut buf = plaintext.to_vec();
        dir.aead
            .seal_in_place_append_tag(nonce, aead::Aad::from(&aad), &mut buf)
            .unwrap();
        let mut payload = Vec::with_capacity(rec_iv + buf.len());
        payload.extend_from_slice(&explicit[..rec_iv]);
        payload.extend_from_slice(&buf);
        payload
    }

    // A throwaway master secret / randoms for round-trip tests. Values are
    // arbitrary — the round-trip only needs seal and open to agree.
    const TLS12_MASTER: [u8; 48] = [0x5a; 48];
    const TLS12_CR: [u8; 32] = [0x11; 32];
    const TLS12_SR: [u8; 32] = [0x22; 32];

    fn tls12_roundtrip(suite: Tls12Suite) {
        let plaintext = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let payload = seal_tls12_client(suite, &TLS12_MASTER, &TLS12_CR, &TLS12_SR, 0, plaintext);
        let (mut client, _server) =
            Tls12DirectionKeys::derive(suite, &TLS12_MASTER, &TLS12_CR, &TLS12_SR);
        let out = client
            .decrypt_record_resync(0x17, [0x03, 0x03], &payload, 16)
            .expect("record sealed under client keys must decrypt");
        assert_eq!(out, plaintext);
        assert_eq!(client.next_seq, 1);
    }

    #[test]
    fn tls12_aes128_gcm_roundtrip() {
        tls12_roundtrip(Tls12Suite::Aes128Gcm); // 0xc02f etc.
    }

    #[test]
    fn tls12_aes256_gcm_roundtrip() {
        tls12_roundtrip(Tls12Suite::Aes256Gcm); // SHA-384 PRF, 0xc030 etc.
    }

    #[test]
    fn tls12_chacha20_poly1305_roundtrip() {
        tls12_roundtrip(Tls12Suite::Chacha20Poly1305); // 0xcca8/0xcca9 — no explicit nonce
    }

    #[test]
    fn tls12_resync_recovers_late_sequence() {
        // The first application_data record we see is the client's seq 4 (the
        // Finished and a few records flowed before the keylog secret landed).
        // The receiver starts at next_seq=0 and searches forward.
        let suite = Tls12Suite::Aes128Gcm;
        let pt = b"late but recoverable";
        let payload = seal_tls12_client(suite, &TLS12_MASTER, &TLS12_CR, &TLS12_SR, 4, pt);
        let (mut client, _server) =
            Tls12DirectionKeys::derive(suite, &TLS12_MASTER, &TLS12_CR, &TLS12_SR);
        let out = client
            .decrypt_record_resync(0x17, [0x03, 0x03], &payload, 16)
            .expect("forward search within window must find seq 4");
        assert_eq!(out, pt);
        assert_eq!(client.next_seq, 5);
    }

    #[test]
    fn tls12_wrong_direction_key_fails() {
        // A record sealed under the client write keys must NOT authenticate
        // under the server write keys — proves the key block is sliced per
        // direction, not shared.
        let suite = Tls12Suite::Aes128Gcm;
        let payload = seal_tls12_client(suite, &TLS12_MASTER, &TLS12_CR, &TLS12_SR, 0, b"hi");
        let (_client, mut server) =
            Tls12DirectionKeys::derive(suite, &TLS12_MASTER, &TLS12_CR, &TLS12_SR);
        assert_eq!(
            server.decrypt_record_resync(0x17, [0x03, 0x03], &payload, 16),
            Err(DecryptError::AeadAuthFailed)
        );
    }

    #[test]
    fn tls12_suite_rejects_cbc_and_tls13_suites() {
        assert!(Tls12Suite::from_wire(0x002f).is_none()); // RSA_AES_128_CBC_SHA
        assert!(Tls12Suite::from_wire(0x1301).is_none()); // TLS 1.3 suite
        assert_eq!(Tls12Suite::from_wire(0xc02f), Some(Tls12Suite::Aes128Gcm));
        assert_eq!(Tls12Suite::from_wire(0xc030), Some(Tls12Suite::Aes256Gcm));
        assert_eq!(
            Tls12Suite::from_wire(0xcca8),
            Some(Tls12Suite::Chacha20Poly1305)
        );
    }
}
