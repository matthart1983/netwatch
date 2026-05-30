# QUIC 1-RTT Application-Data Decryption — Implementation Plan

**Status:** in progress (Phase 2a)
**Branch:** `feature/quic-decryption`
**Context:** Extends the TLS 1.3 decryption shipped in v0.24.0 (passive,
`SSLKEYLOGFILE`-based, read-only) from TLS-over-TCP to QUIC 1-RTT
application data. netwatch already decrypts QUIC **Initial** packets (SNI/JA4
via `dpi/quic.rs`); this adds **1-RTT (short-header) app-data** decryption.

## Why it's harder than TCP-TLS decryption

TCP-TLS was "have the key → AEAD-open the record." QUIC needs protocol state:

1. **Short-header parsing** — only long-header/Initial is parsed today.
2. **DCID-length problem** — a short header's Destination CID has *no length
   prefix on the wire*; you must know the connection's CID length from the
   handshake to locate the packet number.
3. **Connection ↔ secret association** — `SSLKEYLOGFILE` indexes by
   `client_random` (seen only in the Initial ClientHello). Short-header
   packets carry only a CID, so we must map the connection → `client_random`.
4. **Cipher suite** — 1-RTT uses the negotiated suite, but the ServerHello is
   inside *encrypted* Handshake packets. Resolve by trial-decryption across
   the 3 QUIC v1 suites (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305).
5. **Key updates** (key-phase bit) — deferred to polish.

## Reuse (≈70% already exists)

- `dpi/quic.rs`: `unprotect_header` (ring `quic::HeaderProtectionKey`),
  `decrypt_payload` (nonce = iv XOR pn), `parse_long_header`, `read_varint`,
  `hkdf_expand_label`, CRYPTO reassembly.
- `dpi/tls_decrypt.rs`: `KeylogStore` (`client_random → secrets`), the
  SSLKEYLOGFILE watcher, `DirectionKeys`. QUIC clients write the same
  `CLIENT_TRAFFIC_SECRET_0`/`SERVER_TRAFFIC_SECRET_0` — only the HKDF labels
  differ (`"quic key"`/`"quic iv"`/`"quic hp"` vs `"key"`/`"iv"`).
- `Stream.quic_crypto_buf`: reassembled ClientHello bytes (mod.rs ~616-665).
- `CapturedPacket.decrypted_plaintext`: the inspection UI (green rows,
  `decrypted:true`, payload pane, `y` yank) already consumes this — wiring
  QUIC plaintext into it lights up the whole UI for free.

## Phases

### Phase 2a — connection-state foundation (no decryption) ← CURRENT
- Add `Stream.quic_client_random: Option<[u8; 32]>`.
- In the QUIC CRYPTO-reassembly block, once the ClientHello is reassembled,
  capture `client_random` via `crate::dpi::tls::extract_client_random`.
- Acceptance: field populated for QUIC flows; no behavior change; tests green.

### Phase 2b — 1-RTT key derivation
- Add QUIC-label key derivation (`"quic key"`/`"quic iv"`/`"quic hp"`) from a
  keylog `*_TRAFFIC_SECRET_0`. Likely a `DirectionKeys::from_quic_secret` or a
  `quic` flag on the existing derivation.
- Acceptance: unit test against an RFC 9001 §A test vector (known secret →
  known key/iv/hp).

### Phase 2c — short-header decrypt
- Track the server's chosen CID (its SCID from server long headers) →
  the client's short-header DCID, and the CID length.
- Parse short headers using the tracked DCID length; reuse `unprotect_header`
  + `decrypt_payload`. Trial-decrypt across cipher suites (2b).
- Wire decrypted 1-RTT payload into `CapturedPacket.decrypted_plaintext`.
- Acceptance: live `cargo run --example` against an HTTP/3 client with
  `SSLKEYLOGFILE` set shows decrypted 1-RTT payload; RFC 9001 KAT for one
  short-header packet.

### Phase 2d — polish
- Key-phase / key-update handling (RFC 9001 §6).
- Packet-number window / reordering tolerance.

## Out of scope (separate efforts)
- TLS 1.2, 0-RTT (`EARLY_TRAFFIC_SECRET`) — tracked separately under TLS Phase 2.

## Verification discipline
Each phase: `cargo build && cargo test && cargo clippy` green, one commit per
phase, behavior-preserving until 2c wires in the decrypted output.
