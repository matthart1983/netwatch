# QUIC 1-RTT Application-Data Decryption — Implementation Plan

**Status:** 2a ✅ · 2b ✅ · 2c-i ✅ · 2c-ii ✅ (wired into capture; live-verified
vs Chrome HTTP/3) · 3a ✅ (HTTP/3 body decompression — gzip/deflate/brotli,
offset-0; live-verified) · 3b next (cross-packet STREAM reassembly) · 2d polish
(key-update) deferred. Shipped in **v0.25.0**.
**Branch:** `feature/quic-decryption` (worktree at `~/netwatch-quic`)
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

### Phase 2a — connection-state foundation (no decryption) ✅ DONE
- Added `Stream.quic_client_random: Option<[u8; 32]>`.
- `extract_handshake_metadata` now also returns `client_random` (captured
  early, survives truncated ClientHellos); the QUIC reassembly block stores it
  on the stream before the buffer is released on SNI success.
- Done: field populated for QUIC flows; no behavior change; 456 tests green.

### Phase 2b — 1-RTT key derivation ✅ DONE
- `dpi/quic::derive_1rtt_keys(secret, suite, version)` → `OneRttKeys {key, iv, hp}`
  using the `"quic key/iv/hp"` labels and the suite's hash/key-len (reuses
  `tls_decrypt::CipherSuite`). Validated against the RFC 9001 §A.5 ChaCha20 KAT.
  Marked `#[allow(dead_code)]` until 2c calls it.

### Phase 2c-i — short-header decrypt function ✅ DONE
- `dpi/quic::decrypt_1rtt_packet(packet, dcid_len, secret, suite, version,
  largest_pn)` — short-header parse, HP removal (`one_rtt_hp_mask`, per-suite
  AES/ChaCha20), packet-number reconstruction (`decode_packet_number`, RFC
  9000 §A.3), AEAD open. **Validated against the RFC 9001 §A.5 ChaCha20
  short-header KAT** (protected packet → payload `01`). `#[allow(dead_code)]`
  until wired in 2c-ii.

### Phase 2c-ii — connection state + capture wiring ✅ DONE
- Server CID / DCID length and per-direction `largest_pn` tracked on `Stream`;
  first packet brute-forces (suite × DCID length) with AEAD as the oracle, then
  caches. Decrypted plaintext flows into `CapturedPacket.decrypted_plaintext`.
- Acceptance met: live capture against Chrome HTTP/3 with `SSLKEYLOGFILE` shows
  decrypted 1-RTT payload (green rows, `decrypted:true`, payload pane, yank).
  Verification harness: `examples/quic_decrypt_test.rs`.

### Phase 3a — HTTP/3 body decompression ✅ DONE
- `dpi/http3.rs`: walk QUIC frames → collect offset-0 STREAM data → parse the
  HTTP/3 framing layer (RFC 9114) → concatenate DATA frames → sniff/trial-
  decompress (gzip/zlib magic, brotli fallback; the `Content-Encoding` lives in
  the QPACK HEADERS frame, which we deliberately skip). zstd deferred.
- Scope: single-packet, offset-0 bodies. Mid-stream fragments can't be
  decompressed alone — that's 3b. Live-verified (brotli) against YouTube QUIC.

### Phase 3b — cross-packet STREAM reassembly ← NEXT
- Buffer STREAM data per (stream_id, direction) by offset into a contiguous,
  capped/evicted per-stream body; decompress once the head (offset 0) plus a
  usable prefix is present. Unlocks large responses (the common case).

### Phase 2d — polish (deferred)
- Key-phase / key-update handling (RFC 9001 §6).
- Packet-number window / reordering tolerance.

## Out of scope (separate efforts)
- TLS 1.2, 0-RTT (`EARLY_TRAFFIC_SECRET`) — tracked separately under TLS Phase 2.

## Verification discipline
Each phase: `cargo build && cargo test && cargo clippy` green, one commit per
phase, behavior-preserving until 2c wires in the decrypted output.
