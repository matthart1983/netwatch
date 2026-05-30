//! HTTP/3 body extraction + decompression for decrypted QUIC 1-RTT
//! payloads.
//!
//! Once `dpi::quic::decrypt_1rtt_packet` hands back a decrypted 1-RTT
//! packet's *frame* bytes, this module turns them into something a human
//! can read:
//!
//! 1. Walk the QUIC frames (RFC 9000 §19) and pull out STREAM-frame data.
//! 2. For a STREAM that starts at offset 0 (so we have the head of the
//!    request/response stream), parse the HTTP/3 framing layer
//!    (RFC 9114 §7.1) and concatenate DATA-frame payloads.
//! 3. Sniff / trial-decompress the body. The `Content-Encoding` lives in
//!    the QPACK-compressed HEADERS frame, which we deliberately do *not*
//!    decode — instead we detect gzip / zlib by magic bytes and attempt
//!    brotli (which has no magic) as a fallback.
//!
//! ## Scope (Phase 3a)
//! Single-packet, offset-0 bodies — i.e. responses small enough that the
//! whole HTTP/3 stream fits in one 1-RTT packet. Mid-stream packets (a
//! STREAM frame at a non-zero offset) can't be decompressed on their own:
//! a gzip/brotli stream must be fed from byte 0. Cross-packet STREAM
//! reassembly is Phase 3b. zstd is out of scope.

use std::io::Read;

/// A STREAM frame located inside a decrypted 1-RTT packet payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamChunk {
    pub stream_id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: Vec<u8>,
}

/// Content coding detected for an HTTP/3 body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyEncoding {
    Gzip,
    Deflate,
    Brotli,
}

impl BodyEncoding {
    pub fn label(self) -> &'static str {
        match self {
            BodyEncoding::Gzip => "gzip",
            BodyEncoding::Deflate => "deflate",
            BodyEncoding::Brotli => "br",
        }
    }
}

/// A decompressed HTTP/3 body ready to show in the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBody {
    pub encoding: BodyEncoding,
    /// Stream the body came from (HTTP/3 request/response stream id).
    pub stream_id: u64,
    pub bytes: Vec<u8>,
}

/// Read a QUIC variable-length integer (RFC 9000 §16). Returns the value
/// and the number of bytes consumed. Self-contained so this module doesn't
/// depend on `quic`'s private helper.
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut val = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        val = (val << 8) | b as u64;
    }
    Some((val, len))
}

/// Skip `n` variable-length integers starting at `pos`, returning the new
/// position or `None` if the buffer runs out.
fn skip_varints(buf: &[u8], mut pos: usize, n: usize) -> Option<usize> {
    for _ in 0..n {
        let (_, used) = read_varint(buf.get(pos..)?)?;
        pos += used;
    }
    Some(pos)
}

/// Walk the QUIC frames in a decrypted 1-RTT packet payload and collect any
/// STREAM-frame chunks (RFC 9000 §19.8). Best-effort: on a frame type we
/// can't size, we stop and return what we have rather than risk
/// misaligned reads. The frame types handled are the ones that realistically
/// precede a STREAM frame in a server→client 1-RTT packet.
pub fn extract_stream_chunks(frames: &[u8]) -> Vec<StreamChunk> {
    let mut chunks = Vec::new();
    let mut pos = 0;
    while pos < frames.len() {
        let Some((frame_type, used)) = read_varint(&frames[pos..]) else {
            break;
        };
        pos += used;
        match frame_type {
            // PADDING / PING — single-byte, nothing follows the type.
            0x00 | 0x01 => continue,
            // ACK (0x02) / ACK+ECN (0x03). Layout: Largest Acked, ACK Delay,
            // Range Count, First Range, then Range Count × (Gap, Length),
            // then 3 ECN counts when the type is 0x03.
            0x02 | 0x03 => {
                // Read Range Count (3rd varint) to know how many ranges follow.
                let Some((range_count, _)) = read_varint(
                    frames
                        .get(skip_varints(frames, pos, 2).unwrap_or(frames.len())..)
                        .unwrap_or(&[]),
                ) else {
                    break;
                };
                // largest, delay, range_count, first_range = 4 varints.
                let Some(mut p) = skip_varints(frames, pos, 4) else {
                    break;
                };
                let mut ok = true;
                for _ in 0..range_count {
                    match skip_varints(frames, p, 2) {
                        Some(np) => p = np,
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    break;
                }
                if frame_type == 0x03 {
                    let Some(np) = skip_varints(frames, p, 3) else {
                        break;
                    };
                    p = np;
                }
                pos = p;
            }
            // RESET_STREAM: stream_id, app_error, final_size.
            0x04 => match skip_varints(frames, pos, 3) {
                Some(np) => pos = np,
                None => break,
            },
            // STOP_SENDING: stream_id, app_error.
            0x05 => match skip_varints(frames, pos, 2) {
                Some(np) => pos = np,
                None => break,
            },
            // CRYPTO: offset, length, data — skip past the data.
            0x06 => {
                let Some((_offset, o)) = read_varint(&frames[pos..]) else {
                    break;
                };
                let Some((length, l)) = read_varint(&frames[pos + o..]) else {
                    break;
                };
                pos = pos + o + l + length as usize;
            }
            // NEW_TOKEN: length, token.
            0x07 => {
                let Some((length, l)) = read_varint(&frames[pos..]) else {
                    break;
                };
                pos = pos + l + length as usize;
            }
            // STREAM frames: 0x08..=0x0f. Low 3 bits are OFF/LEN/FIN.
            0x08..=0x0f => {
                let off_bit = frame_type & 0x04 != 0;
                let len_bit = frame_type & 0x02 != 0;
                let fin = frame_type & 0x01 != 0;
                let Some((stream_id, idu)) = read_varint(&frames[pos..]) else {
                    break;
                };
                pos += idu;
                let offset = if off_bit {
                    let Some((o, ou)) = read_varint(&frames[pos..]) else {
                        break;
                    };
                    pos += ou;
                    o
                } else {
                    0
                };
                let data_len = if len_bit {
                    let Some((l, lu)) = read_varint(&frames[pos..]) else {
                        break;
                    };
                    pos += lu;
                    l as usize
                } else {
                    // No LEN bit → data runs to the end of the packet.
                    frames.len() - pos
                };
                let end = pos.saturating_add(data_len);
                if end > frames.len() {
                    break;
                }
                chunks.push(StreamChunk {
                    stream_id,
                    offset,
                    fin,
                    data: frames[pos..end].to_vec(),
                });
                pos = end;
            }
            // MAX_DATA / MAX_STREAMS(2) — single varint argument.
            0x10 | 0x12 | 0x13 => match skip_varints(frames, pos, 1) {
                Some(np) => pos = np,
                None => break,
            },
            // MAX_STREAM_DATA — two varints.
            0x11 => match skip_varints(frames, pos, 2) {
                Some(np) => pos = np,
                None => break,
            },
            // HANDSHAKE_DONE — no payload.
            0x1e => continue,
            // Anything else (NEW_CONNECTION_ID, path frames, …) has a shape
            // we don't track here; stop rather than misread.
            _ => break,
        }
    }
    chunks
}

/// HTTP/3 frame types we care about (RFC 9114 §7.2).
const H3_FRAME_DATA: u64 = 0x00;
const H3_FRAME_HEADERS: u64 = 0x01;

/// Parse the HTTP/3 framing layer of a request/response stream that starts
/// at offset 0 and concatenate the DATA-frame payloads. Returns `None` if
/// the bytes don't parse as H3 framing or carry no DATA. A trailing frame
/// truncated by the packet boundary is tolerated (we keep what parsed).
pub fn h3_data_payload(stream: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    let mut saw_known_frame = false;
    while pos < stream.len() {
        let (ftype, tu) = read_varint(&stream[pos..])?;
        let Some((flen, lu)) = read_varint(stream.get(pos + tu..)?) else {
            // Length varint truncated at packet edge — stop with what we have.
            break;
        };
        let body_start = pos + tu + lu;
        let body_end = body_start.saturating_add(flen as usize);
        match ftype {
            H3_FRAME_DATA => {
                saw_known_frame = true;
                let end = body_end.min(stream.len());
                if body_start <= end {
                    out.extend_from_slice(&stream[body_start..end]);
                }
                if body_end > stream.len() {
                    break; // truncated final DATA frame
                }
                pos = body_end;
            }
            H3_FRAME_HEADERS => {
                saw_known_frame = true;
                if body_end > stream.len() {
                    break;
                }
                pos = body_end; // QPACK-compressed; we skip it
            }
            // Unknown/extension/GREASE frame — skip by its length.
            _ => {
                if body_end > stream.len() {
                    break;
                }
                pos = body_end;
            }
        }
    }
    if saw_known_frame && !out.is_empty() {
        Some(out)
    } else {
        None
    }
}

/// Sniff / trial-decompress an HTTP body. gzip and zlib are detected by
/// magic bytes; brotli has none, so it's attempted last. Returns the coding
/// and the decompressed bytes, or `None` if nothing produced sane output.
pub fn decompress_body(body: &[u8]) -> Option<(BodyEncoding, Vec<u8>)> {
    if body.len() < 2 {
        return None;
    }
    // gzip: 1f 8b.
    if body[0] == 0x1f && body[1] == 0x8b {
        if let Some(out) = inflate_gzip(body) {
            return Some((BodyEncoding::Gzip, out));
        }
    }
    // zlib/deflate: 0x78 with a valid FCHECK (common variants 0x01/0x9c/0xda).
    if body[0] == 0x78 {
        if let Some(out) = inflate_zlib(body) {
            return Some((BodyEncoding::Deflate, out));
        }
    }
    // brotli — no magic, so only accept if it yields non-empty output.
    if let Some(out) = inflate_brotli(body) {
        if !out.is_empty() {
            return Some((BodyEncoding::Brotli, out));
        }
    }
    None
}

fn inflate_gzip(body: &[u8]) -> Option<Vec<u8>> {
    let mut d = flate2::read::GzDecoder::new(body);
    let mut out = Vec::new();
    d.read_to_end(&mut out).ok().map(|_| out)
}

fn inflate_zlib(body: &[u8]) -> Option<Vec<u8>> {
    let mut d = flate2::read::ZlibDecoder::new(body);
    let mut out = Vec::new();
    d.read_to_end(&mut out).ok().map(|_| out)
}

fn inflate_brotli(body: &[u8]) -> Option<Vec<u8>> {
    let mut d = brotli::Decompressor::new(body, 4096);
    let mut out = Vec::new();
    d.read_to_end(&mut out).ok().map(|_| out)
}

/// Phase 3a: from a single decrypted 1-RTT packet's frame bytes, if it
/// carries an offset-0 STREAM with HTTP/3 DATA we can decompress, return the
/// decoded body. Mid-stream packets (offset > 0) return `None` — those need
/// cross-packet reassembly (Phase 3b).
pub fn try_decode_single_packet(frames: &[u8]) -> Option<DecodedBody> {
    for chunk in extract_stream_chunks(frames) {
        if chunk.offset != 0 {
            continue;
        }
        let Some(body) = h3_data_payload(&chunk.data) else {
            continue;
        };
        if let Some((encoding, bytes)) = decompress_body(&body) {
            return Some(DecodedBody {
                encoding,
                stream_id: chunk.stream_id,
                bytes,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            w.write_all(data).unwrap();
        }
        out
    }

    /// Encode a value as a QUIC varint (minimal width) for test fixtures.
    fn varint(v: u64) -> Vec<u8> {
        if v < 64 {
            vec![v as u8]
        } else if v < 16384 {
            let b = (v as u16) | 0x4000;
            b.to_be_bytes().to_vec()
        } else if v < 1_073_741_824 {
            let b = (v as u32) | 0x8000_0000;
            b.to_be_bytes().to_vec()
        } else {
            let b = v | 0xc000_0000_0000_0000;
            b.to_be_bytes().to_vec()
        }
    }

    /// Build an HTTP/3 DATA frame carrying `body`.
    fn h3_data_frame(body: &[u8]) -> Vec<u8> {
        let mut f = varint(H3_FRAME_DATA);
        f.extend(varint(body.len() as u64));
        f.extend_from_slice(body);
        f
    }

    /// Build a QUIC STREAM frame (OFF + LEN bits set) for `stream_id`.
    fn stream_frame(stream_id: u64, offset: u64, data: &[u8]) -> Vec<u8> {
        // Type 0x0c = STREAM | OFF | LEN (0x08 | 0x04 | 0x02 = 0x0e). Use
        // 0x0e so both offset and length are explicit.
        let mut f = vec![0x0e];
        f.extend(varint(stream_id));
        f.extend(varint(offset));
        f.extend(varint(data.len() as u64));
        f.extend_from_slice(data);
        f
    }

    #[test]
    fn decompress_sniffs_gzip_zlib_brotli() {
        let payload = b"hello world, this is a compressible body ".repeat(8);
        for (mk, want) in [
            (gzip(&payload), BodyEncoding::Gzip),
            (zlib(&payload), BodyEncoding::Deflate),
            (brotli(&payload), BodyEncoding::Brotli),
        ] {
            let (enc, out) = decompress_body(&mk).expect("must decompress");
            assert_eq!(enc, want);
            assert_eq!(out, payload);
        }
    }

    #[test]
    fn extract_stream_chunk_no_len_runs_to_end() {
        // STREAM with OFF set, LEN clear (type 0x0c): data runs to end.
        let mut frame = vec![0x0c];
        frame.extend(varint(248)); // stream id
        frame.extend(varint(92775)); // offset
        frame.extend_from_slice(b"tail-data");
        let chunks = extract_stream_chunks(&frame);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].stream_id, 248);
        assert_eq!(chunks[0].offset, 92775);
        assert_eq!(chunks[0].data, b"tail-data");
    }

    #[test]
    fn ack_frame_then_stream_is_walked() {
        // ACK (0x02): largest=10, delay=0, range_count=0, first_range=3.
        let mut frames = vec![0x02];
        frames.extend(varint(10));
        frames.extend(varint(0));
        frames.extend(varint(0));
        frames.extend(varint(3));
        // Followed by a STREAM frame we must still find.
        frames.extend(stream_frame(0, 0, b"after-ack"));
        let chunks = extract_stream_chunks(&frames);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].data, b"after-ack");
    }

    #[test]
    fn end_to_end_offset0_gzip_body_decodes() {
        let body = b"{\"ok\":true,\"msg\":\"the quick brown fox\"}".repeat(4);
        let h3 = h3_data_frame(&gzip(&body));
        let frame = stream_frame(0, 0, &h3);
        let decoded = try_decode_single_packet(&frame).expect("offset-0 body must decode");
        assert_eq!(decoded.encoding, BodyEncoding::Gzip);
        assert_eq!(decoded.stream_id, 0);
        assert_eq!(decoded.bytes, body);
    }

    #[test]
    fn midstream_offset_is_not_decoded() {
        // Same body but the STREAM frame starts at a non-zero offset — we
        // can't decompress a fragment, so this must return None.
        let body = b"compressible compressible compressible".to_vec();
        let h3 = h3_data_frame(&gzip(&body));
        let frame = stream_frame(0, 4096, &h3);
        assert!(try_decode_single_packet(&frame).is_none());
    }

    #[test]
    fn h3_data_skips_headers_frame() {
        // A HEADERS frame (QPACK bytes we can't read) followed by DATA.
        let mut stream = varint(H3_FRAME_HEADERS);
        let fake_qpack = [0xaa, 0xbb, 0xcc];
        stream.extend(varint(fake_qpack.len() as u64));
        stream.extend_from_slice(&fake_qpack);
        stream.extend(h3_data_frame(b"real-body"));
        let body = h3_data_payload(&stream).expect("must find DATA after HEADERS");
        assert_eq!(body, b"real-body");
    }
}
