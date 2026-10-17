//! HTTP/3 stream frames and body decompression, under the same size limit
//! the decoder uses (the decompression-bomb guard).
#![no_main]
use libfuzzer_sys::fuzz_target;
use netwatch::dpi::http3;

fuzz_target!(|data: &[u8]| {
    let _ = http3::extract_stream_chunks(data);
    let _ = http3::h3_data_payload(data);
    if let Some((&flag, body)) = data.split_first() {
        let _ = http3::decompress_body(body, flag & 1 == 1, http3::MAX_H3_BODY_BYTES);
    }
});
