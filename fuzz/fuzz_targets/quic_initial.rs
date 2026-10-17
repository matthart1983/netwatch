//! Decrypted QUIC Initial payloads: the frame walk and CRYPTO reassembly
//! where 0.32 had two panics reachable from one datagram.
#![no_main]
use libfuzzer_sys::fuzz_target;
use netwatch::dpi::quic;

fuzz_target!(|data: &[u8]| {
    let _ = quic::decode_initial_frame_summary(data);
    let _ = quic::extract_initial_crypto_frames(data);
});
