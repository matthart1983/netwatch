//! TLS records and handshake messages: ClientHello metadata (SNI, ALPN, ECH,
//! JA4 inputs) and the ServerHello fields decryption depends on.
#![no_main]
use libfuzzer_sys::fuzz_target;
use netwatch::dpi::tls;

fuzz_target!(|data: &[u8]| {
    let _ = tls::extract_handshake_metadata(data);
    let _ = tls::extract_client_random(data);
    let _ = tls::extract_server_hello_cipher_suite(data);
    let _ = tls::extract_server_hello_random(data);
});
