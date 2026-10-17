//! A captured Ethernet frame, through the same decode the capture thread
//! runs: link, IP, transport, then every DPI classifier.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    netwatch::collectors::packets::fuzz_parse_frame(data);
});
