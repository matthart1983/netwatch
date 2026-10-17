//! The Packets tab's display-filter language. Typed by the user rather than
//! received from the network, but a panic here takes the TUI down.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = netwatch::collectors::packets::parse_filter(text);
    }
});
