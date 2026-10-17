//! A transport payload, through every DPI classifier. The first five bytes
//! choose TCP or UDP and the two ports, which steer the port-hinted
//! classifiers (DNS/LLMNR, SSDP, SNMP, MQTT, NetBIOS, FTP).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [flags, a, b, c, d, payload @ ..] = data else {
        return;
    };
    let is_tcp = flags & 1 == 1;
    let src = u16::from_be_bytes([*a, *b]);
    let dst = u16::from_be_bytes([*c, *d]);
    let _ = netwatch::dpi::classify_once(payload, is_tcp, src, dst);
});
