// Review-only probes. Not a proposed repository change.
use netwatch::collectors::packets::Replay;
use std::time::Duration;

#[path = "../src/remote/queue.rs"]
mod queue;

fn udp_frame(fragment_offset: u16, declared_ip_len: u16, extra: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; 14 + 20 + 8];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = &mut frame[14..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&declared_ip_len.to_be_bytes());
    ip[6..8].copy_from_slice(&fragment_offset.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
    ip[16..20].copy_from_slice(&[192, 0, 2, 2]);
    ip[20..22].copy_from_slice(&12345u16.to_be_bytes());
    ip[22..24].copy_from_slice(&53u16.to_be_bytes());
    ip[24..26].copy_from_slice(&8u16.to_be_bytes());
    frame.extend_from_slice(extra);
    frame
}

#[test]
fn review_noninitial_fragment_must_not_invent_udp_ports() {
    let packet = Replay::new().frame(&udp_frame(1, 28, &[])).unwrap();
    assert_eq!(packet.src_port, None, "fragment payload became a UDP header");
    assert_eq!(packet.stream_index, None);
}

#[test]
fn review_ip_padding_must_not_become_dns_payload() {
    let dns = [0x12,0x34,0x01,0x00,0,1,0,0,0,0,0,0,1,b'a',0,0,1,0,1];
    let packet = Replay::new().frame(&udp_frame(0, 28, &dns)).unwrap();
    assert!(!packet.info.contains("A a"), "padding decoded as DNS: {}", packet.info);
    assert!(packet.app_protocol.is_none(), "padding classified as {:?}", packet.app_protocol);
}

#[test]
fn review_retry_delay_can_reach_more_than_one_second() {
    // Production jitter_entropy() returns subsec_nanos(), always below 1e9.
    let mut backoff = queue::Backoff::new(Duration::from_millis(500), Duration::from_secs(60));
    let mut longest = Duration::ZERO;
    for _ in 0..20 {
        longest = longest.max(backoff.fail(999_999_999));
    }
    assert!(longest > Duration::from_secs(1), "largest delay after 20 failures: {longest:?}");
}

#[test]
fn review_budget_overflow_is_rejected_without_panicking() {
    let result = std::panic::catch_unwind(|| netwatch::diagnose::run::parse_budget("18446744073709551615m"));
    assert!(result.is_ok(), "invalid CLI duration panicked");
    assert!(result.unwrap().is_err());
}

#[test]
fn review_config_error_must_not_silently_disable_strict_mode() {
    let dir = std::env::temp_dir().join(format!("netwatch-review-config-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("netwatch")).unwrap();
    std::fs::write(dir.join("netwatch/config.toml"), "sandbox = 'strict'\nrecord_uptime = false\nrefresh_rate_ms = 'oops'\n").unwrap();
    let previous = std::env::var_os("XDG_CONFIG_HOME");
    std::env::set_var("XDG_CONFIG_HOME", &dir);
    let loaded = netwatch::config::NetwatchConfig::load();
    match previous {
        Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
        None => std::env::remove_var("XDG_CONFIG_HOME"),
    }
    std::fs::remove_dir_all(dir).unwrap();
    assert_eq!(loaded.sandbox, "strict", "unrelated invalid setting silently reset security policy; uptime recording is {}", loaded.record_uptime);
}
