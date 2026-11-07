//! What STABILITY.md promises, held in place. Removing or renaming anything here
//! breaks 1.x users, so a test failing in this file is a decision to make, not
//! a list to update. Adding a stable key, flag or metric means adding it here.
use std::path::Path;
use std::process::Command;

use netwatch::collectors::egress::load_policy_file;
use netwatch::config::NetwatchConfig;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/stability");

/// Each stable `config.toml` key still parses into what it did, and none reads
/// as unknown. A type change fails the load and a removal warns.
#[test]
fn every_stable_config_key_is_still_known() {
    let config = NetwatchConfig::load_from(&Path::new(FIXTURES).join("config.toml"))
        .expect("the file of every stable key loads");
    assert!(
        config.load_warnings.is_empty(),
        "{:?}",
        config.load_warnings
    );
}

#[test]
fn every_stable_policy_key_is_still_known() {
    let policy = load_policy_file(&Path::new(FIXTURES).join("egress-policy.toml"))
        .expect("the file of every stable key loads");
    assert!(
        policy.load_warnings.is_empty(),
        "{:?}",
        policy.load_warnings
    );
}

const LONG_FLAGS: &[&str] = &[
    "--remote",
    "--api-key",
    "--insecure-remote",
    "--view",
    "--lite",
    "--demo",
    "--no-sandbox",
    "--sandbox-strict",
    "--metrics",
    "--metrics-addr",
    "--daemon",
    "--headless",
    "--unstable",
    "--generate-config",
    "--help",
    "--version",
];

const USAGE: &[&str] = &[
    "daemon",
    "doctor [--json] [--check-capture] [--interface NAME]",
    "diagnose run [--target NAME] [--budget 30s] [--format json]",
    "diagnose coverage [--json]",
    "diagnose episodes",
    "diagnose export [--since DAYS] [--out FILE] [--dry-run]",
    "uptime [--since 7d] [--json | --csv]",
    "geoip update [--city]",
    "resolver status",
];

#[test]
fn every_stable_flag_and_subcommand_is_still_in_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_netwatch"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout).unwrap();
    // Whole words: `--metrics` is inside `--metrics-addr`, so a substring would
    // miss either being renamed.
    let words: Vec<&str> = help
        .split(|c: char| !(c.is_alphanumeric() || c == '-'))
        .collect();
    for flag in LONG_FLAGS {
        assert!(words.contains(flag), "{flag} is gone from --help:\n{help}");
    }
    for usage in USAGE {
        assert!(help.contains(usage), "{usage} is gone from --help:\n{help}");
    }
}

const METRICS: &[&str] = &[
    "netwatch_build_info",
    "netwatch_capture_packets_decoded_total",
    "netwatch_capture_packets_dropped_total",
    "netwatch_capture_packets_received_total",
    "netwatch_collectors_ok",
    "netwatch_connections",
    "netwatch_dns_loss_ratio",
    "netwatch_dns_rtt_seconds",
    "netwatch_gateway_loss_ratio",
    "netwatch_gateway_rtt_seconds",
    "netwatch_interface_receive_bytes_per_second",
    "netwatch_interface_receive_bytes_total",
    "netwatch_interface_receive_drops_total",
    "netwatch_interface_receive_errors_total",
    "netwatch_interface_receive_packets_total",
    "netwatch_interface_transmit_bytes_per_second",
    "netwatch_interface_transmit_bytes_total",
    "netwatch_interface_transmit_drops_total",
    "netwatch_interface_transmit_errors_total",
    "netwatch_interface_transmit_packets_total",
    "netwatch_policy_violations_total",
    "netwatch_tcp_connections",
    "netwatch_up",
];

/// Most series only render with live data, so this reads the source. It catches
/// a name changing, not a label.
#[test]
fn every_stable_metric_name_is_still_written() {
    let source = include_str!("../src/metrics.rs");
    for name in METRICS {
        assert!(
            source.contains(&format!("\"{name}")),
            "{name} is gone from src/metrics.rs"
        );
    }
}

#[test]
fn the_promise_names_every_stable_schema() {
    let doc = include_str!("../STABILITY.md");
    for marker in [
        "schema 2",
        "`schema_version` 1",
        "netwatch.egress.v1.1",
        "version 1",
        "schema 1",
    ] {
        assert!(doc.contains(marker), "STABILITY.md lost {marker}");
    }
    for file in [
        "diagnose-run.v2",
        "doctor.v1",
        "egress.v1.1",
        "diagnose-export.v1",
        "uptime.v1",
    ] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("schemas")
            .join(format!("{file}.schema.json"));
        assert!(path.is_file(), "{} is gone", path.display());
    }
}
