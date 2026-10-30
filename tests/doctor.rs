#![cfg(target_os = "linux")]
use std::{fs, net::TcpListener, path::PathBuf, process::Command};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("netwatch-doctor-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(path.join("config/netwatch")).unwrap();
        fs::create_dir_all(path.join("cache/netwatch")).unwrap();
        fs::write(
            path.join("cache/netwatch/applied.json"),
            "corrupt legacy evidence",
        )
        .unwrap();
        Self(path)
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_netwatch"));
        cmd.env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            .env("XDG_CACHE_HOME", self.0.join("cache"))
            .env("XDG_STATE_HOME", self.0.join("state"));
        cmd
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn static_doctor_does_not_contact_configured_services_or_write_state() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let config = netwatch::config::NetwatchConfig {
        insights_enabled: true,
        insights_endpoint: endpoint.clone(),
        geoip_online: true,
        ..Default::default()
    };
    let raw = toml::to_string(&config).unwrap();
    fs::write(fixture.0.join("config/netwatch/config.toml"), &raw).unwrap();
    let output = fixture
        .command()
        .args(["doctor", "--json"])
        .env("NETWATCH_REMOTE_URL", &endpoint)
        .env("NETWATCH_API_KEY", "doctor-secret-sentinel")
        .env(
            "NETWATCH_METRICS_ADDR",
            listener.local_addr().unwrap().to_string(),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("doctor-secret-sentinel"));
    assert!(!text.contains(&endpoint));
    let snapshot: netwatch::runtime::capabilities::CapabilitySnapshot =
        serde_json::from_str(&text).unwrap();
    assert_eq!(snapshot.scope, "static");
    assert!(snapshot.protections.is_empty());
    assert_eq!(
        snapshot.get("capture").state,
        netwatch::runtime::capabilities::State::NotChecked
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        fs::read_to_string(fixture.0.join("config/netwatch/config.toml")).unwrap(),
        raw
    );
    assert_eq!(
        fs::read_to_string(fixture.0.join("cache/netwatch/applied.json")).unwrap(),
        "corrupt legacy evidence"
    );
    assert!(!fixture.0.join("state").exists());
    assert_eq!(
        fs::read_dir(fixture.0.join("cache/netwatch"))
            .unwrap()
            .count(),
        1
    );
}
#[test]
fn malformed_config_is_reported_without_echoing_secrets() {
    let fixture = Fixture::new();
    fs::write(
        fixture.0.join("config/netwatch/config.toml"),
        "api_key = secret-sentinel-invalid",
    )
    .unwrap();
    let output = fixture
        .command()
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("secret-sentinel"));
    let snapshot: netwatch::runtime::capabilities::CapabilitySnapshot =
        serde_json::from_str(&text).unwrap();
    assert_eq!(snapshot.get("config").reason, "config_invalid");
}
#[test]
fn explicit_capture_check_reports_failure_and_creates_no_state() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args([
            "doctor",
            "--json",
            "--check-capture",
            "--interface",
            "netwatch-nonexistent-interface",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot: netwatch::runtime::capabilities::CapabilitySnapshot =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(snapshot.scope, "capture_check");
    assert_eq!(
        snapshot.get("capture").state,
        netwatch::runtime::capabilities::State::Unavailable
    );
    assert!(!fixture.0.join("state").exists());
    assert_eq!(
        fs::read_dir(fixture.0.join("cache/netwatch"))
            .unwrap()
            .count(),
        1
    );
}
/// Doctor names the connection table a live session will read: `ss` when it
/// is on PATH, `/proc/net` when it is not. PATH is set on the child only.
#[test]
fn doctor_reports_the_proc_net_fallback_when_ss_is_missing() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let empty = fixture.0.join("empty-bin");
    let with_ss = fixture.0.join("ss-bin");
    fs::create_dir_all(&empty).unwrap();
    fs::create_dir_all(&with_ss).unwrap();
    fs::write(with_ss.join("ss"), "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(with_ss.join("ss"), fs::Permissions::from_mode(0o755)).unwrap();
    let connections = |path: &std::path::Path| {
        let output = fixture
            .command()
            .args(["doctor", "--json"])
            .env("PATH", path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let snapshot: netwatch::runtime::capabilities::CapabilitySnapshot =
            serde_json::from_slice(&output.stdout).unwrap();
        snapshot.get("connections").clone()
    };

    let missing = connections(&empty);
    assert_eq!(
        missing.state,
        netwatch::runtime::capabilities::State::Degraded
    );
    assert_eq!(missing.reason, "proc_net_fallback");
    assert!(missing.detail.contains("/proc/net/"), "{}", missing.detail);

    let found = connections(&with_ss);
    assert_eq!(found.state, netwatch::runtime::capabilities::State::Ready);
    assert_eq!(found.reason, "ss_found");
    assert!(
        found
            .detail
            .contains(&with_ss.join("ss").display().to_string()),
        "{}",
        found.detail
    );
}
/// `--check-capture` enters with the capture thread's policy, so it reports
/// what capture runs under: in best-effort that drops CAP_NET_RAW, which main
/// keeps. Holding CAP_NET_RAW takes a user and network namespace, so this
/// skips where it cannot make one.
#[test]
fn capture_check_applies_the_capture_policy() {
    let fixture = Fixture::new();
    let mut command = Command::new("unshare");
    command
        .args(["--user", "--map-root-user", "--net", "sh", "-c"])
        .arg(r#"ip link set lo up && exec "$0" doctor --json --check-capture --interface lo"#)
        .arg(env!("CARGO_BIN_EXE_netwatch"));
    for (key, value) in fixture.command().get_envs() {
        if let Some(value) = value {
            command.env(key, value);
        }
    }
    let output = match command.output() {
        Ok(output) if output.status.success() => output,
        other => {
            eprintln!("skipped: no user and network namespace with lo up: {other:?}");
            return;
        }
    };
    let snapshot: netwatch::runtime::capabilities::CapabilitySnapshot =
        serde_json::from_slice(&output.stdout).unwrap();
    let Some(check) = snapshot
        .protections
        .iter()
        .find(|p| p.component == "capture-check")
    else {
        eprintln!(
            "skipped: capture did not open on lo: {:?}",
            snapshot.get("capture")
        );
        return;
    };
    assert_eq!(check.effective.as_deref(), Some("best-effort"));
    let net_raw = "CAP_NET_RAW".to_string();
    assert!(check.caps_dropped.contains(&net_raw), "{check:?}");
    assert!(!check.caps_retained.contains(&net_raw), "{check:?}");
}
