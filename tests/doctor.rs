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
        ..Default::default()
    };
    // Written by hand: it is read from an old file, never saved to one.
    let raw = format!("geoip_online = true\n{}", toml::to_string(&config).unwrap());
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
    assert_eq!(snapshot.get("online_geo").reason, "removed");
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
    // Where to look, without the line itself.
    let detail = &snapshot.get("config").detail;
    let path = fixture.0.join("config/netwatch/config.toml");
    assert!(detail.contains(&path.display().to_string()), "{detail}");
    assert!(detail.contains("line 1, column 11"), "{detail}");
}
/// A database that does not open used to look the same as no database at all,
/// and doctor reports it without opening any connection to find out.
#[test]
fn a_junk_geoip_db_is_unreadable_and_static_doctor_stays_offline() {
    use netwatch::runtime::capabilities::{CapabilitySnapshot, State};
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let junk = fixture.0.join("junk.mmdb");
    fs::write(&junk, "not a database").unwrap();
    let config = netwatch::config::NetwatchConfig {
        geoip_db: junk.display().to_string(),
        insights_enabled: true,
        insights_endpoint: format!("http://{}", listener.local_addr().unwrap()),
        ..Default::default()
    };
    fs::write(
        fixture.0.join("config/netwatch/config.toml"),
        toml::to_string(&config).unwrap(),
    )
    .unwrap();
    let output = fixture
        .command()
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let snapshot: CapabilitySnapshot = serde_json::from_slice(&output.stdout).unwrap();
    let geoip = snapshot.get("geoip_db");
    assert_eq!(geoip.state, State::Unavailable);
    assert_eq!(geoip.reason, "db_unreadable");
    assert!(geoip.detail.contains("junk.mmdb"), "{}", geoip.detail);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
/// A one-record MaxMind database with this `build_epoch`, by hand: one
/// search-tree node whose two records both point at the data record.
fn mmdb(build_epoch: u64) -> Vec<u8> {
    fn text(s: &str) -> Vec<u8> {
        [&[0x40 | s.len() as u8][..], s.as_bytes()].concat()
    }
    let mut db = vec![0, 0, 17, 0, 0, 17];
    db.extend_from_slice(&[0; 16]);
    db.push(0xE1);
    db.extend(text("country"));
    db.push(0xE1);
    db.extend(text("iso_code"));
    db.extend(text("US"));
    db.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
    let epoch = [&[0x08, 0x02][..], &build_epoch.to_be_bytes()].concat(); // uint64
    let database_type = text("DBIP-Country-Lite");
    let metadata: [(&str, &[u8]); 9] = [
        ("binary_format_major_version", &[0xA1, 2]), // uint16
        ("binary_format_minor_version", &[0xA0]),
        ("build_epoch", &epoch),
        ("database_type", &database_type),
        ("description", &[0xE0]), // empty map
        ("ip_version", &[0xA1, 6]),
        ("languages", b"\x01\x04\x42en"), // array of one string
        ("node_count", &[0xC1, 1]),       // uint32
        ("record_size", &[0xA1, 24]),
    ];
    db.push(0xE0 | metadata.len() as u8);
    for (key, value) in metadata {
        db.extend(text(key));
        db.extend_from_slice(value);
    }
    db
}
impl Fixture {
    fn set_geoip_db(&self, path: &std::path::Path) {
        let config = netwatch::config::NetwatchConfig {
            geoip_db: path.display().to_string(),
            ..Default::default()
        };
        fs::write(
            self.0.join("config/netwatch/config.toml"),
            toml::to_string(&config).unwrap(),
        )
        .unwrap();
    }
    /// The `geoip_db` capability from `netwatch doctor --json`. Fails, rather
    /// than hanging the run, if doctor does not come back.
    fn geoip_db(&self) -> netwatch::runtime::capabilities::Capability {
        use std::process::Stdio;
        let mut child = self
            .command()
            .args(["doctor", "--json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("doctor did not return");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let snapshot: netwatch::runtime::capabilities::CapabilitySnapshot =
            serde_json::from_slice(&output.stdout).unwrap();
        snapshot.get("geoip_db").clone()
    }
}
/// A date that fits `SystemTime` but not chrono made doctor exit 101.
#[test]
fn an_out_of_range_build_epoch_is_unreadable_and_not_a_panic() {
    use netwatch::runtime::capabilities::State;
    let fixture = Fixture::new();
    let path = fixture.0.join("far.mmdb");
    for epoch in [9_000_000_000_000, u64::MAX] {
        fs::write(&path, mmdb(epoch)).unwrap();
        fixture.set_geoip_db(&path);
        let geoip = fixture.geoip_db();
        assert_eq!(geoip.state, State::Unavailable, "{epoch}");
        assert_eq!(geoip.reason, "db_unreadable", "{epoch}");
    }
    // The same file with a real date loads, so the file was not the problem.
    fs::write(&path, mmdb(1_790_818_572)).unwrap();
    assert_ne!(fixture.geoip_db().reason, "db_unreadable");
}
/// The daemon took the same panic while starting up. In a network namespace,
/// so its probes stay on this host. Skips where it cannot make one.
#[test]
fn the_daemon_survives_an_out_of_range_build_epoch() {
    let fixture = Fixture::new();
    let path = fixture.0.join("far.mmdb");
    fs::write(&path, mmdb(9_000_000_000_000)).unwrap();
    fixture.set_geoip_db(&path);
    let mut command = Command::new("unshare");
    command
        .args([
            "--user",
            "--map-root-user",
            "--net",
            "timeout",
            "-s",
            "TERM",
        ])
        .args(["3", env!("CARGO_BIN_EXE_netwatch"), "daemon"]);
    for (key, value) in fixture.command().get_envs() {
        if let Some(value) = value {
            command.env(key, value);
        }
    }
    let Ok(output) = command.output() else {
        eprintln!("skipped: no unshare");
        return;
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("unshare failed") || stderr.contains("unshare:") {
        eprintln!("skipped: no user and network namespace: {stderr}");
        return;
    }
    // 124 is timeout stopping a daemon that was still running.
    assert_ne!(output.status.code(), Some(101), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}
/// Doctor never opened this file before `geoip_db` existed, so a FIFO hung it
/// and a device read until memory ran out.
#[test]
fn a_geoip_db_that_is_not_a_regular_file_is_unreadable() {
    use netwatch::runtime::capabilities::State;
    let fixture = Fixture::new();
    let fifo = fixture.0.join("fifo.mmdb");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    for path in [fifo.as_path(), std::path::Path::new("/dev/zero")] {
        fixture.set_geoip_db(path);
        let geoip = fixture.geoip_db();
        assert_eq!(geoip.state, State::Unavailable, "{}", path.display());
        assert_eq!(geoip.reason, "db_unreadable", "{}", path.display());
        assert!(
            geoip.detail.contains("not a regular file"),
            "{}",
            geoip.detail
        );
    }
}
const MIB: u64 = 1024 * 1024;
/// Sparse, so these cost nothing. A path in the config has room for a commercial
/// database, and what the update saved is held to what it writes.
#[test]
fn an_oversized_geoip_db_is_unreadable() {
    use netwatch::runtime::capabilities::State;
    let fixture = Fixture::new();
    let path = fixture.0.join("big.mmdb");
    fs::File::create(&path)
        .unwrap()
        .set_len(2048 * MIB + 1)
        .unwrap();
    fixture.set_geoip_db(&path);
    let geoip = fixture.geoip_db();
    assert_eq!(geoip.state, State::Unavailable);
    assert_eq!(geoip.reason, "db_unreadable");
    assert!(geoip.detail.contains("limit"), "{}", geoip.detail);
}
#[test]
fn an_oversized_download_is_unreadable() {
    use netwatch::runtime::capabilities::State;
    let fixture = Fixture::new();
    let dir = fixture.0.join("cache/netwatch/geoip");
    fs::create_dir_all(&dir).unwrap();
    fs::File::create(dir.join("dbip-country-lite.mmdb"))
        .unwrap()
        .set_len(256 * MIB + 1)
        .unwrap();
    let geoip = fixture.geoip_db();
    assert_eq!(geoip.state, State::Unavailable);
    assert_eq!(geoip.reason, "db_unreadable");
    assert!(geoip.detail.contains("limit"), "{}", geoip.detail);
}
/// A commercial database larger than the download limit loaded at any size
/// before there was one. Padded inside the data section, and sparse on disk.
#[test]
fn a_configured_geoip_db_over_the_download_limit_still_loads() {
    use std::io::{Seek, Write};
    let fixture = Fixture::new();
    let path = fixture.0.join("commercial.mmdb");
    let db = mmdb(1_790_818_572);
    let marker = db
        .windows(14)
        .rposition(|window| window == b"\xab\xcd\xefMaxMind.com")
        .unwrap();
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(&db[..marker]).unwrap();
    file.seek(std::io::SeekFrom::Start(256 * MIB + 1)).unwrap();
    file.write_all(&db[marker..]).unwrap();
    drop(file);
    fixture.set_geoip_db(&path);
    let geoip = fixture.geoip_db();
    assert_ne!(geoip.reason, "db_unreadable", "{}", geoip.detail);
}
/// An empty `geoip_db` looks where `netwatch geoip update` puts its files,
/// and with nothing there suggests the command. Junk is enough to show which
/// file a session would open.
#[test]
fn an_empty_geoip_db_uses_the_downloaded_file() {
    use netwatch::runtime::capabilities::{CapabilitySnapshot, State};
    let fixture = Fixture::new();
    let doctor = || {
        let output = fixture
            .command()
            .args(["doctor", "--json"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let snapshot: CapabilitySnapshot = serde_json::from_slice(&output.stdout).unwrap();
        snapshot.get("geoip_db").clone()
    };
    let none = doctor();
    assert_eq!(none.state, State::Disabled);
    assert_eq!(none.reason, "not_configured");
    assert_eq!(none.next_check.as_deref(), Some("netwatch geoip update"));

    let dir = fixture.0.join("cache/netwatch/geoip");
    fs::create_dir_all(&dir).unwrap();
    for (name, after) in [
        ("dbip-country-lite.mmdb", "dbip-country-lite.mmdb"),
        ("dbip-city-lite.mmdb", "dbip-city-lite.mmdb"),
    ] {
        fs::write(dir.join(name), "junk").unwrap();
        let found = doctor();
        assert_eq!(found.reason, "db_unreadable");
        assert!(found.detail.contains(after), "{}", found.detail);
    }
    fs::write(dir.join("dbip-asn-lite.mmdb"), "junk").unwrap();
    assert!(doctor().detail.contains("dbip-asn-lite.mmdb"));
}
/// A live session refuses a config that does not load, so the capture check
/// does not run on the defaults in its place: they could check a weaker
/// sandbox than the one configured. The report still completes and exits 0.
#[test]
fn capture_check_does_not_run_on_a_config_that_does_not_load() {
    let fixture = Fixture::new();
    let config = fixture.0.join("config/netwatch/config.toml");
    let broken = "sandbox = 'strict'\nrefresh_rate_ms = 'oops'\n";
    fs::write(&config, broken).unwrap();
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
    assert_eq!(snapshot.get("config").reason, "config_invalid");
    assert!(
        snapshot.get("config").detail.contains("line 2, column 19"),
        "{:?}",
        snapshot.get("config")
    );
    let capture = snapshot.get("capture");
    assert_eq!(
        capture.state,
        netwatch::runtime::capabilities::State::NotChecked
    );
    assert_eq!(capture.reason, "config_not_loaded");
    assert!(snapshot.protections.is_empty());
    assert_eq!(fs::read_to_string(&config).unwrap(), broken);
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
