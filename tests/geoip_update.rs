//! `netwatch geoip update` through the binary. Most of this needs no network,
//! and runs in a network namespace so it cannot reach one. The last test runs
//! against the real provider, by hand at release:
//!
//! cargo nextest run --run-ignored only -E 'test(geoip_update_live)' --no-capture
//!
//! That one downloads about 18 MB. Files go under `$XDG_CACHE_HOME` when that is
//! set and under the system temp directory when it is not, except on Windows,
//! where the cache directory cannot be moved and the real one is used.
use netwatch::collectors::geo::GeoCache;
use netwatch::runtime::capabilities::{CapabilitySnapshot, State};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::{env, fs};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let base = env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        let path = base.join(format!("netwatch-geoip-live-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str]) -> Output {
        let output = Command::new(env!("CARGO_BIN_EXE_netwatch"))
            .args(args)
            .env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            .env("XDG_CACHE_HOME", self.0.join("cache"))
            .env("XDG_STATE_HOME", self.0.join("state"))
            .output()
            .unwrap();
        println!(
            "$ netwatch {}\n{}{}exit: {:?}\n",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            output.status.code()
        );
        output
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The path the command printed for a database. The location is not part of
/// any contract, so the test does not assume one.
fn printed_path<'a>(stdout: &'a str, database_type: &str) -> &'a str {
    let line = stdout
        .lines()
        .find(|line| line.contains(database_type))
        .unwrap_or_else(|| panic!("{database_type} is not in {stdout}"));
    let line = line.split(" (DBIP-").next().unwrap();
    line.strip_prefix("updated ")
        .or_else(|| line.strip_prefix("already current "))
        .unwrap()
}

/// `netwatch geoip update` in a user and network namespace, with these as its
/// output, or `None` where one cannot be made. Nothing is reachable there, so
/// every download fails, quickly.
#[cfg(target_os = "linux")]
fn offline_update(fixture: &Fixture, stdout: Stdio, stderr: Stdio) -> Option<std::process::Child> {
    let namespace = ["--user", "--map-root-user", "--net"];
    let usable = Command::new("unshare")
        .args(namespace)
        .arg("true")
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !usable {
        eprintln!("skipped: no user and network namespace");
        return None;
    }
    let child = Command::new("unshare")
        .args(namespace)
        .args([env!("CARGO_BIN_EXE_netwatch"), "geoip", "update"])
        .env("HOME", &fixture.0)
        .env("XDG_CONFIG_HOME", fixture.0.join("config"))
        .env("XDG_CACHE_HOME", fixture.0.join("cache"))
        .env("XDG_STATE_HOME", fixture.0.join("state"))
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .unwrap();
    Some(child)
}

/// The exit codes are 0 and 1, whatever becomes of the output. The print macros
/// panic on a write error, which made this 101.
#[cfg(target_os = "linux")]
#[test]
fn output_errors_do_not_change_the_exit_status() {
    let full = || Stdio::from(fs::File::options().write(true).open("/dev/full").unwrap());
    let fixture = Fixture::new();
    let Some(mut child) = offline_update(&fixture, full(), full()) else {
        return;
    };
    assert_eq!(child.wait().unwrap().code(), Some(1), "to /dev/full");

    let fixture = Fixture::new();
    let mut child = offline_update(&fixture, Stdio::piped(), Stdio::piped()).unwrap();
    drop(child.stdout.take());
    drop(child.stderr.take());
    assert_eq!(child.wait().unwrap().code(), Some(1), "to closed pipes");
}

/// An interrupted first `--city` left 127 MB nothing would ever look at again,
/// and a run without the flag has to clear it as well.
#[cfg(target_os = "linux")]
#[test]
fn a_run_removes_the_partial_files_an_interrupted_one_left() {
    let fixture = Fixture::new();
    let dir = fixture.0.join("cache/netwatch/geoip");
    fs::create_dir_all(&dir).unwrap();
    let partials =
        ["country", "asn", "city"].map(|db| dir.join(format!(".dbip-{db}-lite.mmdb.partial")));
    for partial in &partials {
        fs::write(partial, "partial").unwrap();
    }
    let Some(mut child) = offline_update(&fixture, Stdio::null(), Stdio::null()) else {
        return;
    };
    assert_eq!(child.wait().unwrap().code(), Some(1));
    for partial in &partials {
        assert!(!partial.exists(), "{}", partial.display());
    }
}

/// A session takes paths as text, so nothing saved under a path that is not
/// UTF-8 could ever load, and rerunning would not help. Refused before anything
/// is created or fetched.
#[cfg(target_os = "linux")]
#[test]
fn a_cache_directory_that_is_not_utf8_is_refused_up_front() {
    use std::os::unix::ffi::OsStrExt;
    let fixture = Fixture::new();
    let cache = fixture.0.join(std::ffi::OsStr::from_bytes(b"cache-\xff"));
    let output = Command::new(env!("CARGO_BIN_EXE_netwatch"))
        .args(["geoip", "update"])
        .env("HOME", &fixture.0)
        .env("XDG_CONFIG_HOME", fixture.0.join("config"))
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_STATE_HOME", fixture.0.join("state"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not valid UTF-8"), "{stderr}");
    assert!(!cache.exists());
}

#[test]
#[ignore = "downloads from download.db-ip.com; run by hand at release"]
fn geoip_update_live() {
    let fixture = Fixture::new();

    let first = fixture.run(&["geoip", "update"]);
    assert_eq!(first.status.code(), Some(0));
    let stdout = String::from_utf8(first.stdout).unwrap();
    // The real cache on Windows may already hold them.
    if !cfg!(windows) {
        assert_eq!(stdout.matches("updated ").count(), 2, "{stdout}");
    }
    assert!(
        stdout.contains("IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0"),
        "{stdout}"
    );

    let again = fixture.run(&["geoip", "update"]);
    assert_eq!(again.status.code(), Some(0));
    let stdout = String::from_utf8(again.stdout).unwrap();
    assert_eq!(stdout.matches("already current ").count(), 2, "{stdout}");
    assert!(!stdout.contains("updated "), "{stdout}");
    assert!(!stdout.contains("restart"), "{stdout}");

    let doctor = fixture.run(&["doctor", "--json"]);
    let snapshot: CapabilitySnapshot = serde_json::from_slice(&doctor.stdout).unwrap();
    let geoip = snapshot.get("geoip_db");
    assert_eq!(geoip.state, State::Ready, "{geoip:?}");
    assert_eq!(geoip.reason, "db_loaded");

    // DB-IP's records decode through the reader a session uses.
    let cache = GeoCache::with_mmdb(
        printed_path(&stdout, "DBIP-Country-Lite"),
        printed_path(&stdout, "DBIP-ASN-Lite"),
    );
    let info = cache.lookup("8.8.8.8").unwrap();
    println!("8.8.8.8: {info:?}");
    assert_eq!(info.country_code, "US");
    assert!(!info.org.is_empty());

    // Output that goes nowhere costs neither a download nor the exit status. On
    // a fresh cache a panic on the first line used to lose ASN.
    let fixture = Fixture::new();
    let mut child = Command::new(env!("CARGO_BIN_EXE_netwatch"))
        .args(["geoip", "update"])
        .env("HOME", &fixture.0)
        .env("XDG_CONFIG_HOME", fixture.0.join("config"))
        .env("XDG_CACHE_HOME", fixture.0.join("cache"))
        .env("XDG_STATE_HOME", fixture.0.join("state"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    drop(child.stderr.take());
    assert_eq!(child.wait().unwrap().code(), Some(0), "to closed pipes");
    let doctor = fixture.run(&["doctor", "--json"]);
    let snapshot: CapabilitySnapshot = serde_json::from_slice(&doctor.stdout).unwrap();
    let geoip = snapshot.get("geoip_db");
    assert_eq!(geoip.reason, "db_loaded", "{geoip:?}");
    assert!(geoip.detail.contains("DBIP-ASN-Lite"), "{geoip:?}");
    if let Ok(full) = fs::File::options().write(true).open("/dev/full") {
        let code = Command::new(env!("CARGO_BIN_EXE_netwatch"))
            .args(["geoip", "update"])
            .env("HOME", &fixture.0)
            .env("XDG_CONFIG_HOME", fixture.0.join("config"))
            .env("XDG_CACHE_HOME", fixture.0.join("cache"))
            .env("XDG_STATE_HOME", fixture.0.join("state"))
            .stdout(Stdio::from(full))
            .status()
            .unwrap()
            .code();
        assert_eq!(code, Some(0), "to /dev/full");
    }
}
