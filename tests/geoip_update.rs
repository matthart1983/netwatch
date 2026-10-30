//! `netwatch geoip update` against the real provider. By hand at release:
//!
//! cargo nextest run --run-ignored only -E 'test(geoip_update_live)' --no-capture
//!
//! It downloads about 9 MB. Files go under `$XDG_CACHE_HOME` when that is set
//! and under the system temp directory when it is not, except on Windows, where
//! the cache directory cannot be moved and the real one is used.
use netwatch::collectors::geo::GeoCache;
use netwatch::runtime::capabilities::{CapabilitySnapshot, State};
use std::path::PathBuf;
use std::process::{Command, Output};
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
}
