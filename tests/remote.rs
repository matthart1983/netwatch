//! `main` is the only place a remote URL from `NETWATCH_REMOTE_URL` meets
//! `remote::check_url`. Its unit tests call the check directly, so they
//! would still pass if `main` stopped calling it; this runs the binary.
#![cfg(target_os = "linux")]
use std::{
    fs,
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
/// `--api-key` warns and keeps working, and the warning does not hold the key.
/// An http:// URL stops the session right after, so this needs no backend.
#[test]
fn api_key_flag_warns_without_printing_the_key() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args(["--remote", "http://192.0.2.1", "--api-key", "key-sentinel"])
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert_eq!(
        stderr
            .lines()
            .filter(|l| l.contains("--api-key is deprecated"))
            .count(),
        1,
        "{stderr}"
    );
    assert!(stderr.contains("NETWATCH_API_KEY"), "{stderr}");
    assert!(
        stderr.contains("cleartext"),
        "it reached the URL check: {stderr}"
    );
    assert!(!stderr.contains("key-sentinel"), "{stderr}");
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .contains("key-sentinel"));

    // The environment variable is what it points at, so that says nothing.
    let output = fixture
        .command()
        .args(["--remote", "http://192.0.2.1"])
        .env("NETWATCH_API_KEY", "key-sentinel")
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(!stderr.contains("deprecated"), "{stderr}");
    assert!(!stderr.contains("key-sentinel"), "{stderr}");
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("netwatch-remote-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
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
fn daemon_refuses_an_http_remote_url_from_the_environment() {
    let fixture = Fixture::new();
    let mut child = fixture
        .command()
        .arg("daemon")
        .env("NETWATCH_REMOTE_URL", "http://agent:s3cret@127.0.0.1:1")
        .env("NETWATCH_API_KEY", "remote-key-sentinel")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Without the check the daemon starts and runs until stopped.
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("daemon started with an http:// remote URL");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("--insecure-remote"), "{stderr}");
    assert!(!stderr.contains("s3cret"), "{stderr}");
    assert!(!stderr.contains("remote-key-sentinel"), "{stderr}");
    // Refused before the exports directory or any state is created.
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
}
