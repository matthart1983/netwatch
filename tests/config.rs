//! A config.toml that is there but does not load. The library returns an
//! error naming the file; the binary refuses to start a session on it rather
//! than run on the defaults.
use netwatch::config::{ConfigError, NetwatchConfig};
use std::{fs, path::PathBuf};

/// The configuration the review reproduced: one value of the wrong type used
/// to discard the whole file, so a strict sandbox started best-effort and
/// uptime recording came back on.
const BROKEN: &str = "sandbox = 'strict'\nrecord_uptime = false\nrefresh_rate_ms = 'oops'\n";

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("netwatch-config-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(path.join("config/netwatch")).unwrap();
        fs::write(path.join("config/netwatch/config.toml"), BROKEN).unwrap();
        Self(path)
    }
    fn config(&self) -> PathBuf {
        self.0.join("config/netwatch/config.toml")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn an_invalid_value_does_not_silently_disable_strict_mode() {
    let fixture = Fixture::new();
    match NetwatchConfig::load_from(&fixture.config()) {
        Err(ConfigError::Parse { path, position, .. }) => {
            assert_eq!(path, fixture.config());
            assert_eq!(position, Some((3, 19)));
        }
        Err(e) => panic!("read error for a readable file: {e}"),
        Ok(config) => panic!(
            "loaded with sandbox {:?} and record_uptime {}",
            config.sandbox, config.record_uptime
        ),
    }
}

/// The binary, with the config directory set on the child only: dirs reads
/// `XDG_CONFIG_HOME` on Linux and the BSDs, where macOS and Windows do not.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod cli {
    use super::Fixture;
    use std::{
        fs,
        io::Read,
        process::{Command, ExitStatus, Stdio},
        time::{Duration, Instant},
    };

    impl Fixture {
        fn command(&self) -> Command {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_netwatch"));
            cmd.env("HOME", &self.0)
                .env("XDG_CONFIG_HOME", self.0.join("config"))
                .env("XDG_CACHE_HOME", self.0.join("cache"))
                .env("XDG_STATE_HOME", self.0.join("state"))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            cmd
        }

        /// Run with `args` until it exits, or fail after 30 s: a session that
        /// started runs until stopped.
        fn run(&self, args: &[&str]) -> (ExitStatus, String, String) {
            let mut child = self.command().args(args).spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("netwatch {args:?} started on a config that does not load");
                }
                std::thread::sleep(Duration::from_millis(50));
            };
            let (mut stdout, mut stderr) = (String::new(), String::new());
            child
                .stdout
                .take()
                .unwrap()
                .read_to_string(&mut stdout)
                .unwrap();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            (status, stdout, stderr)
        }

        /// Only the config directory: no cache, log, state or export
        /// directory, so nothing started.
        fn untouched(&self) -> bool {
            let entries: Vec<_> = fs::read_dir(&self.0)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            entries == ["config"] && fs::read_to_string(self.config()).unwrap() == super::BROKEN
        }
    }

    /// The TUI checks the config before it takes the terminal, so it refuses
    /// without one, the same as the daemon.
    #[test]
    fn tui_and_daemon_refuse_to_start() {
        for args in [&[][..], &["daemon"][..]] {
            let fixture = Fixture::new();
            let (status, _, stderr) = fixture.run(args);
            assert_eq!(status.code(), Some(1), "{args:?}: {stderr}");
            assert!(
                stderr.contains(&format!("invalid config {}", fixture.config().display())),
                "{args:?}: {stderr}"
            );
            assert!(stderr.contains("line 3, column 19"), "{args:?}: {stderr}");
            assert!(fixture.untouched(), "{args:?}: {stderr}");
        }
    }

    /// `diagnose run` keeps its documented status for "no session": 3.
    #[test]
    fn diagnose_run_exits_3() {
        let fixture = Fixture::new();
        let (status, stdout, stderr) = fixture.run(&["diagnose", "run", "--budget", "5s"]);
        assert_eq!(status.code(), Some(3), "{stderr}");
        assert!(stdout.is_empty(), "{stdout}");
        assert!(
            stderr.contains(&fixture.config().display().to_string()),
            "{stderr}"
        );
        assert!(fixture.untouched(), "{stderr}");
    }

    #[test]
    fn commands_that_need_no_config_still_run() {
        let fixture = Fixture::new();
        for args in [&["--version"][..], &["--help"][..], &["uptime"][..]] {
            let (status, _, stderr) = fixture.run(args);
            assert!(status.success(), "{args:?}: {stderr}");
        }
    }

    /// `sandbox_mode = "strict"` does nothing, so it has to say so. A session
    /// says it before anything else, and `--remote` to an http:// URL is a
    /// session that stops right after, so this needs no terminal or capture.
    #[test]
    fn an_unknown_key_warns_on_stderr_and_does_not_stop_anything() {
        let fixture = Fixture::new();
        let config = fixture.config();
        fs::write(
            &config,
            "sandbox_mode = 'strict'\n[alerts]\nbandwidth_thresold = 'secret-value'\n",
        )
        .unwrap();
        let policy = config.with_file_name("egress-policy.toml");
        fs::write(&policy, "[process.curl]\nallow_snis = ['a.example']\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let mut session = fixture.command();
        session
            .args(["--remote", "http://192.0.2.1"])
            .env("NETWATCH_API_KEY", "k");
        let (status, stderr) = {
            let output = session.output().unwrap();
            (output.status, String::from_utf8(output.stderr).unwrap())
        };
        assert_eq!(status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("cleartext"), "{stderr}");
        for line in [
            format!(
                "warning: {}: unknown key sandbox_mode is ignored\n",
                config.display()
            ),
            format!(
                "warning: {}: unknown key alerts.bandwidth_thresold is ignored\n",
                config.display()
            ),
            format!(
                "warning: {}: unknown key process.curl.allow_snis is ignored\n",
                policy.display()
            ),
        ] {
            assert_eq!(stderr.matches(&line).count(), 1, "{line}in\n{stderr}");
        }
        assert!(!stderr.contains("secret-value"), "{stderr}");

        // A command with no session reports it too, with its stdout untouched.
        // No such target, so this is exit 3 without a run.
        let (status, stdout, stderr) =
            fixture.run(&["diagnose", "run", "--format", "json", "--target", "none"]);
        assert_eq!(status.code(), Some(3), "{stderr}");
        assert!(stdout.is_empty(), "{stdout}");
        assert!(stderr.contains("unknown key sandbox_mode"), "{stderr}");
        assert!(stderr.contains("no configured target"), "{stderr}");
    }

    /// `[experimental]` is a note, not a warning, and nothing else in the file
    /// is affected by it.
    #[test]
    fn an_unread_experimental_key_is_a_note() {
        let fixture = Fixture::new();
        fs::write(
            fixture.config(),
            "[experimental]\nsomething = 'value-sentinel'\n",
        )
        .unwrap();
        let (status, _, stderr) =
            fixture.run(&["diagnose", "run", "--format", "json", "--target", "none"]);
        assert_eq!(status.code(), Some(3), "{stderr}");
        assert!(stderr.contains("note: "), "{stderr}");
        assert!(stderr.contains("experimental.something"), "{stderr}");
        assert!(!stderr.contains("warning:"), "{stderr}");
        assert!(!stderr.contains("value-sentinel"), "{stderr}");
    }

    /// The review's reproduction: a write limit standing in for a full disk left
    /// a config that ended mid-line, and netwatch then refused to start. Through
    /// `--generate-config`, which shares its writer with a Settings save.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_save_that_cannot_finish_keeps_the_old_file() {
        let fixture = Fixture::new();
        let old = "# mine\ntheme = 'nord'\nsandbox = 'strict'\n";
        fs::write(fixture.config(), old).unwrap();
        let output = Command::new("sh")
            .args([
                "-c",
                "trap '' XFSZ; ulimit -f 1; exec \"$0\" --generate-config",
            ])
            .arg(env!("CARGO_BIN_EXE_netwatch"))
            .env("HOME", &fixture.0)
            .env("XDG_CONFIG_HOME", fixture.0.join("config"))
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        assert_eq!(fs::read_to_string(fixture.config()).unwrap(), old);
        let names: Vec<_> = fs::read_dir(fixture.config().parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["config.toml"], "a temporary file was left behind");
        // And it still starts on it.
        let (status, _, stderr) = fixture.run(&["doctor"]);
        assert!(status.success(), "{stderr}");
    }

    /// The mode and the link are the user's, through the real path.
    #[test]
    fn a_save_keeps_the_mode_and_follows_a_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let fixture = Fixture::new();
        let elsewhere = fixture.0.join("dotfiles.toml");
        fs::write(&elsewhere, "theme = 'nord'\n").unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o640)).unwrap();
        fs::remove_file(fixture.config()).unwrap();
        symlink(&elsewhere, fixture.config()).unwrap();

        let (status, _, stderr) = fixture.run(&["--generate-config"]);
        assert!(status.success(), "{stderr}");
        assert!(fs::symlink_metadata(fixture.config())
            .unwrap()
            .file_type()
            .is_symlink());
        let saved = fs::read_to_string(&elsewhere).unwrap();
        assert!(saved.starts_with("theme = 'nord'\n"), "{saved}");
        assert!(saved.contains("default_tab"), "{saved}");
        assert_eq!(
            fs::metadata(&elsewhere).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn generate_config_does_not_overwrite_it() {
        let fixture = Fixture::new();
        let (status, _, stderr) = fixture.run(&["--generate-config"]);
        assert_eq!(status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("not overwriting"), "{stderr}");
        assert!(stderr.contains("refresh_rate_ms"), "{stderr}");
        assert!(fixture.untouched(), "{stderr}");
    }
}
