#![cfg(target_os = "linux")]
//! A record an older netwatch left on disk, met by this binary. The unit tests
//! beside the journal and the resolver session hold the formats and the restore.
//! These check the wiring: a recovery path keeps passing those after the CLI or
//! the bootstrap stops calling it.
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

/// See `a_journal_from_a_killed_v0_30_is_reported_with_its_target_and_backup`.
const KILLED_AFTER_APPLY: &str =
    include_str!("fixtures/recovery/v0.30.4-killed-after-apply.applied.json");

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("netwatch-recovery-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(path.join("cache/netwatch")).unwrap();
        Self(path)
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_netwatch"));
        cmd.env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            .env("XDG_CACHE_HOME", self.0.join("cache"))
            .env("XDG_STATE_HOME", self.0.join("state"))
            // Nix's build sets it empty, which filters out every warning.
            .env_remove("RUST_LOG");
        cmd
    }
    fn journal(&self) -> PathBuf {
        self.0.join("cache/netwatch/applied.json")
    }
    /// Everything netwatch has logged so far.
    fn log(&self) -> String {
        let mut text = String::new();
        for entry in fs::read_dir(self.0.join("cache/netwatch")).unwrap() {
            let path = entry.unwrap().path();
            if file_name(&path).starts_with("netwatch.log") {
                text.push_str(&fs::read_to_string(path).unwrap_or_default());
            }
        }
        text
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn file_name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

/// A daemon started on a 0.30 journal logs the backup's path and leaves the
/// journal as it found it.
#[test]
fn a_session_reports_a_journal_from_v0_30_and_leaves_it_alone() {
    let fixture = Fixture::new();
    fs::write(fixture.journal(), KILLED_AFTER_APPLY).unwrap();
    let mut child = fixture
        .command()
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !fixture.log().contains("remediation recovery:") && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    // Before the shutdown pass, which would report it a second time.
    let log = fixture.log();
    kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM).unwrap();
    child.wait().unwrap();
    assert!(log.contains("recovery required for 2026-0908-02"), "{log}");
    assert!(log.contains("/etc/resolv.conf.netwatch-48977.bak"), "{log}");
    assert!(log.contains("applied.json"), "{log}");
    assert_eq!(
        fs::read_to_string(fixture.journal()).unwrap(),
        KILLED_AFTER_APPLY
    );
}

/// `recover` is a real subcommand that reaches the session, on any runner. The
/// restore is `resolver_recover_restores_a_change_v0_31_1_left_behind` where
/// user namespaces allow it, and `records_from_v0_31_1_restore_the_resolver_after_an_upgrade`
/// everywhere.
#[test]
fn resolver_recover_reaches_the_authority_check() {
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipped: as root this would open the real authority store");
        return;
    }
    let output = Fixture::new()
        .command()
        .args(["resolver", "recover", "--unmanaged"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(!stderr.contains("usage:"), "{stderr}");
}

/// What a real 0.31.1 `resolver set` left when SIGKILLed, against this binary's
/// `resolver recover`. `set` and `recover` take no paths and need root, so this
/// builds what they expect in a private root: a tmpfs, the host's programs bound
/// in, and scratch `/etc` and `/var/lib`. It cannot reach the host's resolver.
/// Only the target's device and inode change, because they name this tmpfs.
const PRIVATE_ROOT_RECOVER: &str = r#"
set -e
umask 022
root=$0 bin=$1 fixture=$2
mount -t tmpfs -o mode=755 tmpfs "$root"
mkdir -p "$root/etc" "$root/proc" "$root/var/lib/netwatch/resolver-v2"
chmod 700 "$root/var/lib/netwatch" "$root/var/lib/netwatch/resolver-v2"
for dir in usr bin sbin lib lib64; do
    if [ -L "/$dir" ]; then
        ln -s "$(readlink "/$dir")" "$root/$dir"
    elif [ -d "/$dir" ]; then
        mkdir "$root/$dir"
        mount --rbind "/$dir" "$root/$dir"
    fi
done
mount --rbind /proc "$root/proc"
touch "$root/netwatch"
mount --bind "$bin" "$root/netwatch"
cp "$fixture/resolv.conf.installed" "$root/etc/resolv.conf"
chmod 644 "$root/etc/resolv.conf"
sed -e "s/\"device\": 53/\"device\": $(stat -c %d "$root/etc/resolv.conf")/" \
    -e "s/\"inode\": 11037260/\"inode\": $(stat -c %i "$root/etc/resolv.conf")/" \
    "$fixture/journal.json" > "$root/var/lib/netwatch/resolver-v2/journal.json"
cp "$fixture/bd204382-3ba1-46a0-a521-79de298b097e.backup" "$root/var/lib/netwatch/resolver-v2/"
chmod 600 "$root/var/lib/netwatch/resolver-v2/"*
chroot "$root" /netwatch resolver status
chroot "$root" /netwatch resolver recover --unmanaged
echo "--- /etc/resolv.conf"
cat "$root/etc/resolv.conf"
echo "--- again"
chroot "$root" /netwatch resolver recover --unmanaged
"#;

#[test]
fn resolver_recover_restores_a_change_v0_31_1_left_behind() {
    let fixture = Fixture::new();
    let root = fixture.0.join("root");
    fs::create_dir(&root).unwrap();
    let namespace = ["--user", "--map-root-user", "--mount"];
    let usable = Command::new("unshare")
        .args(namespace)
        .args(["mount", "-t", "tmpfs", "tmpfs"])
        .arg(&root)
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !usable {
        eprintln!("skipped: no user and mount namespace");
        return;
    }
    let records = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/recovery/v0.31.1-killed-resolver-set");
    let output = Command::new("unshare")
        .args(namespace)
        .args(["sh", "-c", PRIVATE_ROOT_RECOVER])
        .arg(&root)
        .arg(env!("CARGO_BIN_EXE_netwatch"))
        .arg(&records)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("1 unresolved operations"), "{stdout}");
    let original =
        fs::read_to_string(records.join("bd204382-3ba1-46a0-a521-79de298b097e.backup")).unwrap();
    let expected = format!(
        "Recovered 1 resolver operations\n--- /etc/resolv.conf\n{original}--- again\nRecovered 0 resolver operations\n"
    );
    assert!(stdout.ends_with(&expected), "{stdout}\n{stderr}");
}
