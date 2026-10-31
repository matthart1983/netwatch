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

/// `status` and `recover` say so when a 0.30 journal is open, even on a host
/// where the command itself is refused. An unprivileged run of `recover` stops at
/// the refusal, which is what its exit status reports.
#[test]
fn resolver_status_and_recover_print_the_notice_for_a_journal_from_v0_30() {
    let fixture = Fixture::new();
    fs::write(fixture.journal(), KILLED_AFTER_APPLY).unwrap();
    let mut commands = vec![vec!["resolver", "status"]];
    if !nix::unistd::geteuid().is_root() {
        commands.push(vec!["resolver", "recover", "--unmanaged"]);
    }
    for args in commands {
        let output = fixture.command().args(&args).output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_legacy_notice(&stdout);
        if args[1] == "recover" {
            assert_eq!(output.status.code(), Some(1), "{stdout}");
        }
    }
    assert_eq!(
        fs::read_to_string(fixture.journal()).unwrap(),
        KILLED_AFTER_APPLY
    );

    // With nothing open there is nothing to say.
    fs::remove_file(fixture.journal()).unwrap();
    let output = fixture
        .command()
        .args(["resolver", "status"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Not restored"), "{stdout}");
}

fn assert_legacy_notice(stdout: &str) {
    assert!(
        stdout.contains("Not restored by resolver recover"),
        "{stdout}"
    );
    assert!(
        stdout.contains("recovery required for 2026-0908-02"),
        "{stdout}"
    );
    assert!(stdout.contains("in /etc/resolv.conf;"), "{stdout}");
    assert!(
        stdout.contains("/etc/resolv.conf.netwatch-48977.bak"),
        "{stdout}"
    );
    assert!(stdout.contains("docs/recovery-store.md"), "{stdout}");
}

/// Run a command with `/var/lib/netwatch` refused by the kernel, as it is for
/// anyone but root once `sudo netwatch resolver set` has run. A mount namespace
/// puts a scratch tmpfs over `/var/lib`, holding a directory with mode 000, and
/// the capabilities that would get past that mode go before the command runs.
const REFUSED_STORE: &str = r#"
mount -t tmpfs tmpfs /var/lib
mkdir -m 000 /var/lib/netwatch
exec setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all "$@"
"#;

fn with_store_refused(command: Command) -> Command {
    let mut wrapped = Command::new("unshare");
    wrapped
        .args(["--user", "--map-current-user", "--keep-caps", "--mount"])
        .args(["sh", "-ec", REFUSED_STORE, "sh"])
        .arg(command.get_program())
        .args(command.get_args());
    for (key, value) in command.get_envs() {
        match value {
            Some(value) => wrapped.env(key, value),
            None => wrapped.env_remove(key),
        };
    }
    wrapped
}

/// None where the runner has no such namespace, and for root, which is who this
/// store is for.
fn store_can_be_refused() -> bool {
    let usable = !nix::unistd::geteuid().is_root()
        && with_store_refused(Command::new("true"))
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
    if !usable {
        eprintln!("skipped: no user and mount namespace to refuse the store in");
    }
    usable
}

/// A session that cannot read the store cannot say what is in it, resolved or
/// not. It keeps that off the Diagnose status line, which reads the notice this
/// checks for in the log, and writes one line saying what to run.
#[test]
fn a_session_the_store_is_refused_to_logs_one_line_and_no_notice() {
    if !store_can_be_refused() {
        return;
    }
    let fixture = Fixture::new();
    let mut daemon = fixture.command();
    daemon.arg("daemon");
    let mut child = with_store_refused(daemon)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !fixture.log().contains("resolver store") && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    // After the shutdown pass too, which must not repeat it.
    kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM).unwrap();
    child.wait().unwrap();
    let log = fixture.log();
    let lines: Vec<_> = log
        .lines()
        .filter(|l| l.contains("resolver store"))
        .collect();
    assert_eq!(lines.len(), 1, "{log}");
    assert!(lines[0].contains("/var/lib/netwatch/resolver-v2"), "{log}");
    assert!(lines[0].contains("sudo netwatch resolver status"), "{log}");
    assert!(!log.contains("remediation recovery:"), "{log}");
    assert!(!log.contains("cannot be inspected"), "{log}");
}

#[test]
fn doctor_reports_a_store_the_kernel_refuses_this_user() {
    if !store_can_be_refused() {
        return;
    }
    let fixture = Fixture::new();
    let mut doctor = fixture.command();
    doctor.args(["doctor", "--json"]);
    let output = with_store_refused(doctor).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let store = report["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|capability| capability["id"] == "resolver_store")
        .unwrap_or_else(|| panic!("{stdout}"));
    assert_eq!(store["state"], "not_checked", "{store}");
    assert_eq!(store["reason"], "authority_store_unreadable", "{store}");
    assert_eq!(
        store["next_check"], "sudo netwatch resolver status",
        "{store}"
    );
    let detail = store["detail"].as_str().unwrap();
    assert!(detail.contains("/var/lib/netwatch/resolver-v2"), "{detail}");
    assert!(detail.contains("unknown"), "{detail}");

    let mut text = fixture.command();
    text.arg("doctor");
    let output = with_store_refused(text).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sudo netwatch resolver status"), "{stdout}");
}

/// Stdout where a write fails: a pipe nobody reads, or a full disk.
fn broken_stdouts() -> Vec<(&'static str, Stdio)> {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    vec![("closed pipe", writer.into()), ("/dev/full", full.into())]
}

/// What the commands do must not depend on where their output goes. Each is run
/// with a good stdout first, with and without a notice due, and has to exit the
/// same way and say the same thing on stderr with a broken one. A refused
/// `recover` keeps its error, and a panic is exit 101 and text on stderr.
#[test]
fn a_broken_stdout_changes_neither_exit_status_nor_error() {
    let fixture = Fixture::new();
    let mut commands = vec![vec!["resolver", "status"]];
    if !nix::unistd::geteuid().is_root() {
        commands.push(vec!["resolver", "recover", "--unmanaged"]);
    }
    for journal in [true, false] {
        if journal {
            fs::write(fixture.journal(), KILLED_AFTER_APPLY).unwrap();
        } else {
            fs::remove_file(fixture.journal()).unwrap();
        }
        for args in &commands {
            let good = fixture.command().args(args).output().unwrap();
            assert_eq!(!good.stdout.is_empty(), journal || args[1] == "status");
            for (what, stdout) in broken_stdouts() {
                let broken = fixture
                    .command()
                    .args(args)
                    .stdout(stdout)
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap()
                    .wait_with_output()
                    .unwrap();
                let context = format!("{args:?} journal={journal} stdout={what}");
                assert_eq!(broken.status.code(), good.status.code(), "{context}");
                assert_eq!(
                    String::from_utf8_lossy(&broken.stderr),
                    String::from_utf8_lossy(&good.stderr),
                    "{context}"
                );
            }
        }
    }
}

/// `set` and `recover` take no paths and need root, so these build what they
/// expect in a private root: a tmpfs, the host's programs bound in, and scratch
/// `/etc`, `/var/lib` and cache. It cannot reach the host's resolver. The resolver
/// file holds what a 0.31.1 `resolver set` installed.
const PRIVATE_ROOT: &str = r#"
set -e
umask 022
root=$0 bin=$1 fixture=$2
mount -t tmpfs -o mode=755 tmpfs "$root"
mkdir -p "$root/etc" "$root/proc" "$root/var/lib" "$root/cache/netwatch"
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
"#;

/// The records a 0.31.1 `resolver set` left when SIGKILLed. Only the target's
/// device and inode change, because they name this tmpfs.
const RESTORE_V0_31_1: &str = r#"
mkdir -p "$root/var/lib/netwatch/resolver-v2"
chmod 700 "$root/var/lib/netwatch" "$root/var/lib/netwatch/resolver-v2"
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

/// A 0.30 journal and nothing in the authority store. `set -e` above means a
/// `recover` that exits nonzero fails this.
const LEGACY_V0_30: &str = r#"
cp "$fixture/../v0.30.4-killed-after-apply.applied.json" "$root/cache/netwatch/applied.json"
chroot "$root" /netwatch resolver status
echo "--- recover"
chroot "$root" /netwatch resolver recover --unmanaged
echo "--- /etc/resolv.conf"
cat "$root/etc/resolv.conf"
"#;

/// The reports go to the broken stdout this runs with, so what the test reads
/// goes to stderr. By its first line `set` has changed the resolver, so a panic
/// there would leave the change in place and the record `applied`.
const SET_WITH_BROKEN_STDOUT: &str = r#"
chroot "$root" /netwatch resolver set 192.0.2.53 --unmanaged --seconds 1
cmp "$fixture/resolv.conf.installed" "$root/etc/resolv.conf" >&2
grep '"state"' "$root/var/lib/netwatch/resolver-v2/journal.json" >&2
"#;

/// A notice is due and `recover` has a record to restore, with stdout broken.
const RECOVER_WITH_BROKEN_STDOUT: &str = r#"
cp "$fixture/../v0.30.4-killed-after-apply.applied.json" "$root/cache/netwatch/applied.json"
mkdir -p "$root/var/lib/netwatch/resolver-v2"
chmod 700 "$root/var/lib/netwatch" "$root/var/lib/netwatch/resolver-v2"
sed -e "s/\"device\": 53/\"device\": $(stat -c %d "$root/etc/resolv.conf")/" \
    -e "s/\"inode\": 11037260/\"inode\": $(stat -c %i "$root/etc/resolv.conf")/" \
    "$fixture/journal.json" > "$root/var/lib/netwatch/resolver-v2/journal.json"
cp "$fixture/bd204382-3ba1-46a0-a521-79de298b097e.backup" "$root/var/lib/netwatch/resolver-v2/"
chmod 600 "$root/var/lib/netwatch/resolver-v2/"*
chroot "$root" /netwatch resolver recover --unmanaged
cmp "$fixture/bd204382-3ba1-46a0-a521-79de298b097e.backup" "$root/etc/resolv.conf" >&2
grep '"state"' "$root/var/lib/netwatch/resolver-v2/journal.json" >&2
"#;

fn records() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/recovery/v0.31.1-killed-resolver-set")
}

/// Runs `scenario` as root in a private root, or None where the runner has no
/// user and mount namespace.
fn in_private_root(fixture: &Fixture, scenario: &str) -> Option<std::process::Output> {
    in_private_root_with_stdout(fixture, scenario, Stdio::piped())
}

fn in_private_root_with_stdout(
    fixture: &Fixture,
    scenario: &str,
    stdout: Stdio,
) -> Option<std::process::Output> {
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
        return None;
    }
    let output = Command::new("unshare")
        .args(namespace)
        .args(["sh", "-c", &format!("{PRIVATE_ROOT}{scenario}")])
        .arg(&root)
        .arg(env!("CARGO_BIN_EXE_netwatch"))
        .arg(records())
        .env("XDG_CACHE_HOME", "/cache")
        .stdout(stdout)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    Some(output)
}

#[test]
fn set_and_recover_finish_their_work_with_a_broken_stdout() {
    for (scenario, state) in [
        (SET_WITH_BROKEN_STDOUT, "reverted"),
        (RECOVER_WITH_BROKEN_STDOUT, "reverted"),
    ] {
        for (what, stdout) in broken_stdouts() {
            let fixture = Fixture::new();
            let Some(output) = in_private_root_with_stdout(&fixture, scenario, stdout) else {
                return;
            };
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(output.status.success(), "{what}: {stderr}");
            assert!(stderr.contains(state), "{what}: {stderr}");
            assert!(!stderr.contains("panicked"), "{what}: {stderr}");
        }
    }
}

#[test]
fn resolver_recover_restores_a_change_v0_31_1_left_behind() {
    let fixture = Fixture::new();
    let Some(output) = in_private_root(&fixture, RESTORE_V0_31_1) else {
        return;
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("1 unresolved operations"), "{stdout}");
    let original =
        fs::read_to_string(records().join("bd204382-3ba1-46a0-a521-79de298b097e.backup")).unwrap();
    let expected = format!(
        "Recovered 1 resolver operations\n--- /etc/resolv.conf\n{original}--- again\nRecovered 0 resolver operations\n"
    );
    assert!(stdout.ends_with(&expected), "{stdout}\n{stderr}");
}

/// As root, with the authority store empty, the two lines that used to read as
/// all clear now come with the notice, and `recover` still exits 0 and restores
/// nothing: the journal is outside recovery authority.
#[test]
fn resolver_recover_exits_0_and_changes_nothing_for_a_journal_from_v0_30() {
    let fixture = Fixture::new();
    let Some(output) = in_private_root(&fixture, LEGACY_V0_30) else {
        return;
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    let (status, rest) = stdout.split_once("--- recover\n").unwrap();
    let (recover, resolver) = rest.split_once("--- /etc/resolv.conf\n").unwrap();
    assert!(
        status.contains("No resolver authority journal\n"),
        "{status}"
    );
    assert_legacy_notice(status);
    assert!(
        recover.starts_with("Recovered 0 resolver operations\n"),
        "{recover}"
    );
    assert_legacy_notice(recover);
    let installed = fs::read_to_string(records().join("resolv.conf.installed")).unwrap();
    assert_eq!(resolver, installed);
}
