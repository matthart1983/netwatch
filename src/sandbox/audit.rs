//! Which threads of the process still hold CAP_NET_RAW or CAP_NET_ADMIN.
//!
//! Capabilities are per thread, so every drop the sandbox makes covers the
//! thread that makes it, and a thread started before main drops that never
//! enters keeps whatever the process started with. Once main has entered,
//! startup reads every thread's Permitted, Effective, Inheritable and Ambient
//! sets from procfs and holds them to the session's [`CaptureAuthority`]. In a
//! session that drops after open, no thread may hold either capability; in a
//! TUI that reopens capture, threads may keep CAP_NET_RAW but none may hold
//! CAP_NET_ADMIN. A thread that breaks the rule is a warning in best-effort
//! and refuses the start in strict. Off Linux there is nothing to read.

use super::{CaptureAuthority, Mode, Report};
use std::sync::Mutex;

/// A thread holding CAP_NET_RAW or CAP_NET_ADMIN in any of its Permitted,
/// Effective, Inheritable or Ambient sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub tid: u32,
    /// Its name, which the kernel cuts to 15 bytes.
    pub comm: String,
    pub net_raw: bool,
    pub net_admin: bool,
}

impl std::fmt::Display for Holder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.comm, self.tid)
    }
}

/// What [`check_threads`] last found. Process-wide, for doctor to report once
/// rather than per component.
static HOLDERS: Mutex<Option<Vec<Holder>>> = Mutex::new(None);

/// Audit every thread, keep what it found for [`tasks_holding_net_raw`], and
/// add a warning to main's `report` for each capability a thread holds that
/// `authority` does not allow. Strict callers refuse to start on any warning.
/// With the sandbox disabled nothing was dropped, so the result is kept but
/// warns about nothing.
pub fn check_threads(mode: Mode, authority: CaptureAuthority, report: &mut Report) {
    #[cfg(target_os = "linux")]
    {
        let enforce = !matches!(mode, Mode::Disabled);
        match audit_tasks() {
            Ok(holders) => {
                if enforce {
                    report.mode.warnings.extend(warnings(authority, &holders));
                }
                *crate::app::safe_lock(&HOLDERS, "audit::check_threads") = Some(holders);
            }
            Err(error) if enforce => report
                .mode
                .warnings
                .push(format!("thread capability audit failed: {error}")),
            Err(_) => {}
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (mode, authority, report);
}

/// The threads that held CAP_NET_RAW when startup audited them. `None` before
/// the audit runs and off Linux.
pub fn tasks_holding_net_raw() -> Option<Vec<Holder>> {
    crate::app::safe_lock(&HOLDERS, "audit::tasks_holding_net_raw")
        .as_ref()
        .map(|holders| holders.iter().filter(|h| h.net_raw).cloned().collect())
}

/// One warning per capability that some thread holds and `authority` does
/// not allow, naming the threads.
#[cfg(target_os = "linux")]
fn warnings(authority: CaptureAuthority, holders: &[Holder]) -> Vec<String> {
    let named = |held: fn(&Holder) -> bool| {
        holders
            .iter()
            .filter(|h| held(h))
            .map(Holder::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut out = Vec::new();
    let raw = named(|h| h.net_raw);
    if authority == CaptureAuthority::DropAfterOpen && !raw.is_empty() {
        out.push(format!(
            "CAP_NET_RAW still held after capture opened by {raw}"
        ));
    }
    let admin = named(|h| h.net_admin);
    if !admin.is_empty() {
        out.push(format!("CAP_NET_ADMIN still held by {admin}"));
    }
    out
}

/// Every thread of this process holding CAP_NET_RAW or CAP_NET_ADMIN, in
/// thread id order.
#[cfg(target_os = "linux")]
pub fn audit_tasks() -> Result<Vec<Holder>, String> {
    let mut holders = Vec::new();
    let tasks =
        std::fs::read_dir("/proc/self/task").map_err(|e| format!("/proc/self/task: {e}"))?;
    for task in tasks {
        let task = task.map_err(|e| format!("/proc/self/task: {e}"))?;
        let Some(tid) = task.file_name().to_str().and_then(|t| t.parse().ok()) else {
            continue;
        };
        // A thread that exits between the listing and the read holds nothing.
        let status = match std::fs::read_to_string(task.path().join("status")) {
            Ok(status) => status,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(nix::libc::ESRCH) =>
            {
                continue
            }
            Err(e) => return Err(format!("task {tid}: {e}")),
        };
        if let Some(holder) = parse_status(tid, &status)? {
            holders.push(holder);
        }
    }
    holders.sort_by_key(|h| h.tid);
    Ok(holders)
}

/// The holder `status`, one thread's `/proc/<pid>/task/<tid>/status`,
/// describes, or `None` if it holds neither capability. The bounding set is
/// not read: no_new_privs already stops a thread raising anything back.
#[cfg(target_os = "linux")]
fn parse_status(tid: u32, status: &str) -> Result<Option<Holder>, String> {
    const NET_ADMIN: u64 = 1 << 12;
    const NET_RAW: u64 = 1 << 13;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
            .map(str::trim)
    };
    let mut held = 0;
    for set in ["CapPrm", "CapEff", "CapInh", "CapAmb"] {
        held |= field(set)
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .ok_or_else(|| format!("task {tid}: no readable {set}"))?;
    }
    if held & (NET_RAW | NET_ADMIN) == 0 {
        return Ok(None);
    }
    Ok(Some(Holder {
        tid,
        comm: field("Name").unwrap_or_default().to_string(),
        net_raw: held & NET_RAW != 0,
        net_admin: held & NET_ADMIN != 0,
    }))
}

/// For a test that needs capabilities and a process of its own: true in a
/// child running as root in a new user namespace, where it holds every
/// capability, so the test goes on. Anywhere else this runs `test`, the
/// test's path from the crate root, in such a child, asserts that run passed
/// and returns false. Where no such namespace can be made, as on CI's
/// runners, it skips and returns false.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn as_root_in_user_namespace(test: &str) -> bool {
    use caps::{CapSet, Capability};
    const CHILD: &str = "NETWATCH_USERNS_TEST";
    if std::env::var_os(CHILD).is_some() {
        assert!(
            caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_RAW).unwrap_or(false),
            "the user namespace gave no CAP_NET_RAW"
        );
        return true;
    }
    let unshare = || {
        let mut command = std::process::Command::new("unshare");
        command.args(["--user", "--map-root-user"]);
        command
    };
    let status = unshare()
        .args(["cat", "/proc/self/status"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    if parse_status(0, &status)
        .ok()
        .flatten()
        .is_none_or(|h| !h.net_raw)
    {
        eprintln!("skipped: no user namespace with CAP_NET_RAW here");
        return false;
    }
    let result = unshare()
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    false
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// A status file as the kernel writes it, with `set` holding `bits`.
    fn status(set: &str, bits: u64) -> String {
        let mask = |name: &str| if name == set { bits } else { 0 };
        format!(
            "Name:\tcapture\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t812\n\
             CapInh:\t{:016x}\nCapPrm:\t{:016x}\nCapEff:\t{:016x}\n\
             CapBnd:\t{:016x}\nCapAmb:\t{:016x}\nNoNewPrivs:\t1\n",
            mask("CapInh"),
            mask("CapPrm"),
            mask("CapEff"),
            mask("CapBnd"),
            mask("CapAmb"),
        )
    }

    #[test]
    fn audit_tasks_parses_status() {
        for set in ["CapPrm", "CapEff", "CapInh", "CapAmb"] {
            for (bit, raw, admin) in [(13, true, false), (12, false, true)] {
                let holder = parse_status(815, &status(set, 1 << bit)).unwrap();
                assert_eq!(
                    holder,
                    Some(Holder {
                        tid: 815,
                        comm: "capture".into(),
                        net_raw: raw,
                        net_admin: admin,
                    }),
                    "bit {bit} in {set}"
                );
            }
        }
        // Neighbouring bits, CAP_NET_BROADCAST and CAP_IPC_LOCK, and the
        // bounding set are not holdings.
        for (set, bits) in [("CapEff", (1 << 11) | (1 << 14)), ("CapBnd", 3 << 12)] {
            assert_eq!(parse_status(815, &status(set, bits)), Ok(None), "{set}");
        }
        // A set it cannot read is an error, not a clean thread.
        let truncated = status("CapEff", 0).replace("CapAmb", "CapXyz");
        assert!(parse_status(815, &truncated).is_err());
    }

    #[test]
    fn warnings_follow_the_authority() {
        let holder = |tid, comm: &str, net_raw, net_admin| Holder {
            tid,
            comm: comm.into(),
            net_raw,
            net_admin,
        };
        let holders = [
            holder(800, "netwatch", true, false),
            holder(815, "capture", true, true),
        ];
        assert_eq!(
            warnings(CaptureAuthority::DropAfterOpen, &holders),
            [
                "CAP_NET_RAW still held after capture opened by netwatch (800), capture (815)",
                "CAP_NET_ADMIN still held by capture (815)",
            ]
        );
        // A reopening TUI keeps CAP_NET_RAW on purpose.
        assert_eq!(
            warnings(CaptureAuthority::RetainForReopen, &holders),
            ["CAP_NET_ADMIN still held by capture (815)"]
        );
        assert!(warnings(CaptureAuthority::RetainForReopen, &holders[..1]).is_empty());
        assert!(warnings(CaptureAuthority::DropAfterOpen, &[]).is_empty());
    }

    #[test]
    fn audit_names_the_threads_that_hold_net_raw() {
        if !as_root_in_user_namespace(
            "sandbox::audit::tests::audit_names_the_threads_that_hold_net_raw",
        ) {
            return;
        }
        let (holding_tx, holding_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
        let holder = std::thread::Builder::new()
            .name("audit-holder".into())
            .spawn(move || {
                let tid = nix::unistd::gettid().as_raw() as u32;
                holding_tx.send(tid).unwrap();
                done_rx.recv().unwrap();
                let mut report = Report::default();
                super::super::linux::relinquish_caps(super::super::Role::Parser, &mut report);
                assert!(report.mode.warnings.is_empty(), "{report:?}");
                dropped_tx.send(()).unwrap();
                done_rx.recv().unwrap();
            })
            .unwrap();
        let tid = holding_rx.recv().unwrap();
        let found = audit_tasks().unwrap();
        assert!(
            found.contains(&Holder {
                tid,
                comm: "audit-holder".into(),
                net_raw: true,
                net_admin: true,
            }),
            "{found:?}"
        );
        // Main holds both as well, so the strict rule names both threads.
        let mut report = Report::default();
        check_threads(Mode::Strict, CaptureAuthority::DropAfterOpen, &mut report);
        assert!(
            report.mode.warnings[0].contains(&format!("audit-holder ({tid})")),
            "{:?}",
            report.mode.warnings
        );
        assert!(tasks_holding_net_raw()
            .unwrap()
            .iter()
            .any(|h| h.tid == tid));

        done_tx.send(()).unwrap();
        dropped_rx.recv().unwrap();
        let found = audit_tasks().unwrap();
        assert!(found.iter().all(|h| h.tid != tid), "{found:?}");
        done_tx.send(()).unwrap();
        holder.join().unwrap();
    }
}
