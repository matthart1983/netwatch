//! Recovery evidence for remediations an older netwatch applied.
//!
//! Live TUI and daemon bootstrap use [`Journal::inspect_recovery`] with explicit
//! [`RecoveryAuthority::InspectOnly`]. Legacy entries do not establish trusted
//! ownership or resolver authority, so the application never executes their paths
//! at startup or shutdown. Unresolved metadata and backup locations are preserved
//! for manual review. Automatic TUI apply actions remain disabled; the explicit
//! Linux resolver command uses its own fixed root-owned authority store.
//!
//! The legacy journal, `applied.json`, is read here and nowhere else. Netwatch
//! 0.30 was the last to apply through it and 0.31.0 the last to roll it back, so
//! this module has neither a writer nor a rollback: a journal an older netwatch
//! left is reported until someone deals with it by hand. Its format is pinned by
//! fixtures under `tests/fixtures/recovery`.

pub mod resolver;
pub mod store;

use serde::Deserialize;
use std::path::PathBuf;

/// Where a journal entry is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EntryState {
    /// Journalled but the write was never confirmed. Under the sandbox this is
    /// usually a refused write that changed nothing; nothing here can tell.
    Pending,
    /// Change was live on the host.
    Applied,
    /// Change was undone; kept in the file as history.
    Reverted,
    /// Could not be undone safely. The backup path was preserved for a human.
    Abandoned,
}

/// The fields of an `applied.json` entry that recovery reports. Older netwatches
/// wrote more (the action, the installed text, the PID); none of it can establish
/// ownership, and serde ignores it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
struct JournalEntry {
    /// Issue this remediation belonged to.
    issue_id: String,
    /// File the change landed in, when it was a file edit.
    target: Option<PathBuf>,
    /// Copy of `target` as it was before the change.
    backup: Option<PathBuf>,
    state: EntryState,
    /// True once the user asked for the change to outlive the session. A
    /// permanent entry needs no recovery.
    #[serde(default)]
    permanent: bool,
}

/// Authority granted by the live bootstrap, independent of UID or sandbox mode.
/// Legacy journals have no verifiable ownership or supported resolver adapter,
/// so no automatic write authority is available yet.
#[derive(Clone, Copy, Debug)]
pub enum RecoveryAuthority {
    InspectOnly,
}

pub struct Journal {
    path: PathBuf,
    entries: Vec<JournalEntry>,
    /// Why recovery needs review: a journal that could not be read, or records
    /// left unresolved. Diagnose shows it until the records are dealt with.
    notice: Option<String>,
}

impl Journal {
    pub fn default_path() -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("netwatch")
            .join("applied.json")
    }

    fn open_entries(&self) -> impl Iterator<Item = &JournalEntry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.state, EntryState::Pending | EntryState::Applied))
    }

    fn load(path: PathBuf) -> Self {
        let read = std::fs::read_to_string(&path);
        Self::parse(path, read)
    }

    /// A journal from the outcome of reading `path`, for a caller that has to be
    /// more careful about the read than [`Self::load`].
    fn parse(path: PathBuf, read: std::io::Result<String>) -> Self {
        let mut journal = Self {
            path,
            entries: Vec::new(),
            notice: None,
        };
        match read {
            Ok(text) => match serde_json::from_str::<Vec<JournalEntry>>(&text) {
                Ok(entries) => journal.entries = entries,
                Err(e) => journal.notice = Some(format!(
                    "invalid or unsupported journal {}: {e}; original preserved; recovery review required",
                    journal.path.display()
                )),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => journal.notice = Some(format!(
                "cannot read journal {}: {e}; recovery review required", journal.path.display()
            )),
        }
        journal
    }

    /// Inspect both formats without migrating or rewriting legacy evidence.
    pub fn load_live() -> Self {
        let mut journal = Self::load_with_store(Self::default_path(), store::default_directory());
        if let Some(notice) = resolver::authority_notice() {
            journal.inspect_recovery(RecoveryAuthority::InspectOnly);
            journal.notice = Some(match journal.notice.take() {
                Some(other) => format!("{other}; {notice}"),
                None => notice,
            });
        }
        journal
    }

    fn load_with_store(legacy: PathBuf, durable: Option<PathBuf>) -> Self {
        let mut journal = Self::load(legacy);
        let warning = match durable {
            None => Some("cannot determine durable recovery state directory".to_owned()),
            Some(directory) => match store::inspect(&directory) {
                Ok(None) => None,
                Ok(Some(snapshot)) => {
                    let pending: Vec<String> = snapshot
                        .operations
                        .iter()
                        .filter(|o| o.state.unresolved())
                        .map(|o| {
                            format!(
                                "{} ({:?}); backup: {} (unverified)",
                                o.id,
                                o.state,
                                directory.join(o.backup_name()).display()
                            )
                        })
                        .collect();
                    (!pending.is_empty()).then(|| format!(
                        "recovery-v2 requires adapter/ownership verification; journal: {}; operations: {}",
                        directory.join("journal.json").display(), pending.join("; ")
                    ))
                }
                Err(error) => Some(format!(
                    "cannot inspect recovery-v2 at {}: {error}; evidence preserved",
                    directory.display()
                )),
            },
        };
        if let Some(warning) = warning {
            // Include legacy unresolved metadata alongside v2 diagnostics. No
            // supplied target or backup is opened by this inspection.
            journal.inspect_recovery(RecoveryAuthority::InspectOnly);
            journal.notice = Some(match journal.notice.take() {
                Some(legacy) => format!("{legacy}; {warning}"),
                None => warning,
            });
        }
        journal
    }

    pub fn recovery_notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    /// A journal holding only `notice`, for drawing one in a test.
    #[cfg(test)]
    pub(crate) fn with_notice(notice: &str) -> Self {
        Self {
            path: PathBuf::new(),
            entries: Vec::new(),
            notice: Some(notice.to_owned()),
        }
    }

    /// Inspect legacy metadata without reading or writing journal-supplied paths.
    /// Preserve unresolved entries and prevent shutdown/PID reuse from turning
    /// them into this session's operations. Root and --no-sandbox are not consent.
    pub fn inspect_recovery(&mut self, authority: RecoveryAuthority) -> Vec<String> {
        match authority {
            RecoveryAuthority::InspectOnly => {}
        }
        if let Some(reason) = &self.notice {
            return vec![reason.clone()];
        }
        let unresolved: Vec<String> = self
            .open_entries()
            .filter(|entry| !entry.permanent)
            .map(|entry| {
                // Target and backup first: the status line cuts off at the width
                // of the terminal, and these are what the reader has to act on.
                format!(
                    "recovery required for {}: an older netwatch may have left a change in {}; \
                     backup: {} (unverified); legacy ownership and resolver authority are \
                     unverified, so automatic rollback is disabled; restore by hand \
                     (docs/recovery-store.md), then remove {}",
                    entry.issue_id,
                    entry
                        .target
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "an unnamed file".into()),
                    entry
                        .backup
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "missing".into()),
                    self.path.display(),
                )
            })
            .collect();
        if !unresolved.is_empty() {
            self.notice = Some(unresolved.join("; "));
        }
        unresolved
    }
}

/// Build the resolv.conf text that switching to `addr` produces: replace the
/// first `nameserver` line, leave every other directive (search, options,
/// comments) untouched.
pub fn resolv_conf_with(original: &str, addr: &str) -> String {
    let mut out = String::new();
    let mut replaced = false;
    for line in original.lines() {
        if !replaced && line.trim_start().starts_with("nameserver") {
            out.push_str(&format!("nameserver {addr}\n"));
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str(&format!("nameserver {addr}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    /// What v0.30.4's own writer left when it was killed after a confirmed write
    /// to /etc/resolv.conf, with an earlier session's clean quit as history. The
    /// bytes are that release's `apply_file_edit` and `flush`, run unedited.
    const KILLED_AFTER_APPLY: &str =
        include_str!("../../tests/fixtures/recovery/v0.30.4-killed-after-apply.applied.json");
    /// The same writer when the sandbox refused the backup: the journal says
    /// pending, and /etc was never changed.
    const SANDBOX_REFUSED: &str =
        include_str!("../../tests/fixtures/recovery/v0.30.4-sandbox-refused-write.applied.json");

    const RESOLV: &str = "# generated\nsearch lan\nnameserver 169.254.1.1\noptions edns0\n";

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("netwatch-journal-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn journal(&self, text: &str) -> PathBuf {
            let path = self.0.join("applied.json");
            fs::write(&path, text).unwrap();
            path
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_journal_from_a_killed_v0_30_is_reported_with_its_target_and_backup() {
        let temp = Temp::new();
        let path = temp.journal(KILLED_AFTER_APPLY);
        let mut journal = Journal::load(path.clone());
        assert_eq!(journal.recovery_notice(), None);
        let unresolved = journal.inspect_recovery(RecoveryAuthority::InspectOnly);
        assert_eq!(unresolved.len(), 1, "{unresolved:?}");
        let notice = journal.recovery_notice().unwrap();
        assert!(notice.contains("2026-0908-02"), "{notice}");
        assert!(notice.contains("in /etc/resolv.conf;"), "{notice}");
        assert!(
            notice.contains("/etc/resolv.conf.netwatch-48977.bak"),
            "{notice}"
        );
        assert!(notice.contains(&path.display().to_string()), "{notice}");
        // The session that quit cleanly is history, not something to recover.
        assert!(!notice.contains("2026-0908-01"), "{notice}");
        assert!(!notice.contains("48213"), "{notice}");
        assert_eq!(fs::read_to_string(&path).unwrap(), KILLED_AFTER_APPLY);
    }

    #[test]
    fn a_v0_30_write_the_sandbox_refused_is_reported_too() {
        let temp = Temp::new();
        let mut journal = Journal::load(temp.journal(SANDBOX_REFUSED));
        assert_eq!(
            journal
                .inspect_recovery(RecoveryAuthority::InspectOnly)
                .len(),
            1
        );
        let notice = journal.recovery_notice().unwrap();
        assert!(
            notice.contains("/etc/resolv.conf.netwatch-51002.bak"),
            "{notice}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn live_load_discovers_both_formats_without_changing_either() {
        use std::os::unix::fs::DirBuilderExt;
        let root =
            std::env::temp_dir().join(format!("netwatch-live-journal-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let directory = root.join("recovery-v2");
        let mut durable = store::Store::open(&directory).unwrap();
        let id = durable
            .prepare(
                "new issue".into(),
                store::Owner::current(),
                store::Resource {
                    adapter: store::Adapter::UnmanagedFile,
                    target: "/synthetic/resolver".into(),
                    device: 1,
                    inode: 2,
                },
                b"original",
                b"installed",
            )
            .unwrap();
        drop(durable);
        let journal_bytes = fs::read(directory.join("journal.json")).unwrap();
        let legacy = root.join("applied.json");
        fs::write(&legacy, KILLED_AFTER_APPLY).unwrap();
        let live = Journal::load_with_store(legacy.clone(), Some(directory.clone()));
        let warning = live.recovery_notice().unwrap();
        assert!(warning.contains(&id.to_string()));
        assert!(warning.contains("legacy ownership"));
        assert_eq!(live.open_entries().count(), 1);
        assert_eq!(fs::read_to_string(&legacy).unwrap(), KILLED_AFTER_APPLY);
        assert_eq!(
            fs::read(directory.join("journal.json")).unwrap(),
            journal_bytes
        );
        fs::write(directory.join("journal.json"), b"corrupt-v2").unwrap();
        let corrupt = Journal::load_with_store(legacy, Some(directory.clone()));
        assert!(corrupt
            .recovery_notice()
            .unwrap()
            .contains("cannot inspect recovery-v2"));
        assert_eq!(
            fs::read(directory.join("journal.json")).unwrap(),
            b"corrupt-v2"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn live_bootstrap_reports_legacy_operations_on_every_pass() {
        use crate::runtime::bootstrap::SessionKind;
        for kind in [SessionKind::Tui, SessionKind::Daemon] {
            let temp = Temp::new();
            let mut restarted = Journal::load(temp.journal(KILLED_AFTER_APPLY));
            let authority = kind.recovery_authority().unwrap();
            let startup = restarted.inspect_recovery(authority);
            assert_eq!(startup.len(), 1);
            assert!(restarted.recovery_notice().unwrap().contains("unverified"));
            // Shutdown inspects again, and must find the same thing still open.
            assert_eq!(restarted.inspect_recovery(authority), startup);
            assert_eq!(restarted.open_entries().count(), 1);
        }
    }

    #[test]
    fn recovery_inspection_preserves_corrupt_and_permanent_history() {
        let temp = Temp::new();
        let path = temp.journal("invalid journal");
        let mut journal = Journal::load(path.clone());
        assert!(!journal
            .inspect_recovery(RecoveryAuthority::InspectOnly)
            .is_empty());
        assert_eq!(fs::read_to_string(&path).unwrap(), "invalid journal");

        let permanent = KILLED_AFTER_APPLY.replace("\"permanent\": false", "\"permanent\": true");
        let path = temp.journal(&permanent);
        let mut journal = Journal::load(path.clone());
        assert!(journal
            .inspect_recovery(RecoveryAuthority::InspectOnly)
            .is_empty());
        assert_eq!(journal.recovery_notice(), None);
        assert_eq!(fs::read_to_string(&path).unwrap(), permanent);
    }

    #[test]
    fn resolv_conf_rewrite_preserves_other_directives() {
        let out = resolv_conf_with(RESOLV, "192.168.8.1");
        assert!(out.contains("nameserver 192.168.8.1"));
        assert!(out.contains("search lan"), "search line must survive");
        assert!(out.contains("options edns0"), "options must survive");
        assert!(out.contains("# generated"), "comments must survive");
        assert!(!out.contains("169.254.1.1"));
    }

    #[test]
    fn resolv_conf_rewrite_adds_a_nameserver_when_there_is_none() {
        let out = resolv_conf_with("search lan\n", "1.1.1.1");
        assert!(out.contains("nameserver 1.1.1.1"));
        assert!(out.contains("search lan"));
    }

    #[test]
    fn invalid_and_unsupported_journals_are_preserved_and_reported() {
        for original in ["[{truncated", r#"{"version":999,"entries":[]}"#] {
            let temp = Temp::new();
            let path = temp.journal(original);
            let mut journal = Journal::load(path.clone());
            assert!(journal.recovery_notice().is_some());
            assert!(!journal
                .inspect_recovery(RecoveryAuthority::InspectOnly)
                .is_empty());
            assert_eq!(fs::read_to_string(&path).unwrap(), original);
        }
    }

    #[test]
    fn missing_journal_is_distinct_from_unreadable_journal() {
        let temp = Temp::new();
        let missing: &Path = &temp.0.join("applied.json");
        assert_eq!(Journal::load(missing.into()).recovery_notice(), None);
        // A directory where the file belongs fails to read on every OS.
        fs::create_dir(missing).unwrap();
        let unreadable = Journal::load(missing.into());
        let notice = unreadable.recovery_notice().unwrap();
        assert!(notice.contains("cannot read"), "{notice}");
    }
}
