use super::*;
use nix::libc;
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

const JOURNAL: &str = "journal.json";

struct Directory(File);
impl Directory {
    fn open(path: &Path, create: bool) -> io::Result<Self> {
        if create {
            // Caller prepares the durable state parent. Only this final directory
            // is created; broad/shared ancestors are never chmod'ed.
            match std::fs::DirBuilder::new().mode(0o700).create(path) {
                Ok(()) => {
                    File::open(
                        path.parent()
                            .ok_or_else(|| io::Error::other("missing parent"))?,
                    )?
                    .sync_all()?;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let meta = file.metadata()?;
        if meta.uid() != nix::unistd::geteuid().as_raw() || meta.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "recovery directory must be owned by this user and private",
            ));
        }
        Ok(Self(file))
    }
    fn open_file(&self, name: &str, flags: i32) -> io::Result<File> {
        let name = CString::new(name).map_err(io::Error::other)?;
        // SAFETY: `self.0` is the open directory this `Directory` owns, so its
        // descriptor is valid for the call, and `name` is a CString that
        // outlives it. The mode goes through openat's variadic argument as a
        // C int, the type mode_t is promoted to.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is the descriptor openat just returned, checked
        // non-negative above and owned by nothing else, so `file` takes sole
        // ownership and closes it once.
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != nix::unistd::geteuid().as_raw()
            || meta.mode() & 0o077 != 0
            || meta.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe recovery file identity or permissions",
            ));
        }
        Ok(file)
    }
    fn read(&self, name: &str) -> io::Result<Vec<u8>> {
        let mut out = vec![];
        self.open_file(name, libc::O_RDONLY | libc::O_NONBLOCK)?
            .take(MAX_JOURNAL_BYTES + 1)
            .read_to_end(&mut out)?;
        if out.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(io::Error::other("recovery file exceeds size limit"));
        }
        Ok(out)
    }
    fn load(&self) -> io::Result<Option<Snapshot>> {
        match self.read(JOURNAL) {
            Ok(bytes) => Snapshot::decode(&bytes).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn replace(&self, from: &str) -> io::Result<()> {
        let from = CString::new(from).map_err(io::Error::other)?;
        let to = CString::new(JOURNAL).unwrap();
        // SAFETY: both directory descriptors are `self.0`, open for as long as
        // `self` lives, and `from` and `to` are CStrings that outlive the call.
        if unsafe {
            libc::renameat(
                self.0.as_raw_fd(),
                from.as_ptr(),
                self.0.as_raw_fd(),
                to.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Holds an exclusive OS lock from load through every update. Drop/crash releases
/// the lock; the lock file is never unlinked. Not a host-wide resolver lease.
pub struct Store {
    directory: Directory,
    _lock: File,
    snapshot: Snapshot,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<Stage>,
}
impl Drop for Store {
    fn drop(&mut self) {
        // A concurrent fork can temporarily inherit the open-file description
        // until exec closes O_CLOEXEC descriptors. Explicit unlock prevents that
        // unrelated child from extending this owner's lease after Store drops.
        let _ = self._lock.unlock();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    BackupPartial,
    BackupWritten,
    BackupSynced,
    JournalPartial,
    JournalWritten,
    JournalSynced,
    Renamed,
    DirectorySynced,
}
impl Store {
    pub fn open(directory: &Path) -> io::Result<Self> {
        let directory = Directory::open(directory, true)?;
        let lock = directory.open_file(
            "store.lock",
            libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
        )?;
        lock.try_lock().map_err(io::Error::other)?;
        directory.0.sync_all()?;
        let loaded = directory.load()?;
        let initialize = loaded.is_none();
        let snapshot = loaded.unwrap_or_default();
        let mut store = Self {
            directory,
            _lock: lock,
            snapshot,
            poisoned: false,
            #[cfg(test)]
            fault: None,
        };
        if initialize {
            store.persist(Snapshot::default())?;
        }
        Ok(store)
    }
    // Only the Linux resolver's own tests call this (via
    // `resolver::linux`, itself `target_os = "linux"`-gated); on any other
    // unix `cfg(test)` alone leaves it unused and fails `-D warnings`
    // clippy in CI (found on macOS after v0.31.1 — the release build
    // itself never compiles the test profile, so it slipped past that).
    // `unix.rs`'s own tests set `store.fault` directly (see below) and stay
    // covered on every platform regardless of this method's cfg.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn fail_next_update_after_rename(&mut self) {
        self.fault = Some(Stage::Renamed);
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    fn writable(&self) -> io::Result<()> {
        if self.poisoned {
            Err(io::Error::other(
                "recovery store persistence is uncertain; reopen and inspect before further writes",
            ))
        } else {
            Ok(())
        }
    }
    fn checkpoint(&self, stage: Stage) -> io::Result<()> {
        #[cfg(test)]
        {
            if self.fault == Some(stage) {
                return Err(io::Error::other("injected persistence failure"));
            }
            if std::env::var("NETWATCH_STORE_CRASH_STAGE").ok().as_deref()
                == Some(&format!("{stage:?}"))
            {
                println!("STORE_CRASH_READY");
                io::stdout().flush()?;
                loop {
                    std::thread::park();
                }
            }
        }
        let _ = stage;
        Ok(())
    }
    fn persist(&mut self, snapshot: Snapshot) -> io::Result<()> {
        let result = (|| {
            let bytes = serde_json::to_vec_pretty(&snapshot).map_err(io::Error::other)?;
            if bytes.len() as u64 > MAX_JOURNAL_BYTES {
                return Err(io::Error::other("recovery journal exceeds size limit"));
            }
            let temp = format!("{}.tmp", Uuid::new_v4());
            let mut file = self
                .directory
                .open_file(&temp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
            let split = bytes.len().min(7);
            file.write_all(&bytes[..split])?;
            self.checkpoint(Stage::JournalPartial)?;
            file.write_all(&bytes[split..])?;
            self.checkpoint(Stage::JournalWritten)?;
            file.sync_all()?;
            self.checkpoint(Stage::JournalSynced)?;
            self.directory.replace(&temp)?;
            self.checkpoint(Stage::Renamed)?;
            self.directory.0.sync_all()?;
            self.checkpoint(Stage::DirectorySynced)?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        } else {
            self.snapshot = snapshot;
        }
        result
    }
    /// Sync an immutable original backup before making Prepared discoverable.
    /// This grants no permission to mutate the resource identified by metadata.
    pub fn prepare(
        &mut self,
        issue_id: String,
        owner: Owner,
        resource: Resource,
        original: &[u8],
        installed: &[u8],
    ) -> io::Result<Uuid> {
        self.writable()?;
        if !resource.target.is_absolute() || original.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(io::Error::other("invalid resource or oversized backup"));
        }
        if self.snapshot.operations.iter().any(|o| {
            o.state.unresolved()
                && (o.resource.target == resource.target
                    || (o.resource.device, o.resource.inode) == (resource.device, resource.inode))
        }) {
            return Err(io::Error::other("resource already has unresolved recovery"));
        }
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().to_rfc3339();
        let operation = Operation {
            id,
            issue_id,
            owner,
            resource,
            original_sha256: digest(original),
            installed_sha256: digest(installed),
            state: State::Prepared,
            created_at: now.clone(),
            updated_at: now,
            detail: None,
        };
        let result = (|| {
            let mut backup = self.directory.open_file(
                &operation.backup_name(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )?;
            let split = original.len().min(7);
            backup.write_all(&original[..split])?;
            self.checkpoint(Stage::BackupPartial)?;
            backup.write_all(&original[split..])?;
            self.checkpoint(Stage::BackupWritten)?;
            backup.sync_all()?;
            self.directory.0.sync_all()?;
            self.checkpoint(Stage::BackupSynced)?;
            let mut snapshot = self.snapshot.clone();
            snapshot.revision = snapshot
                .revision
                .checked_add(1)
                .ok_or_else(|| io::Error::other("revision overflow"))?;
            snapshot.operations.push(operation);
            self.persist(snapshot)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result.map(|()| id)
    }
    pub fn transition(
        &mut self,
        id: Uuid,
        owner: &Owner,
        state: State,
        detail: Option<String>,
    ) -> io::Result<()> {
        self.writable()?;
        let mut snapshot = self.snapshot.clone();
        let operation = snapshot
            .operations
            .iter_mut()
            .find(|o| o.id == id)
            .ok_or_else(|| io::Error::other("unknown operation"))?;
        if &operation.owner != owner {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "operation belongs to another session",
            ));
        }
        let valid = matches!(
            (operation.state, state),
            (
                State::Prepared,
                State::Applied | State::RecoveryRequired | State::Reverted
            ) | (
                State::Applied,
                State::RecoveryRequired | State::Reverted | State::Committed
            ) | (State::RecoveryRequired, State::Reverted)
        );
        if !valid {
            return Err(io::Error::other("invalid recovery state transition"));
        }
        operation.state = state;
        operation.updated_at = chrono::Utc::now().to_rfc3339();
        operation.detail = detail;
        snapshot.revision = snapshot
            .revision
            .checked_add(1)
            .ok_or_else(|| io::Error::other("revision overflow"))?;
        self.persist(snapshot)
    }
    /// Read immutable backup bytes and verify their digest. Never follows target
    /// paths or arbitrary backup paths from recovery metadata.
    pub fn original(&self, id: Uuid) -> io::Result<Vec<u8>> {
        let operation = self
            .snapshot
            .operations
            .iter()
            .find(|o| o.id == id)
            .ok_or_else(|| io::Error::other("unknown operation"))?;
        let bytes = self.directory.read(&operation.backup_name())?;
        if digest(&bytes) != operation.original_sha256 {
            return Err(io::Error::other("backup digest mismatch; recovery blocked"));
        }
        Ok(bytes)
    }
}
pub(super) fn inspect(path: &Path) -> io::Result<Option<Snapshot>> {
    let directory = match Directory::open(path, false) {
        Ok(directory) => directory,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    // An absent journal in an existing directory may be an interrupted prepare;
    // preserve orphan evidence rather than treating the store as empty.
    let bytes = directory.read(JOURNAL)?;
    Snapshot::decode(&bytes).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        process::{Command, Stdio},
        sync::mpsc,
        time::Duration,
    };

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("netwatch-recovery-{}", Uuid::new_v4()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
        fn store(&self) -> PathBuf {
            self.0.join("recovery")
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn resource(n: u64) -> Resource {
        Resource {
            adapter: Adapter::UnmanagedFile,
            target: PathBuf::from(format!("/synthetic/resolver-{n}")),
            device: 1,
            inode: n,
        }
    }
    fn prepare(store: &mut Store, n: u64) -> Uuid {
        store
            .prepare(
                "issue".into(),
                Owner::current(),
                resource(n),
                b"original\0bytes",
                b"installed",
            )
            .unwrap()
    }

    #[test]
    fn dropping_owner_releases_lease_even_with_an_inherited_descriptor() {
        let temp = Temp::new();
        let store = Store::open(&temp.store()).unwrap();
        let inherited = store._lock.try_clone().unwrap();
        drop(store);
        let next_owner = Store::open(&temp.store()).unwrap();
        drop(inherited);
        assert!(Store::open(&temp.store()).is_err());
        drop(next_owner);
        assert!(Store::open(&temp.store()).is_ok());
    }

    #[test]
    fn roundtrip_backups_transitions_and_session_ownership() {
        let temp = Temp::new();
        let mut store = Store::open(&temp.store()).unwrap();
        let id = prepare(&mut store, 1);
        let owner = store.snapshot().operations[0].owner.clone();
        assert_eq!(store.original(id).unwrap(), b"original\0bytes");
        assert!(store
            .transition(id, &Owner::current(), State::Applied, None)
            .is_err());
        assert!(store
            .transition(id, &owner, State::Committed, None)
            .is_err());
        store.transition(id, &owner, State::Applied, None).unwrap();
        store
            .transition(id, &owner, State::Committed, None)
            .unwrap();
        assert!(store.transition(id, &owner, State::Reverted, None).is_err());
        let second = prepare(&mut store, 1);
        assert_ne!(id, second);
        assert!(store
            .prepare("other".into(), Owner::current(), resource(1), b"x", b"y")
            .is_err());
        let expected = store.snapshot().clone();
        drop(store);
        let reopened = Store::open(&temp.store()).unwrap();
        assert_eq!(reopened.snapshot(), &expected);
        assert_eq!(reopened.original(id).unwrap(), b"original\0bytes");
        assert_eq!(inspect(&temp.store()).unwrap(), Some(expected));
    }

    #[test]
    fn persistence_failures_keep_old_or_new_snapshot_and_poison_writer() {
        for stage in [
            Stage::BackupPartial,
            Stage::BackupWritten,
            Stage::BackupSynced,
            Stage::JournalPartial,
            Stage::JournalWritten,
            Stage::JournalSynced,
            Stage::Renamed,
            Stage::DirectorySynced,
        ] {
            let temp = Temp::new();
            let mut store = Store::open(&temp.store()).unwrap();
            prepare(&mut store, 1);
            store.fault = Some(stage);
            assert!(store
                .prepare(
                    "next".into(),
                    Owner::current(),
                    resource(2),
                    b"second",
                    b"replacement"
                )
                .is_err());
            assert!(store.is_poisoned());
            assert!(store
                .prepare("blocked".into(), Owner::current(), resource(3), b"a", b"b")
                .is_err());
            drop(store);
            let reopened = Store::open(&temp.store()).unwrap();
            let expected = if matches!(stage, Stage::Renamed | Stage::DirectorySynced) {
                2
            } else {
                1
            };
            assert_eq!(reopened.snapshot().operations.len(), expected, "{stage:?}");
            for operation in &reopened.snapshot().operations {
                reopened.original(operation.id).unwrap();
            }
        }
    }

    #[test]
    fn corruption_unknown_versions_and_backup_tampering_are_preserved() {
        let temp = Temp::new();
        let mut store = Store::open(&temp.store()).unwrap();
        let id = prepare(&mut store, 1);
        let journal = temp.store().join(JOURNAL);
        let good = std::fs::read(&journal).unwrap();
        let backup = temp
            .store()
            .join(store.snapshot().operations[0].backup_name());
        std::fs::write(&backup, b"tampered").unwrap();
        assert!(store.original(id).is_err());
        drop(store);
        for bytes in [
            b"{truncated".to_vec(),
            String::from_utf8(good)
                .unwrap()
                .replace("\"version\": 2", "\"version\": 99")
                .into_bytes(),
        ] {
            std::fs::write(&journal, &bytes).unwrap();
            assert!(Store::open(&temp.store()).is_err());
            assert!(inspect(&temp.store()).is_err());
            assert_eq!(std::fs::read(&journal).unwrap(), bytes);
        }
    }

    #[test]
    fn symlinks_hardlinks_and_replaced_directory_do_not_redirect_writes() {
        use std::os::unix::fs::symlink;
        let temp = Temp::new();
        let mut store = Store::open(&temp.store()).unwrap();
        let id = prepare(&mut store, 1);
        let operation = store.snapshot().operations[0].clone();
        let moved = temp.0.join("pinned");
        std::fs::rename(temp.store(), &moved).unwrap();
        let other = temp.0.join("other");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&other)
            .unwrap();
        symlink(&other, temp.store()).unwrap();
        assert!(Store::open(&temp.store()).is_err());
        store
            .transition(id, &operation.owner, State::Applied, None)
            .unwrap();
        assert!(!other.join(JOURNAL).exists());
        assert!(moved.join(JOURNAL).exists());
        let backup = moved.join(operation.backup_name());
        let original = moved.join("original");
        std::fs::rename(&backup, &original).unwrap();
        symlink(&original, &backup).unwrap();
        assert!(store.original(id).is_err());
        std::fs::remove_file(&backup).unwrap();
        std::fs::hard_link(&original, &backup).unwrap();
        assert!(store.original(id).is_err());
    }

    fn child_command(path: &Path) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "diagnose::remediation::store::unix::tests::crash_child",
                "--nocapture",
            ])
            .env("NETWATCH_STORE_CHILD_PATH", path);
        command
    }
    #[test]
    fn crash_child() {
        let Some(path) = std::env::var_os("NETWATCH_STORE_CHILD_PATH") else {
            return;
        };
        if std::env::var_os("NETWATCH_STORE_TRY_LOCK").is_some() {
            assert!(Store::open(Path::new(&path)).is_err());
            return;
        }
        let mut store = Store::open(Path::new(&path)).unwrap();
        prepare(&mut store, 2);
        panic!("expected parent to kill this process at a checkpoint");
    }
    #[test]
    fn another_process_cannot_open_a_locked_store() {
        let temp = Temp::new();
        let store = Store::open(&temp.store()).unwrap();
        let output = child_command(&temp.store())
            .env("NETWATCH_STORE_TRY_LOCK", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        drop(store);
        assert!(Store::open(&temp.store()).is_ok());
    }
    #[test]
    fn process_kill_at_each_boundary_releases_lock_and_preserves_evidence() {
        for stage in [
            Stage::BackupPartial,
            Stage::BackupWritten,
            Stage::BackupSynced,
            Stage::JournalPartial,
            Stage::JournalWritten,
            Stage::JournalSynced,
            Stage::Renamed,
            Stage::DirectorySynced,
        ] {
            let temp = Temp::new();
            let mut store = Store::open(&temp.store()).unwrap();
            prepare(&mut store, 1);
            drop(store);
            let mut child = child_command(&temp.store())
                .env("NETWATCH_STORE_CRASH_STAGE", format!("{stage:?}"))
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let stdout = child.stdout.take().unwrap();
            let (tx, rx) = mpsc::channel();
            let reader = std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    if line.contains("STORE_CRASH_READY") {
                        let _ = tx.send(());
                        break;
                    }
                }
            });
            let ready = rx.recv_timeout(Duration::from_secs(15));
            child.kill().unwrap();
            child.wait().unwrap();
            reader.join().unwrap();
            ready.expect("child failed to reach crash checkpoint");
            let reopened = Store::open(&temp.store()).unwrap();
            let expected = if matches!(stage, Stage::Renamed | Stage::DirectorySynced) {
                2
            } else {
                1
            };
            assert_eq!(reopened.snapshot().operations.len(), expected, "{stage:?}");
            for operation in &reopened.snapshot().operations {
                reopened.original(operation.id).unwrap();
            }
        }
    }
}
