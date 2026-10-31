use super::*;
use crate::diagnose::remediation::{
    resolv_conf_with,
    store::{self, Adapter, Operation, Owner, Resource, State, Store},
    Journal, RecoveryAuthority,
};
use nix::libc;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;
const TARGET: &str = "/etc/resolv.conf";
const STATE_PARENT: &str = "/var/lib/netwatch";
const STATE_DIR: &str = "/var/lib/netwatch/resolver-v2";
const LIMIT: u64 = 64 * 1024;

fn read_bounded(file: &mut File) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = vec![];
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(io::Error::other("resolver file exceeds 64 KiB"));
    }
    Ok(bytes)
}
fn file(path: &Path, write: bool, uid: u32) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::other("resolver must be a regular, single-link file owned by the authority and not writable by others"));
    }
    Ok(file)
}
fn classify_path(path: &Path, uid: u32) -> io::Result<Ownership> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        let link = std::fs::read_link(path)?;
        return Ok(classify(Some(&link.to_string_lossy()), ""));
    }
    let mut target = file(path, false, uid)?;
    let bytes = read_bounded(&mut target)?;
    let contents = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
    Ok(classify(None, contents))
}
pub(super) fn ownership() -> io::Result<Ownership> {
    let classified = classify_path(Path::new(TARGET), 0)?;
    if classified != Ownership::UnconfirmedRegular {
        return Ok(classified);
    }
    // Presence is conservative; absence does not establish ownership. The
    // administrator's --unmanaged assertion remains required for a plain file.
    if Path::new("/run/NetworkManager").exists() {
        return Ok(Ownership::NetworkManager);
    }
    if Path::new("/run/systemd/resolve").exists() {
        return Ok(Ownership::SystemdResolved);
    }
    Ok(classified)
}

fn trusted_directory(path: &Path, uid: u32) -> io::Result<()> {
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != uid
            || metadata.mode() & 0o022 != 0
        {
            return Err(io::Error::other(format!(
                "untrusted authority directory {}",
                ancestor.display()
            )));
        }
    }
    Ok(())
}
fn live_store() -> io::Result<Store> {
    if nix::unistd::geteuid().as_raw() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "resolver command requires explicit root authority",
        ));
    }
    trusted_directory(Path::new("/var/lib"), 0)?;
    match std::fs::DirBuilder::new().mode(0o700).create(STATE_PARENT) {
        Ok(()) => File::open("/var/lib")?.sync_all()?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    trusted_directory(Path::new(STATE_PARENT), 0)?;
    Store::open(Path::new(STATE_DIR))
}

#[derive(Debug, PartialEq, Eq)]
enum OwnerStatus {
    Alive,
    Gone,
    Unknown,
}
fn owner_status(owner: &Owner, uid: u32) -> OwnerStatus {
    let current = Owner::current();
    let (Some(old_boot), Some(boot), Some(start)) =
        (&owner.boot_id, current.boot_id, &owner.process_start)
    else {
        return OwnerStatus::Unknown;
    };
    if owner.uid != Some(uid)
        || owner.pid == 0
        || Uuid::parse_str(old_boot).is_err()
        || start.parse::<u64>().is_err()
    {
        return OwnerStatus::Unknown;
    }
    if old_boot != &boot {
        return OwnerStatus::Gone;
    }
    if owner.pid_namespace.is_none() || owner.pid_namespace != current.pid_namespace {
        return OwnerStatus::Unknown;
    }
    match std::fs::read_to_string(format!("/proc/{}/stat", owner.pid)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => OwnerStatus::Gone,
        Err(_) => OwnerStatus::Unknown,
        Ok(stat) => match stat
            .rsplit_once(") ")
            .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        {
            Some(actual) if actual == start => OwnerStatus::Alive,
            Some(_) => OwnerStatus::Gone,
            None => OwnerStatus::Unknown,
        },
    }
}
fn hash(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A fixed authority path plus the root-owned store's lifetime lock form the
/// resolver lease. Fixture paths exist only in private tests, never CLI input.
struct Session {
    store: Store,
    path: PathBuf,
    uid: u32,
    owner: Owner,
    active: Option<Uuid>,
    live: bool,
    #[cfg(test)]
    fail_target_write: bool,
    #[cfg(test)]
    fail_completion: bool,
}
impl Session {
    fn live() -> io::Result<Self> {
        let classified = ownership()?;
        if classified != Ownership::UnconfirmedRegular {
            return Err(io::Error::other(classified.description()));
        }
        trusted_directory(Path::new("/etc"), 0)?;
        let store = live_store()?;
        Ok(Self {
            store,
            path: TARGET.into(),
            uid: 0,
            owner: Owner::current(),
            active: None,
            live: true,
            #[cfg(test)]
            fail_target_write: false,
            #[cfg(test)]
            fail_completion: false,
        })
    }
    fn target(&self) -> io::Result<(File, Resource, Vec<u8>)> {
        if self.live && ownership()? != Ownership::UnconfirmedRegular {
            return Err(io::Error::other(
                "resolver manager now owns the target; write refused",
            ));
        }
        let classified = classify_path(&self.path, self.uid)?;
        if classified != Ownership::UnconfirmedRegular {
            return Err(io::Error::other(classified.description()));
        }
        let mut file = file(&self.path, true, self.uid)?;
        let metadata = file.metadata()?;
        let bytes = read_bounded(&mut file)?;
        // Reclassify the descriptor's bytes too, closing the inspection/open gap.
        if classify(None, std::str::from_utf8(&bytes).map_err(io::Error::other)?)
            != Ownership::UnconfirmedRegular
        {
            return Err(io::Error::other("resolver ownership changed"));
        }
        let resource = Resource {
            adapter: Adapter::UnmanagedFile,
            target: self.path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        Ok((file, resource, bytes))
    }
    fn verify(&self, file: &mut File, resource: &Resource, expected: &[u8]) -> io::Result<()> {
        let metadata = std::fs::symlink_metadata(&self.path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != self.uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
            || (metadata.dev(), metadata.ino()) != (resource.device, resource.inode)
            || read_bounded(file)? != expected
        {
            return Err(io::Error::other(
                "resolver identity or contents changed; automatic write refused",
            ));
        }
        Ok(())
    }
    fn write(
        &self,
        file: &mut File,
        resource: &Resource,
        before: &[u8],
        after: &[u8],
    ) -> io::Result<()> {
        self.verify(file, resource, before)?;
        file.seek(SeekFrom::Start(0))?;
        #[cfg(test)]
        if self.fail_target_write {
            file.write_all(&after[..after.len().min(7)])?;
            file.set_len(after.len().min(7) as u64)?;
            file.sync_all()?;
            return Err(io::Error::other("injected partial target write"));
        }
        file.write_all(after)?;
        file.set_len(after.len() as u64)?;
        file.sync_all()?;
        self.verify(file, resource, after)
    }
    fn apply(&mut self, address: IpAddr) -> io::Result<Uuid> {
        if self
            .store
            .snapshot()
            .operations
            .iter()
            .any(|o| o.state.unresolved())
        {
            return Err(io::Error::other(
                "unresolved resolver operation; run resolver recover --unmanaged first",
            ));
        }
        let (mut target, resource, before) = self.target()?;
        let after = resolv_conf_with(
            std::str::from_utf8(&before).map_err(io::Error::other)?,
            &address.to_string(),
        )
        .into_bytes();
        let id = self.store.prepare(
            "resolver-command".into(),
            self.owner.clone(),
            resource.clone(),
            &before,
            &after,
        )?;
        self.active = Some(id);
        checkpoint("Prepared");
        if let Err(error) = self.write(&mut target, &resource, &before, &after) {
            let detail = format!("target write/readback failed: {error}");
            let recording = self.store.transition(
                id,
                &self.owner,
                State::RecoveryRequired,
                Some(detail.clone()),
            );
            return Err(io::Error::other(format!(
                "recovery required for {id}: {detail}; recording: {recording:?}"
            )));
        }
        checkpoint("TargetSynced");
        #[cfg(test)]
        if self.fail_completion {
            self.store.fail_next_update_after_rename();
        }
        if let Err(error) = self.store.transition(id, &self.owner, State::Applied, None) {
            return Err(io::Error::other(format!("recovery required for {id}: resolver changed but completion could not be recorded: {error}")));
        }
        checkpoint("Applied");
        Ok(id)
    }
    fn revert(&mut self, operation: &Operation) -> io::Result<()> {
        if self.store.is_poisoned() {
            return Err(io::Error::other(
                "journal durability is uncertain; reopen and inspect before recovery",
            ));
        }
        if operation.resource.target != self.path
            || operation.resource.adapter != Adapter::UnmanagedFile
        {
            return Err(io::Error::other(
                "operation targets another resource; preserved",
            ));
        }
        let (mut target, resource, current) = self.target()?;
        if resource != operation.resource {
            return Err(io::Error::other(
                "resolver file identity changed; recovery refused",
            ));
        }
        let original = self.store.original(operation.id)?;
        let current_hash = hash(&current);
        if current_hash == operation.original_sha256 {
            // Prepared may never have reached a target write; an external restore
            // to the verified original also needs no target mutation.
        } else if current_hash == operation.installed_sha256 {
            if let Err(error) = self.write(&mut target, &resource, &current, &original) {
                return Err(io::Error::other(format!(
                    "recovery required for {}: rollback write failed: {error}",
                    operation.id
                )));
            }
        } else {
            return Err(io::Error::other(
                "resolver changed externally or partially; preserve evidence for manual recovery",
            ));
        }
        checkpoint("Restored");
        self.store
            .transition(operation.id, &operation.owner, State::Reverted, None)
            .map_err(|e| {
                io::Error::other(format!(
                    "resolver restored but completion recording failed for {}: {e}",
                    operation.id
                ))
            })?;
        self.active = None;
        Ok(())
    }
    fn finish(&mut self) -> io::Result<()> {
        if let Some(id) = self.active {
            let operation = self
                .store
                .snapshot()
                .operations
                .iter()
                .find(|o| o.id == id)
                .cloned()
                .ok_or_else(|| io::Error::other("active operation not recorded"))?;
            self.revert(&operation)?;
        }
        Ok(())
    }
    fn recover(&mut self) -> io::Result<usize> {
        let operations: Vec<_> = self
            .store
            .snapshot()
            .operations
            .iter()
            .filter(|o| o.state.unresolved())
            .cloned()
            .collect();
        let mut recovered = 0;
        for operation in operations {
            if owner_status(&operation.owner, self.uid) != OwnerStatus::Gone {
                return Err(io::Error::other(format!(
                    "owner of {} is alive or unverifiable; recovery refused",
                    operation.id
                )));
            }
            self.revert(&operation)?;
            recovered += 1;
        }
        Ok(recovered)
    }
}

fn checkpoint(stage: &str) {
    #[cfg(test)]
    if std::env::var("NETWATCH_RESOLVER_CRASH").ok().as_deref() == Some(stage) {
        println!("RESOLVER_CRASH_READY");
        io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }
    let _ = stage;
}

pub(super) fn authority_notice() -> Option<String> {
    authority_notice_at(Path::new(STATE_DIR), nix::unistd::geteuid().is_root())
}

fn authority_notice_at(directory: &Path, root: bool) -> Option<String> {
    match store::inspect(directory) {
        Ok(None) => None,
        Ok(Some(snapshot)) => {
            let ids: Vec<_> = snapshot.operations.iter().filter(|o| o.state.unresolved()).map(|o| o.id.to_string()).collect();
            (!ids.is_empty()).then(|| format!("resolver authority recovery required: {}; journal: {}/journal.json; review with sudo netwatch resolver status", ids.join(", "), directory.display()))
        }
        // `live_store` keeps this store private to root, so after one `set` or
        // `recover` the kernel refuses every other user, whatever the store holds.
        // That says nothing about recovery and they cannot act on it. Root reads
        // the real state, and `status` still tells them to ask root. Only the
        // kernel's refusal counts: the store's own ownership and privacy checks
        // also report PermissionDenied, and those are worth reporting.
        Err(error) if !root && error.raw_os_error() == Some(libc::EACCES) => None,
        Err(error) => Some(format!("resolver authority journal cannot be inspected: {error}; preserved at {}; review with sudo netwatch resolver status", directory.display())),
    }
}

/// Read the legacy journal for a command that may be running as root. Under a
/// `sudo` that keeps HOME this path is in someone else's home, so a symlink, a
/// FIFO, a device or another user's file gets an error instead of a read.
fn read_legacy_journal(path: &Path, uid: u32) -> io::Result<String> {
    let mut journal = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = journal.metadata()?;
    if !metadata.is_file() || metadata.uid() != uid || metadata.nlink() != 1 {
        return Err(io::Error::other(
            "not a regular, single-link file owned by this user",
        ));
    }
    String::from_utf8(read_bounded(&mut journal)?).map_err(io::Error::other)
}

/// What `status` and `recover` say about the legacy journal, which neither acts
/// on: an empty authority store does not mean the resolver is as it was. Printed
/// to a terminal, so nothing from the file reaches it unscrubbed.
fn legacy_notice(path: PathBuf, uid: u32) -> Option<String> {
    let read = read_legacy_journal(&path, uid);
    let mut journal = Journal::parse(path, read);
    journal.inspect_recovery(RecoveryAuthority::InspectOnly);
    let notice = journal.recovery_notice()?;
    Some(format!(
        "Not restored by resolver recover: {}",
        crate::ui::sanitize::display(notice)
    ))
}

pub(super) fn command(request: Request) -> anyhow::Result<()> {
    let reports_legacy = matches!(request, Request::Status | Request::Recover);
    let result = run(request);
    // After the result, where it gets read, and whether or not that succeeded.
    // It never changes the result: the journal is outside recovery authority, so
    // a file a user can write must not be able to fail a root command.
    if reports_legacy {
        let uid = nix::unistd::geteuid().as_raw();
        if let Some(notice) = legacy_notice(Journal::default_path(), uid) {
            report(&notice);
        }
    }
    result
}

fn run(request: Request) -> anyhow::Result<()> {
    match request {
        Request::Status => {
            report(ownership()?.description());
            match store::inspect(Path::new(STATE_DIR)) {
                Ok(Some(snapshot)) => report(&format!(
                    "{} unresolved operations in {STATE_DIR}",
                    snapshot
                        .operations
                        .iter()
                        .filter(|o| o.state.unresolved())
                        .count()
                )),
                Ok(None) => report("No resolver authority journal"),
                Err(error) => report(&format!(
                    "Authority journal unavailable: {error}; inspect with root authority"
                )),
            }
            Ok(())
        }
        Request::Recover => {
            let mut session = Session::live()?;
            report(&format!(
                "Recovered {} resolver operations",
                session.recover()?
            ));
            Ok(())
        }
        Request::Set { address, seconds } => {
            // Register shutdown handling before any target change. No packet
            // collectors, model/remote workers or privileged parser are started.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                use tokio::signal::unix::{signal, SignalKind};
                let mut interrupt = signal(SignalKind::interrupt())?;
                let mut terminate = signal(SignalKind::terminate())?;
                let mut session = Session::live()?;
                let id = session.apply(address)?;
                report(&format!("Temporary resolver file change to {address}; effective resolution unverified; operation {id}; reverting in {seconds}s or on Ctrl-C/SIGTERM"));
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(seconds)) => {},
                    _ = interrupt.recv() => {},
                    _ = terminate.recv() => {},
                }
                session.finish()?;
                report(&format!("Resolver restored; operation {id}"));
                Ok(())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        os::unix::fs::{symlink, PermissionsExt},
        process::{Command, Stdio},
        sync::mpsc,
        time::Duration,
    };
    const ORIGINAL: &[u8] =
        b"# owned by the test\nsearch example.test\nnameserver 192.0.2.1\noptions edns0\n";
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("netwatch-resolver-{}", Uuid::new_v4()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            std::fs::write(path.join("resolv.conf"), ORIGINAL).unwrap();
            std::fs::set_permissions(
                path.join("resolv.conf"),
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
            Self(path)
        }
        fn session(&self) -> io::Result<Session> {
            fixture_session(&self.0)
        }
        fn bytes(&self) -> Vec<u8> {
            std::fs::read(self.0.join("resolv.conf")).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn fixture_session(root: &Path) -> io::Result<Session> {
        Ok(Session {
            store: Store::open(&root.join("state"))?,
            path: root.join("resolv.conf"),
            uid: nix::unistd::geteuid().as_raw(),
            owner: Owner::current(),
            active: None,
            live: false,
            fail_target_write: false,
            #[cfg(test)]
            fail_completion: false,
        })
    }
    fn address() -> IpAddr {
        "192.0.2.53".parse().unwrap()
    }

    #[test]
    fn apply_and_restore_preserve_original_bytes_identity_and_permissions() {
        let fixture = Fixture::new();
        let before = std::fs::metadata(fixture.0.join("resolv.conf")).unwrap();
        let mut session = fixture.session().unwrap();
        let id = session.apply(address()).unwrap();
        assert!(String::from_utf8(fixture.bytes())
            .unwrap()
            .contains("nameserver 192.0.2.53"));
        assert!(
            fixture.session().is_err(),
            "lease must remain held throughout the temporary change"
        );
        assert_eq!(session.store.original(id).unwrap(), ORIGINAL);
        session.finish().unwrap();
        assert_eq!(fixture.bytes(), ORIGINAL);
        let after = std::fs::metadata(fixture.0.join("resolv.conf")).unwrap();
        assert_eq!(
            (before.dev(), before.ino(), before.mode()),
            (after.dev(), after.ino(), after.mode())
        );
        assert_eq!(
            session.store.snapshot().operations[0].state,
            State::Reverted
        );
    }
    #[test]
    fn completion_failure_preserves_changed_target_and_blocks_further_writes() {
        let fixture = Fixture::new();
        let mut session = fixture.session().unwrap();
        session.fail_completion = true;
        let error = session.apply(address()).unwrap_err();
        assert!(error
            .to_string()
            .contains("resolver changed but completion could not be recorded"));
        assert!(session.store.is_poisoned());
        let installed = fixture.bytes();
        assert_ne!(installed, ORIGINAL);
        assert!(session.finish().is_err());
        assert_eq!(fixture.bytes(), installed);
        drop(session);
        let snapshot = store::inspect(&fixture.0.join("state")).unwrap().unwrap();
        assert_eq!(snapshot.operations[0].state, State::Applied);
        let reopened = fixture.session().unwrap();
        assert_eq!(
            reopened.store.original(snapshot.operations[0].id).unwrap(),
            ORIGINAL
        );
    }

    #[test]
    fn managed_symlink_and_external_edits_are_never_overwritten() {
        let fixture = Fixture::new();
        let mut session = fixture.session().unwrap();
        std::fs::write(
            &session.path,
            b"# Generated by NetworkManager\nnameserver 192.0.2.1\n",
        )
        .unwrap();
        assert!(session.apply(address()).is_err());
        assert!(session.store.snapshot().operations.is_empty());
        std::fs::write(&session.path, ORIGINAL).unwrap();
        session.apply(address()).unwrap();
        std::fs::write(&session.path, b"external configuration").unwrap();
        assert!(session.finish().is_err());
        assert_eq!(fixture.bytes(), b"external configuration");
        let other = fixture.0.join("other");
        std::fs::write(&other, b"unrelated file").unwrap();
        std::fs::remove_file(&session.path).unwrap();
        symlink(&other, &session.path).unwrap();
        assert!(session.finish().is_err());
        assert_eq!(std::fs::read(other).unwrap(), b"unrelated file");
        assert!(session.store.snapshot().operations[0].state.unresolved());
    }
    #[test]
    fn replacement_inode_and_changed_backup_block_rollback() {
        let fixture = Fixture::new();
        let mut session = fixture.session().unwrap();
        session.apply(address()).unwrap();
        let installed = fixture.bytes();
        let replacement = fixture.0.join("replacement");
        std::fs::write(&replacement, &installed).unwrap();
        std::fs::rename(replacement, &session.path).unwrap();
        assert!(session.finish().is_err());
        assert_eq!(fixture.bytes(), installed);
        drop(session);
        let fixture = Fixture::new();
        let mut session = fixture.session().unwrap();
        session.apply(address()).unwrap();
        let installed = fixture.bytes();
        let name = session.store.snapshot().operations[0].backup_name();
        std::fs::write(fixture.0.join("state").join(name), b"tampered backup").unwrap();
        assert!(session.finish().is_err());
        assert_eq!(fixture.bytes(), installed);
    }
    #[test]
    fn partial_write_is_recovery_required_and_never_speculatively_reverted() {
        let fixture = Fixture::new();
        let mut session = fixture.session().unwrap();
        session.fail_target_write = true;
        let error = session.apply(address()).unwrap_err();
        assert!(error.to_string().contains("recovery required"));
        assert_eq!(
            session.store.snapshot().operations[0].state,
            State::RecoveryRequired
        );
        let partial = fixture.bytes();
        assert_ne!(partial, ORIGINAL);
        session.fail_target_write = false;
        assert!(session.finish().is_err());
        assert_eq!(fixture.bytes(), partial);
    }
    #[test]
    fn pid_reuse_missing_tokens_and_other_namespaces_are_distinguished() {
        let mut owner = Owner::current();
        let uid = nix::unistd::geteuid().as_raw();
        assert_eq!(owner_status(&owner, uid), OwnerStatus::Alive);
        owner.process_start = Some("0".into());
        assert_eq!(owner_status(&owner, uid), OwnerStatus::Gone);
        owner.process_start = None;
        assert_eq!(owner_status(&owner, uid), OwnerStatus::Unknown);
        owner = Owner::current();
        owner.pid_namespace = None;
        assert_eq!(owner_status(&owner, uid), OwnerStatus::Unknown);
    }
    /// What `netwatch resolver set` from 0.31.1, the first release with this
    /// store, left behind when SIGKILLed: its journal and backup, captured from
    /// that binary in a private root. Only the boot ID is edited, so the test
    /// never runs in the boot that wrote it. The target's identity and owner are
    /// set per run below, because they name a file and a user on that host.
    const V0_31_1_JOURNAL: &str = include_str!(
        "../../../../tests/fixtures/recovery/v0.31.1-killed-resolver-set/journal.json"
    );
    const V0_31_1_ID: &str = "bd204382-3ba1-46a0-a521-79de298b097e";
    const V0_31_1_ORIGINAL: &[u8] = include_bytes!(
        "../../../../tests/fixtures/recovery/v0.31.1-killed-resolver-set/bd204382-3ba1-46a0-a521-79de298b097e.backup"
    );
    const V0_31_1_INSTALLED: &[u8] = include_bytes!(
        "../../../../tests/fixtures/recovery/v0.31.1-killed-resolver-set/resolv.conf.installed"
    );

    /// A fixture root holding the 0.31.1 records in `state`, as an upgrade finds
    /// them, with the target holding `current` and the operation in `state_name`.
    fn upgraded_from_v0_31_1(state_name: &str, current: &[u8]) -> Fixture {
        let fixture = Fixture::new();
        let target = fixture.0.join("resolv.conf");
        std::fs::write(&target, current).unwrap();
        let metadata = std::fs::metadata(&target).unwrap();
        let mut journal: serde_json::Value = serde_json::from_str(V0_31_1_JOURNAL).unwrap();
        let operation = &mut journal["operations"][0];
        operation["state"] = state_name.into();
        operation["owner"]["uid"] = nix::unistd::geteuid().as_raw().into();
        operation["resource"]["target"] = target.to_str().unwrap().into();
        operation["resource"]["device"] = metadata.dev().into();
        operation["resource"]["inode"] = metadata.ino().into();
        let state = fixture.0.join("state");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .unwrap();
        for (name, bytes) in [
            ("journal.json".to_owned(), journal.to_string().into_bytes()),
            (format!("{V0_31_1_ID}.backup"), V0_31_1_ORIGINAL.to_vec()),
        ] {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(state.join(name))
                .unwrap();
            file.write_all(&bytes).unwrap();
        }
        fixture
    }

    #[test]
    fn records_from_v0_31_1_restore_the_resolver_after_an_upgrade() {
        for (state, current) in [
            ("applied", V0_31_1_INSTALLED),
            // Killed after the target write, before Applied was recorded.
            ("prepared", V0_31_1_INSTALLED),
            // Killed before the target write: nothing to put back.
            ("prepared", V0_31_1_ORIGINAL),
            ("recovery_required", V0_31_1_INSTALLED),
        ] {
            let fixture = upgraded_from_v0_31_1(state, current);
            let mut session = fixture.session().unwrap();
            assert_eq!(session.recover().unwrap(), 1, "{state}");
            assert_eq!(fixture.bytes(), V0_31_1_ORIGINAL, "{state}");
            let operation = &session.store.snapshot().operations[0];
            assert_eq!(operation.state, State::Reverted, "{state}");
            // Once recorded, a later `recover` has nothing left to do.
            assert_eq!(session.recover().unwrap(), 0, "{state}");
        }
    }

    #[test]
    fn a_v0_31_1_record_is_not_restored_over_a_later_edit() {
        let fixture = upgraded_from_v0_31_1("applied", b"nameserver 192.0.2.99\n");
        let mut session = fixture.session().unwrap();
        assert!(session.recover().is_err());
        assert_eq!(fixture.bytes(), b"nameserver 192.0.2.99\n");
        assert!(session.store.snapshot().operations[0].state.unresolved());
    }

    /// A store with one unresolved record, inside a directory of its own.
    fn store_with_a_record(parent: &Path) -> (PathBuf, Uuid) {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(parent)
            .unwrap();
        let directory = parent.join("resolver-v2");
        let mut store = Store::open(&directory).unwrap();
        let id = store
            .prepare(
                "resolver-command".into(),
                Owner::current(),
                Resource {
                    adapter: Adapter::UnmanagedFile,
                    target: "/synthetic/resolver".into(),
                    device: 1,
                    inode: 2,
                },
                b"original",
                b"installed",
            )
            .unwrap();
        (directory, id)
    }

    #[test]
    fn a_store_root_keeps_private_is_only_a_notice_for_root() {
        if nix::unistd::geteuid().is_root() {
            eprintln!("skipped: root passes the permission check this needs refused");
            return;
        }
        let fixture = Fixture::new();
        let parent = fixture.0.join("netwatch");
        let (directory, id) = store_with_a_record(&parent);
        // As `/var/lib/netwatch` is to anyone but root.
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o000)).unwrap();
        let other_user = authority_notice_at(&directory, false);
        let root_refused = authority_notice_at(&directory, true);
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(other_user, None);
        // A root session the kernel refuses (NFS root squash, say) still says so.
        assert!(root_refused.unwrap().contains("cannot be inspected"));
        // A session that can read it gets the record.
        let readable = authority_notice_at(&directory, false).unwrap();
        assert!(readable.contains("recovery required"), "{readable}");
        assert!(readable.contains(&id.to_string()), "{readable}");
    }

    #[test]
    fn a_store_a_session_can_open_but_not_trust_is_still_reported() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("netwatch");
        let (directory, _) = store_with_a_record(&parent);
        // The store's own privacy check says PermissionDenied too.
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exposed = authority_notice_at(&directory, false).unwrap();
        assert!(exposed.contains("cannot be inspected"), "{exposed}");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(directory.join("journal.json"), b"corrupt").unwrap();
        let corrupt = authority_notice_at(&directory, false).unwrap();
        assert!(corrupt.contains("cannot be inspected"), "{corrupt}");
    }

    #[test]
    fn the_legacy_journal_is_read_only_as_a_small_file_this_user_owns() {
        let fixture = Fixture::new();
        let uid = nix::unistd::geteuid().as_raw();
        let journal = fixture.0.join("applied.json");
        std::fs::write(&journal, "[]").unwrap();
        assert_eq!(read_legacy_journal(&journal, uid).unwrap(), "[]");
        assert!(read_legacy_journal(&journal, uid + 1).is_err());

        let link = fixture.0.join("link.json");
        symlink(&journal, &link).unwrap();
        assert!(read_legacy_journal(&link, uid).is_err());
        let second_name = fixture.0.join("second.json");
        std::fs::hard_link(&journal, &second_name).unwrap();
        assert!(read_legacy_journal(&journal, uid).is_err());
        std::fs::remove_file(second_name).unwrap();

        let large = fixture.0.join("large.json");
        std::fs::write(&large, vec![b' '; LIMIT as usize + 1]).unwrap();
        assert!(read_legacy_journal(&large, uid).is_err());

        // Would block forever if it were opened for an ordinary read.
        let fifo = fixture.0.join("fifo.json");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(read_legacy_journal(&fifo, uid).is_err());
        assert!(read_legacy_journal(Path::new("/dev/zero"), 0).is_err());
    }

    #[test]
    fn the_legacy_notice_is_scrubbed_and_absent_when_nothing_is_open() {
        let fixture = Fixture::new();
        let uid = nix::unistd::geteuid().as_raw();
        let journal = fixture.0.join("applied.json");
        assert_eq!(legacy_notice(journal.clone(), uid), None);
        std::fs::write(&journal, "[]").unwrap();
        assert_eq!(legacy_notice(journal.clone(), uid), None);
        std::fs::write(
            &journal,
            r#"[{"issue_id":"a\u001b[2Jb","target":"/etc/resolv.conf","backup":null,"state":"applied"}]"#,
        )
        .unwrap();
        let notice = legacy_notice(journal, uid).unwrap();
        assert!(!notice.contains('\u{1b}'), "{notice:?}");
        assert!(notice.contains("/etc/resolv.conf"), "{notice}");
    }

    #[test]
    fn resolver_crash_child() {
        let Some(root) = std::env::var_os("NETWATCH_RESOLVER_TEST_ROOT") else {
            return;
        };
        let mut session = fixture_session(Path::new(&root)).unwrap();
        session.apply(address()).unwrap();
        session.finish().unwrap();
        panic!("expected parent kill at transaction checkpoint");
    }
    #[test]
    fn crashed_transactions_are_recovered_only_under_the_resource_lease() {
        for stage in ["Prepared", "TargetSynced", "Applied", "Restored"] {
            let fixture = Fixture::new();
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "diagnose::remediation::resolver::linux::tests::resolver_crash_child",
                    "--nocapture",
                ])
                .env("NETWATCH_RESOLVER_TEST_ROOT", &fixture.0)
                .env("NETWATCH_RESOLVER_CRASH", stage)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let stdout = child.stdout.take().unwrap();
            let (tx, rx) = mpsc::channel();
            let reader = std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    if line.contains("RESOLVER_CRASH_READY") {
                        let _ = tx.send(());
                        break;
                    }
                }
            });
            let ready = rx.recv_timeout(Duration::from_secs(15));
            if ready.is_ok() {
                assert!(fixture.session().is_err());
            }
            child.kill().unwrap();
            child.wait().unwrap();
            reader.join().unwrap();
            ready.expect("child did not reach resolver transaction checkpoint");
            let mut recovery = fixture.session().unwrap();
            assert_eq!(recovery.recover().unwrap(), 1, "{stage}");
            assert_eq!(fixture.bytes(), ORIGINAL, "{stage}");
            assert_eq!(
                recovery.store.snapshot().operations[0].state,
                State::Reverted
            );
        }
    }
}
