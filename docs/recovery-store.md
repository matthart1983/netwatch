# Recovery store v2

The durable store is separate from resolver execution. Live TUI and daemon startup
inspect it and preserve legacy cache journals. Automatic TUI/daemon apply and rollback remain disabled. The explicit
[Linux resolver command](resolver-adapter.md) uses a separate root-owned authority
store, target validation and a lease covering its fixed host resource. Running as root does not authorize
journal-supplied paths.

## Location and compatibility

The v2 directory is `netwatch/recovery-v2` under `dirs::state_dir()`, falling back
to local application data. On Linux this normally means
`~/.local/state/netwatch/recovery-v2`. It contains `journal.json`, `store.lock`,
UUID-named `.backup` files, and possibly temporary/orphan evidence after failures.
The [legacy cache](#legacy-journal) `netwatch/applied.json` remains in place, inspection-only. Neither
format is silently migrated or overwritten by application startup/shutdown.

Ordinary observation does not create the v2 directory. The Unix `Store` API creates
its final private directory when explicitly opened for a transaction; its parent
must already exist. An existing directory without a readable journal is reported
by inspection, rather than silently treated as no recovery data. Only the Linux
resolver command opens a store, at its own fixed location, so no release has written
this per-user directory. Startup inspects it anyway, and `netwatch resolver recover`
does not read it.

The persistence backend is implemented for Unix and tested on Linux. Windows
writes are unavailable; an existing v2 directory reports an unsupported-backend
warning and remains untouched. A Windows backend must validate reparse points and
provide its own replacement/synchronization contract before writes are enabled.
No generic Unix rename sequence is claimed to work on Windows.

## Records and write protocol

Version 2 records contain operation/session UUIDs, process ID, UID where available,
Linux boot/process-start/PID-namespace tokens where readable, adapter/resource identity,
original and installed SHA-256 digests, timestamps and operation state. Missing
process tokens mean unknown ownership. Equality of recorded owner fields is a
consistency check, not authorization to restore a target from an untrusted journal.

1. Open the private, owned directory with no symlink following and pin its file
   descriptor. Open the permanent lock file and acquire a nonblocking OS lock.
2. Load and validate the journal while holding the lock. Unknown versions,
   corruption and unsafe files stop updates without replacing their contents.
3. Create a new UUID backup with exclusive creation. Write original bytes, sync
   the backup, then sync the directory before recording `Prepared`.
4. Write the next snapshot to a unique same-directory temporary file, sync it,
   atomically rename it over `journal.json`, then sync the directory.
5. Only return success after synchronization completes. A persistence error
   poisons that store instance: callers must reopen and inspect before more writes.

The adapter may mutate a resolver only after a successful preparation, and must
record the resulting state through the same durable replacement path. This store
itself never opens the target in a record. Backups are immutable through the API;
reads derive their basename from the UUID and verify the original digest. Tampered
or missing bytes block recovery. Failed temporary files and orphan backups are
preserved; automatic cleanup is intentionally not implemented.

States are `Prepared`, `Applied`, `RecoveryRequired`, `Reverted`, and `Committed`.
Terminal states cannot transition again. A second unresolved operation for the same
path or file identity is rejected. Permanent operations retain their original
backup; a later operation receives a different UUID backup. No command writes
`Committed` today; the format keeps it.

## Legacy journal

Netwatch 0.30.0 to 0.30.4 recorded live resolver changes in `netwatch/applied.json`,
in the cache directory of whichever home the session used. For a change that reached
`/etc/resolv.conf` that means a root session, and under `sudo` usually root's home.
0.31.0 was the last release to roll an entry back. Netwatch now only reads this
file: it has no writer and no rollback.

An entry still marked pending or applied puts `recovery required` on the Diagnose
status line and in the report's timeline, and in the log at startup and shutdown.
`netwatch resolver status` and `recover` print the same notice on Linux, naming the
file and the backup. Nothing restores the entry. The journal cannot authorize a
write: nothing proves who wrote it, and every confined thread but capture can write
the cache. So `recover` can print `Recovered 0 resolver operations` and exit 0 with
`/etc/resolv.conf` still holding netwatch's change. The notice is what says so.

To deal with an entry by hand:

1. Compare `/etc/resolv.conf` with the backup the notice names,
   `/etc/resolv.conf.netwatch-<pid>.bak`. A pending entry with no backup file is a
   write the sandbox refused, and nothing changed.
2. If the file still holds netwatch's change, copy the backup over it as root.
3. Remove the backup and `applied.json`. The notice goes with the next start.

A session in another home does not see the journal, so a leftover backup is the
other way to find one: `ls /etc/resolv.conf.netwatch-*.bak`. Check for one too when
the notice says the journal is invalid or cannot be read, since then it cannot name
a backup.

A confined thread can write the cache, and under a `sudo` that keeps HOME the journal
is in someone else's home. So every session and command reads it only as a regular,
single-link file the current user owns, up to 64 KiB, without following a symlink, and
only prints from it, with control characters replaced on the command line. Anything else
gets `cannot read journal` in place of the entry.

## Lock and trust scope

The OS lock spans a store instance's load and updates and is released on drop or
process death. A lock-file's existence is not treated as a live owner. Readers can
inspect an atomically published snapshot while a writer is active; they see an
old or new complete record, never a partially written replacement.

This is a **per-store lock**, not a host-wide resolver lease. Separate users or
store directories are not mutually excluded. The Linux resolver command fixes its
store location under root-owned system state and retains the lock through each
temporary change; per-user stores never authorize a host-wide resolver edit. Same-user malicious replacement of the store/lock namespace is outside this
cooperating-writer contract. Descriptor-relative operations cannot be redirected
by replacing the opened directory pathname, but a privileged helper must not
trust a user-editable store as its authority.

## Validation and limits

Linux tests kill child processes at partial/full backup writes, backup sync,
partial/full journal writes, journal sync, rename, and directory sync. Reopening
must release the dead writer's lock and yield the old or new complete snapshot;
every referenced backup must pass digest verification. Additional tests cover
competing processes, invalid transitions/session identity, backup reuse prevention,
corruption/version rejection, digest tampering, symlinks/hardlinks and directory
replacement. Live discovery tests preserve both v2 and legacy bytes.

Fixtures in `tests/fixtures/recovery` hold what older releases wrote: the journal
from 0.30.4's own writer, and the journal and backup a real 0.31.1 `resolver set`
left when SIGKILLed. Tests read the first and restore from the second.
`tests/recovery.rs` runs a real daemon on the first and, where a user namespace is
available, the real `resolver recover` on the second.

These tests demonstrate process-crash behavior on the test filesystem. They do not
simulate hardware power loss, disk-controller caches, or establish durability on
network filesystems. macOS runtime validation and a Windows write backend remain
outstanding. No actual resolver is modified by these tests or by this store.
