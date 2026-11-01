# Linux resolver authority command

Experimental. `netwatch resolver set` and `recover` can change or go away in any release, and
are outside the 1.0 compatibility promise.

The first adapter supports an explicitly administrator-confirmed unmanaged regular
`/etc/resolv.conf` on Linux. It runs in a separate invocation before application
runtime, packet capture, remote publishing, model workers, or parser confinement.
It does not widen the TUI/parser's filesystem grants. Automatic TUI/daemon edits
and startup rollback remain disabled; both modes inspect recovery evidence.
Resolver changes are experimental, outside the 1.0 compatibility promise.

## Commands

Read-only inspection, without creating a journal:

```sh
netwatch resolver status
```

After independently confirming that the file is administrator-owned and unmanaged,
an explicit temporary change can be requested:

```sh
sudo netwatch resolver set 1.1.1.1 --unmanaged --seconds 60
```

The command stays in the foreground and holds the resolver lease. It restores the
verified original at the deadline or on SIGINT/SIGTERM. The default is 60 seconds;
the permitted range is 1–3600. Hostnames, unspecified/multicast/loopback addresses,
IPv4 broadcast and IPv6 addresses needing a link-local scope are rejected. No
arbitrary target, backup, journal path, or shell command is accepted.

After an interrupted command, inspect its evidence and request recovery explicitly:

```sh
sudo netwatch resolver status
sudo netwatch resolver recover --unmanaged
```

Recovery proceeds only for an owner proven gone, with the expected target identity
and a valid original backup. Unknown ownership, changed contents or identity, and
partial writes remain unresolved for manual review. There is no automatic keep or
permanent-change command in this first adapter.

`recover` restores from this command's store and nothing else. It exits 0 when no
unresolved record is left there and 1 when it refuses or a record stays unresolved.

`status` and `recover` also print a notice when 0.30's
[legacy journal](recovery-store.md#legacy-journal) has an entry open, because
`Recovered 0 resolver operations` and `No resolver authority journal` only speak for
this store. The notice names the file and the backup. It restores nothing and never
changes the exit status: the journal is outside recovery authority, so a file a user
can write cannot fail a root command. Exit 0 therefore says nothing about that
journal, so read the output.

A failed write to stdout changes nothing: a closed pipe or a full disk loses the text,
and each command still finishes, with the same exit status and the same error on stderr.

## Ownership and supported scope

A plain regular file is only an unmanaged *candidate*. `--unmanaged` is the
administrator's assertion after checking the host; absence of markers is not proof
that DHCP or another agent will never rewrite it. Known systemd-resolved and
NetworkManager paths/content, generated-file markers, other symlinks, and active
manager runtime directories are rejected. All symlinks are preserved.

These conservative classifications follow the documented systemd resolver-file
modes and NetworkManager DNS ownership behavior. A manager needs its own per-link
or connection adapter; rewriting the file is insufficient. See
[systemd resolver-file modes](https://www.freedesktop.org/software/systemd/man/247/org.freedesktop.resolve1.html)
and [NetworkManager DNS configuration](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/NetworkManager.conf.html).

The file adapter verifies installed bytes and file identity, **not effective system
DNS resolution**. Applications may use caches or other resolver paths. The command
states this limit; it does not report a network diagnosis as fixed. macOS, Windows,
managed resolvers and symlink targets have no apply adapter.

## Authority, lease and recovery

Mutation commands require root. They validate root-owned, non-symlink directory
ancestry for `/etc` and `/var/lib/netwatch`, and use one fixed shared authority
store at `/var/lib/netwatch/resolver-v2`. Its OS lock is held throughout the
transaction and temporary change. Different invoking users therefore contend on
the same store under root authority. User cache/state journals are never promoted
into privileged recovery authority.

The store is private to root, so the kernel refuses every other user once `set` or
`recover` has run. Such a user cannot tell a resolved store from an unresolved one, so
netwatch claims neither. Their TUI or daemon session keeps the Diagnose status line
clear and writes one line to the log, at startup, saying the store exists, this user
cannot read it, and to run `sudo netwatch resolver status`. `netwatch doctor` reports
the same as `resolver_store`, `not_checked`. Root sessions report unresolved records on
the status line. Any other failure to read the store is reported to everyone.

The target must be a single-link regular file owned by root and not writable by
group/others. Open uses no-follow/nonblocking flags. The adapter validates device,
inode, ownership, permissions and expected bytes before writes and checks identity
and bytes again after sync. Changes use the opened file descriptor and preserve
inode and permissions. Another process that replaces or edits the file causes a
recovery refusal; it is never intentionally overwritten during rollback.

A durable Prepared record and immutable original backup precede the target write.
Readback precedes the Applied record. Failures after write attempts retain
recovery-required evidence; uncertain journal persistence prevents more writes in
that session. Rollback requires the expected identity and either the installed
hash or the verified original hash. Partial/foreign contents are not speculative
rollback candidates. Restored state is durably recorded before success is reported.

Owner identity includes session UUID, UID, PID, boot ID, process-start token and
PID namespace. A reused PID with a different start token establishes that the old
owner is gone; a missing token or another PID namespace is unknown. A live owner
is never recovered even if its lease was released. The authority file remains
root-trusted metadata, not a general authorization system for arbitrary callers.

The lease serializes cooperating Netwatch commands. It cannot prevent writes by
other root processes or network managers, and checks cannot eliminate a malicious
noncooperating writer's compare/write race. In-place writes are not atomic for DNS
readers and can be interrupted; the journal preserves recovery evidence. Unexpected
process exit/power loss may require the explicit recover command. Hardware
power-loss guarantees remain bounded by the [store contract](recovery-store.md).

Writes stay in place (decision X02, September 2026). Writing a temporary file and
renaming it over the target would give the target a new inode, which verification
compares and recovery refuses as a changed identity. An interrupted in-place write
already leaves recovery-required evidence that blocks further operations until
`recover` runs. The TUI's older file-edit and make-permanent journal helpers had
no caller and were deleted rather than converted, and 0.40 deleted the rollback
that went with them, which nothing had called since 0.31.1.

## Validation

Linux tests use disposable resolver files only. They cover temporary apply/restore,
identity/permissions preservation, held-lease exclusion, manager/symlink refusal,
external edits, inode replacement, tampered backups, partial target writes,
completion-record failure, PID reuse/unknown namespaces, and SIGKILL after Prepared,
target sync, Applied, and restoration. Another process must acquire the released
lease and restore only the verified original. A journal and backup that a real 0.31.1
`resolver set` left when SIGKILLed must restore the original through the current session
code, so an upgrade cannot strand one.

`tests/recovery.rs` runs that record through the real `resolver recover` in a private
root inside a user namespace. It skips where the runner has no such namespace, which
is the default CI runner, and the sandbox lab runs it. Privileged disposable-VM
acceptance of `set`, real system-resolver behavior
and deployment on actual unmanaged hosts remain outstanding. No real host resolver
was modified during implementation. Broader manager/platform adapters remain
unavailable rather than inferred from root privileges.
