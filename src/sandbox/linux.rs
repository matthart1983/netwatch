//! Linux sandbox backend — capability drop plus Landlock layers.
//!
//! Every confined thread takes the filesystem layer. Parser and capture
//! threads (see [`Role`]) stack a second layer on it, with no rules, that
//! denies TCP bind and connect, connecting to Unix sockets outside the
//! thread's domain and, with erratum 2 fixed, signalling outside it.
//! Capture's layer also handles every filesystem right and grants back only
//! the read grants. Main and the network workers keep the network: main starts
//! network workers after its own entry, and a thread keeps every layer it
//! inherits. A TCP rule names a port, not a host, so allowing 443 to a
//! network worker would still let it reach any host on 443; they get no TCP
//! rules at all.

use super::paths::SandboxPaths;
use super::{CaptureAuthority, Mode, NetRaw, Report, Role};

use caps::{CapSet, Capability, CapsHashSet};
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, Erratum, PathBeneath,
    RestrictionStatus, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};
use std::path::{Path, PathBuf};

/// Highest requested ABI for the filesystem layer. Only filesystem access
/// types are handled there; compatibility is best-effort on kernels
/// supporting fewer access types.
pub(crate) const TARGET_ABI: ABI = ABI::V4;

/// The parser and capture layers handle `AccessNet::from_all` of this ABI,
/// TCP bind and connect (Linux 6.7), with no rule, so both are denied.
/// Strict mode requires them.
pub(crate) const PARSER_NET_ABI: ABI = ABI::V4;

/// Those layers take `Scope::from_all` of this ABI where the kernel has it:
/// abstract Unix sockets and signals outside the thread's domain (Linux
/// 6.12). Signals only once erratum 2 is fixed; see [`scoped_signals`].
pub(crate) const PARSER_SCOPE_ABI: ABI = ABI::V6;

/// The filesystem right those layers handle where the kernel has it (ABI 9,
/// Linux 7.1), with no rule granting it back: connecting to a pathname Unix
/// socket, which is how a parser would reach D-Bus, nscd or any other local
/// service.
pub(crate) const PARSER_FS: AccessFs = AccessFs::ResolveUnix;

/// Capabilities dropped in every mode that runs `drop_caps`.
///
/// Without elevation the thread holds none of them and this changes nothing.
/// Under the documented `setcap` line it takes CAP_BPF and CAP_PERFMON. Under
/// root it takes everything no code path needs after startup (CAP_SYS_PTRACE
/// costs process names; see below): a confined thread otherwise keeps
/// almost every capability, and with CAP_SYS_RAWIO and the `/proc` grant it
/// could read kernel memory, page cache included, through `/proc/kcore`,
/// which no filesystem rule stops. What root keeps is file
/// access in the user's directories (CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH,
/// CAP_FOWNER, CAP_CHOWN, CAP_FSETID), limits and scheduling
/// (CAP_SYS_RESOURCE, CAP_SYS_NICE, CAP_IPC_LOCK), CAP_NET_BIND_SERVICE for a
/// metrics port below 1024, and CAP_NET_RAW on main and the network workers in
/// a best-effort TUI so capture can reopen (see `CAPS_TO_DROP_STRICT`,
/// `CAPS_TO_DROP_PARSER` and `CAPS_TO_DROP_AFTER_OPEN`).
pub(crate) const CAPS_TO_DROP_DEFAULT: &[Capability] = &[
    // Once the kprobe is attached and the ringbuffer is open, we don't need
    // to load new BPF programs at runtime.
    Capability::CAP_BPF,
    Capability::CAP_PERFMON,
    // CAP_SYS_ADMIN is the legacy fallback for BPF on pre-5.8 kernels.
    // Drop it too — modern userspaces don't need it post-attach.
    Capability::CAP_SYS_ADMIN,
    // Kernel memory, modules, the clock and the machine itself.
    Capability::CAP_SYS_RAWIO,
    Capability::CAP_SYS_MODULE,
    Capability::CAP_SYS_BOOT,
    Capability::CAP_SYS_TIME,
    Capability::CAP_SYS_PACCT,
    Capability::CAP_SYS_TTY_CONFIG,
    Capability::CAP_SYSLOG,
    Capability::CAP_WAKE_ALARM,
    Capability::CAP_BLOCK_SUSPEND,
    // Other processes. Landlock already refuses a confined thread ptrace
    // access outside its domain; the ProcBroker, which never enters, keeps
    // CAP_SYS_PTRACE for its socket scan (`CAPS_FOR_PROC_BROKER`). Where
    // Landlock does not enforce, this drop is what refuses it, and under root
    // that costs something. Without CAP_SYS_PTRACE the kernel's ptrace read
    // check passes for another process only if its uids and gids match the
    // reader's, it is dumpable, and its permitted set lies within the
    // reader's effective set. A confined thread keeps at most 10
    // capabilities, so the connections worker can no longer read
    // `/proc/<pid>/exe` or the `/proc/<pid>/fd` links of almost any process
    // but netwatch's own: not another user's, not one that is not dumpable,
    // and not a root process holding a capability the thread dropped, which
    // takes in most root daemons, systemd included. Such a process keeps the
    // 15-character `comm` the broker gave it as its name, and a poll with no
    // fresh broker snapshot leaves its sockets unattributed. Resolving names
    // in the broker would bring them back.
    Capability::CAP_SYS_PTRACE,
    Capability::CAP_KILL,
    Capability::CAP_CHECKPOINT_RESTORE,
    Capability::CAP_IPC_OWNER,
    // Identity and capability changes.
    Capability::CAP_SETUID,
    Capability::CAP_SETGID,
    Capability::CAP_SETPCAP,
    Capability::CAP_SETFCAP,
    // Filesystem objects and attributes netwatch never creates or sets.
    Capability::CAP_MKNOD,
    Capability::CAP_SYS_CHROOT,
    Capability::CAP_LINUX_IMMUTABLE,
    Capability::CAP_LEASE,
    // LSM and audit.
    Capability::CAP_MAC_ADMIN,
    Capability::CAP_MAC_OVERRIDE,
    Capability::CAP_AUDIT_CONTROL,
    Capability::CAP_AUDIT_WRITE,
    Capability::CAP_AUDIT_READ,
    // Checked nowhere in the kernel; dropped so every capability is either
    // here or kept for a reason above.
    Capability::CAP_NET_BROADCAST,
    // Interfaces, routes and firewall rules. No code path configures any.
    // There is no ethtool or SIOCS* ioctl, `iw dev link` reads unprivileged,
    // inet_diag reads over netlink, and promiscuous capture opens with
    // CAP_NET_RAW alone.
    Capability::CAP_NET_ADMIN,
];

/// Additional caps dropped in `Mode::Strict` only. CAP_NET_RAW is the
/// painful one: pcap needs it for `socket(AF_PACKET, SOCK_RAW, …)`, and
/// the user can re-open pcap handles mid-run by toggling capture from
/// the Packets tab (`c`), cycling the capture interface (`i`), or arming
/// the Flight Recorder (`Shift+R`) when capture is paused. Dropping it
/// in BestEffort caused `Capture failed: libpcap error: socket:
/// Operation not permitted` the moment a user pressed `c` twice. Strict
/// users have opted into "fail closed" semantics — we keep dropping it
/// there.
pub(crate) const CAPS_TO_DROP_STRICT: &[Capability] = &[Capability::CAP_NET_RAW];

/// Additional caps parser and capture threads drop in every mode. Landlock
/// does not mediate raw or packet sockets, so this is what stops a parser
/// opening one. Capture opens its device before entry, and every reopen
/// (`c`, `i`, `Shift+R`) runs on a new thread main starts, which keeps
/// CAP_NET_RAW in a best-effort TUI. The open device is not revoked: whoever
/// holds its descriptor can still capture and inject on it.
pub(crate) const CAPS_TO_DROP_PARSER: &[Capability] = &[Capability::CAP_NET_RAW];

/// Additional caps main and the network workers drop under
/// [`CaptureAuthority::DropAfterOpen`]: in the daemon, the Diagnose CLI and
/// strict sessions, which open capture once and never reopen it. Main drops
/// after `start_workers`, so capture has opened by then. The `ping` that
/// health falls back to, and Diagnose's PMTU probe, can hold no more than the
/// worker running them, so on a host whose `ping_group_range` excludes the
/// user both fail there and health falls back to TCP.
pub(crate) const CAPS_TO_DROP_AFTER_OPEN: &[Capability] = &[Capability::CAP_NET_RAW];

/// What loading and attaching a BPF program needs. CAP_SYS_ADMIN is the
/// pre-5.8 fallback and is listed for the same kernels the drop list names.
pub(crate) const CAPS_FOR_BPF_LOAD: &[Capability] = &[
    Capability::CAP_BPF,
    Capability::CAP_PERFMON,
    Capability::CAP_SYS_ADMIN,
];

/// What the ProcBroker keeps of whatever the process started with. Under
/// root, listing another user's `/proc/<pid>/fd` takes CAP_DAC_READ_SEARCH,
/// and reading its links, `exe` and `ns/net` takes CAP_SYS_PTRACE. The scan
/// does nothing else.
pub(crate) const CAPS_FOR_PROC_BROKER: &[Capability] =
    &[Capability::CAP_SYS_PTRACE, Capability::CAP_DAC_READ_SEARCH];

/// Drop the load capabilities on the calling thread.
///
/// Called by the eBPF worker once its programs are attached, so the thread
/// that goes on to read kernel events holds nothing it no longer needs.
pub fn drop_bpf_caps() -> Result<(), String> {
    for cap in CAPS_FOR_BPF_LOAD {
        for set in [CapSet::Effective, CapSet::Inheritable, CapSet::Permitted] {
            caps::drop(None, set, *cap).map_err(|e| format!("{cap} {set:?}: {e}"))?;
            if caps::has_cap(None, set, *cap).unwrap_or(true) {
                return Err(format!("{cap} still present in {set:?}"));
            }
        }
    }
    Ok(())
}

/// Drop every capability `role` does not keep unconfined from the calling
/// thread's Effective, Inheritable, Permitted and Ambient sets. No Landlock.
pub fn relinquish_caps(role: Role, report: &mut Report) {
    let held = held_caps(report);
    for cap in relinquish_set(&held, kept_unconfined(role)) {
        drop_verified(cap, ALL_SETS, report);
    }
    record_net_raw(&held, report);
    record_retained(report);
}

/// What a thread that never enters keeps: the broker its scan's two
/// capabilities, any other thread nothing.
fn kept_unconfined(role: Role) -> &'static [Capability] {
    match role {
        Role::Broker => CAPS_FOR_PROC_BROKER,
        _ => &[],
    }
}

/// Everything in `held` but `keep`, in capability order.
fn relinquish_set(held: &CapsHashSet, keep: &[Capability]) -> Vec<Capability> {
    let mut drop: Vec<_> = held
        .iter()
        .filter(|cap| !keep.contains(cap))
        .copied()
        .collect();
    drop.sort_by_key(|cap| cap.index());
    drop
}

/// Every set a drop is checked in. The kernel lowers a capability's Ambient
/// bit when it leaves Permitted or Inheritable; checking it too makes an
/// Ambient grant, as the systemd unit gives, visible if that ever fails.
const ALL_SETS: &[CapSet] = &[
    CapSet::Effective,
    CapSet::Inheritable,
    CapSet::Permitted,
    CapSet::Ambient,
];

/// Drop capabilities, then stack the filesystem layer and the role's layer,
/// in that order. A worker started from main carries main's layer too, and
/// the metrics client its listener's two, so no thread holds more than four
/// of the kernel's sixteen.
pub fn apply(
    mode: Mode,
    paths: &SandboxPaths,
    retain: super::Retain,
    role: Role,
    authority: CaptureAuthority,
    report: &mut Report,
) {
    report.mode.effective = Some(mode.label());

    drop_caps(mode, retain, role, authority, report);
    record_retained(report);

    let result = if let Some(prepared) = super::worker::prepared_ruleset() {
        match prepared {
            Ok(ruleset) => ruleset
                .try_clone()
                .map_err(|e| e.to_string())
                .and_then(|r| enforce(r, report)),
            Err(error) => Err(error.clone()),
        }
    } else {
        prepare_ruleset(paths).and_then(|r| enforce(r, report))
    };
    let kernel = match result {
        Ok(abi) => Some(abi),
        Err(error) => {
            report
                .mode
                .warnings
                .push(format!("Landlock not applied: {error}"));
            None
        }
    };

    if matches!(mode, Mode::Strict) && report.platform.landlock_abi == 0 {
        report
            .mode
            .warnings
            .push("strict sandbox requested but Landlock did not enforce".into());
    }

    if role.layer().is_some() {
        enforce_layer(mode, paths, role, report);
    } else if role == Role::Main {
        // Parser workers share main's kernel and enter before logging
        // starts, so main says it once for all of them.
        if let Some(abi) = kernel.filter(|abi| AccessNet::from_all(*abi).is_empty()) {
            static LOGGED: std::sync::Once = std::sync::Once::new();
            LOGGED.call_once(|| {
                tracing::warn!(target: "netwatch::sandbox", "{}", deny_unavailable(abi));
            });
        }
    }
}

/// The capabilities a `role` thread drops on entry in `mode` under
/// `authority`, before `Retain` holds any back.
fn drop_list(mode: Mode, role: Role, authority: CaptureAuthority) -> Vec<Capability> {
    let mut drop = CAPS_TO_DROP_DEFAULT.to_vec();
    let strict: &[Capability] = if matches!(mode, Mode::Strict) {
        CAPS_TO_DROP_STRICT
    } else {
        &[]
    };
    let parser: &[Capability] = if role.layer().is_some() {
        CAPS_TO_DROP_PARSER
    } else {
        &[]
    };
    let after_open: &[Capability] = if authority == CaptureAuthority::DropAfterOpen {
        CAPS_TO_DROP_AFTER_OPEN
    } else {
        &[]
    };
    for cap in strict.iter().chain(parser).chain(after_open) {
        if !drop.contains(cap) {
            drop.push(*cap);
        }
    }
    drop
}

fn drop_caps(
    mode: Mode,
    retain: super::Retain,
    role: Role,
    authority: CaptureAuthority,
    report: &mut Report,
) {
    let held = held_caps(report);
    for cap in &drop_list(mode, role, authority) {
        // Held deliberately and briefly — see `Retain`. The worker drops
        // them itself once the load is done, and the report says which
        // worker held what until it did.
        if matches!(retain, super::Retain::BpfLoad) && CAPS_FOR_BPF_LOAD.contains(cap) {
            report.platform.caps_retained_for_load.push(cap.to_string());
            continue;
        }
        // Only what the thread holds: every worker entry runs this, and an
        // unprivileged one holds nothing on the list.
        if held.contains(cap) {
            drop_verified(*cap, ALL_SETS, report);
        }
    }
    record_net_raw(&held, report);
}

/// Record what the drops left of CAP_NET_RAW, given what the thread `held`
/// before them.
fn record_net_raw(held: &CapsHashSet, report: &mut Report) {
    let cap = Capability::CAP_NET_RAW;
    let still = [CapSet::Permitted, CapSet::Inheritable]
        .into_iter()
        .any(|set| caps::has_cap(None, set, cap).unwrap_or(true));
    report.platform.capture_authority = if !held.contains(&cap) {
        NetRaw::NotHeld
    } else if still {
        NetRaw::RetainedForReopen
    } else {
        NetRaw::Dropped
    };
}

/// Every capability the calling thread holds in any set. Effective is within
/// Permitted, and Ambient within both Permitted and Inheritable, so those two
/// cover all four. If either can't be read, every capability is tried, so the
/// failure is reported rather than read as nothing to drop.
fn held_caps(report: &mut Report) -> CapsHashSet {
    match (
        caps::read(None, CapSet::Permitted),
        caps::read(None, CapSet::Inheritable),
    ) {
        (Ok(permitted), Ok(inheritable)) => &permitted | &inheritable,
        (Err(error), _) | (_, Err(error)) => {
            report
                .mode
                .warnings
                .push(format!("held capabilities unknown: {error}"));
            caps::all()
        }
    }
}

/// Drop `cap` from each of `sets` on the calling thread and check it is gone.
fn drop_verified(cap: Capability, sets: &[CapSet], report: &mut Report) {
    let permitted_before = caps::has_cap(None, CapSet::Permitted, cap).unwrap_or(false);

    let mut verified = true;
    for &set in sets {
        if let Err(error) = caps::drop(None, set, cap) {
            verified = false;
            report
                .mode
                .warnings
                .push(format!("{cap} {set:?} drop failed: {error}"));
        }
        match caps::has_cap(None, set, cap) {
            Ok(false) => {}
            other => {
                verified = false;
                report
                    .mode
                    .warnings
                    .push(format!("{cap} {set:?} removal unverified: {other:?}"));
            }
        }
    }
    if verified && permitted_before {
        report.platform.caps_dropped.push(cap.to_string());
    }
}

fn record_retained(report: &mut Report) {
    match caps::read(None, CapSet::Effective) {
        Ok(caps) => {
            report.platform.caps_retained = caps.iter().map(|c| c.to_string()).collect();
            report.platform.caps_retained.sort();
        }
        Err(error) => report
            .mode
            .warnings
            .push(format!("retained capabilities unknown: {error}")),
    }
}

/// Paths we need to be able to read once restricted. Order doesn't
/// matter; missing paths are silently skipped.
///
/// System executable/library paths are broad; /etc uses an explicit list.
/// Configured database/keylog parents and read/write grants can widen access
/// to sensitive files. These rules apply only to confined threads.
pub(super) fn collect_read_only(paths: &SandboxPaths) -> Vec<PathBuf> {
    let mut out = Vec::new();

    for path in [
        // procfs — interface counters, /proc/net/dev, process attribution.
        "/proc",
        // sysfs — interface info, statistics, wireless detection
        // (`/sys/class/net/*/{statistics,operstate,carrier,mtu,address,wireless}`).
        "/sys",
        // Executables the connection / topology / WHOIS collectors spawn
        // (ss, lsof, ip, traceroute, whois, host). Landlock applies its
        // policy to children, so the children also need Execute on
        // their own binaries. Allow these broadly.
        "/bin",
        "/sbin",
        "/usr",
        // Dynamic linker / shared library load paths.
        "/lib",
        "/lib64",
        // System resolver + service-name files. getaddrinfo() walks NSS
        // modules from /usr/lib/x86_64-linux-gnu/libnss_*.so plus
        // /etc/{passwd,group,nsswitch.conf}. Narrow list (instead of
        // allow-all /etc) limits access for confined threads, unless a
        // broader grant such as startup CWD also permits those files.
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/services",
        "/etc/nsswitch.conf",
        "/etc/host.conf",
        "/etc/gai.conf",
        "/etc/protocols",
        "/etc/passwd",
        "/etc/group",
        "/etc/os-release",
        "/etc/localtime",
        "/etc/timezone",
        "/etc/ssl",
        "/etc/pki",
        "/etc/ca-certificates",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        // systemd-resolved socket dir (NSS via systemd-resolved variant).
        "/run/systemd/resolve",
        // DBus runtime dir for tools that talk to system services.
        "/run/dbus",
    ] {
        out.push(PathBuf::from(path));
    }

    if let Some(p) = &paths.geoip_db_dir {
        out.push(p.clone());
    }
    if let Some(p) = &paths.geoip_asn_db_dir {
        out.push(p.clone());
    }
    if let Some(p) = &paths.keylog_dir {
        out.push(p.clone());
    }

    out
}

/// Paths we need to be able to write to. Read access is implied by
/// `AccessFs::from_all` so these don't also need to appear in the
/// read-only list.
pub(super) fn collect_read_write(paths: &SandboxPaths) -> Vec<PathBuf> {
    let mut out = Vec::new();

    // The config dir needs write access too — `NetwatchConfig::save()`
    // writes config.toml here when the user changes a setting in the
    // overlay. If this is read-only the user gets "Permission denied
    // (os error 13)" and, worst of all, can't even flip the sandbox
    // setting itself to escape. Found on a Linux NUC trying to disable
    // the sandbox via the Settings overlay.
    if let Some(p) = &paths.config_dir {
        out.push(p.clone());
    }

    if let Some(p) = &paths.cache_dir {
        out.push(p.clone());
    }
    // The learned egress baseline persists here on a rate-limited tick
    // and at quit — both long after the sandbox is applied.
    if let Some(p) = &paths.state_dir {
        out.push(p.clone());
    }
    if let Some(p) = &paths.cwd {
        // Legacy field name: this is the dedicated exports directory.
        out.push(p.clone());
    }
    // No shared /tmp grant: use the prepared application scratch directory.
    if let Some(cache) = &paths.cache_dir {
        out.push(cache.join("scratch"));
    }
    // `/dev/null` is needed for various stdlib paths (e.g., NSS
    // canary opens).
    out.push(PathBuf::from("/dev/null"));

    out
}

/// Build once before workers start; kernel rules pin the opened filesystem
/// objects, so later symlink replacement cannot widen a worker's grants.
pub(super) fn prepare_ruleset(paths: &SandboxPaths) -> Result<landlock::RulesetCreated, String> {
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .map_err(|e| e.to_string())?
        .create()
        .map_err(|e| e.to_string())?;
    add_grants(ruleset, grants(paths))
}

/// The parser layer, built once before workers start like
/// [`prepare_ruleset`]. In strict mode a kernel that cannot deny TCP fails
/// it here, and every parser entry with it.
pub(super) fn prepare_parser_layer(mode: Mode) -> Result<landlock::RulesetCreated, String> {
    layer_ruleset(mode, PARSER_FS.into())?
        .create()
        .map_err(|e| e.to_string())
}

/// Whether the kernel enforces the filesystem layer in full but cannot deny
/// TCP, as Linux 6.2 to 6.6 do. Strict refuses every parser thread there, so
/// a strict test that starts one cannot pass.
#[cfg(test)]
pub(super) fn kernel_denies_files_but_not_tcp() -> bool {
    let required = || Ruleset::default().set_compatibility(CompatLevel::HardRequirement);
    required()
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .is_ok()
        && required()
            .handle_access(AccessNet::from_all(PARSER_NET_ABI))
            .is_err()
}

/// The capture layer: the parser layer's rights plus every filesystem
/// right, with the read grants and none of the write grants. Nothing the
/// capture loop runs writes a file; exports and incident bundles are written
/// by other threads.
pub(super) fn prepare_capture_layer(
    mode: Mode,
    paths: &SandboxPaths,
) -> Result<landlock::RulesetCreated, String> {
    let ruleset = layer_ruleset(mode, AccessFs::from_all(TARGET_ABI) | PARSER_FS)?
        .create()
        .map_err(|e| e.to_string())?;
    add_grants(ruleset, grants(paths).into_iter().filter(|g| !g.write))
}

/// What the parser and capture layers handle. The TCP part is a hard
/// requirement in strict mode; the scopes and `fs` are taken where the
/// kernel has them.
fn layer_ruleset(mode: Mode, fs: BitFlags<AccessFs>) -> Result<Ruleset, String> {
    let tcp = if matches!(mode, Mode::Strict) {
        CompatLevel::HardRequirement
    } else {
        CompatLevel::BestEffort
    };
    let mut scopes = Scope::from_all(PARSER_SCOPE_ABI);
    if !scoped_signals() {
        scopes.remove(Scope::Signal);
    }
    Ruleset::default()
        .set_compatibility(tcp)
        .handle_access(AccessNet::from_all(PARSER_NET_ABI))
        .map_err(|_| "kernel Landlock below ABI 4 cannot deny TCP (needs Linux 6.7)".to_string())?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(fs)
        .map_err(|e| e.to_string())?
        .scope(scopes)
        .map_err(|e| e.to_string())
}

/// Whether the kernel has the fix for Landlock erratum 2. Without it, a
/// signal scope also stops a thread signalling its own process's threads in
/// other domains, so the scope is added only once the fix is reported, as
/// the crate's errata guidance says.
fn scoped_signals() -> bool {
    static FIXED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FIXED.get_or_init(|| Erratum::current().contains(Erratum::ScopedSignalHandling))
}

/// Add each grant's rule, opening its path first.
fn add_grants(
    mut ruleset: landlock::RulesetCreated,
    grants: impl IntoIterator<Item = Grant>,
) -> Result<landlock::RulesetCreated, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    for grant in grants {
        let (path, write) = (&grant.path, grant.write);
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(nix::libc::O_PATH | if write { nix::libc::O_NOFOLLOW } else { 0 });
        let file = match options.open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !write => continue,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if grant.configured_file && !meta.is_file() {
            return Err(format!("expected file grant: {}", path.display()));
        }
        if write && path != Path::new("/dev/null") {
            if !meta.is_dir()
                || meta.uid() != unsafe { nix::libc::geteuid() }
                || meta.mode() & 0o077 != 0
            {
                return Err(format!(
                    "directory must be owned and private: {}",
                    path.display()
                ));
            }
            for broad in [
                Some(PathBuf::from("/")),
                Some(PathBuf::from("/tmp")),
                dirs::home_dir(),
            ]
            .into_iter()
            .flatten()
            {
                if let Ok(other) = std::fs::metadata(broad) {
                    if meta.dev() == other.dev() && meta.ino() == other.ino() {
                        return Err("broad directory grant rejected".into());
                    }
                }
            }
        }
        ruleset = ruleset
            .add_rule(PathBeneath::new(file, grant.access(meta.is_dir())))
            .map_err(|e| e.to_string())?;
    }
    Ok(ruleset)
}

/// One rule [`prepare_ruleset`] adds, before its path is opened.
pub(super) struct Grant {
    pub(super) path: PathBuf,
    /// A write grant, labelled `write:` in docs/THREAT-MODEL.md, rather
    /// than a read grant, labelled `read:`.
    pub(super) write: bool,
    /// A GeoIP database or keylog file the user configured.
    configured_file: bool,
}

/// Every rule [`prepare_ruleset`] adds, read grants first. The threat
/// model's grants table is checked against this list, labels included.
pub(super) fn grants(paths: &SandboxPaths) -> Vec<Grant> {
    let configured = [
        &paths.geoip_db_dir,
        &paths.geoip_asn_db_dir,
        &paths.keylog_dir,
    ];
    let read = collect_read_only(paths).into_iter().map(|p| (p, false));
    let write = collect_read_write(paths).into_iter().map(|p| (p, true));
    read.chain(write)
        .map(|(path, write)| Grant {
            configured_file: configured.iter().copied().flatten().any(|p| *p == path),
            path,
            write,
        })
        .collect()
}

impl Grant {
    /// What the grant allows: every handled right for a write grant,
    /// reading for a read grant, and only reading the file itself for a
    /// configured GeoIP or keylog file. A non-directory takes only the file
    /// rights.
    pub(super) fn access(&self, is_dir: bool) -> landlock::BitFlags<AccessFs> {
        if self.configured_file {
            return AccessFs::ReadFile.into();
        }
        let mut access = if self.write {
            AccessFs::from_all(TARGET_ABI)
        } else {
            AccessFs::from_read(TARGET_ABI)
        };
        if !is_dir {
            access &=
                AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Execute | AccessFs::Truncate;
        }
        access
    }
}

/// Restrict the calling thread with the filesystem layer. Returns the ABI
/// the kernel reported.
fn enforce(ruleset: landlock::RulesetCreated, report: &mut Report) -> Result<ABI, String> {
    let status = ruleset.restrict_self().map_err(|e| e.to_string())?;

    // Record the effective ABI for the Settings overlay. `landlock`
    // exposes the effective ABI inside `LandlockStatus::Available`.
    // Without Landlock this is `Unsupported`, which keeps landlock_abi at 0.
    let abi = kernel_abi(&status);
    report.platform.landlock_abi = abi as u32;

    if status.ruleset == RulesetStatus::NotEnforced {
        report
            .mode
            .warnings
            .push("Landlock present but ruleset was not enforced".into());
    } else if status.ruleset == RulesetStatus::PartiallyEnforced {
        report
            .mode
            .warnings
            .push("Landlock ruleset partially enforced (older kernel)".into());
    }

    Ok(abi)
}

/// The ABI the kernel reported to a restriction, `Unsupported` without
/// Landlock.
fn kernel_abi(status: &RestrictionStatus) -> ABI {
    match status.landlock {
        landlock::LandlockStatus::Available { effective_abi, .. } => effective_abi,
        landlock::LandlockStatus::NotEnabled | landlock::LandlockStatus::NotImplemented => {
            ABI::Unsupported
        }
    }
}

fn deny_unavailable(abi: ABI) -> String {
    format!(
        "parser network deny unavailable: kernel Landlock ABI {} (needs 4, Linux 6.7)",
        abi as u32
    )
}

/// Stack the role's parser or capture layer on the calling thread and record
/// what the kernel enforced.
///
/// A kernel below ABI 4 cannot deny TCP. Best-effort carries on without a
/// per-worker warning, and main's entry logs it once for the process; strict
/// refuses the entry. The scopes and pathname sockets are taken silently
/// where the kernel has them, so ABI 4 to 8 report a partly enforced layer
/// as normal.
fn enforce_layer(mode: Mode, paths: &SandboxPaths, role: Role, report: &mut Report) {
    let Some(layer) = role.layer() else {
        return;
    };
    report.platform.landlock_layer = Some(layer);
    let capture = role == Role::Capture;
    let status = match super::worker::prepared_layer(role) {
        Some(Ok(ruleset)) => ruleset
            .try_clone()
            .map_err(|e| e.to_string())
            .and_then(restrict),
        Some(Err(error)) => Err(error.clone()),
        None if capture => prepare_capture_layer(mode, paths).and_then(restrict),
        None => prepare_parser_layer(mode).and_then(restrict),
    };
    let status = match status {
        Ok(status) => status,
        Err(error) => {
            report
                .mode
                .warnings
                .push(format!("{layer} layer not applied: {error}"));
            return;
        }
    };
    let abi = kernel_abi(&status);
    let enforced = status.ruleset != RulesetStatus::NotEnforced;
    let restrictions = layer_restrictions(abi, enforced, capture, scoped_signals());
    report.platform.landlock_network_blocked =
        restrictions.contains(&"tcp_bind") && restrictions.contains(&"tcp_connect");
    report.platform.landlock_restrictions = restrictions;
    if !report.platform.landlock_network_blocked && matches!(mode, Mode::Strict) {
        report.mode.warnings.push(deny_unavailable(abi));
    }
}

fn restrict(ruleset: landlock::RulesetCreated) -> Result<RestrictionStatus, String> {
    ruleset.restrict_self().map_err(|e| e.to_string())
}

/// What a parser or capture layer enforced, from the ABI the kernel reported
/// and whether the layer took effect. Best-effort drops exactly the rights
/// the kernel lacks, so a right is in force once the kernel has its ABI.
fn layer_restrictions(abi: ABI, enforced: bool, capture: bool, signals: bool) -> Vec<&'static str> {
    let mut out = Vec::new();
    if !enforced {
        return out;
    }
    if capture {
        out.push("filesystem_write");
    }
    let net = AccessNet::from_all(abi);
    if net.contains(AccessNet::BindTcp) {
        out.push("tcp_bind");
    }
    if net.contains(AccessNet::ConnectTcp) {
        out.push("tcp_connect");
    }
    let scopes = Scope::from_all(abi);
    if scopes.contains(Scope::AbstractUnixSocket) {
        out.push("abstract_unix_socket");
    }
    if signals && scopes.contains(Scope::Signal) {
        out.push("signal");
    }
    if AccessFs::from_all(abi).contains(PARSER_FS) {
        out.push("pathname_unix_socket");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bpf_load_capabilities_are_the_ones_entry_drops() {
        // If the drop list and the load list ever diverge, the eBPF worker
        // either enters without a capability it needs or keeps one nothing
        // asked it to keep. Both are quiet failures, so they are asserted.
        for cap in CAPS_FOR_BPF_LOAD {
            assert!(
                CAPS_TO_DROP_DEFAULT.contains(cap),
                "{cap:?} is held for the load but entry never drops it"
            );
        }
        assert!(
            !CAPS_FOR_BPF_LOAD.contains(&Capability::CAP_NET_RAW),
            "capture's capability is not the loader's to keep"
        );
    }

    #[test]
    fn only_the_load_policy_keeps_capabilities_back() {
        let mut report = Report::default();
        drop_caps(
            Mode::BestEffort,
            super::super::Retain::Nothing,
            Role::Network,
            CaptureAuthority::RetainForReopen,
            &mut report,
        );
        assert!(
            report.platform.caps_retained_for_load.is_empty(),
            "an ordinary worker keeps nothing back: {:?}",
            report.platform.caps_retained_for_load
        );

        let mut report = Report::default();
        drop_caps(
            Mode::BestEffort,
            super::super::Retain::BpfLoad,
            Role::Parser,
            CaptureAuthority::DropAfterOpen,
            &mut report,
        );
        // Reported whether or not the process had them: the field says what
        // the policy held back, not what the thread happened to own.
        assert_eq!(
            report.platform.caps_retained_for_load.len(),
            CAPS_FOR_BPF_LOAD.len()
        );
        assert!(report
            .platform
            .caps_retained_for_load
            .iter()
            .any(|c| c.contains("BPF")));
    }

    #[test]
    fn collect_read_only_includes_proc_and_etc() {
        let paths = SandboxPaths::default();
        let ro = collect_read_only(&paths);
        assert!(ro.iter().any(|p| p == Path::new("/proc")));
        assert!(ro.iter().any(|p| p == Path::new("/etc/resolv.conf")));
    }

    #[test]
    fn collect_read_write_excludes_shared_tmp() {
        let paths = SandboxPaths::default();
        let rw = collect_read_write(&paths);
        assert!(!rw.iter().any(|p| p == Path::new("/tmp")));
    }

    #[test]
    fn collect_read_write_includes_config_dir_so_save_works() {
        // Regression for the "Permission denied (os error 13)" report on
        // a Linux NUC running v0.21.5 with the sandbox on. If the config
        // dir slips back into the read-only bucket, NetwatchConfig::save()
        // breaks under Landlock and users get trapped in whatever sandbox
        // mode they launched with.
        let paths = SandboxPaths {
            config_dir: Some(PathBuf::from("/tmp/netwatch-test-cfg")),
            ..Default::default()
        };
        let rw = collect_read_write(&paths);
        assert!(
            rw.iter().any(|p| p == Path::new("/tmp/netwatch-test-cfg")),
            "config_dir must be writable so the Settings overlay can save"
        );
    }

    #[test]
    fn besteffort_keeps_cap_net_raw_for_pcap_reopen() {
        // Regression: pcap re-opens (Packets `c` toggle, interface cycle
        // via `i`, Flight Recorder arm) need CAP_NET_RAW on main, which
        // starts each new capture thread. Dropping it in a best-effort TUI
        // produced "Capture failed: libpcap error: socket: Operation not
        // permitted" on Linux NUCs. Strict still drops it, since those users
        // opted in to fail-closed semantics, and so do the sessions that
        // never reopen.
        assert!(
            !CAPS_TO_DROP_DEFAULT.contains(&Capability::CAP_NET_RAW),
            "BestEffort must keep CAP_NET_RAW so capture toggle works"
        );
        assert!(
            !drop_list(
                Mode::BestEffort,
                Role::Main,
                CaptureAuthority::RetainForReopen
            )
            .contains(&Capability::CAP_NET_RAW),
            "a best-effort TUI's main must keep CAP_NET_RAW so capture toggle works"
        );
        assert!(
            CAPS_TO_DROP_STRICT.contains(&Capability::CAP_NET_RAW),
            "Strict mode should still drop CAP_NET_RAW (opt-in trade-off)"
        );
        assert!(
            drop_list(
                Mode::BestEffort,
                Role::Main,
                CaptureAuthority::DropAfterOpen
            )
            .contains(&Capability::CAP_NET_RAW),
            "the daemon never reopens, so its main drops CAP_NET_RAW"
        );
    }

    #[test]
    fn default_drop_list_covers_dangerous_root_caps() {
        // Under root a confined thread starts with every capability, so the
        // deny-list is all that stands between a parser bug and these.
        for cap in [
            Capability::CAP_SYS_RAWIO,
            Capability::CAP_SYS_MODULE,
            Capability::CAP_SYS_BOOT,
            Capability::CAP_SYS_PTRACE,
            Capability::CAP_SETUID,
            Capability::CAP_SETGID,
            Capability::CAP_SETPCAP,
            Capability::CAP_SETFCAP,
            Capability::CAP_MKNOD,
            Capability::CAP_SYS_CHROOT,
            Capability::CAP_SYS_TIME,
            Capability::CAP_MAC_ADMIN,
            Capability::CAP_MAC_OVERRIDE,
            Capability::CAP_LINUX_IMMUTABLE,
            Capability::CAP_SYSLOG,
            Capability::CAP_AUDIT_CONTROL,
            Capability::CAP_AUDIT_WRITE,
            Capability::CAP_AUDIT_READ,
            Capability::CAP_KILL,
            Capability::CAP_BPF,
            Capability::CAP_PERFMON,
            Capability::CAP_SYS_ADMIN,
            Capability::CAP_NET_ADMIN,
        ] {
            assert!(CAPS_TO_DROP_DEFAULT.contains(&cap), "{cap} kept under root");
        }
        // Everything else is kept on purpose: a root session's file access in
        // the user's directories, limits and scheduling, a low metrics port,
        // and reopening capture. A capability in neither list, such as one a
        // caps upgrade adds, fails here until someone decides.
        let kept = [
            Capability::CAP_CHOWN,
            Capability::CAP_DAC_OVERRIDE,
            Capability::CAP_DAC_READ_SEARCH,
            Capability::CAP_FOWNER,
            Capability::CAP_FSETID,
            Capability::CAP_SYS_RESOURCE,
            Capability::CAP_SYS_NICE,
            Capability::CAP_IPC_LOCK,
            Capability::CAP_NET_BIND_SERVICE,
            Capability::CAP_NET_RAW,
        ];
        for cap in caps::all() {
            assert_ne!(
                CAPS_TO_DROP_DEFAULT.contains(&cap),
                kept.contains(&cap),
                "{cap} must be either dropped or kept"
            );
        }
    }

    #[test]
    fn broker_relinquish_keeps_only_ptrace_and_dac_read_search() {
        // Root's set, which the broker starts with under sudo.
        let full = caps::all();
        let dropped = relinquish_set(&full, kept_unconfined(Role::Broker));
        assert_eq!(dropped.len(), full.len() - CAPS_FOR_PROC_BROKER.len());
        for cap in [Capability::CAP_SYS_PTRACE, Capability::CAP_DAC_READ_SEARCH] {
            assert!(!dropped.contains(&cap), "{cap} dropped");
        }
        for cap in [
            Capability::CAP_NET_RAW,
            Capability::CAP_NET_ADMIN,
            Capability::CAP_BPF,
            Capability::CAP_PERFMON,
            Capability::CAP_SYS_ADMIN,
            Capability::CAP_DAC_OVERRIDE,
        ] {
            assert!(dropped.contains(&cap), "{cap} kept");
        }

        // Any other thread that never enters, such as the TUI's shutdown
        // deadline or a capture thread that failed to open, keeps nothing.
        for role in [Role::Parser, Role::Capture, Role::Network, Role::Main] {
            assert!(kept_unconfined(role).is_empty(), "{role:?}");
            assert_eq!(
                relinquish_set(&full, kept_unconfined(role)).len(),
                full.len()
            );
        }

        // On a real thread, whatever it held, only those two remain.
        let (report, permitted) = std::thread::spawn(|| {
            let mut report = Report::default();
            relinquish_caps(Role::Broker, &mut report);
            (report, caps::read(None, CapSet::Permitted).unwrap())
        })
        .join()
        .unwrap();
        assert!(
            report.mode.warnings.is_empty(),
            "{:?}",
            report.mode.warnings
        );
        assert!(
            permitted.iter().all(|c| CAPS_FOR_PROC_BROKER.contains(c)),
            "{permitted:?}"
        );
    }

    #[test]
    fn unprivileged_runs_drop_nothing_and_warn_about_nothing() {
        std::thread::spawn(|| {
            if !caps::read(None, CapSet::Permitted).unwrap().is_empty() {
                // A privileged test run; the user-namespace lab covers it.
                return;
            }
            let mut report = Report::default();
            drop_caps(
                Mode::Strict,
                super::super::Retain::Nothing,
                Role::Parser,
                CaptureAuthority::DropAfterOpen,
                &mut report,
            );
            assert_eq!(report.platform.capture_authority, NetRaw::NotHeld);
            relinquish_caps(Role::Broker, &mut report);
            assert!(
                report.mode.warnings.is_empty(),
                "{:?}",
                report.mode.warnings
            );
            assert!(report.platform.caps_dropped.is_empty());
            assert!(report.platform.caps_retained.is_empty());
            assert_eq!(report.platform.capture_authority, NetRaw::NotHeld);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn besteffort_still_drops_bpf_caps_after_kprobe_attached() {
        // BPF caps (CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN) aren't needed at
        // runtime once the kprobe is attached and the ringbuffer is open,
        // so they stay in the default drop list even in BestEffort.
        for cap in [
            Capability::CAP_BPF,
            Capability::CAP_PERFMON,
            Capability::CAP_SYS_ADMIN,
        ] {
            assert!(
                CAPS_TO_DROP_DEFAULT.contains(&cap),
                "{cap:?} should be dropped in BestEffort"
            );
        }
    }

    /// Apply `role`'s best-effort policy on the calling thread, as a TUI
    /// session would.
    fn enter_as(role: Role, paths: &SandboxPaths) -> Report {
        enter_under(role, paths, CaptureAuthority::RetainForReopen)
    }

    /// Apply `role`'s best-effort policy on the calling thread under
    /// `authority`.
    fn enter_under(role: Role, paths: &SandboxPaths, authority: CaptureAuthority) -> Report {
        let mut report = Report::default();
        apply(
            Mode::BestEffort,
            paths,
            super::super::Retain::Nothing,
            role,
            authority,
            &mut report,
        );
        report
    }

    /// Whether the kernel can deny TCP, asked apart from the layer under test.
    fn kernel_denies_tcp() -> bool {
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessNet::from_all(PARSER_NET_ABI))
            .is_ok()
    }

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("netwatch-roles-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn layer_restrictions_follow_the_kernel_abi() {
        let parser = |abi| layer_restrictions(abi, true, false, true);
        assert!(parser(ABI::Unsupported).is_empty());
        assert!(parser(ABI::V3).is_empty());
        assert_eq!(parser(ABI::V4), ["tcp_bind", "tcp_connect"]);
        assert_eq!(parser(ABI::V5), ["tcp_bind", "tcp_connect"]);
        assert_eq!(
            parser(ABI::V6),
            ["tcp_bind", "tcp_connect", "abstract_unix_socket", "signal"]
        );
        // Without erratum 2's fix the signal scope is never requested.
        assert_eq!(
            layer_restrictions(ABI::V8, true, false, false),
            ["tcp_bind", "tcp_connect", "abstract_unix_socket"]
        );
        assert_eq!(
            parser(ABI::V9),
            [
                "tcp_bind",
                "tcp_connect",
                "abstract_unix_socket",
                "signal",
                "pathname_unix_socket"
            ]
        );
        assert_eq!(
            layer_restrictions(ABI::V3, true, true, true),
            ["filesystem_write"]
        );
        assert!(layer_restrictions(ABI::V9, false, true, true).is_empty());
    }

    #[test]
    fn strict_parser_layer_requires_tcp() {
        // Strict fails the layer, and with it every parser entry, on a kernel
        // that cannot deny TCP; best-effort builds it anyway.
        assert_eq!(
            prepare_parser_layer(Mode::Strict).is_ok(),
            kernel_denies_tcp()
        );
        assert!(prepare_parser_layer(Mode::BestEffort).is_ok());
    }

    #[test]
    fn parser_layer_denies_tcp_bind_and_connect() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let denies = kernel_denies_tcp();
        std::thread::spawn(move || {
            let report = enter_as(Role::Parser, &SandboxPaths::default());
            let connect = std::net::TcpStream::connect(addr).map(|_| ());
            let bind = std::net::TcpListener::bind("127.0.0.1:0").map(|_| ());
            assert_eq!(report.platform.landlock_layer, Some("parser"));
            if denies {
                assert!(report.platform.landlock_network_blocked, "{report:?}");
                assert_eq!(connect.unwrap_err().raw_os_error(), Some(nix::libc::EACCES));
                assert_eq!(bind.unwrap_err().raw_os_error(), Some(nix::libc::EACCES));
                // A kernel without the scopes or pathname sockets is no
                // reason to warn.
                assert!(
                    report.mode.warnings.is_empty(),
                    "{:?}",
                    report.mode.warnings
                );
            } else {
                assert!(!report.platform.landlock_network_blocked, "{report:?}");
                assert!(!report
                    .platform
                    .landlock_restrictions
                    .contains(&"tcp_connect"));
                connect.unwrap();
                bind.unwrap();
            }
        })
        .join()
        .unwrap();
    }

    #[test]
    fn parser_layer_leaves_udp_open() {
        // Landlock mediates TCP only. The threat model says so; this fails if
        // that changes under it.
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = peer.local_addr().unwrap();
        std::thread::spawn(move || {
            enter_as(Role::Parser, &SandboxPaths::default());
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.send_to(b"udp", addr).unwrap();
        })
        .join()
        .unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0; 8];
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"udp");
    }

    #[test]
    fn parser_layer_leaves_fast_open_and_autobind_open() {
        // Landlock checks connect(2) and bind(2). A TCP Fast Open sendto
        // connects without the first, and listen(2) on an unbound socket
        // takes an ephemeral port on every address without the second. The
        // threat model says so; this fails if that changes under it.
        use nix::sys::socket::{
            listen, sendto, socket, AddressFamily, Backlog, MsgFlags, SockFlag, SockType,
            SockaddrIn,
        };
        use std::os::fd::AsRawFd;
        if !kernel_denies_tcp() {
            eprintln!("skipped: kernel Landlock ABI below 4");
            return;
        }
        let outside = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(addr) = outside.local_addr().unwrap() else {
            unreachable!()
        };
        // Bit 0 enables the client side; it is on by default.
        let fast_open = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_fastopen")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .is_some_and(|v| v & 1 != 0);
        let (sent, stream, server) = std::thread::spawn(move || {
            let report = enter_as(Role::Parser, &SandboxPaths::default());
            assert!(report.platform.landlock_network_blocked, "{report:?}");
            let tcp = || {
                socket(
                    AddressFamily::Inet,
                    SockType::Stream,
                    SockFlag::empty(),
                    None,
                )
            };
            let stream = tcp().unwrap();
            assert_eq!(
                std::net::TcpStream::connect(addr)
                    .unwrap_err()
                    .raw_os_error(),
                Some(nix::libc::EACCES)
            );
            let sent = fast_open.then(|| {
                sendto(
                    stream.as_raw_fd(),
                    b"fast-open",
                    &SockaddrIn::from(addr),
                    MsgFlags::from_bits_retain(nix::libc::MSG_FASTOPEN),
                )
            });
            let server = tcp().unwrap();
            listen(&server, Backlog::new(1).unwrap()).unwrap();
            (
                sent,
                std::net::TcpStream::from(stream),
                std::net::TcpListener::from(server),
            )
        })
        .join()
        .unwrap();

        if let Some(sent) = sent {
            assert_eq!(sent, Ok(9));
            outside.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut accepted = loop {
                match outside.accept() {
                    Ok((accepted, _)) => break accepted,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline, "nothing arrived");
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            accepted.set_nonblocking(false).unwrap();
            accepted
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut data = [0; 9];
            std::io::Read::read_exact(&mut accepted, &mut data).unwrap();
            assert_eq!(&data, b"fast-open");
        }
        drop(stream);

        let bound = server.local_addr().unwrap();
        assert!(bound.ip().is_unspecified(), "{bound}");
        std::net::TcpStream::connect(("127.0.0.1", bound.port())).unwrap();
    }

    #[test]
    fn parser_layer_scopes_abstract_sockets_and_signals() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("netwatch-roles-{}", uuid::Uuid::new_v4());
        let address = std::os::unix::net::SocketAddr::from_abstract_name(&name).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind_addr(&address).unwrap();
        // A process outside the thread's domain, and this process.
        let mut outside = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let outside_pid = nix::unistd::Pid::from_raw(outside.id() as i32);
        // Each check holds the report to what the kernel did, both ways.
        let checked = std::thread::spawn(move || {
            let report = enter_as(Role::Parser, &SandboxPaths::default());
            let restrictions = report.platform.landlock_restrictions;
            let connect = std::os::unix::net::UnixStream::connect_addr(&address);
            if restrictions.contains(&"abstract_unix_socket") {
                assert_eq!(connect.unwrap_err().raw_os_error(), Some(nix::libc::EPERM));
            } else {
                connect.unwrap();
            }
            let signal = nix::sys::signal::kill(outside_pid, None);
            if restrictions.contains(&"signal") {
                assert_eq!(signal, Err(nix::errno::Errno::EPERM));
            } else {
                signal.unwrap();
            }
            // Signalling its own process stays allowed: the scope is only
            // added on kernels with that fixed.
            nix::sys::signal::kill(nix::unistd::getpid(), None).unwrap();
        })
        .join();
        let _ = outside.kill();
        let _ = outside.wait();
        checked.unwrap();
    }

    #[test]
    fn network_role_gets_no_parser_layer() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        for role in [Role::Network, Role::Main] {
            std::thread::spawn(move || {
                let report = enter_as(role, &SandboxPaths::default());
                assert_eq!(report.platform.landlock_layer, None);
                assert!(report.platform.landlock_restrictions.is_empty());
                assert!(!report.platform.landlock_network_blocked);
                std::net::TcpStream::connect(addr).unwrap();
            })
            .join()
            .unwrap();
        }
    }

    #[test]
    fn drop_list_for_authority() {
        // The drop itself is checked below, in a user namespace, which CI's
        // runners refuse. This checks the list without one. Parser and
        // capture threads drop CAP_NET_RAW in every mode; main and the
        // network workers only where capture never reopens.
        for mode in [Mode::BestEffort, Mode::Strict] {
            let strict = matches!(mode, Mode::Strict);
            for authority in [
                CaptureAuthority::RetainForReopen,
                CaptureAuthority::DropAfterOpen,
            ] {
                let after_open = authority == CaptureAuthority::DropAfterOpen;
                for (role, drops) in [
                    (Role::Parser, true),
                    (Role::Capture, true),
                    (Role::Broker, true),
                    (Role::Network, strict || after_open),
                    (Role::Main, strict || after_open),
                ] {
                    let drop = drop_list(mode, role, authority);
                    assert_eq!(
                        drop.contains(&Capability::CAP_NET_RAW),
                        drops,
                        "{role:?} in {mode:?} under {authority:?}"
                    );
                    assert!(
                        drop.contains(&Capability::CAP_NET_ADMIN),
                        "{role:?} in {mode:?} under {authority:?}"
                    );
                    assert!(CAPS_TO_DROP_DEFAULT.iter().all(|cap| drop.contains(cap)));
                }
            }
        }
    }

    #[test]
    fn denied_thread_drops_cap_net_raw_only_on_itself() {
        if !super::super::audit::as_root_in_user_namespace(
            "sandbox::linux::tests::denied_thread_drops_cap_net_raw_only_on_itself",
        ) {
            return;
        }
        let held = |cap, set| caps::has_cap(None, set, cap).unwrap();
        // The sets the calling thread holds `cap` in, by name.
        let in_all = move |cap| {
            ALL_SETS
                .iter()
                .filter(|&&set| held(cap, set))
                .map(|set| format!("{set:?}"))
                .collect::<Vec<_>>()
        };
        for (authority, network_keeps) in [
            (CaptureAuthority::RetainForReopen, true),
            (CaptureAuthority::DropAfterOpen, false),
        ] {
            for (role, keeps) in [
                (Role::Parser, false),
                (Role::Capture, false),
                (Role::Network, network_keeps),
                (Role::Main, network_keeps),
            ] {
                let (report, net_raw, net_admin) = std::thread::spawn(move || {
                    let report = enter_under(role, &SandboxPaths::default(), authority);
                    (
                        report,
                        in_all(Capability::CAP_NET_RAW),
                        in_all(Capability::CAP_NET_ADMIN),
                    )
                })
                .join()
                .unwrap();
                let context = format!("{role:?} under {authority:?}: {report:?}");
                // Root in a user namespace holds every capability in its
                // Effective, Permitted and Bounding sets, none Inheritable
                // or Ambient.
                let kept: &[&str] = if keeps {
                    &["Effective", "Permitted"]
                } else {
                    &[]
                };
                assert_eq!(net_raw, kept, "{context}");
                assert!(net_admin.is_empty(), "{context}");
                let dropped = &report.platform.caps_dropped;
                assert_eq!(
                    dropped.contains(&Capability::CAP_NET_RAW.to_string()),
                    !keeps,
                    "{context}"
                );
                assert!(
                    dropped.contains(&Capability::CAP_NET_ADMIN.to_string()),
                    "{context}"
                );
                assert_eq!(
                    report.platform.capture_authority,
                    if keeps {
                        NetRaw::RetainedForReopen
                    } else {
                        NetRaw::Dropped
                    },
                    "{context}"
                );
                assert!(report.mode.warnings.is_empty(), "{context}");
            }
        }
        // The thread that started them keeps both.
        assert!(held(Capability::CAP_NET_RAW, CapSet::Effective));
        assert!(held(Capability::CAP_NET_ADMIN, CapSet::Effective));
    }

    #[test]
    fn capture_role_cannot_write_config() {
        let landlock = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V1))
            .is_ok();
        if !landlock {
            eprintln!("skipped: Landlock is not enabled on this kernel");
            return;
        }
        let root = TestDir::new();
        let paths = SandboxPaths {
            config_dir: Some(root.0.join("config")),
            cache_dir: Some(root.0.join("cache")),
            ..Default::default()
        };
        paths.prepare().unwrap();
        // A parser may save the config, as the Settings overlay does from
        // the UI thread; the capture thread may not.
        for (role, writes) in [(Role::Parser, true), (Role::Capture, false)] {
            let paths = paths.clone();
            let config = root.0.join("config").join("config.toml");
            std::thread::spawn(move || {
                let report = enter_as(role, &paths);
                let wrote = std::fs::write(&config, b"sandbox = \"off\"\n");
                if writes {
                    wrote.unwrap();
                } else {
                    assert_eq!(
                        wrote.unwrap_err().kind(),
                        std::io::ErrorKind::PermissionDenied
                    );
                    assert!(
                        report
                            .platform
                            .landlock_restrictions
                            .contains(&"filesystem_write"),
                        "{report:?}"
                    );
                }
                // The read grants still hold.
                std::fs::read_to_string("/proc/self/status").unwrap();
            })
            .join()
            .unwrap();
        }
    }

    #[test]
    fn capture_role_cannot_connect_pathname_unix() {
        let resolves = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(PARSER_FS)
            .is_ok();
        if !resolves {
            eprintln!("skipped: kernel Landlock ABI below 9");
            return;
        }
        let root = TestDir::new();
        let socket = root.0.join("service.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        for (role, connects) in [
            (Role::Capture, false),
            (Role::Parser, false),
            (Role::Network, true),
        ] {
            let socket = socket.clone();
            std::thread::spawn(move || {
                let report = enter_as(role, &SandboxPaths::default());
                let connect = std::os::unix::net::UnixStream::connect(&socket);
                if connects {
                    connect.unwrap();
                } else {
                    assert!(
                        report
                            .platform
                            .landlock_restrictions
                            .contains(&"pathname_unix_socket"),
                        "{report:?}"
                    );
                    assert_eq!(connect.unwrap_err().raw_os_error(), Some(nix::libc::EACCES));
                }
            })
            .join()
            .unwrap();
        }
    }
}
