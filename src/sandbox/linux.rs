//! Linux sandbox backend — capability drop + Landlock filesystem
//! restrictions.
//!
//! Phase 1 does *not* enable Landlock's network-block (ABI V4) rule. The
//! TUI makes legitimate outbound calls for the ip-api.com GeoIP fallback
//! (cleartext HTTP), `--remote` metric streaming, and inline WHOIS lookups; a
//! blanket TCP-block would silently break working features. A later
//! phase can add port-allow-listing once those endpoints are known at
//! startup.

use super::paths::SandboxPaths;
use super::{Mode, Report};

use caps::{CapSet, Capability, CapsHashSet};
use landlock::{
    Access, AccessFs, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::path::{Path, PathBuf};

/// Highest requested ABI. Only filesystem access types are handled here;
/// compatibility is best-effort on kernels supporting fewer access types.
pub(crate) const TARGET_ABI: ABI = ABI::V4;

/// Capabilities dropped in every mode that runs `drop_caps`.
///
/// Without elevation the thread holds none of them and this changes nothing.
/// Under the documented `setcap` line it takes CAP_BPF and CAP_PERFMON. Under
/// root it takes everything no code path needs after startup (CAP_SYS_PTRACE
/// costs some process names; see below): a confined thread otherwise keeps
/// almost every capability, and with CAP_SYS_RAWIO and the `/proc` grant it
/// could read kernel memory, page cache included, through `/proc/kcore`,
/// which no filesystem rule stops. What root keeps is file
/// access in the user's directories (CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH,
/// CAP_FOWNER, CAP_CHOWN, CAP_FSETID), limits and scheduling
/// (CAP_SYS_RESOURCE, CAP_SYS_NICE, CAP_IPC_LOCK), CAP_NET_BIND_SERVICE for a
/// metrics port below 1024, CAP_NET_RAW to reopen capture (see
/// `CAPS_TO_DROP_STRICT`), and for now CAP_NET_ADMIN.
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
    // that costs something: the connections worker can no longer read
    // `/proc/<pid>/exe` or the `/proc/<pid>/fd` links of a process root does
    // not own, or of one that is not dumpable. Such a process keeps the
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

/// Drop every capability but [`CAPS_FOR_PROC_BROKER`] from the calling
/// thread's Effective, Inheritable, Permitted and Ambient sets. No Landlock.
pub fn relinquish_caps(report: &mut Report) {
    let held = held_caps(report);
    for cap in broker_drop_set(&held) {
        drop_verified(
            cap,
            &[
                CapSet::Effective,
                CapSet::Inheritable,
                CapSet::Permitted,
                CapSet::Ambient,
            ],
            report,
        );
    }
    record_retained(report);
}

/// Everything in `held` the broker does not keep, in capability order.
fn broker_drop_set(held: &CapsHashSet) -> Vec<Capability> {
    let mut drop: Vec<_> = held
        .iter()
        .filter(|cap| !CAPS_FOR_PROC_BROKER.contains(cap))
        .copied()
        .collect();
    drop.sort_by_key(|cap| cap.index());
    drop
}

pub fn apply(mode: Mode, paths: &SandboxPaths, retain: super::Retain, report: &mut Report) {
    report.mode.effective = Some(mode.label());

    drop_caps(mode, retain, report);
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
    if let Err(error) = result {
        report
            .mode
            .warnings
            .push(format!("Landlock not applied: {error}"));
    }

    if matches!(mode, Mode::Strict) && report.platform.landlock_abi == 0 {
        report
            .mode
            .warnings
            .push("strict sandbox requested but Landlock did not enforce".into());
    }
}

fn drop_caps(mode: Mode, retain: super::Retain, report: &mut Report) {
    let extra: &[Capability] = if matches!(mode, Mode::Strict) {
        CAPS_TO_DROP_STRICT
    } else {
        &[]
    };
    let held = held_caps(report);
    for cap in CAPS_TO_DROP_DEFAULT.iter().chain(extra.iter()) {
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
            drop_verified(
                *cap,
                &[CapSet::Effective, CapSet::Inheritable, CapSet::Permitted],
                report,
            );
        }
    }
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
fn collect_read_only(paths: &SandboxPaths) -> Vec<PathBuf> {
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
fn collect_read_write(paths: &SandboxPaths) -> Vec<PathBuf> {
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
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .map_err(|e| e.to_string())?
        .create()
        .map_err(|e| e.to_string())?;
    for (paths_to_open, write) in [
        (collect_read_only(paths), false),
        (collect_read_write(paths), true),
    ] {
        for path in paths_to_open {
            let configured_file = [
                &paths.geoip_db_dir,
                &paths.geoip_asn_db_dir,
                &paths.keylog_dir,
            ]
            .into_iter()
            .flatten()
            .any(|p| *p == path);
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(nix::libc::O_PATH | if write { nix::libc::O_NOFOLLOW } else { 0 });
            let file = match options.open(&path) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && !write => continue,
                Err(e) => return Err(format!("{}: {e}", path.display())),
            };
            let meta = file.metadata().map_err(|e| e.to_string())?;
            if configured_file && !meta.is_file() {
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
            let mut access = if write {
                AccessFs::from_all(TARGET_ABI)
            } else {
                AccessFs::from_read(TARGET_ABI)
            };
            if !meta.is_dir() {
                access &= AccessFs::ReadFile
                    | AccessFs::WriteFile
                    | AccessFs::Execute
                    | AccessFs::Truncate;
            }
            if configured_file {
                access = AccessFs::ReadFile.into();
            }
            ruleset = ruleset
                .add_rule(PathBeneath::new(file, access))
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(ruleset)
}

fn enforce(ruleset: landlock::RulesetCreated, report: &mut Report) -> Result<(), String> {
    let status = ruleset.restrict_self().map_err(|e| e.to_string())?;

    // Record the effective ABI for the Settings overlay. `landlock`
    // exposes the effective ABI inside `LandlockStatus::Available`.
    match status.landlock {
        landlock::LandlockStatus::Available { effective_abi, .. } => {
            report.platform.landlock_abi = effective_abi as u32;
        }
        landlock::LandlockStatus::NotEnabled | landlock::LandlockStatus::NotImplemented => {
            // Ruleset wasn't enforced — keep landlock_abi at 0.
        }
    }

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

    Ok(())
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
        drop_caps(Mode::BestEffort, super::super::Retain::Nothing, &mut report);
        assert!(
            report.platform.caps_retained_for_load.is_empty(),
            "an ordinary worker keeps nothing back: {:?}",
            report.platform.caps_retained_for_load
        );

        let mut report = Report::default();
        drop_caps(Mode::BestEffort, super::super::Retain::BpfLoad, &mut report);
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
        // via `i`, Flight Recorder arm) need CAP_NET_RAW. Dropping it in
        // BestEffort produced "Capture failed: libpcap error: socket:
        // Operation not permitted" on Linux NUCs. Strict still drops it
        // — those users opted in to fail-closed semantics.
        assert!(
            !CAPS_TO_DROP_DEFAULT.contains(&Capability::CAP_NET_RAW),
            "BestEffort must keep CAP_NET_RAW so capture toggle works"
        );
        assert!(
            CAPS_TO_DROP_STRICT.contains(&Capability::CAP_NET_RAW),
            "Strict mode should still drop CAP_NET_RAW (opt-in trade-off)"
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
        ] {
            assert!(CAPS_TO_DROP_DEFAULT.contains(&cap), "{cap} kept under root");
        }
        // Everything else is kept on purpose: a root session's file access in
        // the user's directories, limits and scheduling, a low metrics port,
        // reopening capture, and for now CAP_NET_ADMIN. A capability in
        // neither list, such as one a caps upgrade adds, fails here until
        // someone decides.
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
            Capability::CAP_NET_ADMIN,
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
        let dropped = broker_drop_set(&full);
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

        // On a real thread, whatever it held, only those two remain.
        let (report, permitted) = std::thread::spawn(|| {
            let mut report = Report::default();
            relinquish_caps(&mut report);
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
            drop_caps(Mode::Strict, super::super::Retain::Nothing, &mut report);
            relinquish_caps(&mut report);
            assert!(
                report.mode.warnings.is_empty(),
                "{:?}",
                report.mode.warnings
            );
            assert!(report.platform.caps_dropped.is_empty());
            assert!(report.platform.caps_retained.is_empty());
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
}
