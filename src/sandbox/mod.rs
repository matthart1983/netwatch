//! Per-thread Linux enforcement using prepared, pinned rulesets. Every
//! confined thread takes the filesystem layer. Parser and capture threads
//! ([`roles`]) stack a second layer on it that denies TCP bind and connect,
//! connecting to Unix sockets outside the thread's domain and, on a kernel
//! with the erratum 2 fix, signalling outside it. Capture's layer also
//! leaves it no write grant. Main and the network workers keep the network.
//! Application worker entry points apply policy before processing; capture
//! prepares its device first. Strict entry failure withholds processing, and
//! strict requires the TCP deny (Landlock ABI 4, Linux 6.7). Capture, keylog and
//! the metrics threads ([`roles::no_sockets`]) also take a seccomp filter that
//! returns EPERM for socket(2) and io_uring_setup(2). Main applies its policy
//! after resource startup. macOS, Windows and FreeBSD have no backend.
//!
//! Selected capability removals are checked after each attempt. Every
//! confined thread drops CAP_NET_ADMIN, which nothing uses. A best-effort TUI
//! keeps CAP_NET_RAW on main and the network workers so capture can reopen
//! ([`CaptureAuthority`]); parser and capture threads drop it in every mode,
//! and the daemon, the Diagnose CLI and strict drop it on every confined
//! thread, so a later capture reopen fails there. Once main has entered,
//! [`audit`] checks every thread of the process for either capability.
//! Worker reports describe policy entry, not an exploit-proof process boundary.
//! The eBPF SDK reader inherits the eBPF worker's policy but retains load
//! capabilities. See docs/THREAT-MODEL.md for the remaining containment limits.

pub mod audit;
pub mod paths;
pub mod roles;
pub mod worker;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod seccomp;

pub use paths::SandboxPaths;
pub use roles::Role;

/// Sandbox enforcement mode, selected via CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `--no-sandbox`: skip all enforcement. Escape hatch for debugging.
    Disabled,
    /// Default. Attempt supported restrictions and report warnings when the
    /// filesystem layer degrades. The parser layer takes what the kernel
    /// offers without a warning.
    BestEffort,
    /// `--sandbox-strict`: callers abort on reported application warnings.
    /// Parser and capture entry warn unless TCP bind and connect are denied,
    /// so strict needs Landlock ABI 4 (Linux 6.7). A kernel refusing the
    /// no-socket filter warns too, on an architecture that has it. This does
    /// not establish worker confinement or successful capability drops.
    Strict,
}

impl Mode {
    pub fn label(&self) -> &'static str {
        match self {
            Mode::Disabled => "disabled",
            Mode::BestEffort => "best-effort",
            Mode::Strict => "strict",
        }
    }

    /// Parse the persistent config string from `NetwatchConfig::sandbox`.
    /// Unknown values fall back to [`Mode::BestEffort`] so a typo doesn't
    /// silently disable enforcement.
    pub fn from_config(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "disabled" | "false" | "no" | "0" => Mode::Disabled,
            "strict" => Mode::Strict,
            _ => Mode::BestEffort,
        }
    }
}

/// Whether main and the network workers keep CAP_NET_RAW after capture has
/// opened.
///
/// Capabilities are per thread, and every capture reopen (`c`, `i`,
/// `Shift+R`) opens a new packet socket on a thread main starts, so keeping
/// the ability to reopen means main keeps CAP_NET_RAW. Dropping it does not
/// revoke the descriptor capture already holds, which can still capture and
/// inject on every interface in the network namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureAuthority {
    /// A best-effort TUI session, which reopens capture on a key press.
    RetainForReopen,
    /// Sessions that open capture once and never reopen it: the daemon,
    /// `diagnose run` and `diagnose coverage`, and any strict session. Also
    /// what a thread gets that enters before the session says which it is.
    DropAfterOpen,
}

/// What a thread's entry left of CAP_NET_RAW, the capability every capture
/// open needs. Reported per component as its capture authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetRaw {
    /// Held before entry and verified absent after it.
    Dropped,
    /// Still held after entry. Main and the network workers keep it under
    /// [`CaptureAuthority::RetainForReopen`]; anywhere else the report's
    /// warnings say why the drop failed.
    RetainedForReopen,
    /// The thread never held it.
    NotHeld,
    /// No capability backend ran, off Linux or with the sandbox disabled.
    #[default]
    NotApplicable,
}

impl NetRaw {
    pub fn label(self) -> &'static str {
        match self {
            NetRaw::Dropped => "dropped",
            NetRaw::RetainedForReopen => "retained_for_reopen",
            NetRaw::NotHeld => "not_held",
            NetRaw::NotApplicable => "not_applicable",
        }
    }
}

/// What became of a thread's no-socket filter ([`roles::no_sockets`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SocketFilter {
    /// On the thread: socket(2) and io_uring_setup(2) return EPERM there and in
    /// what it starts.
    Installed,
    /// Skipped: this build's architecture has no syscall table. Not a warning,
    /// so strict runs without it.
    UnknownArch,
    /// The kernel refused it. The report's warnings say why, and strict
    /// refuses the entry.
    Failed,
    /// The thread's worker takes none, the sandbox is disabled or this is not
    /// Linux.
    #[default]
    NotApplicable,
}

impl SocketFilter {
    pub fn label(self) -> &'static str {
        match self {
            SocketFilter::Installed => "installed",
            SocketFilter::UnknownArch => "unknown_arch",
            SocketFilter::Failed => "failed",
            SocketFilter::NotApplicable => "not_applicable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_parses_known_values() {
        assert_eq!(Mode::from_config("on"), Mode::BestEffort);
        assert_eq!(Mode::from_config("ON"), Mode::BestEffort);
        assert_eq!(Mode::from_config("strict"), Mode::Strict);
        assert_eq!(Mode::from_config("Strict "), Mode::Strict);
        assert_eq!(Mode::from_config("off"), Mode::Disabled);
        assert_eq!(Mode::from_config("disabled"), Mode::Disabled);
        assert_eq!(Mode::from_config("false"), Mode::Disabled);
    }

    #[test]
    fn from_config_unknown_falls_back_to_best_effort() {
        // A typo should not silently disable enforcement — that would
        // change security behavior in a way the user didn't ask for.
        assert_eq!(Mode::from_config("loose"), Mode::BestEffort);
        assert_eq!(Mode::from_config(""), Mode::BestEffort);
    }
}

/// Results of the calling-thread sandbox application, surfaced in Settings.
/// This is not a verified worker or capability inventory. Strict callers use
/// reported warnings to decide whether to abort startup.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub mode: ModeReport,
    pub platform: PlatformReport,
}

#[derive(Debug, Clone, Default)]
pub struct ModeReport {
    /// Requested application mode; unsupported strict mode produces warnings
    /// for the caller to reject rather than downgrading to best-effort.
    pub effective: Option<&'static str>,
    /// Human-readable warning shown in Settings + logged once at startup.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PlatformReport {
    /// Linux: the Landlock ABI of what this thread actually enforces: the
    /// newest feature in force (`linux::enforced_abi`). The filesystem
    /// layer alone is ABI 3 at most, whatever the kernel. 0 = not applied.
    pub landlock_abi: u32,
    /// Linux: the ABI the kernel reports, 0 without Landlock.
    pub landlock_kernel_abi: u32,
    /// Linux: `available`, `not_enabled` or `not_built`. `None` before the
    /// kernel has been asked, or when the layer could not be built to ask.
    pub landlock_availability: Option<&'static str>,
    /// Linux: connect(2) and bind(2) on TCP sockets denied on this thread by
    /// its parser or capture layer. The network stays reachable: UDP, MPTCP,
    /// a TCP Fast Open send and listen(2) on an unbound socket all get past
    /// it (docs/THREAT-MODEL.md, item 4). Main and the network workers leave
    /// this false.
    pub landlock_network_blocked: bool,
    /// Linux: the layer this thread's role stacks on the filesystem one,
    /// "parser" or "capture", whether or not the kernel enforced it. `None`
    /// for main and the network workers.
    pub landlock_layer: Option<&'static str>,
    /// Linux: what this thread's entry enforced on this kernel: `filesystem`,
    /// then from the role's layer `filesystem_write` (capture only),
    /// `tcp_bind`, `tcp_connect`, `abstract_unix_socket`, `signal` and
    /// `pathname_unix_socket`. Also `socket_create`, which is the seccomp filter
    /// rather than Landlock, when it is on the thread.
    pub landlock_restrictions: Vec<&'static str>,
    /// Linux: the no-socket filter, for the workers that take it.
    pub socket_filter: SocketFilter,
    /// Linux: capabilities present before removal and verified absent afterward.
    pub caps_dropped: Vec<String>,
    /// Effective capabilities still held after verified drop attempts.
    pub caps_retained: Vec<String>,
    /// Capabilities entry deliberately left in place for a load that needs
    /// them, which the worker then drops itself. Reported separately from
    /// `caps_retained` so "still held because the policy kept it" cannot be
    /// read as "the drop failed".
    pub caps_retained_for_load: Vec<String>,
    /// Linux: what this thread's entry did with CAP_NET_RAW. Which threads of
    /// the process still hold it is process-wide, in [`audit`].
    pub capture_authority: NetRaw,
    /// macOS: whether `sandbox_init_with_parameters` returned 0.
    pub macos_seatbelt: bool,
    /// Windows: whether the restricted-token + job-object pair applied.
    pub windows_restricted: bool,
}

impl PlatformReport {
    /// Whether this thread's TCP bind and connect are denied, as doctor
    /// reports it. Which sockets that does and does not stop is in
    /// docs/THREAT-MODEL.md, item 4.
    pub fn network_policy(&self) -> &'static str {
        if self.landlock_network_blocked {
            "denied"
        } else {
            "allowed"
        }
    }
}

impl Report {
    /// One-line summary for logs and the Settings overlay header.
    pub fn summary(&self) -> String {
        if let Some(mode) = self.mode.effective {
            match mode {
                "disabled" => "disabled".to_string(),
                _ => {
                    let mut parts: Vec<String> = Vec::new();
                    if self.platform.landlock_abi > 0 {
                        // Without a layer on top it is the filesystem layer.
                        let scope = if self.platform.landlock_layer.is_some() {
                            ""
                        } else {
                            " fs"
                        };
                        parts.push(format!(
                            "Landlock{scope} ABI {} (kernel {})",
                            self.platform.landlock_abi, self.platform.landlock_kernel_abi
                        ));
                    }
                    if self.platform.landlock_network_blocked {
                        parts.push("TCP connect and bind denied".into());
                    }
                    if !self.platform.caps_dropped.is_empty() {
                        parts.push(format!("{} caps dropped", self.platform.caps_dropped.len()));
                    }
                    if self.platform.macos_seatbelt {
                        parts.push("Seatbelt".into());
                    }
                    if self.platform.windows_restricted {
                        parts.push("restricted token".into());
                    }
                    if parts.is_empty() {
                        format!("{mode} (no restrictions applied)")
                    } else {
                        format!("{mode}: {}", parts.join(", "))
                    }
                }
            }
        } else {
            "unknown".to_string()
        }
    }
}

/// Apply main's restrictions to the calling thread. Current callers invoke
/// this after App construction; this does not confine already-running
/// workers.
///
/// Returns the Report unconditionally. In `Mode::Strict`, callers should
/// check `report.mode.warnings` and abort if non-empty.
pub fn apply(mode: Mode, paths: &SandboxPaths) -> Report {
    apply_retaining(mode, paths, Retain::Nothing, Role::Main)
}

/// Capabilities a worker keeps through entry.
///
/// Loading a BPF program needs CAP_BPF and CAP_PERFMON, and entry drops
/// both — so the eBPF worker would confine itself out of the one syscall it
/// exists to make. It enters with the filesystem policy applied and those two
/// capabilities held, loads, and drops them itself before reading a single
/// event. Nothing else uses this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retain {
    Nothing,
    /// CAP_BPF, CAP_PERFMON and the pre-5.8 CAP_SYS_ADMIN fallback.
    BpfLoad,
}

/// The Landlock errata this kernel reports fixed, by erratum number. Empty off
/// Linux and on a kernel without the interface.
pub fn landlock_errata() -> Vec<u32> {
    #[cfg(target_os = "linux")]
    return linux::fixed_errata();
    #[cfg(not(target_os = "linux"))]
    Vec::new()
}

/// Take socket(2) from the calling thread and everything it starts, after
/// its Landlock layers, and add the outcome to `report`. Only the Linux
/// backend has this, and disabled mode installs nothing.
pub fn deny_socket_create(mode: Mode, report: &mut Report) {
    if matches!(mode, Mode::Disabled) {
        return;
    }
    #[cfg(target_os = "linux")]
    seccomp::install(report);
    #[cfg(not(target_os = "linux"))]
    let _ = report;
}

/// [`apply`] with `role`'s policy, keeping the capabilities `retain` names.
pub fn apply_retaining(mode: Mode, paths: &SandboxPaths, retain: Retain, role: Role) -> Report {
    let mut report = Report::default();

    if matches!(mode, Mode::Disabled) {
        report.mode.effective = Some("disabled");
        return report;
    }

    #[cfg(target_os = "linux")]
    {
        let authority = worker::capture_authority();
        linux::apply(mode, paths, retain, role, authority, &mut report);
    }

    #[cfg(not(target_os = "linux"))]
    let _ = (retain, role);

    #[cfg(not(target_os = "linux"))]
    {
        // Phase 2/3 land platform backends here. Until then, Strict on
        // an unsupported platform should not silently succeed.
        let _ = paths;
        report.mode.effective = Some(mode.label());
        if matches!(mode, Mode::Strict) {
            report
                .mode
                .warnings
                .push("strict sandbox requested but no backend on this platform".into());
        } else {
            report
                .mode
                .warnings
                .push("sandbox not yet implemented on this platform".into());
        }
    }

    report
}

#[cfg(test)]
mod threat_model_tests;
