//! Security sandbox — restrict netwatch's authority after pcap + eBPF setup.
//!
//! Designed to mirror rustnet's three-OS approach (Landlock / Seatbelt /
//! restricted token) but shipped in phases:
//!
//! - **Phase 1 (this module): Linux** — `caps` drop + `landlock` filesystem
//!   and network restrictions. Applied after `ConnTracker::new()` returns
//!   so the kprobe is already attached and pcap fds are already open.
//! - **Phase 2: macOS Seatbelt** — inline SBPL profile via
//!   `sandbox_init_with_parameters` (stubbed below).
//! - **Phase 3: Windows** — restricted token + job object (stubbed below).
//!
//! The application boundary the sandbox draws around netwatch:
//!
//! - Read: `/proc`, configured GeoIP dbs, config dir, cache/log dir,
//!   `/etc/{resolv,hosts,services}.conf`, zoneinfo, configured PCAP export
//!   dir.
//! - Write: cache/log dir, Flight Recorder bundle dir, configured PCAP
//!   export dir.
//! - Network (Landlock ABI V4 / kernel ≥ 6.4 only): block new TCP bind +
//!   connect. Existing pcap and remote-publisher sockets unaffected.
//! - Caps (Linux): drop CAP_NET_RAW, CAP_BPF, CAP_PERFMON.

pub mod paths;

#[cfg(target_os = "linux")]
mod linux;

pub use paths::SandboxPaths;

/// Sandbox enforcement mode, selected via CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `--no-sandbox`: skip all enforcement. Escape hatch for debugging.
    Disabled,
    /// Default. Apply what the platform supports; degrade silently on old
    /// kernels (e.g., Landlock unavailable, ABI < V4 means no network
    /// restriction). Log a single warning when degraded.
    BestEffort,
    /// `--sandbox-strict`: fail to start if any platform-supported
    /// restriction can't be applied. Intended for CI / production
    /// deployments where the user wants a hard guarantee.
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

/// What the sandbox actually applied. Surfaced in the Settings overlay so
/// users can confirm enforcement happened, and consumed by `Mode::Strict`
/// to decide whether to abort startup.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub mode: ModeReport,
    pub platform: PlatformReport,
}

#[derive(Debug, Clone, Default)]
pub struct ModeReport {
    /// Effective mode after fallback (e.g., Strict downgraded to
    /// BestEffort when the platform has no backend).
    pub effective: Option<&'static str>,
    /// Human-readable warning shown in Settings + logged once at startup.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PlatformReport {
    /// Linux: Landlock ABI level actually enforced (0 = not applied).
    pub landlock_abi: u32,
    /// Linux: whether the network-block ruleset was applied (ABI ≥ V4 only).
    pub landlock_network_blocked: bool,
    /// Linux: capabilities dropped (names as the `caps` crate spells them).
    pub caps_dropped: Vec<String>,
    /// macOS: whether `sandbox_init_with_parameters` returned 0.
    pub macos_seatbelt: bool,
    /// Windows: whether the restricted-token + job-object pair applied.
    pub windows_restricted: bool,
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
                        parts.push(format!("Landlock ABI V{}", self.platform.landlock_abi));
                    }
                    if self.platform.landlock_network_blocked {
                        parts.push("network blocked".into());
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

/// Apply the sandbox. Call once, after every privileged fd (pcap handles,
/// eBPF ring buffer, remote-publisher socket) is already open.
///
/// Returns the Report unconditionally. In `Mode::Strict`, callers should
/// check `report.mode.warnings` and abort if non-empty.
pub fn apply(mode: Mode, paths: &SandboxPaths) -> Report {
    let mut report = Report::default();

    if matches!(mode, Mode::Disabled) {
        report.mode.effective = Some("disabled");
        return report;
    }

    #[cfg(target_os = "linux")]
    {
        linux::apply(mode, paths, &mut report);
    }

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
