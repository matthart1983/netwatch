//! Per-thread Linux filesystem enforcement using a prepared, pinned ruleset.
//! Application worker entry points apply policy before processing; capture
//! prepares its device first. Strict entry failure withholds processing.
//! Main applies the same policy after resource startup. No network restrictions
//! are installed, and macOS/Windows/FreeBSD have no filesystem backend.
//!
//! Selected capability removals are checked after each attempt. Best-effort
//! retains CAP_NET_RAW; strict drops it, so later capture reopening may fail.
//! Worker reports describe policy entry, not an exploit-proof process boundary.
//! The eBPF SDK reader inherits filesystem policy but retains load capabilities.
//! See docs/THREAT-MODEL.md for the remaining containment limits.

pub mod paths;
pub mod worker;

#[cfg(target_os = "linux")]
mod linux;

pub use paths::SandboxPaths;

/// Sandbox enforcement mode, selected via CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `--no-sandbox`: skip all enforcement. Escape hatch for debugging.
    Disabled,
    /// Default. Attempt supported filesystem restrictions and report warnings
    /// on degradation. Network restrictions are not installed in any mode.
    BestEffort,
    /// `--sandbox-strict`: callers abort on reported application warnings.
    /// This does not establish worker confinement or successful capability drops.
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
    /// Linux: Landlock ABI level actually enforced (0 = not applied).
    pub landlock_abi: u32,
    /// Reserved for network restrictions; the current backend leaves this false.
    pub landlock_network_blocked: bool,
    /// Linux: capabilities present before removal and verified absent afterward.
    pub caps_dropped: Vec<String>,
    /// Effective capabilities still held after verified drop attempts.
    pub caps_retained: Vec<String>,
    /// Capabilities entry deliberately left in place for a load that needs
    /// them, which the worker then drops itself. Reported separately from
    /// `caps_retained` so "still held because the policy kept it" cannot be
    /// read as "the drop failed".
    pub caps_retained_for_load: Vec<String>,
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

/// Apply restrictions to the calling thread. Current callers invoke this
/// after App construction; this does not confine already-running workers.
///
/// Returns the Report unconditionally. In `Mode::Strict`, callers should
/// check `report.mode.warnings` and abort if non-empty.
pub fn apply(mode: Mode, paths: &SandboxPaths) -> Report {
    apply_retaining(mode, paths, Retain::Nothing)
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

/// [`apply`], keeping the capabilities `retain` names.
pub fn apply_retaining(mode: Mode, paths: &SandboxPaths, retain: Retain) -> Report {
    let mut report = Report::default();

    if matches!(mode, Mode::Disabled) {
        report.mode.effective = Some("disabled");
        return report;
    }

    #[cfg(target_os = "linux")]
    {
        linux::apply(mode, paths, retain, &mut report);
    }

    #[cfg(not(target_os = "linux"))]
    let _ = retain;

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
