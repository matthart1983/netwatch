//! Observed capability state, shared by doctor and live presentation. Static
//! inspection never starts collectors, loads Npcap, or contacts an endpoint.
use crate::{
    app::{App, AttributionStatus},
    config::NetwatchConfig,
    sandbox::{self, Mode},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Ready,
    NotChecked,
    Unavailable,
    Disabled,
    Degraded,
    Stale,
}
impl State {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NotChecked => "not checked",
            Self::Unavailable => "unavailable",
            Self::Disabled => "disabled",
            Self::Degraded => "degraded",
            Self::Stale => "stale",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    pub state: State,
    pub reason: String,
    pub detail: String,
    pub next_check: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Protection {
    pub component: String,
    pub entry_ready: bool,
    pub effective: Option<String>,
    pub landlock_abi: u32,
    pub caps_dropped: Vec<String>,
    pub caps_retained: Vec<String>,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}
impl Protection {
    fn from_report(
        name: &str,
        ready: bool,
        report: Option<&sandbox::Report>,
        error: Option<String>,
    ) -> Self {
        Self {
            component: name.into(),
            entry_ready: ready,
            effective: report.and_then(|r| r.mode.effective.map(str::to_owned)),
            landlock_abi: report.map_or(0, |r| r.platform.landlock_abi),
            caps_dropped: report
                .map(|r| r.platform.caps_dropped.clone())
                .unwrap_or_default(),
            caps_retained: report
                .map(|r| r.platform.caps_retained.clone())
                .unwrap_or_default(),
            warnings: report.map(|r| r.mode.warnings.clone()).unwrap_or_default(),
            error,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    pub schema_version: u32,
    pub scope: String,
    pub platform: String,
    pub interface: Option<String>,
    pub capabilities: Vec<Capability>,
    pub protections: Vec<Protection>,
    pub network_restricted: bool,
    #[serde(default)]
    pub attribution_coverage: Option<crate::collectors::attribution::Coverage>,
}
impl CapabilitySnapshot {
    fn configured(config: &NetwatchConfig) -> Self {
        let mut snapshot = Self {
            schema_version: 1,
            scope: "static".into(),
            platform: std::env::consts::OS.into(),
            interface: (!config.capture_interface.is_empty())
                .then(|| config.capture_interface.clone()),
            capabilities: vec![],
            protections: vec![],
            network_restricted: false,
            attribution_coverage: None,
        };
        snapshot.put(
            "config",
            State::NotChecked,
            "not_loaded",
            "Configuration has not been validated",
            Some("netwatch doctor"),
        );
        snapshot.put(
            "interface",
            State::NotChecked,
            "selection_pending",
            "Auto-selection is deferred to live startup",
            Some("doctor --interface NAME --check-capture"),
        );
        snapshot.put(
            "capture_library",
            State::NotChecked,
            "driver_unchecked",
            "Capture dependency has not been checked",
            Some("Install libpcap or Npcap for your platform"),
        );
        snapshot.put(
            "capture",
            State::NotChecked,
            "open_not_attempted",
            "No capture opened; traffic visibility is unknown",
            Some("netwatch doctor --check-capture --interface NAME"),
        );
        let ebpf = cfg!(all(target_os = "linux", feature = "ebpf"));
        let attribution = if ebpf && !matches!(Mode::from_config(&config.sandbox), Mode::Disabled) {
            "eBPF disabled by sandbox policy; socket polling fallback not checked"
        } else if ebpf {
            "eBPF compiled in; initialization and socket fallback not checked"
        } else {
            "Socket polling fallback; kernel attribution not checked"
        };
        snapshot.put(
            "attribution",
            State::NotChecked,
            "backend_unchecked",
            attribution,
            Some("Inspect live Settings for backend and fallback"),
        );
        snapshot.put(
            "probes",
            State::NotChecked,
            "no_active_probes",
            "Gateway, DNS and Internet probes were not sent",
            Some("Open a live session and inspect Diagnose coverage"),
        );
        let tcp_supported = cfg!(any(target_os = "linux", target_os = "macos"));
        snapshot.put(
            "tcp_metrics",
            if tcp_supported {
                State::NotChecked
            } else {
                State::Unavailable
            },
            if tcp_supported {
                "collector_unchecked"
            } else {
                "platform_unsupported"
            },
            "TCP metrics require platform support and a completed observation",
            Some("Inspect live TCP metrics; missing values are not zero"),
        );
        let mode = Mode::from_config(&config.sandbox);
        snapshot.put(
            "sandbox",
            if matches!(mode, Mode::Disabled) {
                State::Disabled
            } else if cfg!(target_os = "linux") {
                State::NotChecked
            } else {
                State::Unavailable
            },
            "policy_not_applied",
            &format!(
                "Requested {:?}; no policy applied by static doctor; networking unrestricted",
                mode
            ),
            Some("Inspect live Settings for component enforcement"),
        );
        for (id, enabled, detail) in [
            (
                "online_geo",
                config.geoip_online,
                "Online GeoIP configured (ip-api.com, cleartext HTTP); endpoint not contacted",
            ),
            (
                "insights",
                config.insights_enabled,
                "Insights configured; endpoint not contacted",
            ),
        ] {
            snapshot.put(
                id,
                if enabled {
                    State::NotChecked
                } else {
                    State::Disabled
                },
                "configuration_only",
                detail,
                Some("Review external-service settings before live use"),
            );
        }
        snapshot.put(
            "whois",
            State::NotChecked,
            "demand_driven",
            "WHOIS may contact external servers in live use; no request sent",
            None,
        );
        snapshot.put(
            "reverse_dns",
            State::NotChecked,
            "demand_driven",
            "Reverse DNS may send live lookup requests; none sent here",
            None,
        );
        snapshot.put(
            "remote",
            State::NotChecked,
            "startup_configuration",
            "Remote publishing is controlled by CLI/environment; no sender started",
            None,
        );
        snapshot.put(
            "metrics",
            State::NotChecked,
            "startup_configuration",
            "Metrics listener is controlled by daemon CLI/environment; none started",
            None,
        );
        snapshot.put("resolver",if cfg!(target_os="linux") {State::NotChecked} else {State::Unavailable},"authority_not_granted","Automatic TUI edits disabled; Linux requires separate confirmed-unmanaged root command",Some("netwatch resolver status"));
        snapshot
    }
    pub fn get(&self, id: &str) -> &Capability {
        self.capabilities
            .iter()
            .find(|c| c.id == id)
            .expect("known capability")
    }
    fn put(&mut self, id: &str, state: State, reason: &str, detail: &str, next: Option<&str>) {
        let item = Capability {
            id: id.into(),
            state,
            reason: reason.into(),
            detail: detail.into(),
            next_check: next.map(str::to_owned),
        };
        if let Some(old) = self.capabilities.iter_mut().find(|c| c.id == id) {
            *old = item;
        } else {
            self.capabilities.push(item);
        }
    }
    pub fn compact(&self) -> String {
        format!(
            "capture: {} · attribution: {} · sandbox: {}",
            self.get("capture").state.label(),
            self.get("attribution").state.label(),
            self.get("sandbox").state.label()
        )
    }
    pub fn text(&self) -> String {
        let mut lines = vec![
            format!("Netwatch doctor · {} · {}", self.platform, self.scope),
            "Ready describes a checked capability, not network health.".into(),
        ];
        for cap in &self.capabilities {
            lines.push(format!(
                "{}: {} [{}]",
                cap.id,
                cap.state.label(),
                cap.reason
            ));
            wrap(&mut lines, &cap.detail);
            if let Some(next) = &cap.next_check {
                wrap(&mut lines, &format!("Next: {next}"));
            }
        }
        lines.join("\n") + "\n"
    }
    pub fn live(app: &App) -> Self {
        let mut snapshot = Self::configured(&app.user_config);
        snapshot.scope = "runtime".into();
        snapshot.interface = Some(app.capture_interface.clone());
        snapshot.put(
            "config",
            State::Ready,
            "runtime_config",
            "Effective in-memory configuration (may include defaults)",
            None,
        );
        snapshot.put(
            "interface",
            State::Ready,
            "selected",
            &app.capture_interface,
            None,
        );
        snapshot.put(
            "capture_library",
            State::Ready,
            "runtime_loaded",
            "Capture library loaded; capture permission is reported separately",
            None,
        );
        let (state, reason, detail) = if app.packet_collector.is_capturing() {
            (
                State::Ready,
                "capture_running",
                "Capture open and worker ready".into(),
            )
        } else if let Some(error) = app.packet_collector.get_error() {
            (State::Unavailable, "capture_failed", error)
        } else if app.packet_collector.capture_requested() {
            (
                State::NotChecked,
                "capture_starting",
                "Capture requested; not ready".into(),
            )
        } else {
            (
                State::Disabled,
                "capture_stopped",
                "Capture is stopped; no packet observation".into(),
            )
        };
        snapshot.put(
            "capture",
            state,
            reason,
            &detail,
            Some("Inspect capture permissions and selected interface"),
        );
        match app.attribution_status() {
            AttributionStatus::Active(source)=>snapshot.put("attribution",State::Ready,"kernel_backend",source,None),
            AttributionStatus::Failed(source,error)=>snapshot.put("attribution",State::Degraded,"polling_fallback",&format!("{source}: {error}; socket polling fallback; per-flow attribution may be unknown"),Some("Check backend permissions in Settings")),
            AttributionStatus::Lsof=>snapshot.put("attribution",State::Degraded,"polling_only","Socket polling only; visibility depends on process permissions",None),
        }
        let coverage = app.connection_collector.coverage();
        let state = if coverage.completed_at.is_none() {
            State::NotChecked
        } else if coverage
            .completed_at
            .is_some_and(|t| t.elapsed() > crate::collectors::attribution::MAX_MATCH_AGE)
        {
            State::Stale
        } else if coverage.eligible_flows == 0 {
            State::NotChecked
        } else if coverage.attributed_flows == coverage.eligible_flows {
            State::Ready
        } else {
            State::Degraded
        };
        snapshot.put("attribution_coverage", state, "observed_payload_interval",
            &format!("{}; capture drops {}; eBPF destination-only events require socket corroboration; polling misses short-lived flows",
                coverage.summary(), coverage.capture_drops.map(|n| n.to_string()).unwrap_or_else(|| "not measured".into())), None);
        snapshot.attribution_coverage = Some(coverage);
        let health = app.health_prober.status();
        let times = [
            health.completed.gateway,
            health.completed.dns,
            health.completed.internet,
        ];
        let fresh = times
            .iter()
            .filter(|t| t.is_some_and(|at| at.elapsed() < Duration::from_secs(30)))
            .count();
        snapshot.put(
            "probes",
            if fresh == 3 {
                State::Ready
            } else if fresh > 0 {
                State::Degraded
            } else if times.iter().any(Option::is_some) {
                State::Stale
            } else {
                State::NotChecked
            },
            "probe_completions",
            &format!(
                "{fresh}/3 probe targets have fresh completions; completion does not imply success"
            ),
            Some("Inspect Diagnose for RTT, loss and target coverage"),
        );
        let (flows, at) = app.tcp_info.timed_snapshot();
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            snapshot.put(
                "tcp_metrics",
                if at.is_none() {
                    State::NotChecked
                } else if at.is_some_and(|t| t.elapsed() > Duration::from_secs(30)) {
                    State::Stale
                } else if flows.is_empty() {
                    State::NotChecked
                } else {
                    State::Ready
                },
                "observed_flows",
                &format!(
                    "{} flows with TCP metrics; absent flows remain unknown",
                    flows.len()
                ),
                None,
            );
        }
        let report = &app.sandbox_report;
        let protected = report.platform.landlock_abi > 0
            || report.platform.macos_seatbelt
            || report.platform.windows_restricted;
        let state = if report.mode.effective == Some("disabled") {
            State::Disabled
        } else if protected && report.mode.warnings.is_empty() && sandbox::worker::all_verified() {
            State::Ready
        } else {
            State::Degraded
        };
        snapshot.put(
            "sandbox",
            state,
            "runtime_enforcement",
            &format!("{} · {}", report.summary(), sandbox::worker::summary()),
            Some("netwatch doctor --json; networking is unrestricted"),
        );
        snapshot
            .protections
            .push(Protection::from_report("main", true, Some(report), None));
        for (name, component) in sandbox::worker::snapshot() {
            snapshot.protections.push(Protection::from_report(
                &name,
                component.ready,
                component.report.as_ref(),
                component.error,
            ));
        }
        snapshot.put(
            "online_geo",
            if app.user_config.geoip_online {
                State::NotChecked
            } else {
                State::Disabled
            },
            "live_configuration",
            "Live online lookup setting (ip-api.com, cleartext HTTP); per-request outcomes not tracked here",
            None,
        );
        for id in ["whois", "reverse_dns"] {
            snapshot.put(
                id,
                State::NotChecked,
                "live_lookup_worker",
                "Live lookup worker; per-request success is not represented by entry readiness",
                None,
            );
        }
        if let Some(insights) = &app.insights_collector {
            use crate::collectors::insights::InsightsStatus;
            let (state, detail) = match &*insights.get_status() {
                InsightsStatus::Available => (
                    State::Ready,
                    "At least one model response available; freshness not established",
                ),
                InsightsStatus::Analyzing => (State::NotChecked, "Model request in progress"),
                InsightsStatus::Idle => (
                    State::NotChecked,
                    "Model collector idle; endpoint not verified",
                ),
                InsightsStatus::Error(_) | InsightsStatus::OllamaUnavailable => (
                    State::Unavailable,
                    "Model request failed; check endpoint settings",
                ),
            };
            snapshot.put(
                "insights",
                state,
                "collector_status",
                detail,
                Some("Review Insights settings and data sharing"),
            );
        } else {
            snapshot.put(
                "insights",
                State::Disabled,
                "not_started",
                "Model collector not started",
                None,
            );
        }
        let workers = sandbox::worker::snapshot();
        for (id, worker) in [("remote", "remote"), ("metrics", "metrics-listener")] {
            let entry = workers
                .iter()
                .find(|(name, _)| name.as_str() == worker)
                .map(|(_, entry)| entry);
            snapshot.put(
                id,
                if entry.is_none() {
                    State::Disabled
                } else if entry.is_some_and(|e| e.error.is_some()) {
                    State::Unavailable
                } else {
                    State::NotChecked
                },
                "worker_entry_only",
                "Worker entry status only; delivery/listener health is not measured here",
                None,
            );
        }
        snapshot
    }
}
fn wrap(lines: &mut Vec<String>, value: &str) {
    let clean: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut line = String::from("  ");
    for ch in clean.chars() {
        if unicode_width::UnicodeWidthStr::width(line.as_str())
            + unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0)
            > 78
        {
            lines.push(line);
            line = "  ".into();
        }
        line.push(ch);
    }
    lines.push(line);
}

/// What static doctor can learn about Npcap without loading it: whether
/// `wpcap.dll` is where an install puts it and, if so, what the Service
/// Control Manager says about the `npcap` driver service. Only Windows asks,
/// but this and the wording below are built for tests too, so the wording is
/// checked on every platform and not only on the Windows runner.
#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Npcap {
    /// No `wpcap.dll` in `System32\Npcap` or `System32`.
    Missing,
    /// The DLL is there. The service's `dwCurrentState`, or the Win32 error
    /// from asking for it.
    Installed(Result<u32, u32>),
}

/// The `capture_library` entry for what was found: state, reason, detail and
/// next step. A missing Npcap gets the fix the capture error and the
/// Dashboard banner give, link included. Files without a running driver say
/// that, where doctor used to say "not loaded" whether Npcap was there or not.
#[cfg(any(target_os = "windows", test))]
fn npcap_capture_library(npcap: Npcap) -> (State, &'static str, String, String) {
    const SERVICE_RUNNING: u32 = 4;
    const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
    let check = "netwatch doctor --check-capture --interface NAME";
    let install = format!("{}; then run {check}", crate::platform::WINDOWS_CAPTURE_FIX);
    match npcap {
        Npcap::Missing => (
            State::Unavailable,
            "npcap_missing",
            r"Npcap is not installed: no wpcap.dll in System32\Npcap or System32".into(),
            install,
        ),
        Npcap::Installed(Ok(SERVICE_RUNNING)) => (
            State::NotChecked,
            "npcap_present_unloaded",
            "Npcap installed and its driver service running; DLL not loaded, no capture opened"
                .into(),
            check.into(),
        ),
        // `sc.exe`, not `sc`: in Windows PowerShell `sc` is Set-Content, so
        // `sc start npcap` writes a file named `start` and starts nothing.
        Npcap::Installed(Ok(_)) => (
            State::Unavailable,
            "npcap_driver_stopped",
            "Npcap is installed but its driver service (npcap) is not running".into(),
            format!("As administrator, run sc.exe start npcap or reinstall Npcap; then run {check}"),
        ),
        // WinPcap's DLL, or files a partial uninstall left behind. Either way
        // the driver Npcap registers is not there to start.
        Npcap::Installed(Err(ERROR_SERVICE_DOES_NOT_EXIST)) => (
            State::Unavailable,
            "npcap_driver_missing",
            "wpcap.dll found, but no npcap driver service is registered (WinPcap, or a partial Npcap uninstall)".into(),
            install,
        ),
        Npcap::Installed(Err(code)) => (
            State::NotChecked,
            "npcap_present_unloaded",
            format!("Npcap files found; driver service state unreadable (Win32 error {code}); DLL not loaded"),
            check.into(),
        ),
    }
}

pub fn inspect_static(interface: Option<String>) -> CapabilitySnapshot {
    let (config, config_state, code, detail) =
        match NetwatchConfig::path().map(std::fs::read_to_string) {
            Some(Ok(raw)) => match toml::from_str::<NetwatchConfig>(&raw) {
                Ok(config) => (
                    config,
                    State::Ready,
                    "config_valid",
                    "Configuration parsed; endpoints not contacted",
                ),
                Err(_) => (
                    NetwatchConfig::default(),
                    State::Unavailable,
                    "config_invalid",
                    "Configuration is invalid; defaults shown. Fix config before live use",
                ),
            },
            Some(Err(e)) if e.kind() != std::io::ErrorKind::NotFound => (
                NetwatchConfig::default(),
                State::Unavailable,
                "config_unreadable",
                "Configuration cannot be read; defaults shown",
            ),
            _ => (
                NetwatchConfig::default(),
                State::Ready,
                "defaults",
                "No saved configuration; defaults shown",
            ),
        };
    let mut snapshot = CapabilitySnapshot::configured(&config);
    snapshot.put(
        "config",
        config_state,
        code,
        detail,
        Some("Review config.toml; doctor never writes it"),
    );
    if interface.is_some() {
        snapshot.interface = interface;
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(name) = &snapshot.interface {
            let exists = std::fs::read_dir("/sys/class/net")
                .ok()
                .is_some_and(|items| {
                    items
                        .filter_map(Result::ok)
                        .any(|e| e.file_name().to_string_lossy() == *name)
                });
            let name = name.clone();
            snapshot.put(
                "interface",
                if exists {
                    State::Ready
                } else {
                    State::Unavailable
                },
                if exists {
                    "interface_present"
                } else {
                    "interface_missing"
                },
                &name,
                Some("Confirm the capture interface; existence is not capture authority"),
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    if let Some(name) = snapshot.interface.clone() {
        snapshot.put(
            "interface",
            State::NotChecked,
            "configured_interface",
            &name,
            Some("Use --check-capture to validate this interface"),
        );
    }
    #[cfg(not(target_os = "windows"))]
    snapshot.put(
        "capture_library",
        State::Ready,
        "linked_library",
        "libpcap linked and loaded; no capture opened",
        None,
    );
    #[cfg(target_os = "windows")]
    {
        use crate::platform::npcap;
        let found = if npcap::installed() {
            Npcap::Installed(npcap::driver_service_state())
        } else {
            Npcap::Missing
        };
        let (state, reason, detail, next) = npcap_capture_library(found);
        snapshot.put("capture_library", state, reason, &detail, Some(&next));
    }
    snapshot.put(
        "remote",
        if std::env::var_os("NETWATCH_REMOTE_URL").is_some() {
            State::NotChecked
        } else {
            State::Disabled
        },
        "environment_only",
        "Remote environment presence inspected; URL/key not printed or used",
        None,
    );
    snapshot.put(
        "metrics",
        if std::env::var_os("NETWATCH_METRICS_ADDR").is_some() {
            State::NotChecked
        } else {
            State::Disabled
        },
        "environment_only",
        "Metrics environment presence inspected; no listener started",
        None,
    );
    if let Ok(owner) = crate::diagnose::remediation::resolver::ownership() {
        snapshot.put(
            "resolver",
            if matches!(
                owner,
                crate::diagnose::remediation::resolver::Ownership::UnconfirmedRegular
            ) {
                State::NotChecked
            } else {
                State::Unavailable
            },
            "resolver_ownership",
            owner.description(),
            Some("netwatch resolver status; no recovery attempted by doctor"),
        );
    }
    snapshot
}

#[derive(Debug, Serialize, Deserialize)]
struct CaptureResult {
    interface: String,
    opened: bool,
    error: Option<String>,
    protection: Option<Protection>,
}
pub fn capture_child(interface: &str, mode: Mode) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    if let Err(error) = crate::platform::npcap::ensure_wpcap() {
        println!(
            "{}",
            serde_json::to_string(&CaptureResult {
                interface: interface.into(),
                opened: false,
                error: Some(error),
                protection: None
            })?
        );
        return Ok(());
    }
    let selection = (|| -> anyhow::Result<String> {
        if interface.is_empty() {
            let interfaces = crate::platform::collect_interface_info()?;
            if !interfaces.iter().any(|i| i.is_up) {
                anyhow::bail!("No up interface found");
            }
            Ok(App::pick_capture_interface(
                &interfaces,
                crate::platform::default_route_interface().as_deref(),
            ))
        } else {
            Ok(interface.to_owned())
        }
    })();
    let selected = match selection {
        Ok(selected) => selected,
        Err(error) => {
            println!(
                "{}",
                serde_json::to_string(&CaptureResult {
                    interface: interface.into(),
                    opened: false,
                    error: Some(error.to_string()),
                    protection: None
                })?
            );
            return Ok(());
        }
    };
    let interface = selected.as_str();
    let config = NetwatchConfig::load();
    let filter = (!config.bpf_filter.is_empty()).then_some(config.bpf_filter.as_str());
    let result = match crate::collectors::packets::prepare_capture(interface, filter) {
        Err(error) => CaptureResult {
            interface: interface.into(),
            opened: false,
            error: Some(error),
            protection: None,
        },
        Ok(capture) => {
            let report = sandbox::apply(mode, &sandbox::SandboxPaths::default());
            let rejected = matches!(mode, Mode::Strict) && !report.mode.warnings.is_empty();
            let result = CaptureResult {
                interface: interface.into(),
                opened: true,
                error: rejected.then(|| "Strict capture-check policy could not be enforced".into()),
                protection: Some(Protection::from_report(
                    "capture-check",
                    !rejected,
                    Some(&report),
                    None,
                )),
            };
            drop(capture);
            result
        }
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
pub fn doctor(json: bool, check_capture: bool, interface: Option<String>) -> anyhow::Result<()> {
    let mut snapshot = inspect_static(interface);
    if check_capture {
        snapshot.scope = "capture_check".into();
        {
            let interface = snapshot.interface.clone().unwrap_or_default();
            let mode = Mode::from_config(&NetwatchConfig::load().sandbox);
            let result = bounded_check(&interface, mode);
            match result {
                Ok(result) => {
                    snapshot.interface = Some(result.interface.clone());
                    if result.opened {
                        snapshot.put(
                            "interface",
                            State::Ready,
                            "capture_selection",
                            &result.interface,
                            None,
                        );
                    } else if result.interface.is_empty() {
                        snapshot.put(
                            "interface",
                            State::Unavailable,
                            "selection_failed",
                            "No capture interface selected",
                            Some("Pass --interface NAME"),
                        );
                    }
                    let state = if result.error.is_some() {
                        State::Unavailable
                    } else if result.opened {
                        State::Ready
                    } else {
                        State::Unavailable
                    };
                    snapshot.put("capture",state,if result.opened{"open_close_checked"}else{"capture_open_failed"},result.error.as_deref().unwrap_or("Opened/configured and closed; no packets read; this does not verify traffic or attribution"),Some("Inspect live Settings for ongoing capture readiness"));
                    if let Some(protection) = result.protection {
                        let state = if protection.effective.as_deref() == Some("disabled") {
                            State::Disabled
                        } else if protection.landlock_abi > 0 && protection.warnings.is_empty() {
                            State::Ready
                        } else {
                            State::Degraded
                        };
                        snapshot.put("sandbox",state,"isolated_capture_check","Protection applies only to the isolated check process; live worker enforcement is not tested",None);
                        snapshot.protections.push(protection);
                    }
                }
                Err(error) => snapshot.put(
                    "capture",
                    State::Unavailable,
                    "capture_check_failed",
                    &error.to_string(),
                    Some("Check interface and driver; check is limited to five seconds"),
                ),
            }
        }
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
    } else {
        print!("{}", snapshot.text());
    }
    Ok(())
}
fn bounded_check(interface: &str, mode: Mode) -> anyhow::Result<CaptureResult> {
    use std::process::{Command, Stdio};
    let mode = match mode {
        Mode::Disabled => "off",
        Mode::Strict => "strict",
        Mode::BestEffort => "best-effort",
    };
    let child = Command::new(std::env::current_exe()?)
        .args(["__capture-check", interface, mode])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    wait_capture(child, Duration::from_secs(5))
}
fn wait_capture(
    mut child: std::process::Child,
    timeout: Duration,
) -> anyhow::Result<CaptureResult> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Capture open timed out after five seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!("Capture-check subprocess failed");
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocked_capture_child_is_terminated_at_deadline() {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::capabilities::tests::slow_capture_child",
                "--nocapture",
            ])
            .env("NETWATCH_TEST_SLOW_CAPTURE", "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let start = Instant::now();
        assert!(wait_capture(child, Duration::from_millis(100))
            .unwrap_err()
            .to_string()
            .contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(5));
    }
    #[test]
    fn slow_capture_child() {
        if std::env::var_os("NETWATCH_TEST_SLOW_CAPTURE").is_some() {
            loop {
                std::thread::park();
            }
        }
    }
    #[test]
    fn static_configuration_never_implies_observation_success() {
        let snapshot = CapabilitySnapshot::configured(&NetwatchConfig::default());
        assert_eq!(snapshot.get("capture").state, State::NotChecked);
        assert_eq!(snapshot.get("probes").state, State::NotChecked);
        assert!(snapshot.protections.is_empty());
        assert!(!snapshot.network_restricted);
        let restored: CapabilitySnapshot =
            serde_json::from_str(&serde_json::to_string(&snapshot).unwrap()).unwrap();
        assert_eq!(restored.get("capture").reason, "open_not_attempted");
    }
    #[test]
    fn online_geo_is_labelled_cleartext() {
        let config = NetwatchConfig {
            geoip_online: true,
            ..Default::default()
        };
        let snapshot = CapabilitySnapshot::configured(&config);
        assert_eq!(snapshot.get("online_geo").state, State::NotChecked);
        assert!(snapshot.get("online_geo").detail.contains("cleartext"));
    }
    #[test]
    fn doctor_text_fits_an_80_column_terminal_and_sanitizes_controls() {
        let mut snapshot = CapabilitySnapshot::configured(&NetwatchConfig::default());
        snapshot.put(
            "capture",
            State::Unavailable,
            "denied",
            &format!("\x1b[31m{}", "界".repeat(120)),
            Some("Check capture permissions"),
        );
        let text = snapshot.text();
        assert!(!text.contains('\x1b'));
        assert!(text
            .lines()
            .all(|line| unicode_width::UnicodeWidthStr::width(line) <= 80));
    }

    /// A machine with no Npcap is told where to get it, with the same words
    /// as the capture error, and is not told the driver merely isn't loaded.
    #[test]
    fn missing_npcap_names_the_download() {
        let (state, reason, detail, next) = npcap_capture_library(Npcap::Missing);
        assert_eq!(state, State::Unavailable);
        assert_eq!(reason, "npcap_missing");
        assert!(detail.contains("not installed"), "{detail}");
        assert!(
            next.starts_with(crate::platform::WINDOWS_CAPTURE_FIX),
            "{next}"
        );
        assert!(next.contains("https://npcap.com/#download"), "{next}");
        assert!(next.contains("--check-capture"), "{next}");
    }

    /// Installed with the driver running is as far as static doctor can see:
    /// not ready, because nothing was loaded or opened, and no install advice.
    #[test]
    fn installed_npcap_with_running_driver_is_not_checked() {
        let (state, reason, detail, next) = npcap_capture_library(Npcap::Installed(Ok(4)));
        assert_eq!(state, State::NotChecked);
        assert_eq!(reason, "npcap_present_unloaded");
        assert!(detail.contains("running"), "{detail}");
        assert!(!next.contains("install"), "{next}");
        assert!(next.contains("--check-capture"), "{next}");
    }

    /// SERVICE_STOPPED (1) and the pending states all mean capture would fail
    /// now, and the fix is starting the driver, not installing Npcap again.
    /// The command has to work in cmd and in Windows PowerShell, where a bare
    /// `sc` is the Set-Content alias.
    #[test]
    fn installed_npcap_with_stopped_driver_says_so() {
        for state_code in [1, 2, 3, 7] {
            let (state, reason, detail, next) =
                npcap_capture_library(Npcap::Installed(Ok(state_code)));
            assert_eq!(state, State::Unavailable);
            assert_eq!(reason, "npcap_driver_stopped");
            assert!(detail.contains("not running"), "{detail}");
            assert!(next.contains("sc.exe start npcap"), "{next}");
            assert!(!next.contains("sc start"), "{next}");
        }
    }

    /// A wpcap.dll with no npcap service behind it is WinPcap or uninstall
    /// debris; the fix is installing Npcap, so it gets the download link.
    #[test]
    fn dll_without_a_driver_service_gets_the_install_fix() {
        let (state, reason, _, next) = npcap_capture_library(Npcap::Installed(Err(1060)));
        assert_eq!(state, State::Unavailable);
        assert_eq!(reason, "npcap_driver_missing");
        assert!(next.contains("https://npcap.com/#download"), "{next}");
    }

    /// An unanswered service query (access denied is 5) is not evidence of
    /// anything, so the entry stays as it was before the query existed.
    #[test]
    fn unreadable_driver_state_claims_nothing() {
        let (state, reason, detail, next) = npcap_capture_library(Npcap::Installed(Err(5)));
        assert_eq!(state, State::NotChecked);
        assert_eq!(reason, "npcap_present_unloaded");
        assert!(detail.contains("Win32 error 5"), "{detail}");
        assert!(!next.contains("install"), "{next}");
    }

    /// doctor's text wraps at 80 columns by character, so a link that
    /// straddled a wrap would print in two pieces that neither a terminal nor
    /// a reader can follow. The install advice must keep it on one line.
    #[test]
    fn npcap_download_link_survives_text_wrapping() {
        for npcap in [Npcap::Missing, Npcap::Installed(Err(1060))] {
            let mut snapshot = CapabilitySnapshot::configured(&NetwatchConfig::default());
            let (state, reason, detail, next) = npcap_capture_library(npcap);
            snapshot.put("capture_library", state, reason, &detail, Some(&next));
            let text = snapshot.text();
            assert!(
                text.lines()
                    .any(|line| line.contains("https://npcap.com/#download")),
                "{text}"
            );
        }
    }

    /// This machine's answer, end to end. The CI runner has the Npcap SDK but
    /// not Npcap, which is the case `npcap_missing` exists for.
    #[cfg(target_os = "windows")]
    #[test]
    fn static_doctor_reports_this_machines_npcap() {
        let entry = inspect_static(None).get("capture_library").clone();
        if !crate::platform::npcap::installed() {
            assert_eq!(entry.reason, "npcap_missing");
            assert!(entry
                .next_check
                .is_some_and(|next| next.contains("https://npcap.com/#download")));
        } else {
            assert_ne!(entry.reason, "npcap_missing");
        }
    }
}
