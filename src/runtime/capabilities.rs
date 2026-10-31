//! Observed capability state, shared by doctor and live presentation. Static
//! inspection never starts collectors, loads Npcap, or contacts an endpoint.
use crate::{
    app::{App, AttributionStatus},
    collectors::geo::{DbFile, DbStatus},
    config::{ConfigWarning, ConfigWarningKind, NetwatchConfig},
    sandbox::{self, Mode},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How old a loaded GeoIP database gets before doctor calls it stale. DB-IP
/// publishes monthly, so this is a refresh or two missed.
const GEOIP_DB_STALE_AFTER: Duration = Duration::from_secs(60 * 86_400);

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
    /// The Landlock ABI of what this thread enforces: the newest feature in
    /// force, so 3 for the filesystem layer alone on any newer kernel.
    pub landlock_abi: u32,
    pub caps_dropped: Vec<String>,
    pub caps_retained: Vec<String>,
    pub warnings: Vec<String>,
    pub error: Option<String>,
    /// The ABI the kernel reports.
    #[serde(default)]
    pub landlock_kernel_abi: u32,
    /// `denied` when this thread's TCP bind and connect are, `allowed` when it
    /// entered and they are not, and `not_entered` when it has no report: a
    /// capture that failed to open, a worker just started, or the note for the
    /// eBPF SDK's reader, which inherits the `ebpf` worker's policy.
    #[serde(default)]
    pub network_policy: String,
    /// `filesystem`, `filesystem_write`, `tcp_bind`, `tcp_connect`,
    /// `abstract_unix_socket`, `signal`, `pathname_unix_socket` and, from the
    /// seccomp filter, `socket_create`.
    #[serde(default)]
    pub landlock_restrictions: Vec<String>,
    /// CAP_NET_RAW on this thread: `dropped`, `retained_for_reopen`, `not_held`
    /// or `not_applicable`.
    #[serde(default)]
    pub capture_authority: String,
    /// The no-socket filter: `installed`, `unknown_arch`, `failed` or
    /// `not_applicable`.
    #[serde(default)]
    pub socket_filter: String,
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
            landlock_kernel_abi: report.map_or(0, |r| r.platform.landlock_kernel_abi),
            network_policy: report
                .map_or("not_entered", |r| r.platform.network_policy())
                .into(),
            landlock_restrictions: report
                .map(|r| {
                    r.platform
                        .landlock_restrictions
                        .iter()
                        .map(|restriction| (*restriction).to_owned())
                        .collect()
                })
                .unwrap_or_default(),
            capture_authority: report
                .map_or(sandbox::NetRaw::NotApplicable, |r| {
                    r.platform.capture_authority
                })
                .label()
                .into(),
            socket_filter: report
                .map_or(sandbox::SocketFilter::NotApplicable, |r| {
                    r.platform.socket_filter
                })
                .label()
                .into(),
        }
    }
}
/// What Landlock this kernel has and what a parser thread gets from it. Null
/// off Linux.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Landlock {
    /// The ABI the kernel reports, 0 without Landlock.
    pub kernel_abi: u32,
    /// `available`, `not_enabled`, `not_built` or `unknown`. `not_built` also
    /// covers a seccomp profile blocking the syscalls with any errno but
    /// EOPNOTSUPP: the landlock crate reports both the same way.
    pub availability: String,
    /// The errata the kernel reports fixed, by the numbers in the kernel's
    /// documentation.
    pub errata: Vec<u32>,
    /// Static doctor runs this on a disposable thread. A live session reads it
    /// from a parser worker's entry report. Null if neither has one.
    pub parser_check: Option<ParserCheck>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserCheck {
    /// The same meaning as a protection's `landlock_abi`.
    pub enforced_abi: u32,
    pub restrictions: Vec<String>,
    /// `denied`, `allowed` or `error`, for anything else a check got back.
    pub tcp_bind: String,
    pub tcp_connect: String,
}
/// A thread still holding CAP_NET_RAW when startup audited the process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetRawTask {
    pub tid: u32,
    pub comm: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    pub schema_version: u32,
    pub scope: String,
    pub platform: String,
    pub interface: Option<String>,
    pub capabilities: Vec<Capability>,
    pub protections: Vec<Protection>,
    /// Always false: this is about the whole process, and main and the network
    /// workers keep the network. Each protection has its own `network_policy`.
    pub network_restricted: bool,
    #[serde(default)]
    pub attribution_coverage: Option<crate::collectors::attribution::Coverage>,
    #[serde(default)]
    pub landlock: Option<Landlock>,
    /// Process-wide, from the audit at startup. Null in doctor, which starts
    /// no session to audit, and off Linux. A session writes it to its log, which
    /// is the only place to read it.
    #[serde(default)]
    pub tasks_holding_net_raw: Option<Vec<NetRawTask>>,
}
impl CapabilitySnapshot {
    /// With the databases read from disk, for a report. A live session passes
    /// what it opened to [`Self::configured_with`] instead, as Settings
    /// redraws this every frame.
    fn configured(config: &NetwatchConfig) -> Self {
        let (db, asn) = config.geoip_paths();
        Self::configured_with(config, &DbStatus::open(&db, &asn))
    }
    fn configured_with(config: &NetwatchConfig, geoip: &DbStatus) -> Self {
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
            landlock: None,
            tasks_holding_net_raw: None,
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
            "eBPF loads under sandbox policy and its reader keeps load capabilities; initialization and socket fallback not checked"
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
        #[cfg(target_os = "linux")]
        snapshot.put(
            "connections",
            State::NotChecked,
            "table_unchecked",
            "Connection table source (ss, or /proc/net without it) not checked",
            Some("netwatch doctor"),
        );
        snapshot.put(
            "probes",
            State::NotChecked,
            "no_active_probes",
            if config.third_party_probes {
                "Gateway, DNS and Internet probes were not sent"
            } else {
                "Gateway and DNS probes were not sent; third_party_probes is off, so a live session sends no Internet probe, STUN or resolver cross-check"
            },
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
            &with_root_note(format!(
                "Requested {:?}; no policy applied by static doctor; see landlock for what a parser thread gets",
                mode
            )),
            Some("Inspect live Settings for component enforcement"),
        );
        let (state, reason, detail, next) =
            landlock_capability(cfg!(target_os = "linux"), mode, None);
        snapshot.put("landlock", state, reason, &detail, next);
        let (state, reason, detail, next) = geoip_db_assessment(geoip, SystemTime::now());
        snapshot.put("geoip_db", state, reason, &detail, next);
        snapshot.put(
            "online_geo",
            State::Disabled,
            "removed",
            if config.geoip_online {
                "Online GeoIP was removed in 0.39; geoip_online in config.toml is ignored"
            } else {
                "Online GeoIP was removed in 0.39; lookups stay on this machine"
            },
            Some("netwatch geoip update"),
        );
        snapshot.put(
            "insights",
            if config.insights_enabled {
                State::NotChecked
            } else {
                State::Disabled
            },
            "configuration_only",
            "Insights configured; endpoint not contacted",
            Some("Review external-service settings before live use"),
        );
        snapshot.flag_cleartext_insights(config);
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
    /// Insights going out unencrypted to another machine is what to report,
    /// whatever the model is doing: every request carries the snapshot. The
    /// endpoint stays out of it, as elsewhere in this report.
    fn flag_cleartext_insights(&mut self, config: &NetwatchConfig) {
        use crate::collectors::insights::{cleartext_off_host, CLEARTEXT_OFF_HOST};
        if !config.insights_enabled || !cleartext_off_host(&config.insights_endpoint) {
            return;
        }
        let detail = format!(
            "{CLEARTEXT_OFF_HOST}: the endpoint is http:// on another host, so DNS names, peer addresses and packet summaries cross the network unencrypted. {}",
            self.get("insights").detail
        );
        self.put(
            "insights",
            State::Degraded,
            "cleartext_off_host",
            &detail,
            Some("Use an https:// endpoint, or one on this host"),
        );
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
    /// The sandbox part of a snapshot as one line of JSON, for the session log:
    /// `landlock`, `protections` and `tasks_holding_net_raw`.
    pub fn sandbox_json(&self) -> String {
        serde_json::json!({
            "landlock": self.landlock,
            "protections": self.protections,
            "tasks_holding_net_raw": self.tasks_holding_net_raw,
        })
        .to_string()
    }
    /// A line for Settings when the connection table is not read from `ss`,
    /// state first. It is a row of its own: appended to [`Self::compact`],
    /// the popup cut it off in any terminal under about 140 columns.
    pub fn connection_table_line(&self) -> Option<String> {
        self.capabilities
            .iter()
            .find(|c| c.id == "connections")
            .filter(|c| matches!(c.state, State::Degraded | State::Unavailable))
            .map(|c| format!("connections: {} · {}", c.state.label(), c.detail))
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
        let mut snapshot = Self::configured_with(&app.user_config, app.geo_cache.db_status());
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
        #[cfg(target_os = "linux")]
        {
            let (state, reason, detail, next) = live_connection_table(&coverage);
            snapshot.put("connections", state, reason, &detail, next);
        }
        snapshot.attribution_coverage = Some(coverage);
        let health = app.health_prober.status();
        // A skipped internet probe still stamps its cycle. That is no
        // completion here: with the switch off, two targets is all of them.
        let third_party = app.health_prober.third_party_probes();
        let times = [
            health.completed.gateway,
            health.completed.dns,
            health.completed.internet.filter(|_| third_party),
        ];
        let targets = if third_party { 3 } else { 2 };
        let fresh = times
            .iter()
            .filter(|t| t.is_some_and(|at| at.elapsed() < Duration::from_secs(30)))
            .count();
        snapshot.put(
            "probes",
            if fresh == targets {
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
                "{fresh}/{targets} probe targets have fresh completions; completion does not imply success{}",
                if third_party {
                    ""
                } else {
                    "; third_party_probes is off, so the Internet probe, STUN and resolver cross-check are not measured"
                }
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
        let workers = sandbox::worker::snapshot();
        snapshot.put(
            "sandbox",
            state,
            "runtime_enforcement",
            &sandbox_detail(report, &workers, &sandbox::worker::summary()),
            Some("netwatch doctor --json"),
        );
        snapshot.landlock = live_landlock(report, &workers);
        let (state, reason, detail, next) = landlock_capability(
            cfg!(target_os = "linux"),
            sandbox::worker::mode(),
            snapshot.landlock.as_ref(),
        );
        snapshot.put("landlock", state, reason, &detail, next);
        snapshot.tasks_holding_net_raw = sandbox::audit::tasks_holding_net_raw().map(|holders| {
            holders
                .into_iter()
                .map(|holder| NetRawTask {
                    tid: holder.tid,
                    comm: holder.comm,
                })
                .collect()
        });
        snapshot
            .protections
            .push(Protection::from_report("main", true, Some(report), None));
        for (name, component) in workers {
            snapshot.protections.push(Protection::from_report(
                &name,
                component.ready,
                component.report.as_ref(),
                component.error,
            ));
        }
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
            snapshot.flag_cleartext_insights(&app.user_config);
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
/// Added to the sandbox capability wherever it is shown when netwatch runs as
/// root. Most files stay readable and writable there whatever the sandbox does,
/// so an escape is not what it promises (SECURITY.md).
const ROOT_NOTE: &str = "running as root: containment limited";

fn running_as_root() -> bool {
    #[cfg(unix)]
    return nix::unistd::geteuid().is_root();
    #[cfg(not(unix))]
    false
}

fn with_root_note(detail: String) -> String {
    if running_as_root() {
        format!("{detail} · {ROOT_NOTE}")
    } else {
        detail
    }
}

/// The live sandbox capability's detail, as clauses Settings puts on a row
/// each. `verified` is [`sandbox::worker::summary`]'s line.
fn sandbox_detail(
    main: &sandbox::Report,
    workers: &std::collections::BTreeMap<String, sandbox::worker::Component>,
    verified: &str,
) -> String {
    use sandbox::{NetRaw, SocketFilter};
    let mut clauses = vec![main.summary()];
    if cfg!(target_os = "linux") && main.mode.effective != Some("disabled") {
        let (denied, parsers) = sandbox::worker::parser_tcp_coverage(workers);
        if parsers > 0 {
            clauses.push(format!("TCP denied on {denied}/{parsers} parser workers"));
        }
        let unfiltered = workers
            .values()
            .filter_map(|w| w.report.as_ref())
            .any(|r| r.platform.socket_filter == SocketFilter::UnknownArch);
        if unfiltered {
            clauses.push(format!(
                "no-socket filter skipped: no syscall table for {}",
                std::env::consts::ARCH
            ));
        }
        match main.platform.capture_authority {
            NetRaw::RetainedForReopen => {
                clauses.push("CAP_NET_RAW kept on main to reopen capture (c, i, Shift+R)".into())
            }
            NetRaw::Dropped => clauses.push("CAP_NET_RAW dropped once capture opened".into()),
            NetRaw::NotHeld | NetRaw::NotApplicable => {}
        }
    }
    clauses.push(verified.to_owned());
    with_root_note(clauses.join(" · "))
}

/// The `landlock` capability, from what doctor or a live session found.
/// `linux` says whether there is a backend; the sandbox mode comes next because
/// the object is reported either way, and only this says whether it applies.
fn landlock_capability(
    linux: bool,
    mode: Mode,
    landlock: Option<&Landlock>,
) -> (State, &'static str, String, Option<&'static str>) {
    if !linux {
        return (
            State::Unavailable,
            "platform_unsupported",
            "Landlock is Linux only; this platform has no sandbox backend".into(),
            None,
        );
    }
    if matches!(mode, Mode::Disabled) {
        return (
            State::Disabled,
            "sandbox_disabled",
            "Sandbox disabled by configuration; no thread takes a Landlock policy".into(),
            Some("Set sandbox = \"on\" or drop --no-sandbox"),
        );
    }
    let Some(landlock) = landlock else {
        return (
            State::NotChecked,
            "self_test_not_run",
            "Landlock has not been checked".into(),
            Some("netwatch doctor"),
        );
    };
    match landlock.availability.as_str() {
        "not_enabled" => {
            return (
                State::Unavailable,
                "landlock_not_enabled",
                "This kernel has Landlock built in but it is not enabled (EOPNOTSUPP); parser threads keep the network".into(),
                Some("Add landlock to the kernel's lsm= boot parameter"),
            )
        }
        "not_built" => {
            return (
                State::Unavailable,
                "landlock_not_built",
                "This kernel has no Landlock (ENOSYS), or something such as a container's seccomp profile blocks it; parser threads keep the network".into(),
                Some("Use a kernel built with CONFIG_SECURITY_LANDLOCK, or allow syscalls 444-446 in the seccomp profile"),
            )
        }
        _ => {}
    }
    let kernel = landlock.kernel_abi;
    if landlock.availability == "available" && kernel < 4 {
        return (
            State::Degraded,
            "kernel_abi_below_4",
            format!(
                "Kernel Landlock ABI {kernel} cannot deny TCP; parser threads keep the network and --sandbox-strict refuses to start"
            ),
            Some("Linux 6.7 or newer has ABI 4"),
        );
    }
    match &landlock.parser_check {
        Some(check) if check.tcp_bind == "denied" && check.tcp_connect == "denied" => (
            State::Ready,
            "parser_network_denied",
            format!(
                "Kernel Landlock ABI {kernel}; a parser thread enforces ABI {} and is denied TCP bind and connect",
                check.enforced_abi
            ),
            None,
        ),
        Some(check) => (
            State::Unavailable,
            "self_test_failed",
            format!(
                "Kernel Landlock ABI {kernel}, but a parser thread got TCP bind {} and connect {}",
                check.tcp_bind, check.tcp_connect
            ),
            Some("Report this: the kernel should deny both"),
        ),
        None => (
            State::Unavailable,
            "self_test_failed",
            format!("Kernel Landlock ABI {kernel}, but the parser check did not complete"),
            Some("Report this: the kernel should deny both"),
        ),
    }
}

/// What the reports of a live session say of Landlock. Entry reports only, so
/// the check says what each worker's layer enforced rather than trying a
/// connection: Settings asks for this on every frame.
#[cfg(target_os = "linux")]
fn live_landlock(
    main: &sandbox::Report,
    workers: &std::collections::BTreeMap<String, sandbox::worker::Component>,
) -> Option<Landlock> {
    let parser = workers.iter().find_map(|(name, worker)| {
        let is_parser = sandbox::roles::role_for(name) == sandbox::Role::Parser;
        worker.report.as_ref().filter(|_| is_parser)
    });
    let report = parser.unwrap_or(main);
    Some(Landlock {
        kernel_abi: report.platform.landlock_kernel_abi,
        availability: report
            .platform
            .landlock_availability
            .unwrap_or("unknown")
            .into(),
        errata: sandbox::landlock_errata(),
        parser_check: parser.map(|parser| {
            let held = |restriction: &'static str| {
                let denied = parser.platform.landlock_restrictions.contains(&restriction);
                String::from(if denied { "denied" } else { "allowed" })
            };
            ParserCheck {
                enforced_abi: parser.platform.landlock_abi,
                restrictions: restrictions_of(parser),
                tcp_bind: held("tcp_bind"),
                tcp_connect: held("tcp_connect"),
            }
        }),
    })
}
#[cfg(not(target_os = "linux"))]
fn live_landlock(
    _main: &sandbox::Report,
    _workers: &std::collections::BTreeMap<String, sandbox::worker::Component>,
) -> Option<Landlock> {
    None
}

#[cfg(target_os = "linux")]
fn restrictions_of(report: &sandbox::Report) -> Vec<String> {
    report
        .platform
        .landlock_restrictions
        .iter()
        .map(|restriction| (*restriction).to_owned())
        .collect()
}

/// A loopback listener doctor binds itself, so that a TCP connect that is not
/// denied reaches nothing else. Without one, as with loopback down, the connect
/// goes to port 0, which nothing can listen on.
#[cfg(target_os = "linux")]
struct TcpCheck(Option<std::net::TcpListener>);
#[cfg(target_os = "linux")]
impl TcpCheck {
    fn new() -> Self {
        Self(std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).ok())
    }
    /// What TCP bind and connect do on the calling thread. Landlock answers
    /// EACCES before it looks at the address, so a down loopback does not hide
    /// a deny.
    fn run(&self) -> (&'static str, &'static str) {
        let observed = |result: std::io::Result<()>| match result {
            Ok(()) => "allowed",
            Err(error) if error.raw_os_error() == Some(nix::libc::EACCES) => "denied",
            Err(_) => "error",
        };
        let port = self
            .0
            .as_ref()
            .and_then(|listener| listener.local_addr().ok())
            .map_or(0, |addr| addr.port());
        let localhost = std::net::Ipv4Addr::LOCALHOST;
        (
            observed(std::net::TcpListener::bind((localhost, 0)).map(drop)),
            observed(std::net::TcpStream::connect((localhost, port)).map(drop)),
        )
    }
}

/// Take a parser's policy on a thread that ends with it, and try TCP from
/// there. It runs with the sandbox disabled too: what this kernel can do does
/// not depend on what the configuration asks for.
#[cfg(target_os = "linux")]
fn landlock_self_test() -> Landlock {
    let check = TcpCheck::new();
    let outcome = std::thread::Builder::new()
        .name("landlock-check".into())
        .spawn(move || {
            let report = sandbox::apply_retaining(
                Mode::BestEffort,
                &sandbox::SandboxPaths::default(),
                sandbox::Retain::Nothing,
                sandbox::Role::Parser,
            );
            let (tcp_bind, tcp_connect) = check.run();
            (report, tcp_bind, tcp_connect)
        })
        .ok()
        .and_then(|thread| thread.join().ok());
    let errata = sandbox::landlock_errata();
    let Some((report, tcp_bind, tcp_connect)) = outcome else {
        return Landlock {
            kernel_abi: 0,
            availability: "unknown".into(),
            errata,
            parser_check: None,
        };
    };
    Landlock {
        kernel_abi: report.platform.landlock_kernel_abi,
        availability: report
            .platform
            .landlock_availability
            .unwrap_or("unknown")
            .into(),
        errata,
        parser_check: Some(ParserCheck {
            enforced_abi: report.platform.landlock_abi,
            restrictions: restrictions_of(&report),
            tcp_bind: tcp_bind.into(),
            tcp_connect: tcp_connect.into(),
        }),
    }
}

/// The capture thread's policy on the calling thread, so strict fails here
/// where it would refuse capture. What the check saw of TCP stands in for what
/// the layer reported, and it runs before the no-socket filter, as a worker's
/// entry does, because the filter would stop it at socket(2).
fn enter_capture_policy(mode: Mode) -> sandbox::Report {
    #[cfg(target_os = "linux")]
    let check = TcpCheck::new();
    let mut report = sandbox::apply_retaining(
        mode,
        &sandbox::SandboxPaths::default(),
        sandbox::Retain::Nothing,
        sandbox::Role::Capture,
    );
    #[cfg(target_os = "linux")]
    if report.platform.landlock_network_blocked {
        let (bind, connect) = check.run();
        if (bind, connect) != ("denied", "denied") {
            report.platform.landlock_network_blocked = false;
            report.mode.warnings.push(format!(
                "capture layer reports TCP denied, but bind got {bind} and connect {connect}"
            ));
        }
    }
    sandbox::deny_socket_create(mode, &mut report);
    report
}

fn wrap(lines: &mut Vec<String>, value: &str) {
    let clean: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    // A fix's commands take a row each. This wraps by the column, and a row
    // broken inside a command pastes as a different one.
    match crate::platform::fix_commands(&clean) {
        Some((sentence, commands)) => {
            wrap_row(lines, sentence);
            for command in commands {
                wrap_row(lines, command);
            }
        }
        None => wrap_row(lines, &clean),
    }
}

fn wrap_row(lines: &mut Vec<String>, clean: &str) {
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

/// A capability's state, reason code, detail and next check.
type Assessment = (State, &'static str, String, Option<&'static str>);

/// One database as doctor words it, and how old it is when it is loaded.
fn describe_db(what: &str, file: &DbFile, now: SystemTime) -> (String, Option<Duration>) {
    match file {
        DbFile::NotConfigured => (format!("{what}: none"), None),
        DbFile::Unreadable { path, error } => {
            (format!("{what}: {path} did not open: {error}"), None)
        }
        DbFile::Loaded {
            path,
            database_type,
            build_epoch,
        } => {
            let built = UNIX_EPOCH.checked_add(Duration::from_secs(*build_epoch));
            let date = crate::collectors::geo::epoch_date(*build_epoch)
                .map_or_else(|| "?".into(), |at| at.format("%Y-%m-%d").to_string());
            (
                format!("{what}: {database_type} built {date}, {path}"),
                built.and_then(|built| now.duration_since(built).ok()),
            )
        }
    }
}

/// Doctor's view of the GeoIP databases, from a read of their metadata. No
/// lookup is made and no endpoint contacted.
fn geoip_db_assessment(status: &DbStatus, now: SystemTime) -> Assessment {
    const UPDATE: &str = "netwatch geoip update";
    const FIX: &str = "netwatch geoip update, or fix the path in config.toml";
    const REFRESH: &str =
        "netwatch geoip update refreshes the downloaded files; replace any you set yourself";
    let (city, city_age) = describe_db("Country/City", &status.city, now);
    let (asn, asn_age) = describe_db("ASN", &status.asn, now);
    // First, so doctor's text, which wraps by character, keeps the link whole.
    let detail = match status.attribution() {
        Some(line) => format!("{line}. {city}; {asn}"),
        None => format!("{city}; {asn}"),
    };
    let stale = [city_age, asn_age]
        .into_iter()
        .flatten()
        .any(|age| age > GEOIP_DB_STALE_AFTER);
    match (&status.city, &status.asn) {
        (DbFile::NotConfigured, _) => (
            State::Disabled,
            "not_configured",
            format!("No Country or City database, so no GeoIP lookups; {asn}"),
            Some(UPDATE),
        ),
        (DbFile::Unreadable { .. }, _) => (State::Unavailable, "db_unreadable", detail, Some(FIX)),
        (DbFile::Loaded { .. }, DbFile::Unreadable { .. }) => {
            (State::Degraded, "db_unreadable", detail, Some(FIX))
        }
        (DbFile::Loaded { .. }, _) if stale => (
            State::Degraded,
            "db_stale",
            format!("Older than 60 days. {detail}"),
            Some(REFRESH),
        ),
        (DbFile::Loaded { .. }, _) => (State::Ready, "db_loaded", detail, None),
    }
}

/// Doctor's view of the Linux connection table, before any poll: `ss` on
/// `PATH`, or the `/proc/net` tables a live session falls back to without it.
/// Nothing is run, so a present `ss` that fails is only seen live.
#[cfg(target_os = "linux")]
fn static_connection_table(ss: Option<&std::path::Path>, proc_net_readable: bool) -> Assessment {
    match (ss, proc_net_readable) {
        (Some(path), _) => (
            State::Ready,
            "ss_found",
            format!(
                "{} found; live sessions read the connection table from ss -tuna (not run here)",
                path.display()
            ),
            None,
        ),
        (None, true) => (
            State::Degraded,
            "proc_net_fallback",
            "ss not found on PATH; live sessions read the connection table from \
             /proc/net/{tcp,tcp6,udp,udp6} instead, without the device names ss prints"
                .into(),
            Some("Install iproute2 for ss"),
        ),
        (None, false) => (
            State::Unavailable,
            "no_connection_table",
            "ss not found on PATH and /proc/net/tcp is unreadable; the connection table \
             will be empty"
                .into(),
            Some("Install iproute2 for ss, or mount /proc"),
        ),
    }
}

/// Where the latest live poll's connection table came from, and why it was
/// not `ss` when it was not.
#[cfg(target_os = "linux")]
fn live_connection_table(coverage: &crate::collectors::attribution::Coverage) -> Assessment {
    use crate::collectors::attribution::TableSource;
    let note = coverage
        .table_note
        .as_deref()
        .unwrap_or("no reason recorded");
    let next = if note.starts_with("ss not found") {
        "Install iproute2 for ss"
    } else {
        "Check that ss -tuna runs for this user and sandbox"
    };
    if coverage.completed_at.is_none() {
        return (
            State::NotChecked,
            "first_poll_pending",
            "No connection poll has completed".into(),
            None,
        );
    }
    match coverage.table_source {
        Some(TableSource::Ss) => (
            State::Ready,
            "ss",
            "Connection table from ss -tuna".into(),
            None,
        ),
        Some(TableSource::ProcNet) => (
            State::Degraded,
            "proc_net_fallback",
            format!("{note}; connection table read from /proc/net/{{tcp,tcp6,udp,udp6}}"),
            Some(next),
        ),
        None => (
            State::Unavailable,
            "collection_failed",
            format!("{note}; the connection table is empty"),
            Some(next),
        ),
    }
}

/// Add what config files got wrong to the `config` row: key names and files,
/// never a value, as with a file that does not parse. A key that is ignored means
/// a setting is not in force, which is `degraded`. A renamed key still works, so
/// the row stays `ready` with a reason of its own.
fn report_config_warnings(
    files: [&Vec<ConfigWarning>; 2],
    state: &mut State,
    code: &mut &'static str,
    detail: &mut String,
) {
    for warnings in files {
        let Some(first) = warnings.first() else {
            continue;
        };
        let messages: Vec<_> = warnings.iter().map(|w| w.kind.message()).collect();
        detail.push_str(&format!(
            "; {}: {}",
            first.file.display(),
            messages.join(", ")
        ));
    }
    if *state != State::Ready {
        return;
    }
    let kinds = || files.into_iter().flatten().map(|w| &w.kind);
    if kinds().any(|kind| matches!(kind, ConfigWarningKind::UnknownKey(_))) {
        *state = State::Degraded;
        *code = "config_unknown_keys";
    } else if kinds().any(|kind| matches!(kind, ConfigWarningKind::RenamedKey { .. })) {
        *code = "config_renamed_keys";
    }
}

pub fn inspect_static(interface: Option<String>) -> CapabilitySnapshot {
    use crate::config::ConfigError;
    // The loader live sessions use, so doctor fails a file exactly when they
    // refuse it. It gives the line and column but not toml's message, which
    // quotes the line: malformed content is never echoed.
    const REFUSED: &str = "defaults shown. Live sessions refuse to start until it is fixed";
    let path = NetwatchConfig::path();
    let loaded = path.as_deref().map(NetwatchConfig::load_from);
    let (config, mut config_state, mut code, mut detail) = match loaded {
        Some(Ok(config)) if path.as_deref().is_some_and(std::path::Path::exists) => (
            config,
            State::Ready,
            "config_valid",
            "Configuration parsed; endpoints not contacted".to_string(),
        ),
        Some(Err(ConfigError::Parse { path, position, .. })) => (
            NetwatchConfig::default(),
            State::Unavailable,
            "config_invalid",
            match position {
                Some((line, column)) => format!(
                    "{} is invalid at line {line}, column {column}; {REFUSED}",
                    path.display()
                ),
                None => format!("{} is invalid; {REFUSED}", path.display()),
            },
        ),
        Some(Err(ConfigError::Read { path, source })) => (
            NetwatchConfig::default(),
            State::Unavailable,
            "config_unreadable",
            format!("{} cannot be read ({source}); {REFUSED}", path.display()),
        ),
        Some(Ok(_)) | None => (
            NetwatchConfig::default(),
            State::Ready,
            "defaults",
            "No saved configuration; defaults shown".to_string(),
        ),
    };
    let policy = crate::collectors::egress::default_policy_warnings();
    report_config_warnings(
        [&config.load_warnings, &policy],
        &mut config_state,
        &mut code,
        &mut detail,
    );
    let mut snapshot = CapabilitySnapshot::configured(&config);
    snapshot.put(
        "config",
        config_state,
        code,
        &detail,
        Some("Review config.toml; doctor never writes it"),
    );
    #[cfg(target_os = "linux")]
    {
        snapshot.landlock = Some(landlock_self_test());
        let (state, reason, detail, next) = landlock_capability(
            true,
            Mode::from_config(&config.sandbox),
            snapshot.landlock.as_ref(),
        );
        snapshot.put("landlock", state, reason, &detail, next);
    }
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
    #[cfg(target_os = "linux")]
    {
        let (state, reason, detail, next) = static_connection_table(
            crate::collectors::connections::ss_on_path().as_deref(),
            std::fs::File::open("/proc/net/tcp").is_ok(),
        );
        snapshot.put("connections", state, reason, &detail, next);
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
    // Doctor runs this check only once the config loads. If it stopped loading
    // since, the check fails rather than opening capture without its filter.
    let config = NetwatchConfig::load()?;
    let filter = (!config.bpf_filter.is_empty()).then_some(config.bpf_filter.as_str());
    let result = match crate::collectors::packets::prepare_capture(interface, filter) {
        Err(error) => CaptureResult {
            interface: interface.into(),
            opened: false,
            error: Some(error),
            protection: None,
        },
        Ok(capture) => {
            let report = enter_capture_policy(mode);
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
        // The check runs under the configured interface, filter and sandbox
        // mode. A config that does not load leaves those unknown, and the
        // defaults could check a weaker sandbox than the one configured.
        if let Ok(config) = NetwatchConfig::load() {
            let interface = snapshot.interface.clone().unwrap_or_default();
            let mode = Mode::from_config(&config.sandbox);
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
                        snapshot.put("sandbox",state,"isolated_capture_check",&with_root_note("Protection applies only to the isolated check process; live worker enforcement is not tested".to_string()),None);
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
        } else {
            snapshot.put(
                "capture",
                State::NotChecked,
                "config_not_loaded",
                "Capture not opened: the configuration does not load",
                Some("Fix config.toml as the config entry says, then check again"),
            );
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
    #[test]
    fn a_renamed_key_leaves_config_ready_and_an_ignored_one_does_not() {
        use crate::config::{ConfigWarning, ConfigWarningKind};
        let warning = |kind| ConfigWarning {
            file: "/etc/netwatch/config.toml".into(),
            kind,
        };
        let renamed = warning(ConfigWarningKind::RenamedKey {
            old: "colour_theme",
            new: "theme",
            since: "1.1",
            both_set: false,
        });
        let unknown = warning(ConfigWarningKind::UnknownKey("typo".into()));
        let report = |warnings: Vec<ConfigWarning>, state: State| {
            let (mut state, mut code, mut detail) = (state, "config_valid", "Parsed".to_string());
            report_config_warnings([&warnings, &Vec::new()], &mut state, &mut code, &mut detail);
            (state, code, detail)
        };

        let (state, code, detail) = report(vec![], State::Ready);
        assert_eq!(
            (state, code, detail.as_str()),
            (State::Ready, "config_valid", "Parsed")
        );

        let (state, code, detail) = report(vec![renamed.clone()], State::Ready);
        assert_eq!((state, code), (State::Ready, "config_renamed_keys"));
        assert!(
            detail.contains("colour_theme was renamed theme in 1.1"),
            "{detail}"
        );
        assert!(detail.contains("/etc/netwatch/config.toml"), "{detail}");

        let (state, code, detail) = report(vec![renamed, unknown.clone()], State::Ready);
        assert_eq!((state, code), (State::Degraded, "config_unknown_keys"));
        assert!(
            detail.contains("colour_theme") && detail.contains("typo"),
            "{detail}"
        );

        // A file that did not load stays what it is.
        let (state, code, _) = report(vec![unknown], State::Unavailable);
        assert_eq!((state, code), (State::Unavailable, "config_valid"));
    }

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
    fn loaded(age_days: u64, now: SystemTime) -> DbFile {
        let built = now.duration_since(UNIX_EPOCH).unwrap().as_secs() - age_days * 86_400;
        DbFile::Loaded {
            path: "/geo/db.mmdb".into(),
            database_type: "DBIP-Country-Lite".into(),
            build_epoch: built,
        }
    }
    #[test]
    fn geoip_db_absent_suggests_update() {
        let snapshot = CapabilitySnapshot::configured(&NetwatchConfig::default());
        let geoip = snapshot.get("geoip_db");
        assert_eq!(geoip.state, State::Disabled);
        assert_eq!(geoip.reason, "not_configured");
        assert_eq!(geoip.next_check.as_deref(), Some("netwatch geoip update"));
    }
    #[test]
    fn geoip_db_unreadable_is_unavailable() {
        let config = NetwatchConfig {
            geoip_db: "/nonexistent/x.mmdb".into(),
            ..Default::default()
        };
        let snapshot = CapabilitySnapshot::configured(&config);
        let geoip = snapshot.get("geoip_db");
        assert_eq!(geoip.state, State::Unavailable);
        assert_eq!(geoip.reason, "db_unreadable");
        assert!(
            geoip.detail.contains("/nonexistent/x.mmdb"),
            "{}",
            geoip.detail
        );
        assert!(geoip
            .next_check
            .as_deref()
            .unwrap()
            .contains("geoip update"));
    }
    /// Country still answers with the ASN file broken, so it is not called
    /// unavailable, but the reason is the same.
    #[test]
    fn geoip_db_with_only_the_asn_file_unreadable_is_degraded() {
        let now = SystemTime::now();
        let status = DbStatus {
            city: loaded(1, now),
            asn: DbFile::Unreadable {
                path: "/geo/asn.mmdb".into(),
                error: "bad".into(),
            },
        };
        let (state, reason, detail, _) = geoip_db_assessment(&status, now);
        assert_eq!((state, reason), (State::Degraded, "db_unreadable"));
        assert!(
            detail.contains("/geo/asn.mmdb did not open: bad"),
            "{detail}"
        );
    }
    #[test]
    fn geoip_db_ready_until_sixty_days_old() {
        let now = SystemTime::now();
        let assess = |city: u64, asn: u64| {
            let status = DbStatus {
                city: loaded(city, now),
                asn: loaded(asn, now),
            };
            geoip_db_assessment(&status, now)
        };
        let (state, reason, detail, next) = assess(59, 59);
        assert_eq!((state, reason, next), (State::Ready, "db_loaded", None));
        assert!(detail.contains("DBIP-Country-Lite built "), "{detail}");
        for (city, asn) in [(61, 1), (1, 61)] {
            let (state, reason, _, next) = assess(city, asn);
            assert_eq!((state, reason), (State::Degraded, "db_stale"));
            assert!(next.unwrap().contains("netwatch geoip update"));
        }
    }
    /// What doctor reports for a file written to `name` with this
    /// `database_type`, as it reads a real one.
    fn geoip_db_for(name: &str, database_type: &str) -> Capability {
        use crate::collectors::geo::test_db;
        let dir = std::env::temp_dir().join(format!("nw-doctor-geo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        std::fs::write(&path, test_db::city(database_type, now.as_secs())).unwrap();
        let config = NetwatchConfig {
            geoip_db: path.to_str().unwrap().to_owned(),
            ..Default::default()
        };
        let snapshot = CapabilitySnapshot::configured(&config);
        let _ = std::fs::remove_dir_all(&dir);
        snapshot.get("geoip_db").clone()
    }
    /// What doctor reports for a file holding `bytes`.
    fn geoip_db_of(bytes: &[u8]) -> Capability {
        let dir = std::env::temp_dir().join(format!("nw-doctor-geo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.mmdb");
        std::fs::write(&path, bytes).unwrap();
        let config = NetwatchConfig {
            geoip_db: path.to_str().unwrap().to_owned(),
            ..Default::default()
        };
        let snapshot = CapabilitySnapshot::configured(&config);
        let _ = std::fs::remove_dir_all(&dir);
        snapshot.get("geoip_db").clone()
    }
    /// This date fits `SystemTime` but not chrono, and chrono's conversion
    /// panicked here: doctor and daemon exited 101, and the TUI left the
    /// alternate screen the same way, on one hand-made file.
    #[test]
    fn geoip_db_with_an_out_of_range_build_epoch_is_unreadable() {
        use crate::collectors::geo::test_db;
        for epoch in [9_000_000_000_000, u64::MAX] {
            let geoip = geoip_db_of(&test_db::city("DBIP-Country-Lite", epoch));
            assert_eq!(geoip.state, State::Unavailable, "{epoch}");
            assert_eq!(geoip.reason, "db_unreadable", "{epoch}");
            assert!(geoip.detail.contains("build_epoch"), "{}", geoip.detail);
        }
    }
    /// The wording itself must not panic on a value that reached it some other
    /// way, and says nothing about a date it cannot state.
    #[test]
    fn describing_an_out_of_range_date_does_not_panic() {
        let now = SystemTime::now();
        for build_epoch in [9_000_000_000_000, u64::MAX] {
            let file = DbFile::Loaded {
                path: "/geo/db.mmdb".into(),
                database_type: "DBIP-Country-Lite".into(),
                build_epoch,
            };
            let (text, age) = describe_db("Country/City", &file, now);
            assert!(text.contains("built ?"), "{text}");
            assert_eq!(age, None);
        }
    }
    /// DB-IP's data carries its attribution wherever the file came from, here
    /// a name the download would never use.
    #[test]
    fn geoip_db_detail_attributes_a_dbip_database() {
        let geoip = geoip_db_for("own.mmdb", "DBIP-City-Lite");
        assert_eq!(
            (geoip.state, geoip.reason.as_str()),
            (State::Ready, "db_loaded")
        );
        assert!(
            geoip
                .detail
                .contains("IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0"),
            "{}",
            geoip.detail
        );
    }
    /// A MaxMind file named as the download names its files is still MaxMind's.
    #[test]
    fn geoip_db_detail_does_not_attribute_another_database() {
        let geoip = geoip_db_for("dbip-city-lite.mmdb", "GeoLite2-City");
        assert_eq!(
            (geoip.state, geoip.reason.as_str()),
            (State::Ready, "db_loaded")
        );
        assert!(geoip.detail.contains("GeoLite2-City"), "{}", geoip.detail);
        assert!(!geoip.detail.contains("IP geolocation"), "{}", geoip.detail);
        assert!(!geoip.detail.contains("db-ip.com"), "{}", geoip.detail);
    }
    /// doctor's text wraps at 80 columns by character, so the line has to come
    /// where a wrap cannot cut its link, stale or not.
    #[test]
    fn geoip_db_attribution_survives_text_wrapping() {
        let now = SystemTime::now();
        for age in [1, 61] {
            let status = DbStatus {
                city: loaded(age, now),
                asn: DbFile::NotConfigured,
            };
            let (state, reason, detail, next) = geoip_db_assessment(&status, now);
            let mut snapshot = CapabilitySnapshot::configured(&NetwatchConfig::default());
            snapshot.put("geoip_db", state, reason, &detail, next);
            let text = snapshot.text();
            assert!(
                text.lines()
                    .any(|line| line
                        .contains("IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0")),
                "{text}"
            );
        }
    }
    /// Without a Country or City database a session makes no lookup, so an
    /// ASN file alone does not count as loaded.
    #[test]
    fn geoip_db_with_only_an_asn_file_is_not_configured() {
        let now = SystemTime::now();
        let status = DbStatus {
            city: DbFile::NotConfigured,
            asn: loaded(1, now),
        };
        let (state, reason, detail, _) = geoip_db_assessment(&status, now);
        assert_eq!((state, reason), (State::Disabled, "not_configured"));
        assert!(detail.contains("ASN: "), "{detail}");
        assert!(!detail.contains("IP geolocation"), "{detail}");
    }
    #[test]
    fn online_geo_reports_removed() {
        for geoip_online in [false, true] {
            let config = NetwatchConfig {
                geoip_online,
                ..Default::default()
            };
            let snapshot = CapabilitySnapshot::configured(&config);
            let online = snapshot.get("online_geo");
            assert_eq!(online.state, State::Disabled);
            assert_eq!(online.reason, "removed");
            assert_eq!(online.detail.contains("is ignored"), geoip_online);
            assert_eq!(online.next_check.as_deref(), Some("netwatch geoip update"));
        }
    }
    fn insights_config(endpoint: &str) -> NetwatchConfig {
        NetwatchConfig {
            insights_enabled: true,
            insights_endpoint: endpoint.into(),
            ..Default::default()
        }
    }
    #[test]
    fn insights_cleartext_is_degraded() {
        let endpoint = "http://10.0.0.5:11434";
        let config = insights_config(endpoint);
        let snapshot = CapabilitySnapshot::configured(&config);
        let cap = snapshot.get("insights");
        assert_eq!(cap.state, State::Degraded);
        assert_eq!(cap.reason, "cleartext_off_host");
        assert!(cap.detail.contains("cleartext, off-host"), "{}", cap.detail);
        assert!(!cap.detail.contains(endpoint), "{}", cap.detail);

        // Live, whatever the collector says: a model that answers makes the
        // data no less readable on the way there.
        let app = App::prepare_with_config(config);
        let cap = CapabilitySnapshot::live(&app);
        let cap = cap.get("insights");
        assert_eq!(cap.state, State::Degraded);
        assert_eq!(cap.reason, "cleartext_off_host");
        assert!(
            cap.detail.contains("endpoint not verified"),
            "{}",
            cap.detail
        );

        // Nothing is sent with the feature off, or to this host, or over TLS.
        let off = NetwatchConfig {
            insights_enabled: false,
            ..insights_config(endpoint)
        };
        assert_eq!(
            CapabilitySnapshot::configured(&off).get("insights").state,
            State::Disabled
        );
        for fine in [
            "local",
            "http://127.0.0.1:11434",
            "https://ollama.example.com",
        ] {
            let snapshot = CapabilitySnapshot::configured(&insights_config(fine));
            let cap = snapshot.get("insights");
            assert_eq!(cap.state, State::NotChecked, "{fine}");
            assert_eq!(cap.reason, "configuration_only", "{fine}");
        }
    }
    /// `--check-capture` prints the refused-capture error as text, and the
    /// header's pointer sends people here. Wrapped by the column, a row ended
    /// in `sudo groupadd -f net`, which pastes as a group named net.
    #[test]
    fn doctor_text_keeps_each_fix_command_on_a_row_of_its_own() {
        let fix = crate::platform::LINUX_CAPTURE_FIX;
        let mut snapshot = CapabilitySnapshot::configured(&NetwatchConfig::default());
        snapshot.put(
            "capture",
            State::Unavailable,
            "capture_open_failed",
            &format!("not permitted — {fix}"),
            None,
        );
        let text = snapshot.text();
        let rows: Vec<&str> = text.lines().map(str::trim).collect();
        let at = rows.iter().position(|r| *r == "not permitted").unwrap();
        for (i, command) in fix.split_inclusive(" && ").enumerate() {
            assert_eq!(rows[at + 1 + i], command.trim_end(), "{text}");
        }
        // And the JSON, which the pointer names, holds the line as one string.
        let json = serde_json::to_value(&snapshot).unwrap();
        assert!(json["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["detail"].as_str().is_some_and(|d| d.contains(fix))));
    }
    /// A completion stamp on a probe that was skipped is not a probe target
    /// answering, so doctor must not count it among the fresh ones.
    #[test]
    fn a_skipped_internet_probe_is_not_a_fresh_completion() {
        let config = NetwatchConfig {
            third_party_probes: false,
            ..Default::default()
        };
        assert!(CapabilitySnapshot::configured(&config)
            .get("probes")
            .detail
            .contains("third_party_probes is off"));
        let app = App::prepare_with_config(config);
        let mut status = (*app.health_prober.status()).clone();
        let now = Instant::now();
        status.completed.gateway = Some(now);
        status.completed.internet = Some(now);
        app.health_prober.publish_for_test(status.clone());
        let snapshot = CapabilitySnapshot::live(&app);
        let probes = snapshot.get("probes");
        assert_eq!(probes.state, State::Degraded);
        assert!(
            probes.detail.starts_with("1/2 probe targets"),
            "{}",
            probes.detail
        );
        assert!(
            probes.detail.contains("third_party_probes is off"),
            "{}",
            probes.detail
        );

        status.completed.dns = Some(now);
        app.health_prober.publish_for_test(status);
        let snapshot = CapabilitySnapshot::live(&app);
        assert_eq!(snapshot.get("probes").state, State::Ready);

        // And with the switch on, the same two local stamps are not all of them.
        let app = App::prepare_with_config(NetwatchConfig::default());
        let mut status = (*app.health_prober.status()).clone();
        status.completed.gateway = Some(now);
        status.completed.dns = Some(now);
        app.health_prober.publish_for_test(status);
        let snapshot = CapabilitySnapshot::live(&app);
        assert_eq!(snapshot.get("probes").state, State::Degraded);
        assert!(snapshot
            .get("probes")
            .detail
            .starts_with("2/3 probe targets"));
    }
    /// Since 0.32.2 eBPF loads inside the sandbox policy, so the default
    /// configuration must not report it switched off by that policy.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[test]
    fn static_doctor_says_ebpf_loads_under_the_sandbox() {
        let snapshot = CapabilitySnapshot::configured(&NetwatchConfig::default());
        let detail = &snapshot.get("attribution").detail;
        assert!(!detail.contains("disabled"), "{detail}");
        assert!(detail.contains("keeps load capabilities"), "{detail}");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn static_doctor_names_the_connection_table_it_expects() {
        let (state, reason, detail, next) =
            static_connection_table(Some(std::path::Path::new("/usr/sbin/ss")), true);
        assert_eq!((state, reason, next), (State::Ready, "ss_found", None));
        assert!(detail.starts_with("/usr/sbin/ss found"), "{detail}");

        let (state, reason, detail, next) = static_connection_table(None, true);
        assert_eq!(
            (state, reason, next),
            (
                State::Degraded,
                "proc_net_fallback",
                Some("Install iproute2 for ss")
            )
        );
        assert!(detail.contains("ss not found") && detail.contains("/proc/net/"));

        let (state, reason, _, _) = static_connection_table(None, false);
        assert_eq!((state, reason), (State::Unavailable, "no_connection_table"));
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn live_report_says_where_the_connection_table_came_from() {
        use crate::collectors::attribution::{Coverage, TableSource};
        let polled = |source: Option<TableSource>, note: Option<&str>| Coverage {
            completed_at: Some(Instant::now()),
            collection_succeeded: source.is_some(),
            table_source: source,
            table_note: note.map(str::to_owned),
            ..Default::default()
        };
        assert_eq!(
            live_connection_table(&Coverage::default()).0,
            State::NotChecked
        );
        let (state, reason, _, next) = live_connection_table(&polled(Some(TableSource::Ss), None));
        assert_eq!((state, reason, next), (State::Ready, "ss", None));

        let (state, reason, detail, next) =
            live_connection_table(&polled(Some(TableSource::ProcNet), Some("ss not found")));
        assert_eq!(
            (state, reason, next),
            (
                State::Degraded,
                "proc_net_fallback",
                Some("Install iproute2 for ss")
            )
        );
        assert_eq!(
            detail,
            "ss not found; connection table read from /proc/net/{tcp,tcp6,udp,udp6}"
        );

        // An ss that exists but cannot run is not fixed by installing it.
        let (_, _, _, next) = live_connection_table(&polled(
            Some(TableSource::ProcNet),
            Some("ss could not start: Permission denied (os error 13)"),
        ));
        assert_eq!(
            next,
            Some("Check that ss -tuna runs for this user and sandbox")
        );

        let (state, reason, detail, _) = live_connection_table(&polled(
            None,
            Some("ss not found; /proc/net/tcp: No such file or directory (os error 2)"),
        ));
        assert_eq!((state, reason), (State::Unavailable, "collection_failed"));
        assert!(
            detail.ends_with("the connection table is empty"),
            "{detail}"
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn settings_names_the_connection_table_only_when_it_is_not_ss() {
        let mut snapshot = CapabilitySnapshot::configured(&NetwatchConfig::default());
        let usual = "capture: not checked · attribution: not checked · sandbox:";
        assert_eq!(snapshot.connection_table_line(), None);
        snapshot.put("connections", State::Ready, "ss", "", None);
        assert_eq!(snapshot.connection_table_line(), None);
        snapshot.put(
            "connections",
            State::Degraded,
            "proc_net_fallback",
            "ss not found; read /proc/net",
            None,
        );
        assert_eq!(
            snapshot.connection_table_line().as_deref(),
            Some("connections: degraded · ss not found; read /proc/net")
        );
        assert!(snapshot.compact().starts_with(usual));
        assert!(!snapshot.compact().contains("connections"));
        snapshot.put("connections", State::Unavailable, "", "empty", None);
        assert_eq!(
            snapshot.connection_table_line().as_deref(),
            Some("connections: unavailable · empty")
        );
    }
    /// A consumer of the stable doctor JSON sees one new capability id and
    /// nothing else changed: the snapshot still parses into the same shape.
    #[cfg(target_os = "linux")]
    #[test]
    fn connections_capability_is_additive() {
        let snapshot = CapabilitySnapshot::configured(&NetwatchConfig::default());
        assert_eq!(snapshot.get("connections").state, State::NotChecked);
        assert_eq!(snapshot.schema_version, 1);
        let ids: Vec<_> = snapshot
            .capabilities
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        let at = ids.iter().position(|id| *id == "connections").unwrap();
        assert_eq!(ids[at - 1], "attribution");
        let restored: CapabilitySnapshot =
            serde_json::from_str(&serde_json::to_string(&snapshot).unwrap()).unwrap();
        assert_eq!(restored.get("connections").reason, "table_unchecked");
    }
    /// A consumer holding a schema_version 1 document from before these
    /// fields still reads it, and so does anything that wrote one.
    #[test]
    fn landlock_fields_are_additive() {
        let old = r#"{
            "schema_version": 1,
            "scope": "capture_check",
            "platform": "linux",
            "interface": "eth0",
            "capabilities": [],
            "protections": [{
                "component": "capture-check",
                "entry_ready": true,
                "effective": "best-effort",
                "landlock_abi": 9,
                "caps_dropped": [],
                "caps_retained": [],
                "warnings": [],
                "error": null
            }],
            "network_restricted": false
        }"#;
        let restored: CapabilitySnapshot = serde_json::from_str(old).unwrap();
        assert_eq!(restored.schema_version, 1);
        assert_eq!(restored.landlock, None);
        assert_eq!(restored.tasks_holding_net_raw, None);
        let protection = &restored.protections[0];
        assert_eq!(protection.landlock_abi, 9);
        assert_eq!(protection.landlock_kernel_abi, 0);
        assert!(protection.landlock_restrictions.is_empty());

        // And what doctor writes now still has every field a v1 consumer read.
        let snapshot = CapabilitySnapshot::configured(&NetwatchConfig::default());
        let json = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["network_restricted"], false);
        assert!(json["landlock"].is_null());
        assert!(json["tasks_holding_net_raw"].is_null());
        for field in [
            "scope",
            "platform",
            "interface",
            "capabilities",
            "protections",
        ] {
            assert!(json.get(field).is_some(), "{field}");
        }
    }
    #[test]
    fn a_protection_says_what_its_report_says() {
        let mut report = sandbox::Report::default();
        report.platform.landlock_abi = 9;
        report.platform.landlock_kernel_abi = 9;
        report.platform.landlock_network_blocked = true;
        report.platform.landlock_restrictions = vec!["filesystem", "tcp_bind", "tcp_connect"];
        report.platform.capture_authority = sandbox::NetRaw::Dropped;
        report.platform.socket_filter = sandbox::SocketFilter::Installed;
        let protection = Protection::from_report("capture", true, Some(&report), None);
        assert_eq!(protection.landlock_kernel_abi, 9);
        assert_eq!(protection.network_policy, "denied");
        assert_eq!(
            protection.landlock_restrictions,
            ["filesystem", "tcp_bind", "tcp_connect"]
        );
        assert_eq!(protection.capture_authority, "dropped");
        assert_eq!(protection.socket_filter, "installed");
        // A worker with no report ran under no policy of its own, which is not
        // the same as one that entered and was allowed the network.
        let waiting = Protection::from_report("traffic", false, None, None);
        assert_eq!(waiting.network_policy, "not_entered");
        assert_eq!(waiting.capture_authority, "not_applicable");
        assert_eq!(waiting.socket_filter, "not_applicable");
    }
    #[test]
    fn landlock_capability_covers_each_reason() {
        let found = |kernel_abi, availability: &str, bind: &str, connect: &str| Landlock {
            kernel_abi,
            availability: availability.into(),
            errata: vec![],
            parser_check: Some(ParserCheck {
                enforced_abi: kernel_abi,
                restrictions: vec![],
                tcp_bind: bind.into(),
                tcp_connect: connect.into(),
            }),
        };
        let assess = |landlock: &Landlock| {
            let (state, reason, _, _) = landlock_capability(true, Mode::BestEffort, Some(landlock));
            (state, reason)
        };
        assert_eq!(
            assess(&found(9, "available", "denied", "denied")),
            (State::Ready, "parser_network_denied")
        );
        assert_eq!(
            assess(&found(4, "available", "denied", "denied")),
            (State::Ready, "parser_network_denied")
        );
        for kernel in [1, 3] {
            assert_eq!(
                assess(&found(kernel, "available", "allowed", "allowed")),
                (State::Degraded, "kernel_abi_below_4")
            );
        }
        assert_eq!(
            assess(&found(0, "not_enabled", "allowed", "allowed")),
            (State::Unavailable, "landlock_not_enabled")
        );
        assert_eq!(
            assess(&found(0, "not_built", "allowed", "allowed")),
            (State::Unavailable, "landlock_not_built")
        );
        // A kernel that can deny TCP and did not, one way or the other.
        for (bind, connect) in [
            ("allowed", "denied"),
            ("denied", "allowed"),
            ("error", "denied"),
        ] {
            assert_eq!(
                assess(&found(9, "available", bind, connect)),
                (State::Unavailable, "self_test_failed"),
                "{bind} {connect}"
            );
        }
        let unfinished = Landlock {
            parser_check: None,
            ..found(9, "available", "", "")
        };
        assert_eq!(
            assess(&unfinished),
            (State::Unavailable, "self_test_failed")
        );
        let ready = found(9, "available", "denied", "denied");
        let (state, reason, _, _) = landlock_capability(true, Mode::Disabled, Some(&ready));
        assert_eq!((state, reason), (State::Disabled, "sandbox_disabled"));
        let (state, reason, _, _) = landlock_capability(false, Mode::BestEffort, None);
        assert_eq!(
            (state, reason),
            (State::Unavailable, "platform_unsupported")
        );
    }
    #[test]
    fn landlock_capability_is_not_checked_until_someone_checks() {
        let snapshot = CapabilitySnapshot::configured(&NetwatchConfig::default());
        let expected = if cfg!(target_os = "linux") {
            State::NotChecked
        } else {
            State::Unavailable
        };
        assert_eq!(snapshot.get("landlock").state, expected);
        let off = NetwatchConfig {
            sandbox: "off".into(),
            ..Default::default()
        };
        let snapshot = CapabilitySnapshot::configured(&off);
        if cfg!(target_os = "linux") {
            assert_eq!(snapshot.get("landlock").reason, "sandbox_disabled");
        }
    }
    #[test]
    fn sandbox_detail_names_what_each_worker_got() {
        use sandbox::worker::Component;
        use sandbox::NetRaw;
        let entered = |blocked| {
            let mut report = sandbox::Report::default();
            report.platform.landlock_network_blocked = blocked;
            Component {
                ready: true,
                report: Some(report),
                error: None,
            }
        };
        let workers: std::collections::BTreeMap<_, _> = [
            ("capture".to_string(), entered(true)),
            ("connections".to_string(), entered(true)),
            ("keylog".to_string(), entered(false)),
            ("whois".to_string(), entered(false)),
        ]
        .into_iter()
        .collect();
        let mut main = sandbox::Report::default();
        main.mode.effective = Some("best-effort");
        main.platform.landlock_abi = 3;
        main.platform.landlock_kernel_abi = 9;
        main.platform.capture_authority = NetRaw::RetainedForReopen;
        let detail = sandbox_detail(&main, &workers, "4/4 worker entries verified");
        assert!(
            detail.starts_with("best-effort: Landlock fs ABI 3 (kernel 9)"),
            "{detail}"
        );
        if cfg!(target_os = "linux") {
            assert!(
                detail.contains("TCP denied on 2/3 parser workers"),
                "{detail}"
            );
            assert!(detail.contains("CAP_NET_RAW kept on main"), "{detail}");
            main.platform.capture_authority = NetRaw::Dropped;
            let dropped = sandbox_detail(&main, &workers, "");
            assert!(dropped.contains("CAP_NET_RAW dropped"), "{dropped}");
            main.platform.capture_authority = NetRaw::NotHeld;
            let unheld = sandbox_detail(&main, &workers, "");
            assert!(!unheld.contains("CAP_NET_RAW"), "{unheld}");
        }
        assert!(detail.ends_with("4/4 worker entries verified") || running_as_root());
        // No worker that skipped the filter, and then one that did.
        assert!(!detail.contains("no-socket filter"));
        let mut skipped = entered(true);
        skipped.report.as_mut().unwrap().platform.socket_filter =
            sandbox::SocketFilter::UnknownArch;
        let workers: std::collections::BTreeMap<_, _> =
            [("keylog".to_string(), skipped)].into_iter().collect();
        let detail = sandbox_detail(&main, &workers, "");
        if cfg!(target_os = "linux") {
            assert!(detail.contains("no-socket filter skipped"), "{detail}");
        }
        let mut disabled = sandbox::Report::default();
        disabled.mode.effective = Some("disabled");
        let detail = sandbox_detail(&disabled, &workers, "");
        assert!(detail.starts_with("disabled"), "{detail}");
        assert!(!detail.contains("TCP denied"), "{detail}");
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
