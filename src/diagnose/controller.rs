//! The Diagnose tab's controller: the state it owns, the pass that feeds the
//! engine each tick, and what its keys do.
//!
//! This is `App` code kept out of `app.rs`. The tick reads collectors that
//! `App` owns (the health prober, the traceroute runner, the config), so the
//! methods stay on `App` and only the file changed. `App` holds all of the
//! tab's state in one field, [`DiagnoseController`].

use crate::app::{export_dir, App};

/// Everything the Diagnose tab owns.
///
/// The engine, its baselines and the remediation journal live together
/// because they are only meaningful together: an issue's σ figures come from
/// the baselines, and its "applied" status comes from the journal. Splitting
/// them across `App` would let a render read one without the others.
pub struct DiagnoseController {
    pub engine: crate::diagnose::Engine,
    pub baselines: crate::diagnose::baseline::BaselineStore,
    pub sampler: crate::diagnose::live::LiveSampler,
    pub journal: crate::diagnose::remediation::Journal,
    /// Cursor into `engine.primary()`.
    pub selected: usize,
    pub show_report: bool,
    pub show_coverage: bool,
    pub coverage_selected: usize,
    pub target_selected: usize,
    /// Privileges this process actually holds, resolved once at startup.
    /// Apply steps beyond it are hidden rather than offered and then refused.
    pub capability: crate::diagnose::issue::Capability,
    /// Transient line under the panels: export path, applied confirmation, or
    /// what startup recovery inspection found.
    pub status: Option<String>,
    /// An apply step awaiting confirmation, as `(issue id, step key)`.
    /// Nothing touches the host until the user answers this.
    pub pending_apply: Option<(String, char)>,
    /// Set by `--demo`: the engine is fed a recorded scenario instead of the
    /// live network, and remediations are simulated rather than applied. The
    /// Diagnose tab says so on every frame. See [`crate::diagnose::demo`].
    pub demo: Option<crate::diagnose::demo::DemoDriver>,
    status_tick: u32,
    /// Ticks since the baselines were last written.
    persist_tick: u32,
    /// Created on the first live tick when `diagnose_record_episodes` is on.
    pub recorder: Option<crate::diagnose::episode::Recorder>,
    /// Where finished episodes are written. `None` in unit tests, so a test
    /// that ticks the app can never write into the user's state directory.
    pub episode_dir: Option<std::path::PathBuf>,
    /// Discriminating tests in flight, and re-runs after a step is done.
    pub tests: crate::diagnose::next_test::Runner,
    /// Stage-by-stage probes of `diagnose_targets`.
    last_trace_started: Option<std::time::Instant>,
    probe_network: Option<crate::diagnose::baseline::NetworkFingerprint>,
    pub active_prober: crate::diagnose::active::Runner,
    pub target_prober: crate::diagnose::targets::TargetProber,
}

impl DiagnoseController {
    /// A live controller whose engine judges with `thresholds`, the
    /// configured `[diagnose_thresholds]`. A value that cannot mean anything
    /// is logged and replaced by its default rather than refused.
    pub(crate) fn new(thresholds: &crate::diagnose::detectors::Thresholds) -> Self {
        let (thresholds, warnings) = thresholds.validated();
        for warning in &warnings {
            tracing::warn!("{warning}");
        }
        let fingerprint =
            crate::diagnose::baseline::NetworkFingerprint::new(String::new(), None, vec![], None);
        Self {
            engine: crate::diagnose::Engine::new(Box::new(crate::diagnose::engine::SystemClock))
                .with_settings(crate::diagnose::engine::Settings {
                    thresholds,
                    ..Default::default()
                }),
            baselines: crate::diagnose::baseline::BaselineStore::load(
                &crate::diagnose::baseline::BaselineStore::default_path(),
                fingerprint,
            ),
            sampler: crate::diagnose::live::LiveSampler::new(),
            journal: crate::diagnose::remediation::Journal::load_live(),
            selected: 0,
            show_report: false,
            show_coverage: false,
            coverage_selected: 0,
            target_selected: 0,
            capability: detect_capability(),
            status: None,
            pending_apply: None,
            demo: None,
            status_tick: 0,
            persist_tick: 0,
            recorder: None,
            episode_dir: if cfg!(test) {
                None
            } else {
                crate::diagnose::episode::default_dir()
            },
            tests: Default::default(),
            target_prober: Default::default(),
            active_prober: Default::default(),
            probe_network: None,
            last_trace_started: None,
        }
    }

    /// Swap the live engine for a replay of the recorded scenario.
    ///
    /// The engine, its clock and its baselines are all replaced: a demo must
    /// not inherit the host's real baselines (they describe a different
    /// network) and must not write to the host's `baselines.json` (it would
    /// poison them with scenario data). Persistence is disabled for the
    /// lifetime of the process by `App::tick_diagnose`.
    pub fn enter_demo_mode(&mut self) {
        let (driver, engine, baselines) = crate::diagnose::demo::DemoDriver::new();
        self.demo = Some(driver);
        self.engine = engine;
        self.baselines = baselines;
        self.selected = 0;
        // The scenario is an operator who can act on what they find, so the
        // demo offers the key-bound fix regardless of how it was launched.
        // This is a claim about the scenario, not about this process — the
        // banner says DEMO on every frame, and the apply path is simulated,
        // so no privilege is asserted that isn't held.
        self.capability = crate::diagnose::issue::Capability::Root;
    }

    pub fn is_demo(&self) -> bool {
        self.demo.is_some()
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status = Some(msg.into());
        self.status_tick = 0;
    }
}

/// What netwatch may do to the host. Apply steps declare what they need and
/// are hidden when it isn't held — a fix a user can press and then be told
/// "permission denied" is worse than no fix offered.
fn detect_capability() -> crate::diagnose::issue::Capability {
    #[cfg(unix)]
    {
        if effective_uid() == 0 {
            return crate::diagnose::issue::Capability::Root;
        }
    }
    crate::diagnose::issue::Capability::None
}

/// Effective uid, read from procfs so netwatch doesn't take a libc dependency
/// for a single call. Falls back to "not root", which can only ever hide a
/// fix — never offer one that will fail.
#[cfg(unix)]
fn effective_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2))
                .and_then(|uid| uid.parse().ok())
        })
        .unwrap_or(1)
}

impl App {
    /// One diagnose pass: sample, evaluate, then learn.
    ///
    /// Order matters. The detectors judge this tick's readings against the
    /// baseline as it stood *before* those readings, so a reading can never
    /// soften the comparison it is part of. Learning afterwards is also gated
    /// at the detectors' σ threshold, so a sustained incident is not absorbed
    /// into "normal" while it is still open.
    pub(crate) fn tick_diagnose(&mut self) {
        // Demo mode: the recorded scenario drives the engine, nothing is
        // sampled from the host, and nothing is persisted.
        if let Some(mut driver) = self.diagnose.demo.take() {
            let baselines = self.diagnose.baselines.clone();
            driver.tick(&mut self.diagnose.engine, &baselines);
            self.diagnose.demo = Some(driver);

            let open = self.diagnose.engine.open_count();
            if self.diagnose.selected >= open {
                self.diagnose.selected = open.saturating_sub(1);
            }
            self.expire_diagnose_status();
            return;
        }

        // Track which network we're on. Moving networks parks the old
        // baselines rather than comparing a hotspot against an office.
        let fingerprint = crate::diagnose::live::LiveSampler::fingerprint(self);
        if self
            .diagnose
            .probe_network
            .as_ref()
            .is_some_and(|old| old != &fingerprint)
        {
            self.diagnose.target_prober.cancel();
            self.diagnose.tests.cancel_all();
            self.health_prober = crate::collectors::health::HealthProber::with_third_party_probes(
                self.user_config.third_party_probes,
            );
            self.traceroute_runner = Default::default();
            self.diagnose.last_trace_started = None;
        }
        self.diagnose.probe_network = Some(fingerprint.clone());
        self.diagnose.active_prober.context(format!(
            "{fingerprint:?}:{:?}",
            self.user_config.diagnose_probes
        ));
        if !fingerprint.iface.is_empty() {
            self.diagnose.baselines.set_network(fingerprint);
        }

        if let Some(interval) = self.user_config.diagnose_probes.periodic_trace_secs() {
            if self
                .diagnose
                .last_trace_started
                .is_none_or(|at| at.elapsed().as_secs() >= interval)
            {
                self.traceroute_runner
                    .run(&self.user_config.diagnose_probes.trace_target);
                self.diagnose.last_trace_started = Some(std::time::Instant::now());
            }
        }
        if !self.user_config.diagnose_targets.is_empty() {
            let env = crate::diagnose::targets::ProbeEnv {
                resolvers: self
                    .config_collector
                    .config
                    .dns_servers
                    .iter()
                    .filter_map(|d| d.parse().ok())
                    .collect(),
                vpn_ifaces: self
                    .interface_info
                    .iter()
                    .filter(|i| i.is_up && crate::diagnose::targets::is_vpn_iface(&i.name))
                    .map(|i| i.name.clone())
                    .collect(),
            };
            self.diagnose
                .target_prober
                .probe_due(&self.user_config.diagnose_targets, env);
        }

        let mut sampler = std::mem::take(&mut self.diagnose.sampler);
        let readings = sampler.readings(self);

        let thresholds = self.diagnose.engine.settings().thresholds;
        let observations = sampler.sample(self, &thresholds);
        self.diagnose.sampler = sampler;

        let now = std::time::Instant::now();
        let wall = chrono::Local::now();
        self.collect_diagnose_tests(now);
        // User actions since the last tick belong to this frame: replay
        // applies them before evaluating it, which is when they took effect.
        let events = self.diagnose.engine.take_events();
        self.diagnose.engine.observe_live_at(
            &observations,
            &self.diagnose.baselines,
            &self.diagnose.sampler.completed,
            now,
        );
        self.record_episode_tick(&observations, &readings, events, now, wall);

        self.diagnose
            .baselines
            .set_gate(thresholds.sigma_k, thresholds.sigma_floor());
        crate::diagnose::live::LiveSampler::learn(&mut self.diagnose.baselines, &readings);

        // Keep the cursor on a real row as issues open and close.
        let open = self.diagnose.engine.open_count();
        if self.diagnose.selected >= open {
            self.diagnose.selected = open.saturating_sub(1);
        }

        self.expire_diagnose_status();

        // Persist baselines every ~5 minutes. A 20-minute session that never
        // writes has learned nothing the next run can use.
        self.diagnose.persist_tick += 1;
        if self.diagnose.persist_tick >= 300 {
            self.diagnose.persist_tick = 0;
            let path = crate::diagnose::baseline::BaselineStore::default_path();
            if let Err(e) = self.diagnose.baselines.save(&path) {
                tracing::warn!("could not persist baselines to {}: {e}", path.display());
            }
        }
    }

    /// Clear the transient Diagnose status line after a few seconds.
    fn expire_diagnose_status(&mut self) {
        if self.diagnose.status.is_some() {
            self.diagnose.status_tick += 1;
            if self.diagnose.status_tick >= 8 {
                self.diagnose.status = None;
                self.diagnose.status_tick = 0;
            }
        }
    }

    /// Inspect recovery metadata without trusting legacy target paths or PIDs.
    pub fn inspect_remediations(
        &mut self,
        authority: crate::diagnose::remediation::RecoveryAuthority,
    ) {
        let outcome = self.diagnose.journal.inspect_recovery(authority);
        for detail in &outcome.abandoned {
            tracing::warn!("remediation recovery: {detail}");
        }
        if let Some(reason) = self.diagnose.journal.blocked_reason().map(str::to_owned) {
            self.diagnose.set_status(reason);
        }
    }

    /// No automatic rollback authority exists for legacy entries. Preserve them
    /// on shutdown too, including entries whose old PID matches this process.
    pub fn shutdown_diagnose(&mut self) {
        self.diagnose.pending_apply = None;
        if self.diagnose.is_demo() {
            return;
        }
        self.inspect_remediations(crate::diagnose::remediation::RecoveryAuthority::InspectOnly);
        let path = crate::diagnose::baseline::BaselineStore::default_path();
        let _ = self.diagnose.baselines.save(&path);
        // An incident still in progress at quit is worth keeping; write it
        // synchronously, since the process is about to exit.
        let ts = crate::diagnose::engine::format_ts(chrono::Local::now());
        if let (Some(recorder), Some(dir)) = (
            self.diagnose.recorder.as_mut(),
            self.diagnose.episode_dir.as_ref(),
        ) {
            if let Some(episode) = recorder.flush(&self.diagnose.engine, &ts) {
                if let Err(e) = crate::diagnose::episode::save(dir, &episode) {
                    tracing::warn!(target: "netwatch::diagnose", error = %e, "episode not saved at shutdown");
                }
            }
        }
    }

    /// Run a coverage measurement even when no issue has opened yet.
    pub fn start_coverage_test(&mut self) -> Result<String, String> {
        let row = self
            .diagnose
            .engine
            .coverage()
            .rules
            .get(self.diagnose.coverage_selected)
            .ok_or_else(|| "coverage has not been sampled yet".to_string())?;
        if matches!(
            row.rule.as_str(),
            "ipv6.broken" | "captive.portal" | "pmtu.blackhole"
        ) {
            self.diagnose
                .active_prober
                .start(&row.rule, &self.user_config.diagnose_probes)?;
            return Ok("three rounds started; x cancels. IPv6: up to 24 TCP connects; portal: up to 12 GETs; PMTU: six pings and up to six 64 KiB downloads".into());
        }
        if row.rule == "egress.policy_violation" {
            let path = crate::collectors::egress::default_policy_path()
                .ok_or_else(|| "no egress policy path".to_string())?;
            self.egress_profiler.reload_policy(&path);
            if let Some(error) = self.egress_profiler.policy_error() {
                return Err(error.into());
            }
            return Ok(if self.egress_profiler.has_policy() {
                "egress policy reloaded; awaiting a fresh connection sample".into()
            } else {
                format!("no policy configured at {}", path.display())
            });
        }
        if row.rule.starts_with("path.") {
            let target = &self.user_config.diagnose_probes.trace_target;
            if target.parse::<std::net::IpAddr>().is_err() {
                return Err("diagnose_probes.trace_target must be an IP address".into());
            }
            self.traceroute_runner.run(target);
            self.diagnose.last_trace_started = Some(std::time::Instant::now());
            return Ok(format!(
                "tracing {target}; run again for path-change comparison"
            ));
        }
        if row.rule == "nat.symmetric" {
            if !self.user_config.third_party_probes {
                return Err(format!(
                    "{}, so STUN does not run",
                    crate::collectors::health::PROBES_OFF
                ));
            }
            self.health_prober.request_nat();
            let config = &self.config_collector.config;
            self.health_prober
                .probe(config.gateway.as_deref(), config.primary_dns().as_deref());
            return Ok("STUN queued: two UDP mapping probes to Google and Cloudflare".into());
        }
        if row.rule.starts_with("target.") {
            if self.user_config.diagnose_targets.is_empty() {
                return Err(format!(
                    "add [[diagnose_targets]] to {}",
                    crate::config::NetwatchConfig::path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "config.toml".into())
                ));
            }
            self.diagnose.target_prober.probe_now(
                &self.user_config.diagnose_targets,
                crate::diagnose::targets::ProbeEnv {
                    resolvers: self
                        .config_collector
                        .config
                        .dns_servers
                        .iter()
                        .filter_map(|d| d.parse().ok())
                        .collect(),
                    vpn_ifaces: self
                        .interface_info
                        .iter()
                        .filter(|i| i.is_up && crate::diagnose::targets::is_vpn_iface(&i.name))
                        .map(|i| i.name.clone())
                        .collect(),
                },
            )?;
            return Ok("probing configured targets".into());
        }
        if row.rule == "tcp.bufferbloat_local" {
            self.refuse_reference_test("load.idle_vs_loaded")?;
            let mut ctx = crate::diagnose::next_test::Context::new("1.1.1.1".parse().unwrap());
            ctx.loaded_rtt_delta_ms = self
                .diagnose
                .engine
                .settings()
                .thresholds
                .loaded_rtt_delta_ms;
            self.diagnose
                .tests
                .start("coverage", "load.idle_vs_loaded", ctx, false)?;
            return Ok("load test running: up to 25 MB upload to speed.cloudflare.com".into());
        }
        Err(row.next_action().into())
    }

    /// With `third_party_probes` off, no test that asks a public server starts,
    /// by whichever key it was asked for.
    fn refuse_reference_test(&self, test: &str) -> Result<(), String> {
        use crate::diagnose::next_test;
        match next_test::lookup(test) {
            Some(spec) if spec.uses_reference && !self.user_config.third_party_probes => {
                Err(format!(
                    "{}, and this test {}",
                    crate::collectors::health::PROBES_OFF,
                    spec.does
                ))
            }
            _ => Ok(()),
        }
    }

    /// Start a discriminating test on an issue. Context is taken from what the
    /// app currently knows: configured resolver and gateway, the issue's
    /// traced target, and the learned baselines.
    pub fn start_diagnose_test(&mut self, issue_id: &str, test: &str) -> Result<String, String> {
        self.start_diagnose_test_inner(issue_id, test, false)
    }

    fn start_diagnose_test_inner(
        &mut self,
        issue_id: &str,
        test: &str,
        after_action: bool,
    ) -> Result<String, String> {
        use crate::diagnose::{issue::Subject, next_test};
        let issue = self
            .diagnose
            .engine
            .get(issue_id)
            .ok_or_else(|| format!("{issue_id} is no longer tracked"))?;
        if !after_action && !issue.state.is_open() {
            return Err("this incident has already closed".into());
        }
        let spec = next_test::lookup(test).ok_or_else(|| format!("no test named {test}"))?;
        self.refuse_reference_test(test)?;
        if !next_test::offered(issue, self.diagnose.capability)
            .iter()
            .any(|t| t.id == test)
        {
            return Err(format!("{} does not apply to this issue", spec.question));
        }
        let cfg = &self.config_collector.config;
        let reference: std::net::IpAddr = crate::collectors::health::REFERENCE_RESOLVER
            .parse()
            .expect("reference resolver is an address");
        let mut ctx = next_test::Context::new(reference);
        ctx.resolver = match &issue.subject {
            Subject::Resolver { addr } => addr.parse().ok(),
            _ => None,
        }
        .or_else(|| cfg.primary_dns().and_then(|d| d.parse().ok()));
        ctx.gateway = cfg.gateway.as_deref().and_then(|g| g.parse().ok());
        if let Subject::Path { target } = &issue.subject {
            if let Ok(ip) = target.parse() {
                ctx.target = ip;
            }
        }
        let health = self.health_prober.status();
        ctx.gateway_rtt_ms = health.gateway_rtt_ms;
        let base = &self.diagnose.baselines;
        ctx.gateway_baseline_ms = cfg
            .gateway
            .as_deref()
            .and_then(|g| base.get(g, "gateway.rtt"))
            .map(|b| b.mean);
        ctx.path_baseline_ms = base.get("internet", "path.rtt").map(|b| b.mean);
        ctx.loaded_rtt_delta_ms = self
            .diagnose
            .engine
            .settings()
            .thresholds
            .loaded_rtt_delta_ms;
        self.diagnose
            .tests
            .start(issue_id, test, ctx, after_action)?;
        Ok(format!("running: {}", spec.does))
    }

    /// The user says they carried out remediation step `step` (its index).
    /// Re-runs the tests that pointed at the cause a minute later, so recovery
    /// is checked against the same evidence that chose it.
    pub fn mark_diagnose_step_done(
        &mut self,
        issue_id: &str,
        step: usize,
    ) -> Result<String, String> {
        if !self.diagnose.engine.mark_step_done(issue_id, step) {
            return Err("that step can't be marked done on this issue".into());
        }
        let supporting = self
            .diagnose
            .engine
            .get(issue_id)
            .and_then(|i| i.verification.as_ref())
            .map(|v| v.supporting.clone())
            .unwrap_or_default();
        let due = std::time::Instant::now() + std::time::Duration::from_secs(60);
        for test in &supporting {
            self.diagnose.tests.schedule_rerun(due, issue_id, test);
        }
        Ok(if supporting.is_empty() {
            "noted — watching for recovery".into()
        } else {
            format!(
                "noted — re-checking {} test(s) in a minute",
                supporting.len()
            )
        })
    }

    /// Hand finished test runs to the engine and start any re-runs now due.
    fn collect_diagnose_tests(&mut self, now: std::time::Instant) {
        for (issue, run) in self.diagnose.tests.poll() {
            if run.test == "load.idle_vs_loaded" {
                if let (Some(idle), Some(loaded)) = (
                    run.measurements.get("idle_rtt_ms"),
                    run.measurements.get("loaded_rtt_ms"),
                ) {
                    self.diagnose.sampler.load_test = Some((now, *idle, *loaded));
                }
            }
            let line = format!("{}: {}", run.test, run.detail);
            if issue == "coverage" || self.diagnose.engine.record_test(&issue, run) {
                self.diagnose.set_status(line);
            }
        }
        for (issue, test) in self.diagnose.tests.due_reruns(now) {
            let _ = self.start_diagnose_test_inner(&issue, &test, true);
        }
    }

    /// Record what the user says caused an issue, from
    /// [`crate::diagnose::episode::label_choices`]. Lands on the episode being
    /// recorded, or else the newest saved one that covers the issue.
    pub fn label_issue(&mut self, issue_id: &str, cause: &str) -> Result<String, String> {
        use crate::diagnose::episode;
        let issue = self
            .diagnose
            .engine
            .get(issue_id)
            .ok_or_else(|| format!("{issue_id} is no longer tracked"))?;
        if !episode::label_choices(issue)
            .iter()
            .any(|(k, _)| k == cause)
        {
            return Err(format!("{cause} is not an answer offered for {issue_id}"));
        }
        let label = episode::Label {
            issue: episode::issue_key(issue),
            cause: cause.to_string(),
            source: episode::LabelSource::User,
            ts: crate::diagnose::engine::format_ts(chrono::Local::now()),
            note: None,
        };
        if self
            .diagnose
            .recorder
            .as_mut()
            .is_some_and(|r| r.label(&label))
        {
            return Ok("answer saved with this incident".into());
        }
        let dir = self
            .diagnose
            .episode_dir
            .clone()
            .ok_or("episode recording is off")?;
        match episode::label_saved(&dir, &label, 50) {
            Ok(Some(_)) => Ok("answer saved with this incident".into()),
            Ok(None) => Err("no recording of this incident to attach the answer to".into()),
            Err(e) => Err(format!("answer not saved: {e}")),
        }
    }

    /// Feed one live tick to the episode recorder and write any episode it
    /// finishes on a background thread.
    fn record_episode_tick(
        &mut self,
        observations: &crate::diagnose::detectors::Observations,
        readings: &[crate::diagnose::live::Reading],
        events: Vec<crate::diagnose::engine::EngineEvent>,
        now: std::time::Instant,
        wall: chrono::DateTime<chrono::Local>,
    ) {
        use crate::diagnose::episode;
        let Some(dir) = self.diagnose.episode_dir.clone() else {
            return;
        };
        if !self.user_config.diagnose_record_episodes {
            self.diagnose.recorder = None;
            return;
        }
        let at = wall.timestamp_micros() as f64 / 1e6;
        let recorder = self.diagnose.recorder.get_or_insert_with(|| {
            episode::Recorder::new(
                episode::EnvProfile::detect(
                    self.diagnose.capability.label(),
                    self.user_config.refresh_rate_ms,
                ),
                at,
            )
        });
        let finished = recorder.record(episode::Tick {
            at,
            ts: crate::diagnose::engine::format_ts(wall),
            now,
            obs: observations,
            times: &self.diagnose.sampler.completed,
            readings,
            engine: &self.diagnose.engine,
            baselines: &self.diagnose.baselines,
            events,
        });
        if let Some(episode) = finished {
            std::thread::spawn(move || {
                match episode::save(&dir, &episode) {
                    Ok(path) => {
                        tracing::info!(target: "netwatch::diagnose", path = %path.display(), frames = episode.frames.len(), "episode saved")
                    }
                    Err(e) => {
                        tracing::warn!(target: "netwatch::diagnose", error = %e, "episode not saved")
                    }
                }
                episode::prune(
                    &dir,
                    std::time::Duration::from_secs(episode::RETAIN_SECS),
                    episode::RETAIN_BYTES,
                );
            });
        }
    }
}

// ── Diagnose actions ────────────────────────────────────────────────

pub(crate) fn selected_issue_id(app: &App) -> Option<String> {
    let primary = app.diagnose.engine.primary();
    primary
        .get(app.diagnose.selected.min(primary.len().saturating_sub(1)))
        .map(|i| i.id.clone())
}

/// One-line summary of what is wrong, for `y`: the words of the verdict row,
/// so a pasted summary always matches the screenshot next to it.
pub(crate) fn diagnose_summary(app: &App) -> String {
    crate::ui::diagnose::verdict_words(&app.diagnose.engine, &app.diagnose.baselines, &app.theme)
}

/// Stage the first applicable remediation for confirmation.
///
/// Nothing is written here. Apply steps change host state — the resolver, a
/// qdisc, a socket — and a keystroke away from an irreversible edit is not a
/// design, so the actual work happens only after the prompt is answered.
///
/// Only the demo stages anything. Live, netwatch changes nothing from this
/// screen: `↵` says so and records nothing, where it used to apply at once
/// and record "not applied" against the step (C19a; the full handoff is
/// C19b).
pub(crate) fn stage_remediation(app: &mut App) {
    let Some(id) = selected_issue_id(app) else {
        return;
    };
    let cap = app.diagnose.capability;
    let Some(issue) = app.diagnose.engine.get(&id) else {
        return;
    };
    let has_any = issue
        .remediation
        .iter()
        .any(|s| s.kind == crate::diagnose::issue::StepKind::Apply);
    if has_any && !app.diagnose.is_demo() {
        app.diagnose
            .set_status("netwatch won't change this from here; run the command shown");
        return;
    }
    let step = issue
        .remediation
        .iter()
        .find(|s| s.kind == crate::diagnose::issue::StepKind::Apply && s.available(cap));

    match step {
        Some(step) => {
            let key = step.key.unwrap_or('1');
            let text = step.text.clone();
            app.diagnose.pending_apply = Some((id, key));
            app.diagnose
                .set_status(format!("apply: {text}?  y = yes, n = no"));
        }
        None => {
            app.diagnose.set_status(if has_any {
                format!(
                    "nothing to apply — the fix for this issue needs {}",
                    crate::diagnose::issue::Capability::Root.label()
                )
            } else {
                "nothing netwatch can apply for this issue — see the steps listed".to_string()
            });
        }
    }
}

/// Carry out a confirmed remediation. Only the demo stages one, and it
/// simulates it: the scenario changes what the resolver reports, and the
/// engine's own verify condition closes the issue. Nothing on this host is
/// written to.
pub(crate) fn apply_pending_remediation(app: &mut App) {
    let Some((id, key)) = app.diagnose.pending_apply.take() else {
        return;
    };
    let Some(issue) = app.diagnose.engine.get(&id) else {
        return;
    };
    let Some(step) = issue.remediation.iter().find(|s| s.key == Some(key)) else {
        return;
    };
    let Some(action) = step.action.clone() else {
        return;
    };
    let Some(mut driver) = app.diagnose.demo.take() else {
        return;
    };
    let applied = driver.apply(&action);
    app.diagnose.demo = Some(driver);
    let msg = match &applied {
        crate::diagnose::issue::Applied::Yes { before, after, .. } => {
            format!("simulated · {before} → {after} · watching for verify to hold")
        }
        crate::diagnose::issue::Applied::RecoveryRequired { .. } => {
            applied.recovery_summary().unwrap()
        }
        crate::diagnose::issue::Applied::No { reason } => format!("not applied · {reason}"),
        crate::diagnose::issue::Applied::Reverted { reason, .. } => {
            format!("reverted · {reason}")
        }
    };
    app.diagnose.engine.record_applied(&id, key, applied);
    app.diagnose.set_status(msg);
}

/// Write `report.md` and `report.json`, and say where they went.
///
/// The old `E` export wrote eight files and 6.4 MB with no on-screen
/// confirmation and no path, which meant users could not tell it had worked.
/// This one names the directory in the status line.
pub fn export_diagnose_report(app: &mut App) {
    if app.diagnose.is_demo() {
        // A report full of scenario data, sitting in a real directory with a
        // real timestamp, is precisely the artefact that later gets mistaken
        // for a measurement. The demo shows the preview instead.
        app.diagnose.show_report = true;
        app.diagnose
            .set_status("demo — report preview shown; export is disabled for recorded data");
        return;
    }
    let report = build_diagnose_report(app);
    let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let dir = export_dir().join(format!("netwatch_diagnose_{stamp}"));

    let write = || -> std::io::Result<()> {
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("report.md"), report.to_markdown())?;
        std::fs::write(
            dir.join("report.json"),
            report
                .to_json()
                .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")),
        )?;
        Ok(())
    };

    match write() {
        Ok(()) => app
            .diagnose
            .set_status(format!("report.md + report.json → {}", dir.display())),
        Err(e) => app.diagnose.set_status(format!("export failed: {e}")),
    }
}

/// Assemble a report from live state. Issues come straight from the engine,
/// so the export is the screen.
pub fn build_diagnose_report(app: &App) -> crate::diagnose::report::Report {
    let cfg = &app.config_collector.config;
    let base = &app.diagnose.baselines;
    let issues = app.diagnose.engine.issues().to_vec();

    let mut timeline: Vec<crate::diagnose::report::TimelineEvent> = issues
        .iter()
        .map(|i| crate::diagnose::report::TimelineEvent {
            at: i.since.clone(),
            kind: "issue".into(),
            text: format!("{} · {}", i.title, i.subject.label()),
        })
        .collect();
    if let Some(reason) = app.diagnose.journal.blocked_reason() {
        timeline.push(crate::diagnose::report::TimelineEvent {
            at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            kind: "recovery_status".into(),
            text: reason.to_string(),
        });
    }
    timeline.sort_by(|a, b| a.at.cmp(&b.at));

    let iface_info = app
        .interface_info
        .iter()
        .find(|i| i.name == app.capture_interface);

    crate::diagnose::report::Report {
        coverage: app.diagnose.engine.coverage().clone(),
        generated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        window_start: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        window_end: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        environment: crate::diagnose::report::Environment {
            host: cfg.hostname.clone(),
            iface: app.capture_interface.clone(),
            driver: None,
            kernel: None,
            qdisc: None,
            resolvers: cfg.dns_servers.clone(),
            gateway: cfg.gateway.clone(),
            netwatch_version: env!("CARGO_PKG_VERSION").to_string(),
            ruleset_version: "v1".to_string(),
            baseline_state: format!(
                "{} on {}{}",
                base.overall_readiness().label(),
                base.fingerprint().label(),
                if base.switched_network() {
                    " (network changed this session)"
                } else {
                    ""
                }
            ),
        },
        issues,
        timeline,
        artifacts: iface_info
            .and_then(|i| i.mac.clone())
            .map(|_| vec!["report.json".to_string()])
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use crate::app::App;
    use crate::config::NetwatchConfig;
    use crate::diagnose::baseline::{BaselineStore, NetworkFingerprint};
    use crate::diagnose::detectors::{DnsObs, Observations, Thresholds};

    /// Whether three samples of a 40ms resolver, on a network with no
    /// baseline yet, open `dns.slow_resolver` in the app's engine.
    fn a_40ms_resolver_opens_an_issue(app: &mut App) -> bool {
        let obs = Observations {
            dns: Some(DnsObs {
                resolver: "192.0.2.53".into(),
                rtt_p50_ms: Some(40.0),
                rtt_p95_ms: Some(48.0),
                failure_rate_pct: 0.0,
                truncation_rate_pct: 0.0,
                queries: 38,
                failed: 0,
                truncated: 0,
                alt_resolver: None,
                alt_rtt_ms: None,
                icmp_rtt_ms: None,
                cached_rtt_ms: None,
                window_secs: 180,
                cross: None,
            }),
            ..Default::default()
        };
        let base = BaselineStore::new(NetworkFingerprint::new("eth0", None, vec![], None));
        for _ in 0..3 {
            app.diagnose.engine.observe(&obs, &base);
        }
        app.diagnose
            .engine
            .primary()
            .iter()
            .any(|i| i.rule == "dns.slow_resolver")
    }

    fn probes_off() -> App {
        App::prepare_with_config(NetwatchConfig {
            third_party_probes: false,
            diagnose_record_episodes: false,
            ..Default::default()
        })
    }

    /// Moving networks replaces the prober. A new one from `Default` would
    /// turn the probes back on for the rest of the session, on exactly the
    /// kind of move someone who switched them off cares about.
    #[test]
    fn a_network_change_keeps_third_party_probes_off() {
        let mut app = probes_off();
        assert!(!app.health_prober.third_party_probes());
        app.diagnose.probe_network =
            Some(NetworkFingerprint::new("elsewhere0", None, vec![], None));
        let old = app.health_prober.status();
        app.tick_diagnose();
        assert!(
            !std::sync::Arc::ptr_eq(&old, &app.health_prober.status()),
            "the move replaces the prober"
        );
        assert!(!app.health_prober.third_party_probes());
    }

    /// `t` on the NAT row used to queue STUN unconditionally.
    #[test]
    fn coverage_t_will_not_start_stun_with_the_probes_off() {
        let mut app = probes_off();
        let observations = crate::diagnose::live::LiveSampler::new()
            .sample(&app, &app.diagnose.engine.settings().thresholds);
        let base = app.diagnose.baselines.clone();
        app.diagnose.engine.observe(&observations, &base);
        let rules = &app.diagnose.engine.coverage().rules;
        let at = rules
            .iter()
            .position(|r| r.rule == "nat.symmetric")
            .unwrap();
        let row = &rules[at];
        assert_eq!(
            row.status,
            crate::diagnose::coverage::Availability::NotMeasured
        );
        assert!(row.next_action().contains("third_party_probes"), "{row:?}");
        app.diagnose.coverage_selected = at;
        let error = app.start_coverage_test().unwrap_err();
        assert!(error.contains("third_party_probes"), "{error}");
    }

    /// The load test connects to 1.1.1.1:443 and uploads to Cloudflare. It
    /// starts from the coverage row, not from an issue, so it has its own way
    /// in to close.
    #[test]
    fn coverage_t_will_not_start_the_load_test_with_the_probes_off() {
        let mut app = probes_off();
        let observations = crate::diagnose::live::LiveSampler::new()
            .sample(&app, &app.diagnose.engine.settings().thresholds);
        let base = app.diagnose.baselines.clone();
        app.diagnose.engine.observe(&observations, &base);
        let rules = &app.diagnose.engine.coverage().rules;
        let at = rules
            .iter()
            .position(|r| r.rule == "tcp.bufferbloat_local")
            .unwrap();
        let row = &rules[at];
        assert_eq!(
            row.status,
            crate::diagnose::coverage::Availability::NotMeasured
        );
        assert!(row.next_action().contains("third_party_probes"), "{row:?}");
        app.diagnose.coverage_selected = at;
        let error = app.start_coverage_test().unwrap_err();
        assert!(error.contains("third_party_probes"), "{error}");
        assert!(error.contains("1.1.1.1"), "{error}");
        assert!(!app.diagnose.tests.any_running("coverage"));
    }

    /// `dns.alt_resolver` asks 1.1.1.1, so it stays home with the switch off
    /// even when asked for by name; the local test beside it still runs.
    #[test]
    fn a_test_that_asks_the_reference_is_refused_with_the_probes_off() {
        let mut app = App::prepare_with_config(NetwatchConfig {
            third_party_probes: false,
            diagnose_record_episodes: false,
            diagnose_thresholds: Thresholds {
                dns_ceiling_ms: 30.0,
                ..Default::default()
            },
            ..Default::default()
        });
        assert!(a_40ms_resolver_opens_an_issue(&mut app));
        let id = app.diagnose.engine.primary()[0].id.to_string();
        for test in ["dns.alt_resolver", "load.idle_vs_loaded"] {
            let error = app.start_diagnose_test(&id, test).unwrap_err();
            assert!(error.contains("third_party_probes"), "{test}: {error}");
            assert!(error.contains("1.1.1.1"), "{test}: {error}");
            assert!(!app.diagnose.tests.any_running(&id), "{test}");
        }
    }

    /// The engine used to start with `Thresholds::default()` whatever the
    /// config said, so no threshold a user could set reached a detector.
    #[test]
    fn the_engine_starts_with_configured_thresholds() {
        let config: NetwatchConfig = toml::from_str(
            "[diagnose_thresholds]\ndns_ceiling_ms = 30\nsigma_k = 0\nsocket_rtt_ms = inf\n",
        )
        .unwrap();
        let mut app = App::prepare_with_config(config);
        let settings = *app.diagnose.engine.settings();
        let t = settings.thresholds;
        assert_eq!(t.dns_ceiling_ms, 30.0);
        assert_eq!(
            t.sigma_k,
            Thresholds::default().sigma_k,
            "an invalid σ multiple falls back to the default"
        );
        assert_eq!(t.socket_rtt_ms, Thresholds::default().socket_rtt_ms);
        // Every episode embeds these settings, and JSON writes infinity as
        // null, which would not load again.
        let json = serde_json::to_string(&settings).unwrap();
        assert_eq!(
            serde_json::from_str::<crate::diagnose::engine::Settings>(&json).unwrap(),
            settings
        );
        assert!(a_40ms_resolver_opens_an_issue(&mut app));

        // Without the section nothing changes: 40ms is under the default.
        let mut app = App::prepare_with_config(NetwatchConfig::default());
        assert_eq!(
            app.diagnose.engine.settings().thresholds,
            Thresholds::default()
        );
        assert!(!a_40ms_resolver_opens_an_issue(&mut app));
    }
}
