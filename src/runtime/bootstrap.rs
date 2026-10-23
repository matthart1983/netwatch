use crate::{app::App, diagnose::remediation::RecoveryAuthority, sandbox};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    Tui,
    Daemon,
    Demo,
}

impl SessionKind {
    pub fn recovery_authority(self) -> Option<RecoveryAuthority> {
        match self {
            Self::Tui | Self::Daemon => Some(RecoveryAuthority::InspectOnly),
            Self::Demo => None,
        }
    }
}

/// Inspect recovery before starting application workers, then enforce the same
/// readiness and calling-thread boundary for TUI and daemon sessions.
pub fn start(app: &mut App, kind: SessionKind, mode: sandbox::Mode) -> anyhow::Result<()> {
    if let Some(authority) = kind.recovery_authority() {
        app.inspect_remediations(authority);
    } else {
        app.diagnose.enter_demo_mode();
    }
    sandbox::worker::ensure(mode, sandbox::SandboxPaths::from_config(&app.user_config))
        .map_err(anyhow::Error::msg)?;
    app.start_workers();
    if let Err(error) = sandbox::worker::wait_ready(std::time::Duration::from_secs(5)) {
        if matches!(mode, sandbox::Mode::Strict) {
            anyhow::bail!("worker startup: {error}");
        }
        tracing::warn!(%error, "worker readiness incomplete");
    }
    let paths = sandbox::SandboxPaths::from_config(&app.user_config);
    let report = sandbox::apply(mode, &paths);
    if matches!(mode, sandbox::Mode::Strict) && !report.mode.warnings.is_empty() {
        anyhow::bail!(
            "sandbox: strict mode could not be enforced: {}",
            report.mode.warnings.join("; ")
        );
    }
    for warning in &report.mode.warnings {
        tracing::warn!(target: "netwatch::sandbox", "{warning}");
    }
    tracing::info!(target: "netwatch::sandbox", summary = %report.summary(), "sandbox applied");
    app.sandbox_report = report;
    // A demo replays recorded data, so it must not write uptime records.
    if kind != SessionKind::Demo && app.user_config.record_uptime {
        app.uptime = crate::uptime::Monitor::new(crate::uptime::default_dir());
    }
    if app.diagnose.journal.blocked_reason().is_none() && kind != SessionKind::Demo {
        app.diagnose
            .set_status(crate::runtime::capabilities::CapabilitySnapshot::live(app).compact());
    }
    Ok(())
}

/// Both live loops begin with the same initial observations.
pub fn prime_collectors(app: &mut App) {
    app.traffic.update();
    app.connection_collector.update();
    let conns = app.connection_collector.connections();
    app.connection_timeline.update(&conns);
    let gateway = app.config_collector.config.gateway.clone();
    let dns = app.config_collector.config.primary_dns();
    app.health_prober.probe(gateway.as_deref(), dns.as_deref());
}
