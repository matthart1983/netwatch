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

    /// Whether main keeps CAP_NET_RAW once capture has opened. Only an
    /// interactive session reopens capture (`c`, `i`, `Shift+R`), the demo
    /// included; the daemon, `diagnose run` and `diagnose coverage` open it
    /// once. Strict drops it whatever the session.
    pub fn capture_authority(self, mode: sandbox::Mode) -> sandbox::CaptureAuthority {
        match (self, mode) {
            (Self::Tui | Self::Demo, sandbox::Mode::BestEffort | sandbox::Mode::Disabled) => {
                sandbox::CaptureAuthority::RetainForReopen
            }
            _ => sandbox::CaptureAuthority::DropAfterOpen,
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
    let authority = kind.capture_authority(mode);
    sandbox::worker::ensure(
        mode,
        sandbox::SandboxPaths::from_config(&app.user_config),
        authority,
    )
    .map_err(anyhow::Error::msg)?;
    app.start_workers();
    if let Err(error) = sandbox::worker::wait_ready(std::time::Duration::from_secs(5)) {
        if matches!(mode, sandbox::Mode::Strict) {
            anyhow::bail!("worker startup: {error}");
        }
        tracing::warn!(%error, "worker readiness incomplete");
    }
    let paths = sandbox::SandboxPaths::from_config(&app.user_config);
    let report = confine_main(mode, authority, &paths)?;
    for warning in &report.mode.warnings {
        tracing::warn!(target: "netwatch::sandbox", "{warning}");
    }
    tracing::info!(target: "netwatch::sandbox", summary = %report.summary(), "sandbox applied");
    app.sandbox_report = report;
    // A demo replays recorded data, so it must not write uptime records.
    if kind != SessionKind::Demo && app.user_config.record_uptime {
        app.uptime = crate::uptime::Monitor::new(crate::uptime::default_dir());
    }
    if app.diagnose.journal.recovery_notice().is_none() && kind != SessionKind::Demo {
        app.diagnose
            .set_status(crate::runtime::capabilities::CapabilitySnapshot::live(app).compact());
    }
    Ok(())
}

/// Apply main's policy on the calling thread, then audit every thread of the
/// process against `authority`. Strict refuses on any warning, the audit's
/// included.
fn confine_main(
    mode: sandbox::Mode,
    authority: sandbox::CaptureAuthority,
    paths: &sandbox::SandboxPaths,
) -> anyhow::Result<sandbox::Report> {
    let mut report = sandbox::apply(mode, paths);
    // Main has dropped and the workers have entered, so no thread should
    // hold more than `authority` allows.
    sandbox::audit::check_threads(mode, authority, &mut report);
    if matches!(mode, sandbox::Mode::Strict) && !report.mode.warnings.is_empty() {
        anyhow::bail!(
            "sandbox: strict mode could not be enforced: {}",
            report.mode.warnings.join("; ")
        );
    }
    Ok(report)
}

/// Write the session's sandbox report to the log, the first time this is called.
/// `doctor` is another process and cannot see this one, so the log is where each
/// worker's protection and the startup audit can be read (docs/doctor.md).
pub fn log_protections(app: &App) {
    static LOGGED: std::sync::Once = std::sync::Once::new();
    LOGGED.call_once(|| {
        let report = crate::runtime::capabilities::CapabilitySnapshot::live(app).sandbox_json();
        tracing::info!(target: "netwatch::sandbox", report = %report, "session protections");
    });
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

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox::{CaptureAuthority, Mode};

    #[test]
    fn session_kind_maps_to_authority() {
        let (keeps, drops) = (
            CaptureAuthority::RetainForReopen,
            CaptureAuthority::DropAfterOpen,
        );
        for (kind, mode, authority) in [
            (SessionKind::Tui, Mode::BestEffort, keeps),
            (SessionKind::Demo, Mode::BestEffort, keeps),
            (SessionKind::Tui, Mode::Disabled, keeps),
            (SessionKind::Tui, Mode::Strict, drops),
            (SessionKind::Demo, Mode::Strict, drops),
            (SessionKind::Daemon, Mode::BestEffort, drops),
            (SessionKind::Daemon, Mode::Strict, drops),
            (SessionKind::Daemon, Mode::Disabled, drops),
        ] {
            assert_eq!(kind.capture_authority(mode), authority, "{kind:?} {mode:?}");
        }
    }

    /// Main's entry audits every thread: one still holding CAP_NET_RAW in a
    /// session that drops it is a warning in best-effort and refuses a
    /// strict start.
    #[cfg(target_os = "linux")]
    #[test]
    fn main_entry_names_a_thread_that_still_holds_net_raw() {
        if !sandbox::audit::as_root_in_user_namespace(
            "runtime::bootstrap::tests::main_entry_names_a_thread_that_still_holds_net_raw",
        ) {
            return;
        }
        // Never confined, so it keeps every capability root holds here.
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::Builder::new()
            .name("audit-holder".into())
            .spawn(move || {
                tid_tx.send(nix::unistd::gettid().as_raw()).unwrap();
                let _ = done_rx.recv();
            })
            .unwrap();
        let named = format!("audit-holder ({})", tid_rx.recv().unwrap());
        // Entry confines the thread that makes it, so each runs on its own.
        let enter = |mode| {
            std::thread::spawn(move || {
                confine_main(
                    mode,
                    CaptureAuthority::DropAfterOpen,
                    &sandbox::SandboxPaths::default(),
                )
                .map_err(|e| e.to_string())
            })
            .join()
            .unwrap()
        };
        let warnings = enter(Mode::BestEffort).unwrap().mode.warnings;
        assert!(
            warnings.iter().any(|w| w.contains(&named)),
            "{named}: {warnings:?}"
        );
        let error = enter(Mode::Strict).unwrap_err();
        assert!(error.contains(&named), "{named}: {error}");
        done_tx.send(()).unwrap();
        holder.join().unwrap();
    }
}
