//! Explicit per-worker entry policy. No input is processed before entry returns.
use super::{Mode, Report, SandboxPaths};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Component {
    pub ready: bool,
    pub report: Option<Report>,
    pub error: Option<String>,
}
struct Policy {
    mode: Mode,
    paths: SandboxPaths,
    /// Shared by every worker and the UI, the capture thread included, so
    /// every access goes through `safe_lock`.
    components: Mutex<BTreeMap<String, Component>>,
    #[cfg(target_os = "linux")]
    prepared: Result<landlock::RulesetCreated, String>,
}
type SharedJoin = Arc<Mutex<Option<std::thread::JoinHandle<()>>>>;
static HANDLES: Mutex<Vec<SharedJoin>> = Mutex::new(Vec::new());
static STOPPING: AtomicBool = AtomicBool::new(false);

pub struct WorkerHandle(SharedJoin);
impl WorkerHandle {
    pub fn is_finished(&self) -> bool {
        self.0
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|h| h.is_finished())
    }
    pub fn join(self) -> std::thread::Result<()> {
        let handle = self.0.lock().unwrap().take();
        handle.map_or(Ok(()), |h| h.join())
    }
}
pub fn stopping() -> bool {
    STOPPING.load(Ordering::SeqCst)
}
/// Poll a queue so dropping the application can cancel queued work promptly.
pub fn receive<T>(rx: &std::sync::mpsc::Receiver<T>) -> Option<T> {
    while !stopping() {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(value) => return (!stopping()).then_some(value),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
    None
}
/// Stop new work, wait to a shared deadline, then report workers still unwinding.
pub fn shutdown(timeout: Duration) -> usize {
    STOPPING.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + timeout;
    loop {
        let mut handles = HANDLES.lock().unwrap();
        handles.retain(|slot| {
            let mut handle = slot.lock().unwrap();
            if handle.as_ref().is_some_and(|h| h.is_finished()) {
                if let Some(h) = handle.take() {
                    let _ = h.join();
                }
            }
            handle.is_some()
        });
        let remaining = handles.len();
        if remaining == 0 || Instant::now() >= deadline {
            return remaining;
        }
        drop(handles);
        std::thread::sleep(Duration::from_millis(10));
    }
}
pub struct SessionGuard;
impl Drop for SessionGuard {
    fn drop(&mut self) {
        let remaining = shutdown(Duration::from_secs(2));
        if remaining != 0 {
            tracing::warn!(remaining, "workers still unwinding after shutdown deadline");
        }
    }
}

static POLICY: OnceLock<Policy> = OnceLock::new();

/// Called synchronously before constructing runtime or application workers.
pub fn install(mode: Mode, paths: SandboxPaths) -> Result<(), String> {
    POLICY
        .set(Policy {
            mode,
            #[cfg(target_os = "linux")]
            prepared: super::linux::prepare_ruleset(&paths),
            paths,
            components: Mutex::new(BTreeMap::new()),
        })
        .map_err(|_| "worker policy already installed".to_string())
}
#[cfg(target_os = "linux")]
pub(super) fn prepared_ruleset() -> Option<&'static Result<landlock::RulesetCreated, String>> {
    POLICY.get().map(|p| &p.prepared)
}
pub fn ensure(mode: Mode, paths: SandboxPaths) -> Result<(), String> {
    if let Some(policy) = POLICY.get() {
        if policy.mode != mode {
            return Err("worker policy mode cannot change during a session".into());
        }
        return preflight();
    }
    if !matches!(mode, Mode::Disabled) {
        paths.prepare().map_err(|e| e.to_string())?;
    }
    install(mode, paths)?;
    preflight()
}
/// Check enforceability in a disposable thread before opening optional sources.
pub fn preflight() -> Result<(), String> {
    if !snapshot().contains_key("policy-preflight") {
        let handle = spawn("policy-preflight", || {});
        if handle.is_finished() {
            let _ = handle.join();
        }
    }
    if matches!(mode(), Mode::Strict) {
        wait_ready(Duration::from_secs(5))
    } else {
        Ok(())
    }
}
pub fn mode() -> Mode {
    POLICY.get().map_or(Mode::Disabled, |p| p.mode)
}
pub fn begin(name: &str) {
    if let Some(p) = POLICY.get() {
        let mut components = crate::app::safe_lock(&p.components, "worker::begin");
        if components.get(name).is_some_and(|s| s.error.is_some()) {
            return;
        }
        components.insert(
            name.into(),
            Component {
                ready: false,
                report: None,
                error: None,
            },
        );
    }
}
/// Record a component that exists but is only partly confined, with the
/// reason.
///
/// Distinct from [`fail`]: the component is running and useful, and the note
/// is what stops its protection being overstated. Strict mode treats it as a
/// failure, because a partial guarantee is not the one strict promises.
pub fn note(name: &str, detail: impl Into<String>) {
    if let Some(p) = POLICY.get() {
        let mut components = crate::app::safe_lock(&p.components, "worker::note");
        let detail = detail.into();
        let strict = matches!(p.mode, Mode::Strict);
        components.insert(
            name.into(),
            Component {
                ready: !strict,
                report: None,
                error: Some(detail),
            },
        );
    }
}

pub fn fail(name: &str, error: impl Into<String>) {
    if let Some(p) = POLICY.get() {
        crate::app::safe_lock(&p.components, "worker::fail").insert(
            name.into(),
            Component {
                ready: false,
                report: None,
                error: Some(error.into()),
            },
        );
    }
}
/// Enforce on the actual worker. Strict failures return false before processing.
pub fn enter(name: &str) -> bool {
    enter_retaining(name, super::Retain::Nothing)
}

/// Enter while keeping the capabilities `retain` names.
///
/// The eBPF worker is the only caller: it needs CAP_BPF and CAP_PERFMON for
/// the load that entry would otherwise have taken from it. It drops them with
/// [`drop_load_caps`] before reading anything, so the window is the load
/// itself and the report names it.
pub fn enter_retaining(name: &str, retain: super::Retain) -> bool {
    let Some(p) = POLICY.get() else {
        return true;
    };
    let report = super::apply_retaining(p.mode, &p.paths, retain);
    #[cfg(test)]
    let report = {
        let mut report = report;
        if std::env::var("NETWATCH_WORKER_FORCE_FAILURE").as_deref() == Ok(name) {
            report
                .mode
                .warnings
                .push("injected enforcement failure".into());
        }
        report
    };
    #[cfg(test)]
    if let Ok(path) = std::env::var("NETWATCH_WORKER_PROBE") {
        let denied =
            std::fs::read(path).is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied);
        PROBES.lock().unwrap().insert(name.into(), denied);
    }
    let allowed = !matches!(p.mode, Mode::Strict) || report.mode.warnings.is_empty();
    let mut components = crate::app::safe_lock(&p.components, "worker::enter");
    let earlier_error = components.get(name).and_then(|s| s.error.clone());
    // Never overwrite evidence that an earlier entry ran without full protection.
    let error = earlier_error
        .or_else(|| (!report.mode.warnings.is_empty()).then(|| report.mode.warnings.join("; ")));
    components.insert(
        name.into(),
        Component {
            ready: allowed,
            report: Some(report),
            error,
        },
    );
    allowed
}
pub fn snapshot() -> BTreeMap<String, Component> {
    POLICY
        .get()
        .map(|p| crate::app::safe_lock(&p.components, "worker::snapshot").clone())
        .unwrap_or_default()
}
/// Start with a bounded entry handshake. A timed-out worker is never released.
/// Drop the capabilities [`enter_retaining`] kept, on the calling thread.
///
/// Records the outcome against `name`, because a worker that kept CAP_BPF and
/// then failed to drop it is a different state from one that never held it,
/// and the sandbox report should not flatten the two.
pub fn drop_load_caps(name: &str) {
    #[cfg(target_os = "linux")]
    if POLICY.get().is_some() {
        if let Err(error) = super::linux::drop_bpf_caps() {
            fail(name, format!("load capabilities not dropped: {error}"));
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = name;
}

/// What [`relinquish`] left each unconfined thread holding, by name.
static RELINQUISHED: Mutex<BTreeMap<String, Report>> = Mutex::new(BTreeMap::new());

/// Give up, on the calling thread, every capability except CAP_SYS_PTRACE and
/// CAP_DAC_READ_SEARCH, without confining it.
///
/// For the ProcBroker, which stays outside Landlock to read other processes'
/// socket fds and so never enters. Under sudo it would otherwise keep every
/// capability the process started with, CAP_NET_RAW and the BPF set included,
/// for the whole session and in every mode. Needs no policy, because the
/// broker can start before [`ensure`] installs one; the outcome is recorded
/// for [`relinquished`] either way.
pub fn relinquish(name: &str) {
    #[cfg(target_os = "linux")]
    {
        let mut report = Report::default();
        super::linux::relinquish_caps(&mut report);
        for warning in &report.mode.warnings {
            tracing::warn!(target: "netwatch::sandbox", thread = name, "{warning}");
        }
        let mut records = crate::app::safe_lock(&RELINQUISHED, "worker::relinquish");
        // Never overwrite evidence that an earlier thread of the same name
        // kept more than it should have.
        if records
            .get(name)
            .is_none_or(|earlier| earlier.mode.warnings.is_empty())
        {
            records.insert(name.into(), report);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = name;
}

/// The capabilities each [`relinquish`] caller dropped and kept.
pub fn relinquished() -> BTreeMap<String, Report> {
    crate::app::safe_lock(&RELINQUISHED, "worker::relinquished").clone()
}

pub fn spawn(name: &'static str, run: impl FnOnce() + Send + 'static) -> WorkerHandle {
    spawn_retaining(name, super::Retain::Nothing, run)
}

/// [`spawn`], entering with `retain` held.
pub fn spawn_retaining(
    name: &'static str,
    retain: super::Retain,
    run: impl FnOnce() + Send + 'static,
) -> WorkerHandle {
    begin(name);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    // Named so the panic hook, the log and `/proc/<pid>/task/*/comm` can tell
    // workers apart; the kernel keeps the first 15 bytes.
    let handle = std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let allowed = enter_retaining(name, retain);
            let _ = ready_tx.send(allowed);
            if allowed && release_rx.recv().unwrap_or(false) && !stopping() {
                run();
            }
        })
        .expect("failed to spawn thread");
    match ready_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(true) => {
            let _ = release_tx.send(true);
        }
        Ok(false) => {}
        Err(error) => fail(name, format!("worker entry timeout/disconnect: {error}")),
    }
    let slot = Arc::new(Mutex::new(Some(handle)));
    let mut handles = HANDLES.lock().unwrap();
    handles.retain(|slot| {
        !slot
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|h| h.is_finished())
    });
    handles.push(Arc::clone(&slot));
    WorkerHandle(slot)
}
pub fn wait_ready(timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let states = snapshot();
        let errors: Vec<_> = states
            .iter()
            .filter_map(|(name, s)| s.error.as_ref().map(|e| format!("{name}: {e}")))
            .collect();
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        if states.values().all(|s| s.ready) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("worker readiness deadline exceeded".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
pub fn summary() -> String {
    let states = snapshot();
    if states.is_empty() {
        return "worker coverage not recorded".into();
    }
    let ready = states
        .values()
        .filter(|s| {
            s.ready
                && s.error.is_none()
                && s.report
                    .as_ref()
                    .is_some_and(|r| r.platform.landlock_abi > 0 && r.mode.warnings.is_empty())
        })
        .count();
    format!("{ready}/{} worker entries verified", states.len())
}

#[cfg(test)]
static PROBES: Mutex<BTreeMap<String, bool>> = Mutex::new(BTreeMap::new());

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn isolated_worker_boundaries() {
        const CHILD: &str = "NETWATCH_WORKER_POLICY_TEST";
        let Ok(root) = std::env::var(CHILD) else {
            struct TestDir(std::path::PathBuf);
            impl Drop for TestDir {
                fn drop(&mut self) {
                    let _ = std::fs::remove_dir_all(&self.0);
                }
            }
            let temp = TestDir(
                std::env::temp_dir().join(format!("netwatch-worker-{}", uuid::Uuid::new_v4())),
            );
            std::fs::create_dir(&temp.0).unwrap();
            std::fs::write(temp.0.as_path().join("secret"), b"sentinel").unwrap();
            std::fs::write(
                temp.0.as_path().join("keylog"),
                format!(
                    "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
                    "00".repeat(32),
                    "11".repeat(32)
                ),
            )
            .unwrap();
            for injected in ["", "blocked"] {
                let result = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "sandbox::worker::tests::isolated_worker_boundaries",
                        "--nocapture",
                    ])
                    .env(CHILD, temp.0.as_path())
                    .env("NETWATCH_WORKER_FORCE_FAILURE", injected)
                    .env("NETWATCH_WORKER_PROBE", temp.0.as_path().join("secret"))
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "{}\n{}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                );
                if injected.is_empty() {
                    std::fs::remove_file(temp.0.join("exports")).unwrap();
                    std::fs::rename(temp.0.join("exports-pinned"), temp.0.join("exports")).unwrap();
                }
            }
            return;
        };
        let root = std::path::PathBuf::from(root);
        let paths = SandboxPaths {
            cache_dir: Some(root.join("cache")),
            config_dir: Some(root.join("config")),
            state_dir: Some(root.join("state")),
            cwd: Some(root.join("exports")),
            keylog_dir: Some(root.join("keylog")),
            ..Default::default()
        };
        paths.prepare().unwrap();
        install(Mode::Strict, paths).unwrap();
        if std::env::var("NETWATCH_WORKER_FORCE_FAILURE").as_deref() == Ok("blocked") {
            let (tx, rx) = std::sync::mpsc::channel();
            spawn("blocked", move || {
                tx.send(()).unwrap();
            })
            .join()
            .unwrap();
            assert!(rx.try_recv().is_err());
            assert!(wait_ready(Duration::from_secs(1)).is_err());
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        // Replace an allowed pathname after rule preparation. The ruleset
        // must remain pinned to the original directory, not follow the swap.
        let exports = root.join("exports-pinned");
        std::fs::rename(root.join("exports"), &exports).unwrap();
        std::os::unix::fs::symlink(&root, root.join("exports")).unwrap();
        let escape = root.join("exports").join("escape");
        let secret = root.join("secret");
        // /proc is a read grant, and a thread may write its own name to
        // /proc/thread-self/comm. Opening it for writing is allowed here and
        // must be refused once confined, which it would not be if the
        // ruleset gave a read row more than reading.
        let open_comm_for_write = || {
            std::fs::OpenOptions::new()
                .write(true)
                .open("/proc/thread-self/comm")
        };
        open_comm_for_write().unwrap();
        spawn("boundary-check", move || {
            assert_eq!(
                open_comm_for_write().unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                std::fs::read(secret).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            std::fs::write(exports.join("allowed"), b"ok").unwrap();
            // Packet exports publish by hard link and incident bundles by
            // renaming their directory, both within the exports directory,
            // so neither needs a grant beyond it.
            crate::collectors::packets::export::atomic_write(
                &exports.join("published.pcapng"),
                |file| std::io::Write::write_all(file, b"ok"),
            )
            .unwrap();
            let mut recorder = crate::collectors::incident::IncidentRecorder::new();
            recorder.arm();
            recorder.freeze("confined export").unwrap();
            let bundle = recorder.export_bundle(&exports).unwrap();
            assert!(bundle.join("manifest.json").exists());
            assert_eq!(
                std::fs::write(escape, b"blocked").unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            tx.send(()).unwrap();
        })
        .join()
        .unwrap();
        if let Err(error) = rx.recv_timeout(Duration::from_secs(1)) {
            // Strict must refuse all work if the host kernel cannot enforce it.
            assert!(snapshot()["boundary-check"].error.is_some(), "{error}");
            panic!(
                "host cannot run the confinement acceptance test: {:?}",
                snapshot()
            );
        }
        // Online lookups are opt-in (off by default, see `geoip_online` in
        // NetwatchConfig); force them on here so the geoip worker actually
        // spawns and this test still covers its sandbox entry.
        let geo = crate::collectors::geo::GeoCache::with_mmdb_and_online("", "", true);
        geo.start();
        let whois = crate::collectors::whois::WhoisCache::new();
        whois.start();
        let mut packet = crate::collectors::packets::PacketCollector::new();
        packet.dns_cache.start();
        for _ in 0..2 {
            packet.configure_tls_keylog(Some(root.join("keylog")));
            let deadline = Instant::now() + Duration::from_secs(2);
            while packet
                .stream_tracker
                .lock()
                .unwrap()
                .keylog
                .lookup(&[0; 32])
                .is_none()
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(packet
                .stream_tracker
                .lock()
                .unwrap()
                .keylog
                .lookup(&[0; 32])
                .is_some());
            packet.configure_tls_keylog(None);
        }
        let mut ai =
            crate::collectors::insights::InsightsCollector::new("unused", "http://127.0.0.1:1");
        ai.start();
        for name in ["geoip", "whois", "reverse-dns", "keylog", "insights"] {
            assert_eq!(
                PROBES.lock().unwrap().get(name),
                Some(&true),
                "actual {name} worker could read sentinel"
            );
        }
        assert!(wait_ready(Duration::from_secs(1)).is_ok());
        assert_eq!(shutdown(Duration::from_secs(2)), 0);
        // Parent thread remains unrestricted: tests changed the real workers only.
        assert_eq!(std::fs::read(root.join("secret")).unwrap(), b"sentinel");
    }

    #[test]
    fn worker_threads_are_named() {
        // An unnamed worker carries its parent's name, so every worker in a
        // panic message or a task listing used to read "netwatch".
        let (tx, rx) = std::sync::mpsc::channel();
        spawn("policy-preflight", move || {
            let comm = std::fs::read_to_string("/proc/thread-self/comm").unwrap();
            tx.send(comm).unwrap();
        })
        .join()
        .unwrap();
        let comm = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(comm.trim_end(), "policy-prefligh");
    }

    /// The capture thread records its state in the component map and the UI
    /// reads it for Settings and the capability report. Once poisoned, the
    /// map used to panic the next capture start and every screen that read it.
    #[test]
    fn a_poisoned_component_map_still_records_and_reads() {
        const CHILD: &str = "NETWATCH_WORKER_POISON_TEST";
        // POLICY is process-wide, so install and poison it in a child.
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "sandbox::worker::tests::a_poisoned_component_map_still_records_and_reads",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        }
        install(Mode::Disabled, SandboxPaths::default()).unwrap();
        let components = &POLICY.get().unwrap().components;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = components.lock().unwrap();
            panic!("worker bug");
        }));
        assert!(components.is_poisoned());
        begin("capture");
        assert!(enter("capture"));
        fail("capture", "Capture stopped");
        note("ebpf", "partly confined");
        let states = snapshot();
        assert_eq!(states["capture"].error.as_deref(), Some("Capture stopped"));
        assert_eq!(states["ebpf"].error.as_deref(), Some("partly confined"));
    }
}

pub fn all_verified() -> bool {
    let states = snapshot();
    !states.is_empty()
        && states.values().all(|s| {
            s.ready
                && s.error.is_none()
                && s.report
                    .as_ref()
                    .is_some_and(|r| r.platform.landlock_abi > 0 && r.mode.warnings.is_empty())
        })
}
