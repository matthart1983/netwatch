//! Explicit per-worker entry policy. No input is processed before entry returns.
use super::{CaptureAuthority, Mode, Report, SandboxPaths};
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
    /// Set once by [`ensure`], which knows the session; until then
    /// [`capture_authority`] reads [`CaptureAuthority::DropAfterOpen`].
    capture_authority: OnceLock<CaptureAuthority>,
    /// Shared by every worker and the UI, the capture thread included, so
    /// every access goes through `safe_lock`.
    components: Mutex<BTreeMap<String, Component>>,
    #[cfg(target_os = "linux")]
    prepared: Result<landlock::RulesetCreated, String>,
    /// Stacked on `prepared` by parser threads; see [`super::Role`].
    #[cfg(target_os = "linux")]
    prepared_parser: Result<landlock::RulesetCreated, String>,
    /// Stacked on `prepared` by the capture thread.
    #[cfg(target_os = "linux")]
    prepared_capture: Result<landlock::RulesetCreated, String>,
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
            #[cfg(target_os = "linux")]
            prepared_parser: super::linux::prepare_parser_layer(mode),
            #[cfg(target_os = "linux")]
            prepared_capture: super::linux::prepare_capture_layer(mode, &paths),
            paths,
            capture_authority: OnceLock::new(),
            components: Mutex::new(BTreeMap::new()),
        })
        .map_err(|_| "worker policy already installed".to_string())
}
#[cfg(target_os = "linux")]
pub(super) fn prepared_ruleset() -> Option<&'static Result<landlock::RulesetCreated, String>> {
    POLICY.get().map(|p| &p.prepared)
}
/// The layer `role` stacks on the shared ruleset. Each thread clones its own.
#[cfg(target_os = "linux")]
pub(super) fn prepared_layer(
    role: super::Role,
) -> Option<&'static Result<landlock::RulesetCreated, String>> {
    POLICY.get().map(|p| match role {
        super::Role::Capture => &p.prepared_capture,
        _ => &p.prepared_parser,
    })
}
/// Install the policy if `main` has not, and record the session's capture
/// authority. Workers that entered before this took
/// [`CaptureAuthority::DropAfterOpen`].
pub fn ensure(mode: Mode, paths: SandboxPaths, authority: CaptureAuthority) -> Result<(), String> {
    if let Some(policy) = POLICY.get() {
        if policy.mode != mode {
            return Err("worker policy mode cannot change during a session".into());
        }
    } else {
        if !matches!(mode, Mode::Disabled) {
            paths.prepare().map_err(|e| e.to_string())?;
        }
        install(mode, paths)?;
    }
    let policy = POLICY.get().expect("installed above");
    if *policy.capture_authority.get_or_init(|| authority) != authority {
        return Err("capture authority cannot change during a session".into());
    }
    preflight()
}
/// Whether main and the network workers keep CAP_NET_RAW on entry.
pub fn capture_authority() -> CaptureAuthority {
    POLICY
        .get()
        .and_then(|p| p.capture_authority.get().copied())
        .unwrap_or(CaptureAuthority::DropAfterOpen)
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
    #[cfg(all(test, target_os = "linux"))]
    {
        let held = [caps::CapSet::Permitted, caps::CapSet::Inheritable]
            .into_iter()
            .filter_map(|set| caps::read(None, set).ok())
            .flatten()
            .collect();
        FAILED_HOLDING.lock().unwrap().insert(name.into(), held);
    }
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
/// Enforce on the actual worker, with the policy of its role
/// ([`super::roles::role_for`]). Strict failures return false before
/// processing.
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
    let role = super::roles::role_for(name);
    let report = super::apply_retaining(p.mode, &p.paths, retain, role);
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
    #[cfg(test)]
    if let Some(port) = std::env::var("NETWATCH_WORKER_NET_PROBE")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
    {
        // The errno of a TCP connect to a loopback listener, or `None` when
        // it connected.
        let errno = std::net::TcpStream::connect(("127.0.0.1", port))
            .err()
            .map(|e| e.raw_os_error().unwrap_or(-1));
        NET_PROBES.lock().unwrap().insert(name.into(), errno);
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

/// Give up, on the calling thread, every capability its role does not keep
/// unconfined, without confining it. The ProcBroker keeps CAP_SYS_PTRACE and
/// CAP_DAC_READ_SEARCH, and any other thread nothing.
///
/// For threads that never enter. The ProcBroker stays outside Landlock to read
/// other processes' socket fds; the TUI's shutdown deadline waits for signals
/// from before the policy's session starts; a capture thread whose device
/// failed to open returns without entering. Each starts from main before main
/// drops anything, so under sudo it would otherwise keep every capability the
/// process started with, CAP_NET_RAW and the BPF set included, and in every
/// mode. Needs no policy, because the broker can start before [`ensure`]
/// installs one; the outcome is recorded for [`relinquished`] either way.
pub fn relinquish(name: &str) {
    #[cfg(target_os = "linux")]
    {
        let mut report = Report::default();
        super::linux::relinquish_caps(super::roles::role_for(name), &mut report);
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
#[cfg(test)]
static NET_PROBES: Mutex<BTreeMap<String, Option<i32>>> = Mutex::new(BTreeMap::new());
/// What the thread that last called [`fail`] for each name held then.
#[cfg(all(test, target_os = "linux"))]
static FAILED_HOLDING: Mutex<BTreeMap<String, caps::CapsHashSet>> = Mutex::new(BTreeMap::new());
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn held_at_failure(name: &str) -> Option<caps::CapsHashSet> {
    FAILED_HOLDING.lock().unwrap().get(name).cloned()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn isolated_worker_boundaries() {
        const CHILD: &str = "NETWATCH_WORKER_POLICY_TEST";
        let Ok(root) = std::env::var(CHILD) else {
            if super::super::linux::kernel_denies_files_but_not_tcp() {
                eprintln!("skipped: strict needs Landlock ABI 4 (Linux 6.7) to deny TCP");
                return;
            }
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
            // Workers connect to this on entry; the kernel completes the
            // handshake without an accept.
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let probe_port = probe.local_addr().unwrap().port().to_string();
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
                    .env("NETWATCH_WORKER_NET_PROBE", &probe_port)
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
        // Capture enters with the layer `install` prepared for its role, which
        // has the read grants and none of the write grants. Every other
        // confined thread can write the configuration.
        let config = root.join("config").join("config.toml");
        for (name, writes) in [("connections", true), ("capture", false)] {
            let (tx, rx) = std::sync::mpsc::channel();
            let config = config.clone();
            spawn(name, move || {
                let wrote = std::fs::write(&config, b"sandbox = \"off\"\n");
                tx.send(wrote.map_err(|e| e.kind())).unwrap();
            })
            .join()
            .unwrap();
            let expected = if writes {
                Ok(())
            } else {
                Err(std::io::ErrorKind::PermissionDenied)
            };
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(1)),
                Ok(expected),
                "{name}"
            );
        }
        let capture = snapshot()["capture"].report.clone().unwrap();
        assert_eq!(capture.platform.landlock_layer, Some("capture"));
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
        for name in ["whois", "reverse-dns", "keylog", "insights"] {
            assert_eq!(
                PROBES.lock().unwrap().get(name),
                Some(&true),
                "actual {name} worker could read sentinel"
            );
        }
        // The exporter starts metrics-client on the listener's thread, where
        // it inherits the listener's layer whatever its own role, so the
        // scrape below shows the listener's deny only. Entered from this
        // unconfined thread, it has to deny TCP by its own role.
        spawn("metrics-client", || {}).join().unwrap();
        assert_eq!(
            NET_PROBES.lock().unwrap().get("metrics-client"),
            Some(&Some(nix::libc::EACCES)),
            "metrics-client's own role keeps the network"
        );
        // An exporter serving from parser threads still answers a scrape
        // from this unconfined thread: accepting and answering is neither a
        // bind nor a connect, and the listener was bound before entry.
        let metrics_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let exporter = crate::metrics::MetricsExporter::new(format!("127.0.0.1:{metrics_port}"));
        exporter.start();
        let mut scrape = std::net::TcpStream::connect(("127.0.0.1", metrics_port)).unwrap();
        std::io::Write::write_all(&mut scrape, b"GET /metrics HTTP/1.1\r\n\r\n").unwrap();
        let mut response = String::new();
        std::io::Read::read_to_string(&mut scrape, &mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let net = NET_PROBES.lock().unwrap().clone();
        for name in [
            "keylog",
            "metrics-listener",
            "metrics-client",
            "boundary-check",
            "capture",
        ] {
            assert_eq!(
                net.get(name),
                Some(&Some(nix::libc::EACCES)),
                "actual {name} worker could connect: {net:?}"
            );
        }
        for name in ["whois", "reverse-dns", "insights"] {
            assert_eq!(
                net.get(name),
                Some(&None),
                "actual {name} worker could not connect: {net:?}"
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

    /// Make Landlock look absent to the calling thread and every thread it
    /// starts afterwards: landlock_create_ruleset, which every Landlock call
    /// starts with, fails with ENOSYS. Syscalls added since Linux 5.1 have the
    /// same number on every architecture netwatch builds for, so the filter
    /// does not check which.
    fn hide_landlock() {
        use nix::libc;
        let statement = |code: u32, k: u32| libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k,
        };
        let mut filter = [
            statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0),
            libc::sock_filter {
                jf: 1,
                ..statement(
                    libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                    libc::SYS_landlock_create_ruleset as u32,
                )
            },
            statement(
                libc::BPF_RET | libc::BPF_K,
                libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
            ),
            statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        let (zero, one): (libc::c_ulong, libc::c_ulong) = (0, 1);
        let mode = libc::SECCOMP_MODE_FILTER as libc::c_ulong;
        // SAFETY: prctl reads four arguments after the option, each passed
        // as the unsigned long the kernel takes, and PR_SET_NO_NEW_PRIVS
        // fails unless the last three are zero. PR_SET_SECCOMP reads
        // `program` and the `filter` it points to, both alive until it
        // returns.
        let installed = unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero, zero, zero) == 0
                && libc::prctl(
                    libc::PR_SET_SECCOMP,
                    mode,
                    &program as *const libc::sock_fprog,
                    zero,
                    zero,
                ) == 0
        };
        assert!(installed, "{}", std::io::Error::last_os_error());
    }

    /// Strict refuses a parser entry on a kernel that cannot deny TCP
    /// (OD3). The filesystem layer fails too when Landlock is hidden, so the
    /// error has to name the TCP deny; any strict failure would not do.
    #[test]
    fn strict_refuses_parser_entry_without_the_tcp_deny() {
        const CHILD: &str = "NETWATCH_WORKER_NO_LANDLOCK_TEST";
        // The filter cannot be removed, so it goes on a child.
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "sandbox::worker::tests::strict_refuses_parser_entry_without_the_tcp_deny",
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
        hide_landlock();
        install(Mode::Strict, SandboxPaths::default()).unwrap();
        let error = preflight().unwrap_err();
        assert!(
            error.contains("cannot deny TCP") || error.contains("parser network deny unavailable"),
            "{error}"
        );
        assert!(!snapshot()["policy-preflight"].ready);
    }

    /// Workers that enter before the session starts drop CAP_NET_RAW; the
    /// session then says whether main keeps it, once.
    #[test]
    fn ensure_sets_the_capture_authority_once() {
        const CHILD: &str = "NETWATCH_WORKER_AUTHORITY_TEST";
        // POLICY is process-wide, so install it in a child.
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "sandbox::worker::tests::ensure_sets_the_capture_authority_once",
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
        assert_eq!(capture_authority(), CaptureAuthority::DropAfterOpen);
        install(Mode::Disabled, SandboxPaths::default()).unwrap();
        assert_eq!(capture_authority(), CaptureAuthority::DropAfterOpen);
        let tui = CaptureAuthority::RetainForReopen;
        ensure(Mode::Disabled, SandboxPaths::default(), tui).unwrap();
        assert_eq!(capture_authority(), tui);
        ensure(Mode::Disabled, SandboxPaths::default(), tui).unwrap();
        let error = ensure(
            Mode::Disabled,
            SandboxPaths::default(),
            CaptureAuthority::DropAfterOpen,
        )
        .unwrap_err();
        assert!(error.contains("capture authority"), "{error}");
        assert_eq!(capture_authority(), tui);
    }

    /// Whether a `health` worker still holds CAP_NET_RAW once it has entered
    /// on a thread of its own.
    fn health_keeps_net_raw() -> bool {
        std::thread::spawn(|| {
            assert!(enter("health"));
            caps::has_cap(None, caps::CapSet::Permitted, caps::Capability::CAP_NET_RAW).unwrap()
        })
        .join()
        .unwrap()
    }

    /// The session's capture authority reaches each worker's entry: a
    /// network worker drops CAP_NET_RAW until a TUI's `ensure` says capture
    /// reopens, and keeps it from then on.
    #[test]
    fn network_worker_keeps_cap_net_raw_once_a_tui_starts() {
        if !super::super::audit::as_root_in_user_namespace(
            "sandbox::worker::tests::network_worker_keeps_cap_net_raw_once_a_tui_starts",
        ) {
            return;
        }
        install(Mode::BestEffort, SandboxPaths::default()).unwrap();
        assert!(!health_keeps_net_raw(), "entered before the session");
        let tui = CaptureAuthority::RetainForReopen;
        ensure(Mode::BestEffort, SandboxPaths::default(), tui).unwrap();
        assert!(health_keeps_net_raw(), "entered in a TUI");
    }

    /// The daemon and the Diagnose CLI never reopen capture, so their
    /// network workers drop CAP_NET_RAW.
    #[test]
    fn network_worker_drops_cap_net_raw_where_capture_never_reopens() {
        if !super::super::audit::as_root_in_user_namespace(
            "sandbox::worker::tests::network_worker_drops_cap_net_raw_where_capture_never_reopens",
        ) {
            return;
        }
        install(Mode::BestEffort, SandboxPaths::default()).unwrap();
        let daemon = CaptureAuthority::DropAfterOpen;
        ensure(Mode::BestEffort, SandboxPaths::default(), daemon).unwrap();
        assert!(!health_keeps_net_raw());
    }

    /// A thread that never enters keeps only what its name's role needs
    /// unconfined: the proc broker its scan's two capabilities, the TUI's
    /// shutdown deadline and a capture thread whose device failed to open
    /// nothing.
    #[test]
    fn relinquish_keeps_only_what_the_role_needs() {
        use caps::{CapSet, Capability};
        if !super::super::audit::as_root_in_user_namespace(
            "sandbox::worker::tests::relinquish_keeps_only_what_the_role_needs",
        ) {
            return;
        }
        let broker = [Capability::CAP_SYS_PTRACE, Capability::CAP_DAC_READ_SEARCH];
        for (name, keeps) in [
            ("proc-broker", &broker[..]),
            ("shutdown-deadline", &[]),
            ("capture", &[]),
        ] {
            let held = std::thread::spawn(move || {
                // Root in a user namespace holds nothing Inheritable or
                // Ambient, so grant CAP_NET_RAW there first, as the systemd
                // unit's AmbientCapabilities does.
                for set in [CapSet::Inheritable, CapSet::Ambient] {
                    caps::raise(None, set, Capability::CAP_NET_RAW).unwrap();
                }
                relinquish(name);
                [
                    CapSet::Effective,
                    CapSet::Permitted,
                    CapSet::Inheritable,
                    CapSet::Ambient,
                ]
                .map(|set| (set, caps::read(None, set).unwrap()))
            })
            .join()
            .unwrap();
            for (set, held) in held {
                let expected: caps::CapsHashSet =
                    if matches!(set, CapSet::Effective | CapSet::Permitted) {
                        keeps.iter().copied().collect()
                    } else {
                        Default::default()
                    };
                assert_eq!(held, expected, "{name} {set:?}");
            }
            let report = &relinquished()[name];
            assert!(report.mode.warnings.is_empty(), "{name}: {report:?}");
        }
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
