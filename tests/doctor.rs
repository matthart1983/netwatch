#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use std::{fs, net::TcpListener, path::PathBuf, process::Command};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("netwatch-doctor-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(path.join("config/netwatch")).unwrap();
        fs::create_dir_all(path.join("cache/netwatch")).unwrap();
        fs::write(
            path.join("cache/netwatch/applied.json"),
            "corrupt legacy evidence",
        )
        .unwrap();
        Self(path)
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_netwatch"));
        cmd.env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            .env("XDG_CACHE_HOME", self.0.join("cache"))
            .env("XDG_STATE_HOME", self.0.join("state"));
        cmd
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn static_doctor_does_not_contact_configured_services_or_write_state() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let config = netwatch::config::NetwatchConfig {
        insights_enabled: true,
        insights_endpoint: endpoint.clone(),
        geoip_online: true,
        ..Default::default()
    };
    let raw = toml::to_string(&config).unwrap();
    fs::write(fixture.0.join("config/netwatch/config.toml"), &raw).unwrap();
    let output = fixture
        .command()
        .args(["doctor", "--json"])
        .env("NETWATCH_REMOTE_URL", &endpoint)
        .env("NETWATCH_API_KEY", "doctor-secret-sentinel")
        .env(
            "NETWATCH_METRICS_ADDR",
            listener.local_addr().unwrap().to_string(),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("doctor-secret-sentinel"));
    assert!(!text.contains(&endpoint));
    let snapshot: netwatch::runtime::capabilities::CapabilitySnapshot =
        serde_json::from_str(&text).unwrap();
    assert_eq!(snapshot.scope, "static");
    assert!(snapshot.protections.is_empty());
    assert_eq!(
        snapshot.get("capture").state,
        netwatch::runtime::capabilities::State::NotChecked
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        fs::read_to_string(fixture.0.join("config/netwatch/config.toml")).unwrap(),
        raw
    );
    assert_eq!(
        fs::read_to_string(fixture.0.join("cache/netwatch/applied.json")).unwrap(),
        "corrupt legacy evidence"
    );
    assert!(!fixture.0.join("state").exists());
    assert_eq!(
        fs::read_dir(fixture.0.join("cache/netwatch"))
            .unwrap()
            .count(),
        1
    );
}
#[test]
fn malformed_config_is_reported_without_echoing_secrets() {
    let fixture = Fixture::new();
    fs::write(
        fixture.0.join("config/netwatch/config.toml"),
        "api_key = secret-sentinel-invalid",
    )
    .unwrap();
    let output = fixture
        .command()
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("secret-sentinel"));
    let snapshot: netwatch::runtime::capabilities::CapabilitySnapshot =
        serde_json::from_str(&text).unwrap();
    assert_eq!(snapshot.get("config").reason, "config_invalid");
    // Where to look, without the line itself.
    let detail = &snapshot.get("config").detail;
    let path = fixture.0.join("config/netwatch/config.toml");
    assert!(detail.contains(&path.display().to_string()), "{detail}");
    assert!(detail.contains("line 1, column 11"), "{detail}");
}
/// A live session refuses a config that does not load, so the capture check
/// does not run on the defaults in its place: they could check a weaker
/// sandbox than the one configured. The report still completes and exits 0.
#[test]
fn capture_check_does_not_run_on_a_config_that_does_not_load() {
    let fixture = Fixture::new();
    let config = fixture.0.join("config/netwatch/config.toml");
    let broken = "sandbox = 'strict'\nrefresh_rate_ms = 'oops'\n";
    fs::write(&config, broken).unwrap();
    let output = fixture
        .command()
        .args([
            "doctor",
            "--json",
            "--check-capture",
            "--interface",
            "netwatch-nonexistent-interface",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot: netwatch::runtime::capabilities::CapabilitySnapshot =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(snapshot.get("config").reason, "config_invalid");
    assert!(
        snapshot.get("config").detail.contains("line 2, column 19"),
        "{:?}",
        snapshot.get("config")
    );
    let capture = snapshot.get("capture");
    assert_eq!(
        capture.state,
        netwatch::runtime::capabilities::State::NotChecked
    );
    assert_eq!(capture.reason, "config_not_loaded");
    assert!(snapshot.protections.is_empty());
    assert_eq!(fs::read_to_string(&config).unwrap(), broken);
}
#[test]
fn explicit_capture_check_reports_failure_and_creates_no_state() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args([
            "doctor",
            "--json",
            "--check-capture",
            "--interface",
            "netwatch-nonexistent-interface",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot: netwatch::runtime::capabilities::CapabilitySnapshot =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(snapshot.scope, "capture_check");
    assert_eq!(
        snapshot.get("capture").state,
        netwatch::runtime::capabilities::State::Unavailable
    );
    assert!(!fixture.0.join("state").exists());
    assert_eq!(
        fs::read_dir(fixture.0.join("cache/netwatch"))
            .unwrap()
            .count(),
        1
    );
}
/// Doctor names the connection table a live session will read: `ss` when it
/// is on PATH, `/proc/net` when it is not. PATH is set on the child only.
#[test]
fn doctor_reports_the_proc_net_fallback_when_ss_is_missing() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let empty = fixture.0.join("empty-bin");
    let with_ss = fixture.0.join("ss-bin");
    fs::create_dir_all(&empty).unwrap();
    fs::create_dir_all(&with_ss).unwrap();
    fs::write(with_ss.join("ss"), "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(with_ss.join("ss"), fs::Permissions::from_mode(0o755)).unwrap();
    let connections = |path: &std::path::Path| {
        let output = fixture
            .command()
            .args(["doctor", "--json"])
            .env("PATH", path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let snapshot: netwatch::runtime::capabilities::CapabilitySnapshot =
            serde_json::from_slice(&output.stdout).unwrap();
        snapshot.get("connections").clone()
    };

    let missing = connections(&empty);
    assert_eq!(
        missing.state,
        netwatch::runtime::capabilities::State::Degraded
    );
    assert_eq!(missing.reason, "proc_net_fallback");
    assert!(missing.detail.contains("/proc/net/"), "{}", missing.detail);

    let found = connections(&with_ss);
    assert_eq!(found.state, netwatch::runtime::capabilities::State::Ready);
    assert_eq!(found.reason, "ss_found");
    assert!(
        found
            .detail
            .contains(&with_ss.join("ss").display().to_string()),
        "{}",
        found.detail
    );
}
/// `--check-capture` enters with the capture thread's policy, so it reports
/// what capture runs under: in best-effort that drops CAP_NET_RAW, which main
/// keeps. Holding CAP_NET_RAW takes a user and network namespace, so this
/// skips where it cannot make one.
#[test]
fn capture_check_applies_the_capture_policy() {
    let fixture = Fixture::new();
    let mut command = Command::new("unshare");
    command
        .args(["--user", "--map-root-user", "--net", "sh", "-c"])
        .arg(r#"ip link set lo up && exec "$0" doctor --json --check-capture --interface lo"#)
        .arg(env!("CARGO_BIN_EXE_netwatch"));
    for (key, value) in fixture.command().get_envs() {
        if let Some(value) = value {
            command.env(key, value);
        }
    }
    let output = match command.output() {
        Ok(output) if output.status.success() => output,
        other => {
            eprintln!("skipped: no user and network namespace with lo up: {other:?}");
            return;
        }
    };
    let snapshot: netwatch::runtime::capabilities::CapabilitySnapshot =
        serde_json::from_slice(&output.stdout).unwrap();
    let Some(check) = snapshot
        .protections
        .iter()
        .find(|p| p.component == "capture-check")
    else {
        eprintln!(
            "skipped: capture did not open on lo: {:?}",
            snapshot.get("capture")
        );
        return;
    };
    assert_eq!(check.effective.as_deref(), Some("best-effort"));
    let net_raw = "CAP_NET_RAW".to_string();
    assert!(check.caps_dropped.contains(&net_raw), "{check:?}");
    assert!(!check.caps_retained.contains(&net_raw), "{check:?}");
    assert_eq!(check.capture_authority, "dropped");
    let landlock = snapshot.landlock.as_ref().unwrap();
    if landlock.kernel_abi >= 4 {
        // What the check saw: the capture child tries TCP after its layer.
        assert_eq!(check.network_policy, "denied", "{check:?}");
        assert!(
            check.warnings.is_empty(),
            "the capture layer's deny was not observed: {check:?}"
        );
        for restriction in ["filesystem", "filesystem_write", "tcp_bind", "tcp_connect"] {
            assert!(
                check.landlock_restrictions.iter().any(|r| r == restriction),
                "{restriction}: {check:?}"
            );
        }
    }
    assert_eq!(check.landlock_kernel_abi, landlock.kernel_abi);
    assert_eq!(check.socket_filter, "installed");
    assert!(
        check
            .landlock_restrictions
            .iter()
            .any(|r| r == "socket_create"),
        "{check:?}"
    );
}

/// What static doctor's disposable thread found.
fn static_snapshot(command: &mut Command) -> netwatch::runtime::capabilities::CapabilitySnapshot {
    let output = command.args(["doctor", "--json"]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn doctor_reports_kernel_and_enforced_landlock_abi() {
    use netwatch::runtime::capabilities::State;
    let fixture = Fixture::new();
    let snapshot = static_snapshot(&mut fixture.command());
    assert_eq!(snapshot.schema_version, 1);
    let landlock = snapshot.landlock.as_ref().expect("Linux has the object");
    let capability = snapshot.get("landlock");
    // No session, so nothing has been audited, and the parser check is not a
    // component of one.
    assert!(snapshot.tasks_holding_net_raw.is_none());
    assert!(snapshot.protections.is_empty());
    assert!(!snapshot.network_restricted);
    match landlock.availability.as_str() {
        "available" if landlock.kernel_abi >= 4 => {
            let check = landlock.parser_check.as_ref().unwrap();
            assert_eq!(check.tcp_bind, "denied", "{check:?}");
            assert_eq!(check.tcp_connect, "denied", "{check:?}");
            assert!(check.enforced_abi >= 4, "{check:?}");
            assert!(check.enforced_abi <= landlock.kernel_abi, "{check:?}");
            for restriction in ["filesystem", "tcp_bind", "tcp_connect"] {
                assert!(
                    check.restrictions.iter().any(|r| r == restriction),
                    "{restriction}: {check:?}"
                );
            }
            assert_eq!(capability.state, State::Ready);
            assert_eq!(capability.reason, "parser_network_denied");
        }
        "available" => {
            assert_eq!(capability.state, State::Degraded);
            assert_eq!(capability.reason, "kernel_abi_below_4");
        }
        other => panic!("run this on a kernel with Landlock, not {other}"),
    }
}

/// The self-test runs whatever the configuration asks for, and only the
/// capability says the sandbox will not use what it found.
#[test]
fn doctor_checks_landlock_with_the_sandbox_disabled() {
    use netwatch::runtime::capabilities::State;
    let fixture = Fixture::new();
    fs::write(
        fixture.0.join("config/netwatch/config.toml"),
        "sandbox = \"off\"\n",
    )
    .unwrap();
    let snapshot = static_snapshot(&mut fixture.command());
    assert_eq!(snapshot.get("landlock").state, State::Disabled);
    assert_eq!(snapshot.get("landlock").reason, "sandbox_disabled");
    assert!(snapshot.landlock.is_some());
}

/// `command` with Landlock's three syscalls returning `errno`, as on a kernel
/// that lacks it or left it out of the boot's LSM list. Their numbers are the
/// same on every architecture.
fn without_landlock(command: &mut Command, errno: i32) {
    use nix::libc;
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure runs between fork and exec, where only
    // async-signal-safe calls may be made. It makes two prctl calls, and
    // builds the filter on the stack. PR_SET_NO_NEW_PRIVS takes four unsigned
    // long arguments and reads no memory; PR_SET_SECCOMP reads the program and
    // the filter, both alive until it returns.
    unsafe {
        command.pre_exec(move || {
            let op = |code: u32, jt: u8, jf: u8, k: u32| libc::sock_filter {
                code: code as u16,
                jt,
                jf,
                k,
            };
            let mut filter = [
                op(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
                op(libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K, 0, 2, 444),
                op(libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K, 1, 0, 446),
                op(
                    libc::BPF_RET | libc::BPF_K,
                    0,
                    0,
                    libc::SECCOMP_RET_ERRNO | errno as u32,
                ),
                op(libc::BPF_RET | libc::BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW),
            ];
            let program = libc::sock_fprog {
                len: filter.len() as libc::c_ushort,
                filter: filter.as_mut_ptr(),
            };
            let (zero, one): (libc::c_ulong, libc::c_ulong) = (0, 1);
            let mode = libc::SECCOMP_MODE_FILTER as libc::c_ulong;
            let installed = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero, zero, zero) == 0
                && libc::prctl(
                    libc::PR_SET_SECCOMP,
                    mode,
                    &program as *const libc::sock_fprog,
                    zero,
                    zero,
                ) == 0;
            if installed {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
}

#[test]
fn doctor_degrades_without_landlock() {
    use netwatch::runtime::capabilities::State;
    let fixture = Fixture::new();
    let mut command = fixture.command();
    without_landlock(&mut command, nix::libc::ENOSYS);
    let snapshot = static_snapshot(&mut command);
    let landlock = snapshot.landlock.as_ref().unwrap();
    assert_eq!(landlock.kernel_abi, 0);
    assert_eq!(landlock.availability, "not_built");
    assert!(landlock.errata.is_empty());
    let check = landlock.parser_check.as_ref().unwrap();
    assert_eq!(check.enforced_abi, 0);
    assert!(check.restrictions.is_empty(), "{check:?}");
    // The thread had the network: its check reached doctor's own listener.
    assert_eq!(check.tcp_connect, "allowed");
    assert_eq!(check.tcp_bind, "allowed");
    let capability = snapshot.get("landlock");
    assert_eq!(capability.state, State::Unavailable);
    assert_eq!(capability.reason, "landlock_not_built");
    assert!(
        capability.detail.contains("ENOSYS"),
        "{}",
        capability.detail
    );
}

/// The EPERM a container's seccomp profile can return. The landlock crate cannot
/// tell that from a kernel without Landlock, so the reason stays and the wording
/// has to allow for both.
#[test]
fn doctor_does_not_blame_the_kernel_for_a_seccomp_profile() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    without_landlock(&mut command, nix::libc::EPERM);
    let snapshot = static_snapshot(&mut command);
    assert_eq!(
        snapshot.landlock.as_ref().unwrap().availability,
        "not_built"
    );
    let capability = snapshot.get("landlock");
    assert_eq!(capability.reason, "landlock_not_built");
    assert!(
        capability.detail.contains("seccomp profile"),
        "{}",
        capability.detail
    );
    let next = capability.next_check.as_deref().unwrap_or_default();
    assert!(next.contains("seccomp profile"), "{next}");
}

#[test]
fn doctor_reports_landlock_not_enabled() {
    use netwatch::runtime::capabilities::State;
    let fixture = Fixture::new();
    let mut command = fixture.command();
    without_landlock(&mut command, nix::libc::EOPNOTSUPP);
    let snapshot = static_snapshot(&mut command);
    let landlock = snapshot.landlock.as_ref().unwrap();
    assert_eq!(landlock.kernel_abi, 0);
    assert_eq!(landlock.availability, "not_enabled");
    let capability = snapshot.get("landlock");
    assert_eq!(capability.state, State::Unavailable);
    assert_eq!(capability.reason, "landlock_not_enabled");
    assert!(
        capability.detail.contains("EOPNOTSUPP"),
        "{}",
        capability.detail
    );
}

/// `fixture`'s environment on a command that runs as root in a new user and
/// network namespace with loopback up.
fn in_namespace(fixture: &Fixture, script: &str, program: &std::ffi::OsStr) -> Command {
    let mut command = Command::new("unshare");
    command
        .args(["--user", "--map-root-user", "--net", "sh", "-c"])
        .arg(script)
        .arg(program);
    for (key, value) in fixture.command().get_envs() {
        if let Some(value) = value {
            command.env(key, value);
        }
    }
    command
}

/// As root the sandbox says what it cannot promise. Being root in a user
/// namespace is enough for that, and this skips where there is none.
#[test]
fn doctor_says_when_running_as_root() {
    const NOTE: &str = "running as root: containment limited";
    let fixture = Fixture::new();
    // SAFETY: geteuid takes no arguments, reads no memory of ours and cannot
    // fail.
    if unsafe { nix::libc::geteuid() } != 0 {
        let snapshot = static_snapshot(&mut fixture.command());
        let detail = &snapshot.get("sandbox").detail;
        assert!(!detail.contains(NOTE), "{detail}");
    }
    let program = std::ffi::OsStr::new(env!("CARGO_BIN_EXE_netwatch"));
    let mut command = in_namespace(&fixture, r#"exec "$0" doctor --json"#, program);
    let output = match command.output() {
        Ok(output) if output.status.success() => output,
        other => {
            eprintln!("skipped: no user and network namespace: {other:?}");
            return;
        }
    };
    let snapshot: netwatch::runtime::capabilities::CapabilitySnapshot =
        serde_json::from_slice(&output.stdout).unwrap();
    let detail = &snapshot.get("sandbox").detail;
    assert!(detail.contains(NOTE), "{detail}");
}

fn namespace_with_loopback() -> bool {
    Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--net",
            "ip",
            "link",
            "set",
            "lo",
            "up",
        ])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// `netwatch daemon` writes its sandbox report to its log once, which is where
/// docs/doctor.md sends a reader for what no JSON command prints. Runs where it
/// can make a network namespace, so its probes reach nothing, and the sandbox lab
/// runs it there. Capture cannot open the missing interface, so this also shows
/// what a worker that never entered reads.
#[test]
fn a_session_logs_its_sandbox_report_once() {
    if !namespace_with_loopback() {
        eprintln!("skipped: no user and network namespace with lo up");
        return;
    }
    assert!(
        include_str!("../docs/doctor.md").contains("grep 'session protections'"),
        "docs/doctor.md no longer says how to find this line"
    );
    let fixture = Fixture::new();
    fs::write(
        fixture.0.join("config/netwatch/config.toml"),
        "refresh_rate_ms = 100\ncapture_interface = \"netwatch-missing\"\n",
    )
    .unwrap();
    let program = std::ffi::OsStr::new(env!("CARGO_BIN_EXE_netwatch"));
    let mut daemon = in_namespace(
        &fixture,
        r#"ip link set lo up && exec "$0" daemon"#,
        program,
    )
    .env_remove("RUST_LOG")
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .spawn()
    .unwrap();
    let logged = || -> Vec<String> {
        let dir = fixture.0.join("cache/netwatch");
        fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("netwatch.log")
            })
            .filter_map(|entry| fs::read_to_string(entry.path()).ok())
            .flat_map(|text| {
                text.lines()
                    .filter(|line| line.contains("session protections"))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while logged().is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // Long enough for several more health cycles at this tick rate.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let lines = logged();
    let _ = daemon.kill();
    let _ = daemon.wait();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let report: serde_json::Value = lines[0]
        .split_once("report=")
        .and_then(|(_, json)| serde_json::from_str(json).ok())
        .unwrap_or_else(|| panic!("{}", lines[0]));
    assert_eq!(report["tasks_holding_net_raw"], serde_json::json!([]));
    let protection = |name: &str| {
        report["protections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["component"] == name)
            .unwrap_or_else(|| panic!("no {name}: {report}"))
    };
    assert_eq!(protection("capture")["network_policy"], "not_entered");
    assert_eq!(protection("main")["network_policy"], "allowed");
    // A worker the first ticks start, not one startup does. It starts from a main
    // that has dropped CAP_NET_RAW, so it never held it.
    assert_eq!(protection("process-cpu")["capture_authority"], "not_held");
    assert_eq!(protection("health")["network_policy"], "allowed");
    if report["landlock"]["kernel_abi"].as_u64().unwrap() >= 4 {
        assert_eq!(protection("connections")["network_policy"], "denied");
        assert_eq!(report["landlock"]["parser_check"]["tcp_connect"], "denied");
    }
}

/// A live daemon session, in this test's own process: the snapshot Settings
/// reads. The harness's main thread started before the session and never
/// enters, so it is the one thread the audit may name. Holding CAP_NET_RAW
/// takes a user and network namespace, so this skips where it cannot make one.
#[test]
fn live_snapshot_reports_capture_authority_and_tasks_holding_net_raw() {
    use netwatch::runtime::{bootstrap, capabilities::CapabilitySnapshot};
    use netwatch::{app::App, config::NetwatchConfig, sandbox::Mode};
    const CHILD: &str = "NETWATCH_DOCTOR_LIVE_TEST";
    if std::env::var_os(CHILD).is_none() {
        let fixture = Fixture::new();
        let exe = std::env::current_exe().unwrap();
        let mut command = in_namespace(
            &fixture,
            r#"ip link set lo up && exec "$0" --exact live_snapshot_reports_capture_authority_and_tasks_holding_net_raw --nocapture"#,
            exe.as_os_str(),
        );
        command.env(CHILD, "1");
        if !namespace_with_loopback() {
            eprintln!("skipped: no user and network namespace with lo up");
            return;
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let config = NetwatchConfig {
        capture_interface: "lo".into(),
        ..Default::default()
    };
    let mut app = App::prepare_with_config(config);
    bootstrap::start(&mut app, bootstrap::SessionKind::Daemon, Mode::BestEffort).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !app.packet_collector.is_capturing() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        app.packet_collector.is_capturing(),
        "{:?}",
        app.packet_collector.get_error()
    );
    let snapshot = CapabilitySnapshot::live(&app);
    assert_eq!(snapshot.scope, "runtime");
    assert!(!snapshot.network_restricted);

    let tasks = snapshot.tasks_holding_net_raw.as_ref().unwrap();
    let process = std::process::id();
    assert!(
        tasks.iter().all(|task| task.tid == process),
        "only the harness's main thread may hold CAP_NET_RAW: {tasks:?}"
    );
    let protection = |name: &str| {
        snapshot
            .protections
            .iter()
            .find(|p| p.component == name)
            .unwrap_or_else(|| panic!("no {name}: {:?}", snapshot.protections))
    };
    let landlock = snapshot.landlock.as_ref().unwrap();
    let main = protection("main");
    assert_eq!(main.network_policy, "allowed");
    assert_eq!(main.capture_authority, "dropped");
    assert_eq!(main.landlock_kernel_abi, landlock.kernel_abi);
    assert!(main.landlock_abi <= 3, "{main:?}");
    let capture = protection("capture");
    assert_eq!(capture.capture_authority, "dropped");
    assert_eq!(capture.socket_filter, "installed");
    // A parser without the no-socket filter, and a network worker. The workers
    // a tick starts have not started yet.
    let preflight = protection("policy-preflight");
    assert_eq!(preflight.socket_filter, "not_applicable");
    let network = protection("reverse-dns");
    assert_eq!(network.network_policy, "allowed");
    assert!(network.landlock_abi <= 3, "{network:?}");
    if landlock.kernel_abi >= 4 {
        for parser in [capture, preflight] {
            assert_eq!(parser.network_policy, "denied", "{parser:?}");
            assert!(parser.landlock_abi >= 4, "{parser:?}");
        }
        let check = landlock.parser_check.as_ref().unwrap();
        assert_eq!(
            (check.tcp_bind.as_str(), check.tcp_connect.as_str()),
            ("denied", "denied")
        );
        assert_eq!(snapshot.get("landlock").reason, "parser_network_denied");
        let detail = &snapshot.get("sandbox").detail;
        // Every parser and capture worker that has entered, which by now is all
        // of them, and at least the two checked above.
        let (denied, parsers) = detail
            .split_once("TCP denied on ")
            .and_then(|(_, rest)| rest.split_once(" parser workers"))
            .and_then(|(count, _)| count.split_once('/'))
            .unwrap_or_else(|| panic!("{detail}"));
        assert_eq!(denied, parsers, "{detail}");
        assert!(parsers.parse::<u32>().unwrap() >= 2, "{detail}");
        println!("{detail}");
        assert!(detail.contains("CAP_NET_RAW dropped"), "{detail}");
        assert!(
            detail.contains("running as root: containment limited"),
            "{detail}"
        );
    }
    app.packet_collector.stop_capture();
}
