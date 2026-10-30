//! Capture authority and the sandbox, measured on the threads of real sessions.
//!
//! Skips unless `NETWATCH_CAP_LAB=1`, because it needs to be root in a user and
//! network namespace, with a veth pair it creates there:
//!
//! ```text
//! cargo test --test capture_authority --no-run
//! NETWATCH_CAP_LAB=1 unshare --user --map-root-user --net <that binary>
//! ```
//!
//! `.github/workflows/sandbox-lab.yml` runs it. Each case gets a process of its
//! own: worker policy is process-wide and cannot be removed, and this has no test
//! harness because a harness's main thread never enters and would be in every
//! audit. The parent keeps its capabilities and sends frames both ways on the pair
//! throughout.
//!
//! - (a) A daemon session on v0: frames sent on v1 arrive, no thread holds
//!   CAP_NET_RAW or CAP_NET_ADMIN, and a second capture start is refused.
//! - (b) A strict TUI session: the same, with the proc broker in the audit.
//! - (c) A best-effort TUI session: main keeps CAP_NET_RAW, capture reopens on v1,
//!   and the live capture thread has dropped it and is denied TCP connect.
//! - (d) Confined workers hold nothing on the deny-list, and the broker only what
//!   its scan needs.
//! - (e) Capture, keylog and the metrics threads get EPERM from socket(2), while
//!   metrics still answers a scrape and a parser without the filter keeps sockets.
//!
//! What a user namespace cannot show: `/proc/kcore` is checked against capabilities
//! in the initial namespace, so that one stays a manual `sudo` acceptance step.
#![allow(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // What cargo nextest asks of any test binary. One test, which is the lab.
    if args.iter().any(|arg| arg == "--list") {
        if !args.iter().any(|arg| arg == "--ignored") {
            println!("capture_authority: test");
        }
        return;
    }
    #[cfg(target_os = "linux")]
    lab::main();
    #[cfg(not(target_os = "linux"))]
    println!("skipped: the capture authority lab is Linux only");
}

#[cfg(target_os = "linux")]
mod lab {
    use netwatch::app::App;
    use netwatch::config::NetwatchConfig;
    use netwatch::runtime::bootstrap::{self, SessionKind};
    use netwatch::sandbox::{worker, Mode, SocketFilter};
    use nix::libc;
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const CASE: &str = "NETWATCH_CAP_LAB_CASE";
    /// A child's exit status when its case does not apply on this kernel.
    const SKIPPED: i32 = 77;
    const CASES: [(&str, &str); 5] = [
        ("a", "daemon session"),
        ("b", "strict TUI session"),
        ("c", "TUI best-effort reopen"),
        ("d", "confined workers and broker"),
        ("e", "no-socket workers"),
    ];
    /// The UDP destination port of the frames sent out of each end, so a capture
    /// can tell a frame that crossed the pair from its own transmission.
    const SENT_ON_V1: u16 = 40001;
    const SENT_ON_V0: u16 = 40002;
    const NET_ADMIN: u64 = 1 << 12;
    const NET_RAW: u64 = 1 << 13;

    pub fn main() {
        if let Ok(case) = std::env::var(CASE) {
            child(&case);
            // Workers are still running, and nothing here waits for them.
            std::process::exit(0);
        }
        if std::env::var("NETWATCH_CAP_LAB").as_deref() != Ok("1") {
            println!(
                "skipped: set NETWATCH_CAP_LAB=1 and run under \
                 unshare --user --map-root-user --net"
            );
            return;
        }
        std::process::exit(parent());
    }

    fn ip(args: &[&str]) -> Result<(), String> {
        let status = Command::new("ip").args(args).status();
        match status {
            Ok(status) if status.success() => Ok(()),
            other => Err(format!("ip {}: {other:?}", args.join(" "))),
        }
    }

    fn parent() -> i32 {
        let pair = [
            &["link", "set", "lo", "up"][..],
            &["link", "add", "v0", "type", "veth", "peer", "name", "v1"],
            &["link", "set", "v0", "up"],
            &["link", "set", "v1", "up"],
        ]
        .iter()
        .try_for_each(|args| ip(args));
        if let Err(error) = pair {
            eprintln!(
                "capture authority lab: no veth pair, so nothing ran ({error}). \
                 Run it under unshare --user --map-root-user --net."
            );
            return 1;
        }
        let from_v1 = (packet_socket("v1"), frame(1, SENT_ON_V1));
        let from_v0 = (packet_socket("v0"), frame(0, SENT_ON_V0));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_sending = Arc::clone(&stop);
        let sender = std::thread::spawn(move || {
            while !stop_sending.load(Ordering::Relaxed) {
                for (socket, frame) in [&from_v1, &from_v0] {
                    // SAFETY: send reads `frame.len()` bytes of `frame`, alive
                    // until it returns.
                    unsafe {
                        libc::send(socket.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0)
                    };
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });

        let root = std::env::temp_dir().join(format!("netwatch-cap-lab-{}", uuid::Uuid::new_v4()));
        let (mut passed, mut failed, mut skipped) = (0, 0, 0);
        for (case, title) in CASES {
            let result = run_case(case, &root.join(case));
            let (verdict, output) = match result {
                Ok((0, output)) => {
                    passed += 1;
                    ("pass", output)
                }
                Ok((SKIPPED, output)) => {
                    skipped += 1;
                    ("skipped", output)
                }
                Ok((_, output)) => {
                    failed += 1;
                    ("FAIL", output)
                }
                Err(output) => {
                    failed += 1;
                    ("FAIL", output)
                }
            };
            println!("case ({case}) {title}: {verdict}");
            for line in output.lines() {
                println!("    {line}");
            }
        }
        stop.store(true, Ordering::Relaxed);
        let _ = sender.join();
        let _ = std::fs::remove_dir_all(&root);
        println!("capture authority lab: {passed} passed, {failed} failed, {skipped} skipped");
        i32::from(failed > 0)
    }

    /// Run one case in a child, with a home of its own. Its exit status and what
    /// it printed, or what was printed before it hung.
    fn run_case(case: &str, home: &std::path::Path) -> Result<(i32, String), String> {
        std::fs::create_dir_all(home).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .env(CASE, case)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("XDG_STATE_HOME", home.join("state"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let timed_out = loop {
            if child.try_wait().unwrap().is_some() {
                break false;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                break true;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let output = child.wait_with_output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if timed_out {
            return Err(format!("{text}timed out after 60 s"));
        }
        // A signal counts as a failure, and so does anything without a status.
        Ok((output.status.code().unwrap_or(1), text))
    }

    /// An AF_PACKET socket that sends out of `interface`. Taken from the parent,
    /// which keeps CAP_NET_RAW for the whole run.
    fn packet_socket(interface: &str) -> OwnedFd {
        let name = CString::new(interface).unwrap();
        // SAFETY: if_nametoindex reads the C string, alive until it returns.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        assert_ne!(index, 0, "no {interface}");
        // SAFETY: socket takes three integers and reads no memory of ours.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        // SAFETY: socket just returned this descriptor and nothing else owns it.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: an all-zero sockaddr_ll is valid: it has no pointers.
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_ifindex = index as i32;
        // SAFETY: bind reads `address`, whose size is the length it is given.
        let bound = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        assert_eq!(bound, 0, "{}", std::io::Error::last_os_error());
        socket
    }

    /// A broadcast UDP datagram, so no address or promiscuous mode is needed.
    fn frame(sender: u8, port: u16) -> Vec<u8> {
        let payload = b"netwatch capture authority lab";
        let udp_len = (8 + payload.len()) as u16;
        let ip_len = 20 + udp_len;
        let mut ip = vec![0x45, 0];
        ip.extend(ip_len.to_be_bytes());
        ip.extend([
            0,
            0,
            0x40,
            0,
            64,
            17,
            0,
            0,
            10,
            39,
            0,
            sender + 1,
            255,
            255,
            255,
            255,
        ]);
        let sum: u32 = ip
            .chunks(2)
            .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
            .sum();
        let checksum = !((sum & 0xffff) + (sum >> 16)) as u16;
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());

        let mut out = vec![0xff; 6];
        out.extend([2, 0, 0, 0, 0x39, sender]);
        out.extend(0x0800u16.to_be_bytes());
        out.extend(ip);
        out.extend(port.to_be_bytes());
        out.extend(port.to_be_bytes());
        out.extend(udp_len.to_be_bytes());
        out.extend([0, 0]);
        out.extend(payload);
        out
    }

    fn child(case: &str) {
        match case {
            "a" => daemon_session(),
            "b" => strict_tui_session(),
            "c" => tui_reopen(),
            "d" => confined_workers(),
            "e" => no_socket_workers(),
            other => panic!("no case {other}"),
        }
    }

    fn skip(reason: &str) -> ! {
        println!("{reason}");
        std::process::exit(SKIPPED);
    }

    fn session(kind: SessionKind, mode: Mode) -> App {
        let mut app = App::prepare_with_config(NetwatchConfig {
            capture_interface: "v0".into(),
            ..Default::default()
        });
        bootstrap::start(&mut app, kind, mode).expect("the session starts");
        bootstrap::prime_collectors(&mut app);
        app.tick();
        app
    }

    fn wait_for(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            if done() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Whether a frame sent to `port` has been captured on `interface`. A frame
    /// from before a restart was on another interface, so it does not count.
    fn captured(app: &App, interface: &str, port: u16) -> bool {
        app.packet_collector.get_packets().iter().any(|packet| {
            packet.dst_port == Some(port)
                && packet
                    .capture
                    .as_ref()
                    .is_some_and(|meta| &*meta.interface == interface)
        })
    }

    fn frames_arrive(app: &App, interface: &str, port: u16) {
        let started = Instant::now();
        assert!(
            wait_for(Duration::from_secs(3), || captured(app, interface, port)),
            "no frame for port {port} on {interface} in 3 s; capturing {}, error {:?}",
            app.packet_collector.is_capturing(),
            app.packet_collector.get_error()
        );
        println!(
            "frame sent to port {port} captured on {interface} after {:?}",
            started.elapsed()
        );
    }

    /// One line of `/proc/<pid>/task/<tid>/status`'s capability sets.
    #[derive(Debug)]
    struct Task {
        tid: u32,
        comm: String,
        permitted: u64,
        effective: u64,
        inheritable: u64,
        ambient: u64,
    }

    impl Task {
        fn holds(&self, bits: u64) -> bool {
            (self.permitted | self.effective | self.inheritable | self.ambient) & bits != 0
        }
    }

    fn tasks() -> Vec<Task> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir("/proc/self/task").unwrap() {
            let entry = entry.unwrap();
            let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
                continue; // It ended between the listing and the read.
            };
            let field = |name: &str| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
                    .map(str::trim)
                    .unwrap_or_else(|| panic!("no {name} in {status}"))
            };
            let set = |name: &str| u64::from_str_radix(field(name), 16).unwrap();
            out.push(Task {
                tid: entry.file_name().to_str().unwrap().parse().unwrap(),
                comm: field("Name").to_string(),
                permitted: set("CapPrm"),
                effective: set("CapEff"),
                inheritable: set("CapInh"),
                ambient: set("CapAmb"),
            });
        }
        out
    }

    fn task_named(comm: &str) -> Option<Task> {
        tasks().into_iter().find(|task| task.comm == comm)
    }

    /// The kernel cuts thread names to 15 bytes.
    const BROKER: &str = "netwatch-proc-b";

    fn no_thread_holds_net_caps() {
        let all = tasks();
        let holders: Vec<_> = all
            .iter()
            .filter(|task| task.holds(NET_RAW | NET_ADMIN))
            .collect();
        assert!(holders.is_empty(), "{holders:#?}");
        println!(
            "0 of {} tasks hold CAP_NET_RAW or CAP_NET_ADMIN in any set",
            all.len()
        );
    }

    fn second_start_is_refused(app: &mut App) {
        app.packet_collector.stop_capture();
        app.packet_collector.start_capture("v0", None);
        let refused = wait_for(Duration::from_secs(3), || {
            app.packet_collector
                .get_error()
                .is_some_and(|error| error.contains("not permitted"))
        });
        let error = app.packet_collector.get_error();
        assert!(refused, "the second capture start got {error:?}");
        println!("second start_capture: {}", error.unwrap_or_default());
    }

    fn daemon_session() {
        let mut app = session(SessionKind::Daemon, Mode::BestEffort);
        frames_arrive(&app, "v0", SENT_ON_V1);
        no_thread_holds_net_caps();
        second_start_is_refused(&mut app);
    }

    fn kernel_abi() -> u32 {
        netwatch::runtime::capabilities::inspect_static(None)
            .landlock
            .map_or(0, |landlock| landlock.kernel_abi)
    }

    fn strict_tui_session() {
        let abi = kernel_abi();
        if abi < 4 {
            skip(&format!(
                "kernel Landlock ABI {abi}: strict refuses to start below 4"
            ));
        }
        let mut app = session(SessionKind::Tui, Mode::Strict);
        frames_arrive(&app, "v0", SENT_ON_V1);
        assert!(
            task_named(BROKER).is_some(),
            "the proc broker is not in the audit: {:#?}",
            tasks()
        );
        no_thread_holds_net_caps();
        second_start_is_refused(&mut app);
    }

    fn tui_reopen() {
        let mut app = session(SessionKind::Tui, Mode::BestEffort);
        frames_arrive(&app, "v0", SENT_ON_V1);
        let all = tasks();
        let process = std::process::id();
        let main = all.iter().find(|task| task.tid == process).unwrap();
        assert_ne!(main.permitted & NET_RAW, 0, "{main:?}");
        assert_ne!(main.effective & NET_RAW, 0, "{main:?}");
        let admin: Vec<_> = all.iter().filter(|task| task.holds(NET_ADMIN)).collect();
        assert!(admin.is_empty(), "{admin:#?}");
        println!(
            "main keeps CAP_NET_RAW; CAP_NET_ADMIN clear on all {} tasks",
            all.len()
        );

        app.packet_collector.stop_capture();
        app.packet_collector.start_capture("v1", None);
        frames_arrive(&app, "v1", SENT_ON_V0);

        let capture = task_named("capture").expect("the reopened capture thread is running");
        assert!(!capture.holds(NET_RAW | NET_ADMIN), "{capture:?}");
        println!("live capture thread {} holds no CAP_NET_RAW", capture.tid);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let probed = Probe::on(capture.tid, Some(listener.local_addr().unwrap()));
        assert_eq!(probed.sockets, [libc::EPERM; 3], "socket(2) on capture");
        if kernel_abi() < 4 {
            println!("TCP connect not checked: kernel Landlock ABI below 4");
        } else {
            assert_eq!(probed.connect, libc::EACCES, "TCP connect on capture");
            println!("TCP connect on an open socket from capture: EACCES");
        }
    }

    /// Every name on the threat model's `default:` row, which a test holds to the
    /// drop list in the code, as a mask.
    fn deny_list() -> u64 {
        let doc = include_str!("../docs/THREAT-MODEL.md");
        let row = doc
            .lines()
            .find_map(|line| line.strip_prefix("default: "))
            .expect("the threat model's policy:caps block has a default row");
        row.split(", ")
            .map(|name| {
                let cap: caps::Capability = name.parse().unwrap();
                1u64 << cap.index()
            })
            .sum()
    }

    fn confined_workers() {
        let _app = session(SessionKind::Tui, Mode::BestEffort);
        let deny = deny_list();
        assert!(deny.count_ones() >= 31, "{deny:#x}");
        let confined = || -> Vec<Task> {
            tasks()
                .into_iter()
                .filter(|task| task.comm != BROKER)
                .collect()
        };
        // The eBPF worker holds its load capabilities until its load has failed
        // or finished, which here it has to fail: bpf(2) checks the initial
        // namespace.
        wait_for(Duration::from_secs(5), || {
            confined().iter().all(|task| task.effective & deny == 0)
        });
        let all = confined();
        let holding: Vec<_> = all
            .iter()
            .filter(|task| task.holds(deny))
            .map(|task| format!("{} {:#x}", task.comm, task.effective & deny))
            .collect();
        assert!(holding.is_empty(), "{holding:#?}");
        println!(
            "{} confined tasks: none holds any of the {} capabilities on the deny-list",
            all.len(),
            deny.count_ones()
        );
        let broker = task_named(BROKER).expect("the proc broker is running");
        let keep = (1u64 << caps::Capability::CAP_SYS_PTRACE.index())
            | (1u64 << caps::Capability::CAP_DAC_READ_SEARCH.index());
        assert_eq!(broker.permitted, keep, "{broker:?}");
        assert_eq!(broker.effective, keep, "{broker:?}");
        assert_eq!(broker.inheritable, 0, "{broker:?}");
        assert_eq!(broker.ambient, 0, "{broker:?}");
        println!("broker holds only CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH");
    }

    fn no_socket_workers() {
        let mut app = session(SessionKind::Daemon, Mode::BestEffort);
        frames_arrive(&app, "v0", SENT_ON_V1);
        let filter = worker::snapshot()["capture"]
            .report
            .as_ref()
            .map(|report| report.platform.socket_filter);
        if filter == Some(SocketFilter::UnknownArch) {
            skip("this build's architecture has no syscall table for the filter");
        }
        assert_eq!(filter, Some(SocketFilter::Installed));

        // The watcher waits for a file that is not there yet, and that is enough
        // to have its thread.
        let home = std::env::var("HOME").unwrap();
        let keylog = std::path::Path::new(&home).join("keylog");
        app.packet_collector.configure_tls_keylog(Some(keylog));

        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let exporter = netwatch::metrics::MetricsExporter::new(format!("127.0.0.1:{port}"));
        exporter.start();
        // A client that says nothing keeps a real metrics-client thread waiting,
        // started the way the listener starts them.
        let waiting = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();

        for name in ["capture", "keylog", "metrics-listener", "metrics-client"] {
            let mut comm = name.to_string();
            comm.truncate(15);
            assert!(
                wait_for(Duration::from_secs(3), || task_named(&comm).is_some()),
                "no {comm} thread: {:#?}",
                tasks()
            );
            let task = task_named(&comm).unwrap();
            let probed = Probe::on(task.tid, None);
            assert_eq!(probed.sockets, [libc::EPERM; 3], "{name}");
            println!("{name}: socket(2) gets EPERM for UDP, MPTCP and netlink");
        }
        drop(waiting);

        let mut scrape = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        scrape.write_all(b"GET /metrics HTTP/1.1\r\n\r\n").unwrap();
        let mut response = String::new();
        scrape.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        println!("a scrape of the sandboxed metrics threads returns 200");

        // A parser without the filter: what connections, tcp-info and traffic
        // need so that `ss`, `ip` and `iw` work.
        let (tx, rx) = std::sync::mpsc::channel();
        worker::spawn("connections", move || {
            tx.send(socket_errnos()).unwrap();
        })
        .join()
        .unwrap();
        let [udp, _, netlink] = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((udp, netlink), (0, 0), "a parser without the filter");
        println!("connections worker: UDP and netlink sockets still open");
    }

    /// The errno of socket(2) on the calling thread for UDP, MPTCP and netlink,
    /// 0 for one that opened. Async-signal-safe: the signal handler calls it.
    fn socket_errnos() -> [i32; 3] {
        [
            (libc::AF_INET, libc::SOCK_DGRAM, 0),
            (libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_MPTCP),
            (libc::AF_NETLINK, libc::SOCK_RAW, 0),
        ]
        .map(|(domain, kind, protocol)| {
            // SAFETY: socket takes three integers and reads no memory of ours.
            let fd = unsafe { libc::socket(domain, kind, protocol) };
            if fd < 0 {
                // SAFETY: errno's location is valid for the thread's lifetime.
                return unsafe { *libc::__errno_location() };
            }
            // SAFETY: socket just returned this descriptor and nothing else
            // owns it.
            unsafe { libc::close(fd) };
            0
        })
    }

    /// What one thread got back from the handler below.
    struct Probe {
        sockets: [i32; 3],
        connect: i32,
    }

    static PROBE_DONE: AtomicBool = AtomicBool::new(false);
    static PROBE_SOCKETS: [AtomicI32; 3] =
        [AtomicI32::new(0), AtomicI32::new(0), AtomicI32::new(0)];
    /// A TCP socket main opened, for the thread to connect. -1 for none.
    static PROBE_FD: AtomicI32 = AtomicI32::new(-1);
    static PROBE_PORT: AtomicI32 = AtomicI32::new(0);
    static PROBE_CONNECT: AtomicI32 = AtomicI32::new(0);

    /// Runs on the signalled thread, so with its Landlock domain, its seccomp
    /// filter and its capabilities. That is how this looks inside a worker that
    /// has no test hook, the live capture thread among them, without adding one
    /// to the release code. Only async-signal-safe calls, and errno is put back.
    extern "C" fn probe_handler(_signal: libc::c_int) {
        // SAFETY: errno's location is valid for the thread's lifetime.
        let saved = unsafe { *libc::__errno_location() };
        for (slot, errno) in PROBE_SOCKETS.iter().zip(socket_errnos()) {
            slot.store(errno, Ordering::SeqCst);
        }
        let fd = PROBE_FD.load(Ordering::SeqCst);
        if fd >= 0 {
            let address = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: (PROBE_PORT.load(Ordering::SeqCst) as u16).to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: connect reads `address`, whose size is the length it is
            // given, and `fd` stays open until the sender has seen PROBE_DONE.
            let connected = unsafe {
                libc::connect(
                    fd,
                    (&address as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            // SAFETY: errno's location is valid for the thread's lifetime.
            let errno = if connected == 0 {
                0
            } else {
                unsafe { *libc::__errno_location() }
            };
            PROBE_CONNECT.store(errno, Ordering::SeqCst);
        }
        // SAFETY: as above, and this thread owns its errno.
        unsafe { *libc::__errno_location() = saved };
        PROBE_DONE.store(true, Ordering::SeqCst);
    }

    impl Probe {
        /// Run the handler on thread `tid`. With `connect`, it also connects a
        /// TCP socket this thread opened to that address. One probe at a time.
        fn on(tid: u32, connect: Option<std::net::SocketAddr>) -> Self {
            // SAFETY: an all-zero sigaction is valid before its fields are set.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = probe_handler as *const () as usize;
            action.sa_flags = libc::SA_RESTART;
            // SAFETY: sigaction reads `action`, alive until it returns, and the
            // handler lives for the whole process.
            let installed =
                unsafe { libc::sigaction(libc::SIGUSR2, &action, std::ptr::null_mut()) };
            assert_eq!(installed, 0, "{}", std::io::Error::last_os_error());

            let socket = connect.map(|address| {
                PROBE_PORT.store(i32::from(address.port()), Ordering::SeqCst);
                // SAFETY: socket takes three integers and reads no memory of ours.
                let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
                assert!(fd >= 0, "{}", std::io::Error::last_os_error());
                // SAFETY: socket just returned this descriptor and nothing else
                // owns it.
                unsafe { OwnedFd::from_raw_fd(fd) }
            });
            PROBE_FD.store(
                socket.as_ref().map_or(-1, |fd| fd.as_raw_fd()),
                Ordering::SeqCst,
            );
            PROBE_DONE.store(false, Ordering::SeqCst);
            // SAFETY: tgkill takes three integers and reads no memory of ours.
            let sent = unsafe {
                libc::syscall(
                    libc::SYS_tgkill,
                    std::process::id() as libc::c_int,
                    tid as libc::c_int,
                    libc::SIGUSR2,
                )
            };
            assert_eq!(sent, 0, "{}", std::io::Error::last_os_error());
            assert!(
                wait_for(Duration::from_secs(5), || PROBE_DONE.load(Ordering::SeqCst)),
                "thread {tid} did not run the probe"
            );
            drop(socket);
            Self {
                sockets: [0, 1, 2].map(|at| PROBE_SOCKETS[at].load(Ordering::SeqCst)),
                connect: PROBE_CONNECT.load(Ordering::SeqCst),
            }
        }
    }
}
