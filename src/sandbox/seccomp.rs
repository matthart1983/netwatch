//! The no-socket filter: a classic-BPF seccomp program for the workers
//! [`roles::no_sockets`](super::roles::no_sockets) names.
//!
//! Landlock mediates connect(2) and bind(2) on TCP sockets and nothing else,
//! so a parser thread can still open a UDP, netlink or ping socket, and an
//! MPTCP one that falls back to TCP. These workers never open a socket after
//! entry, so socket(2) returns EPERM for them, and socketcall(2) where the
//! architecture has it. So does io_uring_setup(2), because `IORING_OP_SOCKET`
//! makes a socket with no socket(2) for a filter to see, and nothing in netwatch
//! uses a ring. Every other syscall is allowed: this is not an allow-list, and it
//! does nothing about a descriptor opened earlier, a ring's included
//! (docs/THREAT-MODEL.md, items 4 and 6).
//!
//! A syscall made through another architecture's table would skip the socket
//! check, because the same number means something else there, so one of those
//! kills the process. So does an x32 syscall on x86_64, which arrives under
//! the native AUDIT_ARCH with a high bit set on its number.
//!
//! The filter goes on the calling thread after its Landlock layers and is
//! inherited by whatever that thread starts. It cannot be removed. Every row
//! of the table compiles on every architecture, so the tests here run the arm
//! and aarch64 programs on an x86_64 host. A build with no row skips the filter
//! and says so in the report.
#![allow(unsafe_code)]

use super::{Report, SocketFilter};
use nix::libc;

/// The numbers the filter needs on one architecture, from the kernel's
/// `include/uapi/linux/audit.h` and syscall tables.
struct Arch {
    /// `std::env::consts::ARCH` of a build this row is for.
    name: &'static str,
    /// AUDIT_ARCH_*: the ELF machine, with bit 31 for 64-bit and bit 30 for
    /// little-endian.
    audit: u32,
    socket: u32,
    socketcall: Option<u32>,
    io_uring_setup: u32,
    /// Whether syscall numbers with [`X32_SYSCALL_BIT`] set are the x32 ABI's.
    x32: bool,
}

const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const TABLE: [Arch; 3] = [
    Arch {
        name: "x86_64",
        audit: 0xc000_003e,
        socket: 41,
        socketcall: None,
        io_uring_setup: 425,
        x32: true,
    },
    Arch {
        name: "aarch64",
        audit: 0xc000_00b7,
        socket: 198,
        socketcall: None,
        io_uring_setup: 425,
        x32: false,
    },
    // armv5te, EABI. socketcall is in the kernel's OABI table only, but a
    // kernel built with CONFIG_OABI_COMPAT takes an OABI call from any process
    // and reports it under this same AUDIT_ARCH.
    Arch {
        name: "arm",
        audit: 0x4000_0028,
        socket: 281,
        socketcall: Some(102),
        io_uring_setup: 425,
        x32: false,
    },
];

/// The row for this build. Big-endian ARM reports another AUDIT_ARCH, and the
/// x32 ABI sets [`X32_SYSCALL_BIT`] on its own syscalls. With either, the
/// filter would kill the process on its first syscall, so neither has a row.
fn native() -> Option<&'static Arch> {
    let x32 = cfg!(target_arch = "x86_64") && cfg!(target_pointer_width = "32");
    if cfg!(target_endian = "big") || x32 {
        return None;
    }
    TABLE
        .iter()
        .find(|arch| arch.name == std::env::consts::ARCH)
}

/// The filter for `arch`. Every jump skips at most one instruction, so each
/// test reads as "if this, then the next line".
fn program(arch: &Arch) -> Vec<libc::sock_filter> {
    const LOAD: u32 = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    const IF_EQUAL: u32 = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
    const IF_AT_LEAST: u32 = libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K;
    const RETURN: u32 = libc::BPF_RET | libc::BPF_K;
    const ARCH: u32 = std::mem::offset_of!(libc::seccomp_data, arch) as u32;
    const NUMBER: u32 = std::mem::offset_of!(libc::seccomp_data, nr) as u32;
    let op = |code: u32, jt: u8, jf: u8, k: u32| libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    let kill = op(RETURN, 0, 0, libc::SECCOMP_RET_KILL_PROCESS);
    let eperm = op(RETURN, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32);

    let mut filter = vec![
        op(LOAD, 0, 0, ARCH),
        op(IF_EQUAL, 1, 0, arch.audit),
        kill,
        op(LOAD, 0, 0, NUMBER),
    ];
    if arch.x32 {
        filter.extend([op(IF_AT_LEAST, 0, 1, X32_SYSCALL_BIT), kill]);
    }
    for number in [arch.socket, arch.io_uring_setup]
        .into_iter()
        .chain(arch.socketcall)
    {
        filter.extend([op(IF_EQUAL, 0, 1, number), eperm]);
    }
    filter.push(op(RETURN, 0, 0, libc::SECCOMP_RET_ALLOW));
    filter
}

/// Load `filter` on the calling thread.
fn load(filter: &mut [libc::sock_filter]) -> std::io::Result<()> {
    let (zero, one): (libc::c_ulong, libc::c_ulong) = (0, 1);
    // SAFETY: prctl reads four arguments after the option, each passed as the
    // unsigned long the kernel takes, and PR_SET_NO_NEW_PRIVS fails unless the
    // last three are zero. It reads no memory of ours. A failed Landlock entry
    // can leave this unset, and without it the next call needs CAP_SYS_ADMIN.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero, zero, zero) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let program = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_mut_ptr(),
    };
    let mode = libc::SECCOMP_MODE_FILTER as libc::c_ulong;
    // SAFETY: PR_SET_SECCOMP reads `program` and the `filter` it points to,
    // both alive until it returns, and copies them into the kernel.
    let installed = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            mode,
            &program as *const libc::sock_fprog,
            zero,
            zero,
        )
    };
    if installed != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Install the filter on the calling thread and record the outcome in
/// `report`. A failure on a supported architecture is a warning, so strict
/// refuses the entry. A build with no row is not: strict cannot ask for what
/// the build has no table for.
pub(super) fn install(report: &mut Report) {
    install_for(native(), report);
}

fn install_for(arch: Option<&Arch>, report: &mut Report) {
    let Some(arch) = arch else {
        report.platform.socket_filter = SocketFilter::UnknownArch;
        static LOGGED: std::sync::Once = std::sync::Once::new();
        LOGGED.call_once(|| {
            tracing::warn!(
                target: "netwatch::sandbox",
                arch = std::env::consts::ARCH,
                "no-socket filter skipped: no syscall table for this architecture"
            );
        });
        return;
    };
    match load(&mut program(arch)) {
        Ok(()) => {
            report.platform.socket_filter = SocketFilter::Installed;
            report.platform.landlock_restrictions.push("socket_create");
        }
        Err(error) => {
            report.platform.socket_filter = SocketFilter::Failed;
            report
                .mode
                .warnings
                .push(format!("no-socket filter not installed: {error}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn row(name: &str) -> &'static Arch {
        TABLE.iter().find(|arch| arch.name == name).unwrap()
    }

    /// What the kernel would do with `filter` for syscall `number` under
    /// `audit`. Installing a program for another architecture would kill the
    /// test, so the other rows are run here.
    fn run(filter: &[libc::sock_filter], audit: u32, number: u32) -> u32 {
        let mut accumulator = 0;
        let mut at = 0;
        loop {
            let insn = filter[at];
            at += 1;
            let code = u32::from(insn.code);
            if code == libc::BPF_LD | libc::BPF_W | libc::BPF_ABS {
                accumulator = match insn.k {
                    0 => number,
                    4 => audit,
                    k => panic!("load at {k}"),
                };
            } else if code == libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K {
                let taken = accumulator == insn.k;
                at += usize::from(if taken { insn.jt } else { insn.jf });
            } else if code == libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K {
                let taken = accumulator >= insn.k;
                at += usize::from(if taken { insn.jt } else { insn.jf });
            } else if code == libc::BPF_RET | libc::BPF_K {
                return insn.k;
            } else {
                panic!("unexpected instruction {code:#x}");
            }
        }
    }

    const KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;
    const EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;

    #[test]
    fn every_row_denies_socket_and_allows_the_rest() {
        for (name, audit, socket, read) in [
            ("x86_64", 0xc000_003e, 41, 0),
            ("aarch64", 0xc000_00b7, 198, 63),
            ("arm", 0x4000_0028, 281, 3),
        ] {
            let filter = program(row(name));
            assert_eq!(run(&filter, audit, socket), EPERM, "{name}");
            assert_eq!(run(&filter, audit, 425), EPERM, "{name} io_uring_setup");
            assert_eq!(run(&filter, audit, read), ALLOW, "{name}");
            // io_uring_enter and io_uring_register need a ring, and only one
            // opened before the filter can be there to use them.
            assert_eq!(run(&filter, audit, 426), ALLOW, "{name} io_uring_enter");
            assert_eq!(run(&filter, audit, 427), ALLOW, "{name} io_uring_register");
            // accept4 is how a metrics listener takes its connections.
            let accept4 = if name == "x86_64" { 288 } else { 242 };
            assert_eq!(run(&filter, audit, accept4), ALLOW, "{name}");
            // Every other architecture's syscalls die, whatever their number.
            for other in [0x4000_0003, 0x4000_0028, 0xc000_0028, 0xc000_00b7] {
                if other != audit {
                    assert_eq!(run(&filter, other, socket), KILL, "{name} {other:#x}");
                    assert_eq!(run(&filter, other, 425), KILL, "{name} {other:#x}");
                }
            }
        }
    }

    #[test]
    fn socketcall_is_denied_only_on_arm() {
        let arm = program(row("arm"));
        assert_eq!(run(&arm, 0x4000_0028, 102), EPERM);
        // 102 is getuid on x86_64 and an unrelated syscall on aarch64.
        assert_eq!(run(&program(row("x86_64")), 0xc000_003e, 102), ALLOW);
        assert_eq!(run(&program(row("aarch64")), 0xc000_00b7, 102), ALLOW);
    }

    #[test]
    fn x32_numbers_die_on_x86_64_only() {
        let x86_64 = program(row("x86_64"));
        assert_eq!(run(&x86_64, 0xc000_003e, X32_SYSCALL_BIT + 41), KILL);
        assert_eq!(run(&x86_64, 0xc000_003e, X32_SYSCALL_BIT - 1), ALLOW);
        let arm = program(row("arm"));
        assert_eq!(run(&arm, 0x4000_0028, X32_SYSCALL_BIT), ALLOW);
    }

    #[test]
    fn this_builds_row_matches_its_libc() {
        let Some(arch) = native() else {
            return;
        };
        assert_eq!(arch.socket as libc::c_long, libc::SYS_socket);
        assert_eq!(
            arch.io_uring_setup as libc::c_long,
            libc::SYS_io_uring_setup
        );
        assert_eq!(arch.name, std::env::consts::ARCH);
    }

    /// socket(2) on the calling thread: the errno, or `None` if it opened.
    fn socket_errno(domain: i32, kind: i32, protocol: i32) -> Option<i32> {
        // SAFETY: socket takes three integers and reads no memory of ours.
        let fd = unsafe { libc::socket(domain, kind, protocol) };
        if fd < 0 {
            return std::io::Error::last_os_error().raw_os_error();
        }
        // SAFETY: socket just returned this descriptor and nothing else owns it.
        drop(unsafe { OwnedFd::from_raw_fd(fd) });
        None
    }

    /// Run `body` on a thread with the filter on it. The filter dies with the
    /// thread.
    fn filtered<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::spawn(move || {
            let mut report = Report::default();
            install(&mut report);
            assert!(
                report.mode.warnings.is_empty(),
                "{:?}",
                report.mode.warnings
            );
            assert_eq!(report.platform.socket_filter, SocketFilter::Installed);
            assert_eq!(report.platform.landlock_restrictions, ["socket_create"]);
            body()
        })
        .join()
        .unwrap()
    }

    #[test]
    fn socket_returns_eperm_for_every_family_it_was_opened_with() {
        let udp = (libc::AF_INET, libc::SOCK_DGRAM, 0);
        let netlink = (libc::AF_NETLINK, libc::SOCK_RAW, 0);
        // The bypass that justifies the filter: MPTCP falls back to TCP, and
        // Landlock's TCP deny does not see it.
        let mptcp = (libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_MPTCP);
        let tcp = (libc::AF_INET, libc::SOCK_STREAM, 0);
        for (domain, kind, protocol) in [udp, netlink, tcp, mptcp] {
            assert_eq!(
                filtered(move || socket_errno(domain, kind, protocol)),
                Some(libc::EPERM),
                "{domain} {kind} {protocol}"
            );
        }
        // Only that thread. Its parent and its siblings keep socket(2).
        assert_eq!(socket_errno(libc::AF_INET, libc::SOCK_DGRAM, 0), None);
    }

    #[test]
    fn a_thread_started_from_a_filtered_one_inherits_it() {
        let errno = filtered(|| {
            std::thread::spawn(|| socket_errno(libc::AF_INET, libc::SOCK_DGRAM, 0))
                .join()
                .unwrap()
        });
        assert_eq!(errno, Some(libc::EPERM));
    }

    #[test]
    fn a_descriptor_opened_earlier_still_works() {
        // The gap the threat model names: the filter stops new sockets, and
        // threads share every descriptor the process already holds.
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = peer.local_addr().unwrap();
        let earlier = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        filtered(move || earlier.send_to(b"earlier", addr).unwrap());
        peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0; 16];
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"earlier");
    }

    #[test]
    fn accept_still_works() {
        // accept4 is not socket(2), which is how the metrics threads serve.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = std::net::TcpStream::connect(addr).unwrap();
        filtered(move || listener.accept().map(|_| ()).unwrap());
    }

    /// io_uring_setup(2) on the calling thread: the ring, or the errno.
    fn io_uring_setup() -> Result<OwnedFd, i32> {
        let mut params = [0u64; 15];
        // SAFETY: io_uring_setup reads and writes the 120-byte io_uring_params
        // it is given, which `params` is, alive throughout.
        let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 8, params.as_mut_ptr()) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        // SAFETY: the call just returned this descriptor and nothing else owns it.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    #[test]
    fn io_uring_setup_gets_eperm() {
        // IORING_OP_SOCKET makes a socket with no socket(2) for the filter to
        // see, so without a ring there is no such operation to submit.
        assert_eq!(filtered(|| io_uring_setup().map(drop)), Err(libc::EPERM));
    }

    #[test]
    fn a_ring_opened_earlier_still_works() {
        // The gap the threat model names: the filter stops new rings, and a ring
        // is one more descriptor threads share. Nothing in netwatch opens one,
        // which is what keeps this hypothetical. Hosts can turn io_uring off.
        let Ok(ring) = io_uring_setup() else {
            eprintln!("skipped: io_uring is off on this host");
            return;
        };
        let entered = filtered(move || {
            // SAFETY: with nothing to submit or wait for, and no signal mask,
            // io_uring_enter reads no memory of ours.
            let entered = unsafe {
                libc::syscall(
                    libc::SYS_io_uring_enter,
                    ring.as_raw_fd(),
                    0,
                    0,
                    0,
                    std::ptr::null::<libc::c_void>(),
                    0,
                )
            };
            (entered, std::io::Error::last_os_error().raw_os_error())
        });
        assert_eq!(entered.0, 0, "{entered:?}");
    }

    /// Frames of a classic little-endian pcap file, as tests/pcap_golden.rs
    /// reads them.
    fn frames(pcap: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut at = 24;
        while at < pcap.len() {
            let caplen = u32::from_le_bytes(pcap[at + 8..at + 12].try_into().unwrap()) as usize;
            out.push(&pcap[at + 16..at + 16 + caplen]);
            at += 16 + caplen;
        }
        out
    }

    #[test]
    fn replay_decodes_the_golden_fixtures_with_the_filter_on() {
        use crate::collectors::packets::Replay;
        let fixtures: [&[u8]; 3] = [
            include_bytes!("../../tests/fixtures/pcap/dns.pcap"),
            include_bytes!("../../tests/fixtures/pcap/http.pcap"),
            include_bytes!("../../tests/fixtures/pcap/quic.pcap"),
        ];
        let summary = |pcap: &'static [u8]| {
            let replay = Replay::new();
            frames(pcap)
                .into_iter()
                .map(|frame| {
                    replay
                        .frame(frame)
                        .map(|packet| (packet.protocol, packet.info))
                })
                .collect::<Vec<_>>()
        };
        for pcap in fixtures {
            let bytes: &'static [u8] = pcap;
            let open = summary(bytes);
            assert!(open.iter().any(Option::is_some));
            assert_eq!(filtered(move || summary(bytes)), open);
        }
    }

    #[test]
    fn unknown_arch_skips_and_reports() {
        std::thread::spawn(|| {
            let mut report = Report::default();
            install_for(None, &mut report);
            assert_eq!(report.platform.socket_filter, SocketFilter::UnknownArch);
            assert_eq!(report.platform.socket_filter.label(), "unknown_arch");
            // Strict refuses on any warning, and this is not one.
            assert!(report.mode.warnings.is_empty());
            assert!(report.platform.landlock_restrictions.is_empty());
            assert_eq!(socket_errno(libc::AF_INET, libc::SOCK_DGRAM, 0), None);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn a_filter_the_kernel_rejects_is_a_warning() {
        // An empty program is the shortest one the kernel refuses.
        std::thread::spawn(|| {
            let error = load(&mut []).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        })
        .join()
        .unwrap();
    }

    /// The real kernel path for the x32 guard: a process that makes an x32
    /// syscall dies by SIGSYS.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn an_x32_syscall_kills_the_process() {
        use std::os::unix::process::ExitStatusExt;
        const CHILD: &str = "NETWATCH_SECCOMP_X32_TEST";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "sandbox::seccomp::tests::an_x32_syscall_kills_the_process",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.signal(), Some(libc::SIGSYS));
            return;
        }
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit reads the rlimit it is given, alive until it
        // returns. Without a core limit this death would write a dump.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) }, 0);
        let mut report = Report::default();
        install(&mut report);
        assert_eq!(report.platform.socket_filter, SocketFilter::Installed);
        let x32_socket = libc::c_long::from(X32_SYSCALL_BIT as i32 + 41);
        // SAFETY: the filter ends the process before the kernel reads the
        // arguments, and without it this x32 socket(2) reads no memory.
        unsafe { libc::syscall(x32_socket, libc::AF_INET, libc::SOCK_DGRAM, 0) };
        // Reaching here exits 0 with no signal, which the parent rejects.
    }
}
