#![cfg(unix)]
//! `netwatch --demo` on a pty, asked to stop the ways a terminal session is
//! stopped. Each way must exit 0 and leave the pty as it was before netwatch
//! started: out of raw mode, off the alternate screen, mouse reporting off and
//! the cursor shown. Until 0.38.1 only `Ctrl+C` typed at the keyboard did;
//! SIGTERM, SIGINT and SIGHUP killed the process with the terminal still raw.
//! The last two tests take the terminal away or stop it reading, where the
//! pty cannot be put back; netwatch must still end, and not by crashing.
use nix::pty::{openpty, Winsize};
use nix::sys::signal::{kill, Signal};
use nix::sys::termios::{tcgetattr, LocalFlags, Termios};
use nix::unistd::Pid;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};
use std::{fs, thread};

const ENTER: &str = "\x1b[?1049h";

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("netwatch-tty-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(path.join("config/netwatch")).unwrap();
        fs::create_dir_all(path.join("cache/netwatch")).unwrap();
        Self(path)
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_netwatch"));
        cmd.env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            .env("XDG_CACHE_HOME", self.0.join("cache"))
            .env("XDG_STATE_HOME", self.0.join("state"))
            .env("TERM", "xterm-256color");
        cmd
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A process whose stdin, stdout and stderr are one
/// fresh pty, and everything it has written there so far.
struct Pty {
    child: Child,
    slave: OwnedFd,
    master: fs::File,
    chunks: Receiver<Vec<u8>>,
    output: String,
    before: Termios,
}

impl Pty {
    fn spawn(mut cmd: Command) -> Self {
        let size = Winsize {
            ws_row: 40,
            ws_col: 120,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pty = openpty(&size, None).unwrap();
        let before = tcgetattr(&pty.slave).unwrap();
        let stdio = |fd: &OwnedFd| Stdio::from(fd.try_clone().unwrap());
        cmd.stdin(stdio(&pty.slave))
            .stdout(stdio(&pty.slave))
            .stderr(stdio(&pty.slave));
        // Do not acquire the pty as a controlling terminal: macOS revokes
        // its slave when the session leader exits, preventing the parent
        // from checking restoration with tcgetattr after that exit.
        // SAFETY: setsid is async-signal-safe, which is all that
        // may run between fork and exec, and touches only the child.
        unsafe {
            cmd.pre_exec(|| {
                nix::unistd::setsid()?;
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        // A blocking reader: poll(2) on macOS does not support devices.
        let master = fs::File::from(pty.master);
        let mut reader = master.try_clone().unwrap();
        let (tx, chunks) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = [0; 16384];
            while let Ok(n @ 1..) = reader.read(&mut buf) {
                if tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            slave: pty.slave,
            master,
            chunks,
            output: String::new(),
            before,
        }
    }

    /// Collect output until `done` holds or `timeout` passes.
    fn read_until(&mut self, timeout: Duration, done: impl Fn(&str) -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while !done(&self.output) {
            let left = deadline.saturating_duration_since(Instant::now());
            match self
                .chunks
                .recv_timeout(left.min(Duration::from_millis(100)))
            {
                Ok(chunk) => self.output.push_str(&String::from_utf8_lossy(&chunk)),
                Err(_) if left.is_zero() => return false,
                Err(_) => {}
            }
        }
        true
    }

    /// Wait up to `timeout` for the process to exit, then collect what it
    /// wrote before it did.
    fn wait(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("netwatch did not exit: {:?}", self.tail());
            }
            self.read_until(Duration::from_millis(50), |_| false);
        };
        self.read_until(Duration::from_millis(300), |_| false);
        status
    }

    /// The output from the first frame on, where escape sequences that undo
    /// it can appear.
    fn tail(&self) -> &str {
        self.output
            .find(ENTER)
            .map_or(self.output.as_str(), |at| &self.output[at..])
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// The first frame ends by hiding the cursor. By then the TUI is in its
/// event loop, and its signal listeners are registered.
fn first_frame(out: &str) -> bool {
    out.find(ENTER)
        .is_some_and(|at| out[at..].contains("\x1b[?25l"))
}

/// Start `netwatch --demo`, wait for its first frame, stop it with `stop`,
/// and check that it exits 0 and puts the terminal back.
fn stops_cleanly(stop: impl FnOnce(&mut Pty)) {
    let fixture = Fixture::new();
    let mut cmd = fixture.command();
    cmd.arg("--demo");
    let mut pty = Pty::spawn(cmd);
    let started = pty.read_until(Duration::from_secs(10), first_frame);
    assert!(started, "no first frame: {:?}", pty.output);
    stop(&mut pty);
    let status = pty.wait(Duration::from_secs(10));
    assert!(status.success(), "{status}: {:?}", pty.tail());
    let tail = pty.tail();
    for seq in ["\x1b[?1000l", "\x1b[?1049l", "\x1b[?25h"] {
        assert!(tail.contains(seq), "no {seq:?} after {ENTER:?}: {tail:?}");
    }
    let after = tcgetattr(&pty.slave).unwrap();
    let canonical = LocalFlags::ICANON | LocalFlags::ECHO | LocalFlags::ISIG;
    assert!(pty.before.local_flags.contains(canonical));
    // PENDIN is kernel-maintained input state on macOS after restoring ICANON.
    assert_eq!(
        after.local_flags & !LocalFlags::PENDIN,
        pty.before.local_flags & !LocalFlags::PENDIN
    );
    assert_eq!(after.input_flags, pty.before.input_flags);
    assert_eq!(after.output_flags, pty.before.output_flags);
}

fn signal(sig: Signal) -> impl FnOnce(&mut Pty) {
    move |pty| kill(Pid::from_raw(pty.child.id() as i32), sig).unwrap()
}

#[test]
fn sigterm_restores_the_terminal_and_exits_0() {
    stops_cleanly(signal(Signal::SIGTERM));
}

#[test]
fn sigint_restores_the_terminal_and_exits_0() {
    stops_cleanly(signal(Signal::SIGINT));
}

#[test]
fn sighup_restores_the_terminal_and_exits_0() {
    stops_cleanly(signal(Signal::SIGHUP));
}

/// The control: raw mode delivers Ctrl+C as a key, which always quit cleanly.
#[test]
fn ctrl_c_typed_restores_the_terminal_and_exits_0() {
    stops_cleanly(|pty| pty.master.write_all(b"\x03").unwrap());
}

/// Closing the terminal window or losing the SSH connection hangs the pty up:
/// netwatch gets SIGHUP and every write fails. A failed write on the way out
/// panicked, the panic report's own write panicked again, and the process
/// aborted with a core dump. `kill -HUP` above leaves the pty working, so it
/// never saw this.
#[cfg(target_os = "linux")]
#[test]
fn a_hangup_ends_without_a_panic() {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use std::os::fd::AsFd;
    use std::os::unix::process::ExitStatusExt;

    let fixture = Fixture::new();
    let mut cmd = fixture.command();
    cmd.arg("--demo");
    let size = Winsize {
        ws_row: 40,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pty = openpty(&size, None).unwrap();
    let stdio = || Stdio::from(pty.slave.try_clone().unwrap());
    cmd.stdin(stdio()).stdout(stdio()).stderr(stdio());
    // The pty is netwatch's controlling terminal, so closing its master
    // hangs it up the way a terminal emulator closing does.
    // SAFETY: setsid and ioctl are async-signal-safe, which is all that may
    // run between fork and exec, and touch only the child.
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setsid()?;
            if nix::libc::ioctl(0, nix::libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // openpty's descriptors survive exec, and a child holding the master
    // would keep the pty from hanging up. A clone is close-on-exec.
    let mut master = fs::File::from(pty.master.try_clone().unwrap());
    drop(pty.master);
    let mut child = cmd.spawn().unwrap();
    drop(cmd);
    drop(pty.slave);
    // Read here rather than on a thread, which would hold the master open.
    let mut output = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !first_frame(&output) {
        assert!(Instant::now() < deadline, "no first frame: {output:?}");
        let mut fds = [PollFd::new(master.as_fd(), PollFlags::POLLIN)];
        if poll(&mut fds, PollTimeout::from(100u16)).unwrap() > 0 {
            let mut buf = [0; 16384];
            let n = master.read(&mut buf).unwrap();
            output.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    }
    drop(master);
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("netwatch did not exit after the hangup");
        }
        thread::sleep(Duration::from_millis(50));
    };
    // 101 is a panic that unwound out of `main`.
    assert!(
        status.signal().is_none() && status.code() != Some(101),
        "{status}"
    );
}

/// A terminal that stops reading, as a frozen SSH session does, blocks the
/// TUI in a write, where it cannot answer a signal. SIGTERM's default action
/// used to end it there; with the signal handled, nothing did until SIGKILL.
/// Now the default action ends it once it has had 5 seconds to answer.
#[cfg(target_os = "linux")]
#[test]
fn sigterm_ends_a_tui_whose_terminal_stopped_reading() {
    use nix::sys::termios::{tcflow, FlowArg};
    use std::os::unix::process::ExitStatusExt;

    let fixture = Fixture::new();
    let mut cmd = fixture.command();
    cmd.arg("--demo");
    let mut pty = Pty::spawn(cmd);
    let started = pty.read_until(Duration::from_secs(10), first_frame);
    assert!(started, "no first frame: {:?}", pty.output);
    // Suspend the pty's output: every write netwatch makes from here on,
    // the restore's included, blocks.
    tcflow(&pty.slave, FlowArg::TCOOFF).unwrap();
    signal(Signal::SIGTERM)(&mut pty);
    let status = pty.wait(Duration::from_secs(15));
    assert_eq!(status.signal(), Some(Signal::SIGTERM as i32), "{status}");
}
