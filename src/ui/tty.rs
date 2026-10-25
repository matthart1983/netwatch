//! The terminal the TUI draws on: raw mode, the alternate screen and mouse
//! reporting, and putting all three back however the session ends.
//!
//! `main` used to undo them only when `app::run` returned. A panic on the TUI
//! thread unwound past that, and SIGTERM, SIGINT or SIGHUP killed the process
//! outright, so the shell came back without echo or line editing, and every
//! mouse move typed escape codes into it. [`restore`] is idempotent and every
//! exit reaches it: the [`Session`] guard, the panic hook, the signal path in
//! `app::run`, and `main` after a normal return.

use std::backtrace::{Backtrace, BacktraceStatus};
use std::borrow::Cow;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Once, OnceLock};

use crossterm::{
    cursor,
    event::{DisableMouseCapture, EnableMouseCapture},
    execute, queue,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use crate::ui::sanitize;

/// True from [`enter`] until the first [`restore`] after it.
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// The first panic on a thread other than the TUI's, for `main` to name if
/// the session then ends in an error.
static BACKGROUND_PANIC: OnceLock<String> = OnceLock::new();

static PANIC_HOOK_INIT: Once = Once::new();

/// Restores the terminal when it drops, during an unwind as well.
#[must_use = "the terminal is restored when the Session drops"]
pub struct Session(());

impl Drop for Session {
    fn drop(&mut self) {
        restore();
    }
}

/// Switch on raw mode, the alternate screen and mouse reporting. If a step
/// after raw mode fails, what was already on is switched off again before the
/// error returns.
pub fn enter() -> io::Result<Session> {
    enable_raw_mode()?;
    ACTIVE.store(true, Ordering::SeqCst);
    if let Err(error) = execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture) {
        restore();
        return Err(error);
    }
    Ok(Session(()))
}

/// Put the terminal back as [`enter`] found it. Only the first call after
/// `enter` does anything, so any exit path can call it.
pub fn restore() {
    restore_if_active(&mut io::stdout(), disable_raw_mode);
}

fn restore_if_active(out: &mut impl Write, raw_off: impl FnOnce() -> io::Result<()>) {
    if ACTIVE.swap(false, Ordering::SeqCst) {
        restore_into(out, raw_off);
    }
}

/// Each step runs whether or not the one before it worked: a terminal that
/// refuses to leave raw mode should still stop reporting the mouse and get
/// its main screen and cursor back.
fn restore_into(out: &mut impl Write, raw_off: impl FnOnce() -> io::Result<()>) {
    let _ = raw_off();
    let _ = queue!(out, DisableMouseCapture);
    let _ = queue!(out, LeaveAlternateScreen);
    let _ = queue!(out, cursor::Show);
    let _ = out.flush();
}

/// Install the TUI's panic hook, once. Call it on the thread that draws,
/// before [`enter`].
///
/// Every panic goes to the log with its thread's name. A panic on the TUI
/// thread ends the session, and so does any panic when the build aborts on
/// panic, so the hook restores the terminal before the report is printed into
/// the user's shell. The previous hook prints it, with the backtrace
/// `RUST_BACKTRACE` asks for. A report that quotes a peer's bytes is printed
/// here instead, with them replaced, because after the restore the shell is
/// what reads it. A panic on another thread leaves the TUI running and stays
/// off the screen, where the default hook would write it over the frame (a
/// capture-thread panic caught by `run_capture_step` is one). The first is
/// kept for [`background_panic`].
///
/// The TUI thread must never `catch_unwind`. The hook takes any panic there
/// as the end of the session and has handed the terminal back before the
/// unwind could be caught, so the session would carry on drawing over the
/// shell.
pub fn install_panic_hook() {
    PANIC_HOOK_INIT.call_once(|| {
        let tui = std::thread::current().id();
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let thread = std::thread::current();
            let name = thread.name().unwrap_or("unnamed");
            let report = info.to_string();
            tracing::error!(
                target: "netwatch::panic",
                thread = name,
                panic = %sanitize::display(&report),
                "a thread panicked"
            );
            if !is_fatal(thread.id() == tui) {
                let _ = BACKGROUND_PANIC.set(format!(
                    "a background thread ({name}) {}",
                    sanitize::display(&report.replace('\n', " "))
                ));
                return;
            }
            restore();
            match sanitize::display_multiline(&report) {
                Cow::Borrowed(_) => prev(info),
                Cow::Owned(clean) => print_report(name, &clean),
            }
        }));
    });
}

/// Print a fatal panic's report as the default hook would, with `clean` in
/// place of what it says: the backtrace if `RUST_BACKTRACE` asks for one, and
/// how to ask if not. Not `eprintln!`, which panics if the terminal has hung
/// up, and a panic in the hook aborts.
fn print_report(thread: &str, clean: &str) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "\nthread '{}' {clean}", sanitize::display(thread));
    let trace = Backtrace::capture();
    let _ = match trace.status() {
        BacktraceStatus::Captured => writeln!(err, "stack backtrace:\n{trace}"),
        BacktraceStatus::Disabled => writeln!(
            err,
            "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace"
        ),
        _ => Ok(()),
    };
}

/// A panic ends the process when it is on the TUI thread, whose unwind leaves
/// `main`, or anywhere in a build that aborts on panic.
fn is_fatal(on_tui_thread: bool) -> bool {
    on_tui_thread || cfg!(panic = "abort")
}

/// The first background-thread panic of this session, as one line naming the
/// thread, if there was one.
pub fn background_panic() -> Option<&'static str> {
    BACKGROUND_PANIC.get().map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The integration tests in tests/tui_signals.rs run the real binary;
    /// these run a child of this test binary, so that what it does to the
    /// terminal can be checked from outside.
    #[cfg(unix)]
    mod pty {
        use nix::pty::{openpty, Winsize};
        use nix::sys::termios::{tcgetattr, Termios};
        use std::io::Read;
        use std::os::fd::OwnedFd;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, ExitStatus, Stdio};
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        pub struct Run {
            pub status: ExitStatus,
            pub output: String,
            pub before: Termios,
            pub after: Termios,
        }

        /// Run the test `name` of this binary as a child, with `child` set in
        /// its environment and a fresh pty as its stdio, and collect what it
        /// writes until it exits. Backtraces are on, as a user reporting a
        /// panic would be asked to turn them on.
        pub fn run_child(name: &str, child: &str) -> Run {
            let size = Winsize {
                ws_row: 24,
                ws_col: 80,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let pty = openpty(&size, None).unwrap();
            let before = tcgetattr(&pty.slave).unwrap();
            let stdio = |fd: &OwnedFd| Stdio::from(fd.try_clone().unwrap());
            let mut cmd = Command::new(std::env::current_exe().unwrap());
            cmd.args(["--exact", name, "--nocapture"])
                .env(child, "1")
                .env("RUST_BACKTRACE", "1")
                .stdin(stdio(&pty.slave))
                .stdout(stdio(&pty.slave))
                .stderr(stdio(&pty.slave));
            // Do not acquire the pty as a controlling terminal: macOS revokes
            // its slave when the session leader exits, preventing the parent
            // from checking restoration with tcgetattr after that exit.
            // SAFETY: setsid is async-signal-safe, which is all
            // that may run between fork and exec, and touches only the child.
            unsafe {
                cmd.pre_exec(|| {
                    nix::unistd::setsid()?;
                    Ok(())
                });
            }
            let mut process = cmd.spawn().unwrap();
            drop(cmd);
            // A blocking reader: poll(2) on macOS does not support devices.
            let (tx, rx) = mpsc::channel();
            let mut master = std::fs::File::from(pty.master);
            std::thread::spawn(move || {
                let mut buf = [0; 4096];
                while let Ok(n @ 1..) = master.read(&mut buf) {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut output = Vec::new();
            let status = loop {
                if let Some(status) = process.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() > deadline {
                    let _ = process.kill();
                    panic!("{name} timed out: {:?}", String::from_utf8_lossy(&output));
                }
                if let Ok(chunk) = rx.recv_timeout(Duration::from_millis(50)) {
                    output.extend(chunk);
                }
            };
            // Whatever the child wrote before it exited, then nothing more.
            while let Ok(chunk) = rx.recv_timeout(Duration::from_millis(200)) {
                output.extend(chunk);
            }
            let after = tcgetattr(&pty.slave).unwrap();
            Run {
                status,
                output: String::from_utf8_lossy(&output).into_owned(),
                before,
                after,
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn restore_writes_every_step_even_when_raw_mode_fails() {
        let mut out = Vec::new();
        restore_into(&mut out, || Err(io::Error::other("not a tty")));
        let out = String::from_utf8(out).unwrap();
        let at = |seq: &str| out.find(seq).unwrap_or_else(|| panic!("{seq:?}: {out:?}"));
        assert!(at("\x1b[?1000l") < at("\x1b[?1049l"), "{out:?}");
        assert!(at("\x1b[?1049l") < at("\x1b[?25h"), "{out:?}");
    }

    #[test]
    fn restore_runs_once() {
        ACTIVE.store(true, Ordering::SeqCst);
        let mut calls = 0;
        let mut first = Vec::new();
        restore_if_active(&mut first, || {
            calls += 1;
            Ok(())
        });
        let mut second = Vec::new();
        restore_if_active(&mut second, || {
            calls += 1;
            Ok(())
        });
        assert_eq!(calls, 1);
        assert!(second.is_empty(), "{second:?}");
        #[cfg(unix)]
        assert!(!first.is_empty());
    }

    #[test]
    fn only_the_tui_thread_is_fatal_unless_panics_abort() {
        assert!(is_fatal(true));
        assert_eq!(is_fatal(false), cfg!(panic = "abort"));
    }

    /// ratatui 0.30 panics where 0.27 wrote out of bounds, so a layout bug
    /// now ends the session. The report used to go onto the alternate screen,
    /// in raw mode, and the shell came back unusable.
    #[cfg(unix)]
    #[test]
    fn a_tui_panic_restores_the_terminal_before_the_report() {
        const CHILD: &str = "NETWATCH_TTY_TUI_PANIC_TEST";
        if std::env::var_os(CHILD).is_some() {
            install_panic_hook();
            let _session = enter().unwrap();
            panic!("tui-sentinel \x1b]52;c;AAAA\x07");
        }
        let run = pty::run_child(
            "ui::tty::tests::a_tui_panic_restores_the_terminal_before_the_report",
            CHILD,
        );
        let out = &run.output;
        let at = |seq: &str| out.find(seq).unwrap_or_else(|| panic!("{seq:?}: {out:?}"));
        let report = at("tui-sentinel");
        assert!(at("\x1b[?1049h") < at("\x1b[?1049l"), "{out:?}");
        assert!(at("\x1b[?1049l") < report, "{out:?}");
        assert!(at("\x1b[?1000l") < report, "{out:?}");
        assert!(at("\x1b[?25h") < report, "{out:?}");
        // Printed into the shell with the peer's bytes replaced, and the
        // backtrace still after it.
        assert!(!out[at("\x1b[?1049l")..].contains("\x1b]52"), "{out:?}");
        assert!(out.contains("tui-sentinel ·]52;c;AAAA·"), "{out:?}");
        assert!(report < at("stack backtrace:"), "{out:?}");
        use nix::sys::termios::LocalFlags;
        let flags = LocalFlags::ICANON | LocalFlags::ECHO | LocalFlags::ISIG;
        assert!(run.before.local_flags.contains(flags));
        // macOS sets PENDIN itself when ICANON is restored; it is pending
        // input state, not a mode the application failed to restore.
        // https://github.com/apple/darwin-xnu/blob/main/bsd/kern/tty.c#L1202
        assert_eq!(
            run.after.local_flags & !LocalFlags::PENDIN,
            run.before.local_flags & !LocalFlags::PENDIN
        );
        assert_eq!(run.after.input_flags, run.before.input_flags);
        assert_eq!(run.after.output_flags, run.before.output_flags);
    }

    /// The report a user pastes into an issue: after the restore, and with
    /// the backtrace they were asked to turn on.
    #[cfg(unix)]
    #[test]
    fn a_tui_panic_report_keeps_its_backtrace() {
        const CHILD: &str = "NETWATCH_TTY_TUI_BACKTRACE_TEST";
        if std::env::var_os(CHILD).is_some() {
            install_panic_hook();
            let _session = enter().unwrap();
            panic!("tui-sentinel");
        }
        let run = pty::run_child(
            "ui::tty::tests::a_tui_panic_report_keeps_its_backtrace",
            CHILD,
        );
        let out = &run.output;
        let at = |seq: &str| out.find(seq).unwrap_or_else(|| panic!("{seq:?}: {out:?}"));
        assert!(at("\x1b[?1049l") < at("tui-sentinel"), "{out:?}");
        assert!(at("tui-sentinel") < at("stack backtrace:"), "{out:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_background_panic_leaves_the_tui_up() {
        const CHILD: &str = "NETWATCH_TTY_BACKGROUND_PANIC_TEST";
        if std::env::var_os(CHILD).is_some() {
            install_panic_hook();
            let session = enter().unwrap();
            let capture = std::thread::Builder::new()
                .name("packet-capture".into())
                .spawn(|| panic!("bad SNI \x1b]52;c;AAAA\x07 capture-sentinel"))
                .unwrap();
            assert!(capture.join().is_err());
            let recorded = background_panic().unwrap();
            assert!(recorded.contains("(packet-capture)"), "{recorded}");
            assert!(!recorded.contains('\x1b'), "{recorded}");
            println!("child-done");
            drop(session);
            return;
        }
        let run = pty::run_child(
            "ui::tty::tests::a_background_panic_leaves_the_tui_up",
            CHILD,
        );
        let out = &run.output;
        assert!(run.status.success(), "{out:?}");
        let done = out.find("child-done").unwrap();
        assert!(out.find("\x1b[?1049h").unwrap() < done, "{out:?}");
        assert!(!out[..done].contains("\x1b[?1049l"), "{out:?}");
        assert!(!out.contains("capture-sentinel"), "{out:?}");
    }

    /// A capture-thread panic is caught and capture stops, but the default
    /// hook had already written its report, peer bytes and all, over the TUI.
    #[test]
    fn a_background_panic_is_not_written_to_the_terminal() {
        const CHILD: &str = "NETWATCH_TUI_PANIC_HOOK_TEST";
        // The hook is process-wide, and would hide other tests' panics, so
        // install it in a child.
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "ui::tty::tests::a_background_panic_is_not_written_to_the_terminal",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert!(result.status.success(), "{stderr}");
            assert!(!stderr.contains("capture-sentinel"), "{stderr}");
            assert!(!stderr.contains('\x1b'), "{stderr}");
            // The TUI thread's own panics still reach the previous hook.
            assert!(stderr.contains("tui-sentinel"), "{stderr}");
            return;
        }
        install_panic_hook();
        let capture = std::thread::Builder::new()
            .name("packet-capture".into())
            .spawn(|| panic!("bad SNI \x1b]52;c;AAAA\x07 capture-sentinel"))
            .unwrap();
        assert!(capture.join().is_err());
        assert!(std::panic::catch_unwind(|| panic!("tui-sentinel")).is_err());
    }
}
