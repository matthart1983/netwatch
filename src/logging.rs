//! File-only structured logging.
//!
//! The TUI owns stdout/stderr in alternate-screen mode, so the subscriber
//! installed here MUST write only to a file — anything that lands on the
//! terminal corrupts the alternate screen. Logs go to a daily-rotated file
//! under the user's cache dir:
//!
//! - Linux:   `~/.cache/netwatch/netwatch.log.YYYY-MM-DD`
//! - macOS:   `~/Library/Caches/netwatch/netwatch.log.YYYY-MM-DD`
//! - Windows: `%LOCALAPPDATA%\netwatch\netwatch.log.YYYY-MM-DD`
//!
//! Level defaults to WARN (quiet — captures real failures, not chatter).
//! Override via `RUST_LOG`, e.g. `RUST_LOG=netwatch=debug` when reproducing
//! a stuck resolver, a pcap startup failure, or a remote-stream issue.

use std::path::{Path, PathBuf};

use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Install the global subscriber. The returned `WorkerGuard` must be held for
/// the lifetime of the program — when it drops, the non-blocking writer's
/// background thread flushes and exits, so logs queued near shutdown can be
/// lost otherwise.
///
/// Returns `None` if we can't determine a cache dir, create the log directory,
/// or open the log file (e.g. a root-owned file left by a prior `sudo netwatch`
/// run, or a read-only filesystem). The macros become no-ops in that case; the
/// app keeps running. Logging is best-effort diagnostic plumbing, never
/// load-bearing — it must never crash the process, which matters most for the
/// long-running `netwatch daemon`.
///
/// Safe to print to stderr here: `init` always runs before the TUI enters the
/// alternate screen (and the daemon has no alternate screen), so a one-line
/// warning won't corrupt the display.
pub fn init() -> Option<WorkerGuard> {
    let log_dir = log_dir()?;
    if std::fs::create_dir_all(&log_dir).is_err() {
        return None;
    }
    let file_appender = daily_appender(&log_dir)?;
    let (writer, guard) = tracing_appender::non_blocking(file_appender);

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn,netwatch=warn"));

    let layer = fmt::layer()
        .with_writer(writer)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(false);

    // `try_init` so tests and embedded uses that install their own subscriber
    // don't panic; the first installer wins.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init();

    Some(guard)
}

pub fn log_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|c| c.join("netwatch"))
}

/// Build the daily-rotating file appender, returning `None` (with a one-line
/// stderr note) instead of panicking when the log file can't be opened. The
/// non-fallible `rolling::daily` `.expect()`s here, which would crash the app.
fn daily_appender(log_dir: &Path) -> Option<RollingFileAppender> {
    RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("netwatch.log")
        .build(log_dir)
        .map_err(|e| eprintln!("netwatch: file logging disabled ({e})"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn appender_builds_in_writable_dir() {
        let dir = std::env::temp_dir().join(format!("nw-log-ok-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert!(daily_appender(&dir).is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    // Regression: a non-writable log location must degrade to None, not panic.
    // (A root-owned netwatch.log from a prior `sudo netwatch` run used to crash
    // startup — fatal for the daemon.)
    #[cfg(unix)]
    #[test]
    fn appender_is_none_when_dir_unwritable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nw-log-ro-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        // r-x, no write: the owner cannot create the log file inside.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();

        let result = daily_appender(&dir);

        // Restore perms so cleanup can remove the dir.
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&dir);
        assert!(
            result.is_none(),
            "unwritable log dir must yield None, not panic"
        );
    }
}
