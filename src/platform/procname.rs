//! Stable process identity, derived from the kernel's view of the executable.
//!
//! The name a connection is attributed to has three sources, none of which is
//! usable on its own:
//!
//! - **`comm`** (PKTAP's `pth_comm`, procfs `comm`) is kernel-derived and
//!   therefore trustworthy, but the kernel truncates it — 16 bytes on macOS,
//!   15 on Linux. `Google Chrome Helper` and `Google Chrome Helper (GPU)`
//!   both arrive as `Google Chrome He`.
//! - **`lsof`'s command** is untruncated, but it is just the executable's
//!   name, which is not always meaningful: Claude Code installs to
//!   `~/.local/share/claude/versions/2.1.219`, so every process shows up
//!   under its *version number*, and every upgrade invents a new identity.
//! - **`argv[0]`** carries the name a human would recognise (`claude`), and is
//!   the obvious fix — but any process can set it to anything. Keying an
//!   egress *policy* on it would let a program claim another's allowlist by
//!   renaming itself. We never read it.
//!
//! So identity comes from the executable path, which the kernel owns and a
//! process cannot forge, with one transformation: when the file itself is
//! named like a bare version, the name is taken from the nearest meaningful
//! parent directory instead. That collapses
//! `.../claude/versions/2.1.219` → `claude` while leaving `python3.12`,
//! `7z` and `Google Chrome Helper (GPU)` exactly as they are.

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::path::{Path, PathBuf};

/// Directory names that describe *where* a binary lives rather than *what*
/// it is. Skipped when walking up from a version-named executable.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const GENERIC_DIRS: &[&str] = &[
    "versions",
    "version",
    "releases",
    "release",
    "current",
    "bin",
    "sbin",
    "libexec",
    "MacOS",
    "Contents",
    "Resources",
    "dist",
    "build",
    "target",
    "node_modules",
    ".bin",
];

/// True for a component that looks like a bare version string — `2.1.219`,
/// `v1.2.3`, `0.26`, `1.0.0-rc1`.
///
/// Deliberately strict: a component containing any letter other than a
/// leading `v` is a name, not a version. That is what keeps `python3.12`,
/// `7z` and `libexec2` from being collapsed into their parent directory.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn looks_like_version(s: &str) -> bool {
    let body = s.strip_prefix('v').unwrap_or(s);
    if body.is_empty() {
        return false;
    }
    // Must start with a digit and contain at least one separator or be all
    // digits — `2`, `2.1`, `2.1.219`, `1.0.0-rc1`.
    if !body.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    let mut has_digit = false;
    for c in body.chars() {
        if c.is_ascii_digit() {
            has_digit = true;
        } else if c != '.' && c != '-' && c != '_' {
            // Allow a trailing alphanumeric qualifier only after a separator
            // (`1.0.0-rc1`), which the split below handles; anything else
            // means this is a name.
            if !body.contains('-') && !body.contains('.') {
                return false;
            }
            // A letter is only acceptable inside a post-separator qualifier.
            let tail = body.rsplit(['-', '.']).next().unwrap_or("");
            if !tail.chars().any(|t| t.is_ascii_digit()) {
                return false;
            }
        }
    }
    has_digit
}

/// Derive the identity from an executable path.
///
/// Exposed for testing — the path is normally supplied by the kernel.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn name_from_path(path: &Path) -> Option<String> {
    let base = path.file_name()?.to_string_lossy().into_owned();
    if !looks_like_version(&base) {
        return Some(base);
    }
    // The file is a version. Walk up for the first component that names
    // something, skipping layout directories and further version segments.
    for ancestor in path.ancestors().skip(1) {
        let Some(component) = ancestor.file_name() else {
            break;
        };
        let c = component.to_string_lossy();
        if c.is_empty() || looks_like_version(&c) {
            continue;
        }
        if GENERIC_DIRS
            .iter()
            .any(|g| g.eq_ignore_ascii_case(c.as_ref()))
        {
            continue;
        }
        return Some(c.into_owned());
    }
    // Nothing better upstream — the version string is all we have.
    Some(base)
}

/// The kernel's path for a running process's executable.
///
/// `None` when the process is gone, is a kernel task with no image, or the
/// caller lacks the privilege to ask.
#[cfg(target_os = "macos")]
pub fn executable_path(pid: u32) -> Option<PathBuf> {
    use std::os::raw::{c_int, c_void};

    // `proc_pidpath` lives in libproc, which is part of libSystem and so is
    // already linked — no extra dependency.
    extern "C" {
        fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
    }

    // PROC_PIDPATHINFO_MAXSIZE (sys/proc_info.h).
    const MAX: usize = 4 * 1024;
    let mut buf = vec![0u8; MAX];
    // SAFETY: `buf` is a live allocation of exactly `MAX` bytes and the
    // length we hand across matches it; the call only writes within that
    // range and returns the byte count written.
    let n = unsafe { proc_pidpath(pid as c_int, buf.as_mut_ptr() as *mut c_void, MAX as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(PathBuf::from(String::from_utf8_lossy(&buf).into_owned()))
}

#[cfg(target_os = "linux")]
pub fn executable_path(pid: u32) -> Option<PathBuf> {
    // `/proc/<pid>/exe` is a kernel-maintained symlink; reading it requires
    // ptrace-level access to the target, so this returns None for other
    // users' processes when unprivileged. `comm` remains the fallback.
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn executable_path(_pid: u32) -> Option<std::path::PathBuf> {
    None
}

/// Stable identity for a pid, or `None` when the kernel won't tell us and the
/// caller should keep whatever name it already had.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn stable_name(pid: u32) -> Option<String> {
    name_from_path(&executable_path(pid)?)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn stable_name(_pid: u32) -> Option<String> {
    None
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests {
    use super::*;

    fn n(p: &str) -> Option<String> {
        name_from_path(Path::new(p))
    }

    #[test]
    fn ordinary_executables_keep_their_own_name() {
        assert_eq!(n("/usr/bin/curl").as_deref(), Some("curl"));
        assert_eq!(n("/usr/bin/python3.12").as_deref(), Some("python3.12"));
        assert_eq!(n("/opt/homebrew/bin/7z").as_deref(), Some("7z"));
    }

    /// The untruncated name is the whole point — this is what `comm` cuts to
    /// `Google Chrome He` and what split the profile in two.
    #[test]
    fn long_names_survive_intact() {
        assert_eq!(
            n("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper (GPU).app/Contents/MacOS/Google Chrome Helper (GPU)")
                .as_deref(),
            Some("Google Chrome Helper (GPU)")
        );
    }

    /// The case that motivated this: a version-named binary under a
    /// `versions/` directory. Every upgrade used to mint a new identity.
    #[test]
    fn version_named_binary_takes_the_project_name() {
        assert_eq!(
            n("/Users/matt/.local/share/claude/versions/2.1.219").as_deref(),
            Some("claude")
        );
        assert_eq!(
            n("/Users/matt/.local/share/claude/versions/2.1.220").as_deref(),
            Some("claude"),
            "different versions must resolve to the same identity"
        );
    }

    #[test]
    fn generic_directories_are_skipped_on_the_way_up() {
        assert_eq!(
            n("/opt/toolchain/releases/1.4.2/bin/3.2.1").as_deref(),
            Some("toolchain")
        );
        assert_eq!(n("/srv/myapp/current/2.0").as_deref(), Some("myapp"));
    }

    #[test]
    fn version_detection_is_conservative() {
        assert!(looks_like_version("2.1.219"));
        assert!(looks_like_version("v1.2.3"));
        assert!(looks_like_version("1.0.0-rc1"));
        assert!(looks_like_version("2"));
        // Names, not versions — collapsing these would lose real identity.
        assert!(!looks_like_version("python3.12"));
        assert!(!looks_like_version("7z"));
        assert!(!looks_like_version("curl"));
        assert!(!looks_like_version("libexec2"));
        assert!(!looks_like_version(""));
        assert!(!looks_like_version("v"));
    }

    /// A version-named binary with nothing meaningful above it keeps the
    /// version rather than resolving to something absurd like "/".
    #[test]
    fn version_with_no_meaningful_parent_falls_back_to_itself() {
        assert_eq!(n("/2.1.219").as_deref(), Some("2.1.219"));
        assert_eq!(n("/bin/1.0").as_deref(), Some("1.0"));
    }

    /// The live process is us, so this must resolve to the test binary.
    #[test]
    fn resolves_the_current_process() {
        let pid = std::process::id();
        let name = stable_name(pid).expect("own executable path is readable");
        assert!(!name.is_empty());
        assert!(
            name.contains("netwatch"),
            "expected the test binary, got {name:?}"
        );
    }

    #[test]
    fn unknown_pid_yields_nothing() {
        // Reserved as "no process" on both platforms; asking must fail
        // cleanly rather than inventing a name.
        assert!(executable_path(u32::MAX).is_none());
    }
}
