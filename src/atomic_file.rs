//! Replace a file so that a failed write leaves the old one whole.
//!
//! `fs::write` truncates first. With the disk full, a config came back as 300
//! bytes ending `view = "ful`, and netwatch then refused to start on it. These
//! files are ones a person edits or a trust anchor, so the new contents go to a
//! temporary file beside the old one, are synced, and are renamed over it.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Who can read the file afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// The mode and owner of the file being replaced. A new file gets what
    /// `fs::write` would have given it, under the umask.
    KeepExisting,
    /// 0600 on Unix, whatever the file had. Elsewhere, what a new file gets.
    OwnerOnly,
}

/// Replace `path` with `bytes`. A symlink stays, and its target is what changes,
/// as a dotfiles manager's link has to keep working. A file this user may not
/// write stays refused, though the directory would allow a rename over it.
///
/// Where a file cannot be replaced at all this writes in place, as `fs::write`
/// did, and a failed write there can still lose it: a directory this user cannot
/// create in, or a file bind-mounted on its own, which a rename cannot touch.
pub fn replace(path: &Path, bytes: &[u8], access: Access) -> io::Result<()> {
    let target = symlink_target(path);
    let existing = fs::metadata(&target).ok();
    if let Some(meta) = &existing {
        // A rename would put a file where a device or a pipe was.
        if !meta.is_file() {
            return fs::write(&target, bytes);
        }
        OpenOptions::new().write(true).open(&target)?;
    }
    match write_beside(&target, bytes, access, existing.as_ref()) {
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::PermissionDenied
                    | io::ErrorKind::ResourceBusy
                    | io::ErrorKind::CrossesDevices
            ) =>
        {
            write_in_place(&target, bytes, access)
        }
        result => result,
    }
}

/// Where `path` ends up once every symlink is followed, whether or not that file
/// exists yet. The limit is the kernel's own, for a loop of links.
fn symlink_target(path: &Path) -> PathBuf {
    let mut current = path.to_path_buf();
    for _ in 0..40 {
        let Ok(link) = fs::read_link(&current) else {
            break;
        };
        current = match current.parent() {
            Some(parent) => parent.join(link),
            None => link,
        };
    }
    current
}

fn write_beside(
    target: &Path,
    bytes: &[u8],
    access: Access,
    existing: Option<&Metadata>,
) -> io::Result<()> {
    let dir = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let name = target.file_name().unwrap_or_default().to_string_lossy();
    let temp = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    // Private until it has the final mode, so nobody can open it before then.
    let mut options = if access == Access::KeepExisting && existing.is_none() {
        let mut options = OpenOptions::new();
        options.write(true);
        options
    } else {
        crate::owner_only::file_options()
    };
    let mut file = options.create_new(true).open(&temp)?;
    let written = fill(&mut file, bytes, access, existing);
    // Closed before the rename, which Windows refuses on an open file.
    drop(file);
    let replaced = written.and_then(|()| fs::rename(&temp, target));
    if replaced.is_err() {
        let _ = fs::remove_file(&temp);
    }
    replaced?;
    #[cfg(unix)]
    if let Ok(dir) = File::open(dir) {
        // Best effort. The rename has happened, and a crash now is all this covers.
        let _ = dir.sync_all();
    }
    Ok(())
}

fn fill(
    file: &mut File,
    bytes: &[u8],
    access: Access,
    existing: Option<&Metadata>,
) -> io::Result<()> {
    file.write_all(bytes)?;
    match (access, existing) {
        (Access::OwnerOnly, _) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
        }
        (Access::KeepExisting, Some(meta)) => {
            // Best effort: root saving someone's config leaves it theirs, and
            // anyone else cannot give a file away, so it becomes theirs instead.
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let _ = std::os::unix::fs::fchown(&*file, Some(meta.uid()), Some(meta.gid()));
            }
            file.set_permissions(meta.permissions())?;
        }
        (Access::KeepExisting, None) => {}
    }
    file.sync_all()
}

fn write_in_place(target: &Path, bytes: &[u8], access: Access) -> io::Result<()> {
    let mut file = match access {
        Access::OwnerOnly => crate::owner_only::create(target)?,
        Access::KeepExisting => File::create(target)?,
    };
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nw-atomic-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn it_replaces_or_creates_and_leaves_no_temporary_file() {
        let dir = scratch();
        let path = dir.join("file");
        replace(&path, b"one", Access::KeepExisting).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");
        replace(&path, b"two", Access::KeepExisting).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        replace(&path, b"three", Access::OwnerOnly).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"three");
        assert_eq!(names(&dir), ["file"]);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A file size limit is a real write failure: the write returns EFBIG, as a
    /// full disk returns ENOSPC. Linux only, for `ulimit -f` and the signal's name.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_write_keeps_the_old_file_and_leaves_no_temporary_file() {
        use std::process::Command;
        const CHILD: &str = "NETWATCH_ATOMIC_TEST_FILE";
        // Run again under a file size limit, standing in for a full disk.
        if let Some(path) = std::env::var_os(CHILD) {
            for access in [Access::KeepExisting, Access::OwnerOnly] {
                let err = replace(Path::new(&path), &vec![b'x'; 64 * 1024], access).unwrap_err();
                assert_eq!(err.raw_os_error(), Some(nix::libc::EFBIG), "{err}");
            }
            return;
        }
        let dir = scratch();
        let path = dir.join("file");
        fs::write(&path, b"the old contents").unwrap();
        let this_test =
            "atomic_file::tests::a_failed_write_keeps_the_old_file_and_leaves_no_temporary_file";
        let output = Command::new("sh")
            .args(["-c", "trap '' XFSZ; ulimit -f 1; exec \"$0\" \"$@\""])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", this_test])
            .env(CHILD, &path)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{output:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"the old contents");
        assert_eq!(names(&dir), ["file"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};

        fn mode(path: &Path) -> u32 {
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        }

        fn is_root() -> bool {
            nix::unistd::geteuid().is_root()
        }

        #[test]
        fn it_keeps_the_mode_or_makes_it_owner_only() {
            let dir = scratch();
            let path = dir.join("file");
            fs::write(&path, b"old").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            replace(&path, b"new", Access::KeepExisting).unwrap();
            assert_eq!(mode(&path), 0o640);

            replace(&path, b"newer", Access::OwnerOnly).unwrap();
            assert_eq!(mode(&path), 0o600);

            // A new file gets what `fs::write` gives it.
            fs::write(dir.join("plain"), b"x").unwrap();
            replace(&dir.join("new"), b"x", Access::KeepExisting).unwrap();
            assert_eq!(mode(&dir.join("new")), mode(&dir.join("plain")));
            replace(&dir.join("private"), b"x", Access::OwnerOnly).unwrap();
            assert_eq!(mode(&dir.join("private")), 0o600);
            let _ = fs::remove_dir_all(&dir);
        }

        /// The link stays a link, relative or through another link, and what it
        /// points at changes, with its own mode.
        #[test]
        fn it_follows_a_symlink_to_its_target() {
            let dir = scratch();
            fs::create_dir(dir.join("dotfiles")).unwrap();
            let target = dir.join("dotfiles/config.toml");
            fs::write(&target, b"old").unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
            symlink("dotfiles/config.toml", dir.join("first")).unwrap();
            symlink(dir.join("first"), dir.join("second")).unwrap();

            replace(&dir.join("second"), b"new", Access::KeepExisting).unwrap();
            assert_eq!(fs::read(&target).unwrap(), b"new");
            assert_eq!(mode(&target), 0o640);
            for link in ["first", "second"] {
                assert!(fs::symlink_metadata(dir.join(link))
                    .unwrap()
                    .file_type()
                    .is_symlink());
            }
            assert_eq!(names(&dir.join("dotfiles")), ["config.toml"]);

            // A link to a file that is not there yet creates it, as a write did.
            symlink("dotfiles/later", dir.join("dangling")).unwrap();
            replace(&dir.join("dangling"), b"x", Access::KeepExisting).unwrap();
            assert_eq!(fs::read(dir.join("dotfiles/later")).unwrap(), b"x");
            let _ = fs::remove_dir_all(&dir);
        }

        /// Replacing a device would put a regular file in its place.
        #[test]
        fn a_link_to_a_device_is_written_through() {
            let dir = scratch();
            symlink("/dev/null", dir.join("link")).unwrap();
            replace(&dir.join("link"), b"x", Access::KeepExisting).unwrap();
            assert!(fs::symlink_metadata(dir.join("link"))
                .unwrap()
                .file_type()
                .is_symlink());
            let _ = fs::remove_dir_all(&dir);
        }

        /// `chmod a-w` on a config means something, and a rename would ignore it.
        #[test]
        fn a_read_only_file_stays_refused() {
            if is_root() {
                return;
            }
            let dir = scratch();
            let path = dir.join("file");
            fs::write(&path, b"old").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
            let err = replace(&path, b"new", Access::KeepExisting).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(fs::read(&path).unwrap(), b"old");
            let _ = fs::remove_dir_all(&dir);
        }

        /// A writable file in a directory this user cannot create in worked with a
        /// plain write, so it still does.
        #[test]
        fn a_directory_it_cannot_create_in_is_written_in_place() {
            if is_root() {
                return;
            }
            let dir = scratch();
            let path = dir.join("file");
            fs::write(&path, b"old").unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
            let result = replace(&path, b"new", Access::KeepExisting);
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            result.unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"new");
            let _ = fs::remove_dir_all(&dir);
        }
    }
}
