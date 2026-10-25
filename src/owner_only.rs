//! Files and directories only their owner can open, for what netwatch saves:
//! packet captures, incident bundles and the exports directory that holds
//! them.
//!
//! Captures hold packet bytes, and bundles hold addresses, hostnames and
//! process names. The sandbox already made the exports directory 0700
//! (`sandbox::paths`), but every file in it was created under the umask,
//! usually 0644, and `--no-sandbox` left the directory 0755 as well. On Unix
//! these helpers set the mode as the file or directory is created, so there
//! is no moment when someone else can open it. Elsewhere they are the plain
//! `std::fs` calls.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(unix)]
const FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;

/// Write options whose new files are 0600. The caller adds `create`,
/// `create_new` or `truncate`. The mode applies only to a file the open
/// creates; [`create`] also narrows one that already exists.
pub fn file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(FILE_MODE);
    }
    options
}

/// A builder whose new directories are 0700, and so are the parents it
/// creates when made recursive.
pub fn dir_builder() -> DirBuilder {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = DirBuilder::new();
        builder.mode(DIR_MODE);
        builder
    }
    #[cfg(not(unix))]
    {
        DirBuilder::new()
    }
}

/// Create or truncate `path` for writing, 0600. A file that already existed
/// keeps its old mode through the open, so it is narrowed afterwards, and a
/// file this user cannot narrow is an error rather than a readable export.
pub fn create(path: &Path) -> io::Result<File> {
    let file = file_options().create(true).truncate(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
    }
    Ok(file)
}

/// Create `dir` and any missing parents, 0700. A `dir` that already existed,
/// say 0755 from an older netwatch run without the sandbox, is narrowed to
/// 0700 when this user owns it. A symlink, or a directory someone else owns,
/// is left as it is: that is where the user pointed it, and
/// `fs::create_dir_all` accepted it too.
pub fn create_dir_all(dir: &Path) -> io::Result<()> {
    dir_builder().recursive(true).create(dir)?;
    #[cfg(unix)]
    narrow_dir(dir, nix::unistd::geteuid().as_raw());
    Ok(())
}

/// Narrow `dir` to 0700 when `uid` owns it. The chmod would fail on anyone
/// else's directory anyway, except as root, and root (say `sudo -E` with the
/// user's HOME) must leave a directory it does not own as the owner set it.
#[cfg(unix)]
fn narrow_dir(dir: &Path, uid: u32) {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let Ok(handle) = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(dir)
    else {
        return;
    };
    if handle.metadata().is_ok_and(|meta| meta.uid() == uid) {
        let _ = handle.set_permissions(std::fs::Permissions::from_mode(DIR_MODE));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("nw-owner-only-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn new_directories_and_files_are_owner_only() {
        let root = scratch("new");
        let dir = root.join("exports").join("bundle");
        create_dir_all(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        // The parents it created are 0700 less the umask, which only removes bits.
        assert_eq!(mode(&root.join("exports")) & 0o077, 0);
        assert_eq!(mode(&root) & 0o077, 0);

        let file = dir.join("packets.pcap");
        create(&file).unwrap();
        assert_eq!(mode(&file), 0o600);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn existing_directories_and_files_are_narrowed() {
        let root = scratch("existing");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = root.join("summary.md");
        std::fs::write(&file, "old").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();

        create_dir_all(&root).unwrap();
        assert_eq!(mode(&root), 0o700);
        use std::io::Write;
        create(&file).unwrap().write_all(b"new").unwrap();
        assert_eq!(mode(&file), 0o600);
        assert_eq!(
            std::fs::read(&file).unwrap(),
            b"new",
            "the file is truncated"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_someone_else_owns_is_not_narrowed() {
        use std::os::unix::fs::MetadataExt;
        let root = scratch("other-owner");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Only root can chmod another user's directory, so the owner check is
        // exercised with a uid that does not own this one.
        let owner = std::fs::metadata(&root).unwrap().uid();
        narrow_dir(&root, owner.wrapping_add(1));
        assert_eq!(mode(&root), 0o755);
        narrow_dir(&root, owner);
        assert_eq!(mode(&root), 0o700);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlinked_directory_is_used_but_not_changed() {
        let root = scratch("symlink");
        let target = root.join("shared");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = root.join("exports");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        create_dir_all(&link).unwrap();
        assert_eq!(mode(&target), 0o755);
        let _ = std::fs::remove_dir_all(&root);
    }
}
