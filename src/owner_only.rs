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
use std::io::{self, Read};
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

/// Open `path` only if it is a regular file, without following a symlink there.
/// An ordinary open of a FIFO blocks until something writes to it, and a link to
/// `/dev/zero` reads forever.
fn open_regular(path: &Path) -> io::Result<(File, std::fs::Metadata)> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::other("a symbolic link"));
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok((file, metadata))
}

/// More than `config.toml` or `egress-policy.toml` would hold by hand.
pub const MAX_USER_FILE: u64 = 4 << 20;

fn read_limited(file: File, limit: u64) -> io::Result<String> {
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err(io::Error::other(format!("over the {limit} byte limit")));
    }
    Ok(text)
}

/// Read back a file netwatch saved. The directories they live in can be written
/// by any confined thread but capture, and these reads run before the terminal
/// and signal handling that would let a session stop waiting. So what is at the
/// path now may be something else, and anything but a regular file of at most
/// `limit` bytes is an error.
pub fn read_saved(path: &Path, limit: u64) -> io::Result<String> {
    let (file, _) = open_regular(path)?;
    read_limited(file, limit)
}

/// [`read_saved`] for a file the user wrote, up to [`MAX_USER_FILE`]. That may be
/// a symlink into a dotfiles repository, so this follows one, and it still takes
/// only a regular file: opened on a FIFO it doesn't wait for a writer.
pub fn read_user_file(path: &Path) -> io::Result<String> {
    let mut options = File::options();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    read_limited(file, MAX_USER_FILE)
}

/// [`read_saved`], and also only from a file this user owns under one name. For
/// a file whose contents are shown to whoever is running, who may be root with
/// someone else's home.
pub fn read_owned(path: &Path, limit: u64) -> io::Result<String> {
    let (file, metadata) = open_regular(path)?;
    #[cfg(unix)]
    if !owned_once(&metadata, nix::unistd::geteuid().as_raw()) {
        return Err(io::Error::other(
            "not a single-link file owned by this user",
        ));
    }
    #[cfg(not(unix))]
    let _ = metadata;
    read_limited(file, limit)
}

#[cfg(unix)]
fn owned_once(metadata: &std::fs::Metadata, uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.uid() == uid && metadata.nlink() == 1
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

    /// `read` on another thread, so a read that blocks fails here instead of
    /// hanging the run.
    fn within_seconds<T: Send + 'static>(read: impl FnOnce() -> T + Send + 'static) -> T {
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || sent.send(read()));
        received
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("the read blocked")
    }

    #[test]
    fn only_a_small_regular_file_is_read_back() {
        for read in [read_saved, read_owned] {
            let root = scratch("read");
            std::fs::create_dir_all(&root).unwrap();
            let file = root.join("saved");
            std::fs::write(&file, "1234").unwrap();
            assert_eq!(read(&file, 4).unwrap(), "1234");
            assert!(read(&file, 3).is_err(), "over the limit");
            assert_eq!(
                read(&root.join("absent"), 4).unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
            assert!(read(&root, 4).is_err(), "a directory");

            let link = root.join("link");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(read(&link, 4).is_err(), "a symlink to a good file");

            let zero = root.join("zero");
            std::os::unix::fs::symlink("/dev/zero", &zero).unwrap();
            assert!(within_seconds(move || read(&zero, 4)).is_err());

            let fifo = root.join("fifo");
            assert!(std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success());
            assert!(within_seconds(move || read(&fifo, 4)).is_err());
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn a_second_name_or_another_owner_is_refused_only_where_ownership_matters() {
        use std::os::unix::fs::MetadataExt;
        let root = scratch("owned");
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("saved");
        std::fs::write(&file, "1234").unwrap();
        let metadata = std::fs::metadata(&file).unwrap();
        // Only root can give a file away, so the owner check is exercised with a
        // uid that does not own this one.
        assert!(owned_once(&metadata, metadata.uid()));
        assert!(!owned_once(&metadata, metadata.uid().wrapping_add(1)));

        std::fs::hard_link(&file, root.join("second")).unwrap();
        assert!(read_owned(&file, 4).is_err());
        assert_eq!(read_saved(&file, 4).unwrap(), "1234");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_user_file_may_be_a_symlink_but_not_a_fifo_or_too_big() {
        let root = scratch("user-file");
        std::fs::create_dir_all(&root).unwrap();
        let real = root.join("dotfile");
        std::fs::write(&real, "theme = \"dark\"\n").unwrap();
        let link = root.join("config.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(read_user_file(&link).unwrap(), "theme = \"dark\"\n");

        let fifo = root.join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(read_user_file(&fifo).is_err());

        let big = root.join("big");
        std::fs::File::create(&big)
            .unwrap()
            .set_len(MAX_USER_FILE + 1)
            .unwrap();
        assert!(read_user_file(&big).is_err());

        let gone = root.join("gone");
        assert_eq!(
            read_user_file(&gone).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
