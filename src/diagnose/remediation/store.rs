//! Versioned recovery evidence. This store never writes a resolver target.
//! The lock serializes this store, not host-wide resolver operations. An adapter
//! must hold a resource-wide lease and validate identity before applying a change.
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf};
use uuid::Uuid;

const VERSION: u32 = 2;
#[cfg(unix)]
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    pub session: Uuid,
    pub pid: u32,
    pub uid: Option<u32>,
    pub boot_id: Option<String>,
    pub process_start: Option<String>,
    #[serde(default)]
    pub pid_namespace: Option<String>,
}

impl Owner {
    /// Absence of a verifiable token means unknown ownership, never a dead owner.
    pub fn current() -> Self {
        let pid = std::process::id();
        #[cfg(target_os = "linux")]
        let (boot_id, process_start) = (
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .map(|s| s.trim().to_owned()),
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|s| {
                    s.rsplit_once(") ")
                        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
                        .map(str::to_owned)
                }),
        );
        #[cfg(not(target_os = "linux"))]
        let (boot_id, process_start) = (None, None);
        Self {
            session: Uuid::new_v4(),
            pid,
            uid: current_uid(),
            boot_id,
            process_start,
            pid_namespace: {
                #[cfg(target_os = "linux")]
                {
                    std::fs::read_link("/proc/self/ns/pid")
                        .ok()
                        .map(|p| p.to_string_lossy().into_owned())
                }
                #[cfg(not(target_os = "linux"))]
                {
                    None
                }
            },
        }
    }
}

fn current_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        Some(nix::unistd::geteuid().as_raw())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Adapter {
    UnmanagedFile,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub adapter: Adapter,
    pub target: PathBuf,
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Prepared,
    Applied,
    RecoveryRequired,
    Reverted,
    Committed,
}
impl State {
    pub fn unresolved(self) -> bool {
        !matches!(self, Self::Reverted | Self::Committed)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: Uuid,
    pub issue_id: String,
    pub owner: Owner,
    pub resource: Resource,
    pub original_sha256: String,
    pub installed_sha256: String,
    pub state: State,
    pub created_at: String,
    pub updated_at: String,
    pub detail: Option<String>,
}
impl Operation {
    /// A basename derived from the operation ID, never a path read from JSON.
    pub fn backup_name(&self) -> String {
        format!("{}.backup", self.id)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub revision: u64,
    pub operations: Vec<Operation>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            version: VERSION,
            revision: 0,
            operations: vec![],
        }
    }
}
#[cfg(unix)]
impl Snapshot {
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        let value: Self = serde_json::from_slice(bytes).map_err(io::Error::other)?;
        if value.version != VERSION {
            return Err(io::Error::other(
                "unsupported recovery journal version; original preserved",
            ));
        }
        let mut ids = std::collections::HashSet::new();
        for operation in &value.operations {
            if !ids.insert(operation.id)
                || !operation.resource.target.is_absolute()
                || !valid_digest(&operation.original_sha256)
                || !valid_digest(&operation.installed_sha256)
            {
                return Err(io::Error::other(
                    "invalid recovery operation; original preserved",
                ));
            }
        }
        Ok(value)
    }
}
#[cfg(unix)]
fn valid_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}
#[cfg(unix)]
fn digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn default_directory() -> Option<PathBuf> {
    dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .map(|p| p.join("netwatch/recovery-v2"))
}

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::Store;

/// Read only: absence never creates directories or a journal. Atomic replacement
/// gives readers an old or new complete snapshot without taking a writer's lease.
pub fn inspect(directory: &std::path::Path) -> io::Result<Option<Snapshot>> {
    #[cfg(unix)]
    {
        unix::inspect(directory)
    }
    #[cfg(not(unix))]
    {
        // No durable Windows writer is enabled yet. Do not follow reparse-point
        // paths or silently ignore a journal placed here by a newer version.
        match std::fs::symlink_metadata(directory) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "recovery-v2 inspection requires a validated platform backend; records preserved",
            )),
        }
    }
}
