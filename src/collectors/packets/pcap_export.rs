//! Classic PCAP export by path, for callers that want one file and no
//! preview. The writer itself is `export.rs`, shared with PCAPNG.

use super::{
    export::{export_capture, Format},
    CapturedPacket,
};

/// Write `packets` to `path` as classic PCAP and return how many were
/// written. Packets without capture metadata (demo packets, say) are left
/// out rather than given a made-up timestamp, and an existing file at `path`
/// is an error rather than overwritten.
pub fn export_pcap(packets: &[CapturedPacket], path: &str) -> Result<usize, String> {
    export_capture(
        packets,
        std::path::Path::new(path),
        Format::Pcap,
        false,
        &std::sync::atomic::AtomicBool::new(false),
    )
    .map(|s| s.packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn export_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("nw-pcap-mode-{}.pcap", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert_eq!(export_pcap(&[], &path.to_string_lossy()), Ok(0));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn an_existing_file_is_not_overwritten() {
        let path = std::env::temp_dir().join(format!(
            "nw-pcap-keep-{}-{}.pcap",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::write(&path, b"keep").unwrap();
        assert!(export_pcap(&[], &path.to_string_lossy()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        let _ = std::fs::remove_file(&path);
    }
}
