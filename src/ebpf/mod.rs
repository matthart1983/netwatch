#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod conn_tracker;
pub mod rtt_monitor;

/// Status of the eBPF subsystem, used by UI for status bar indicator.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum EbpfStatus {
    /// eBPF is active and collecting data.
    Active,
    /// eBPF failed to initialise; includes reason.
    Unavailable(String),
    /// eBPF feature was not compiled in.
    NotCompiled,
}
