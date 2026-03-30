//! eBPF subsystem for enhanced kernel-level network monitoring.
//!
//! This module is optional and only active on Linux with the `ebpf` feature flag:
//! `cargo build --features ebpf`
//!
//! When not compiled, stubs are provided so the rest of the app works unchanged.

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
