#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub mod pktap;
/// Kernel-derived process identity — every platform, including the fallback
/// that returns nothing so callers keep the name they already had.
pub mod procname;
#[cfg(target_os = "windows")]
pub mod windows;

use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct InterfaceStats {
    #[allow(dead_code)]
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
}

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub mac: Option<String>,
    pub mtu: Option<u32>,
    pub is_up: bool,
    /// `Some(true)` for wireless (Wi-Fi), `Some(false)` for wired Ethernet,
    /// `None` when the OS didn't give us a definitive answer (e.g. loopback,
    /// VPN, virtual interfaces — or the lookup failed).
    pub is_wireless: Option<bool>,
}

pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    #[cfg(target_os = "linux")]
    return linux::collect_interface_stats();

    #[cfg(target_os = "macos")]
    return macos::collect_interface_stats();

    #[cfg(target_os = "windows")]
    return windows::collect_interface_stats();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    anyhow::bail!("Unsupported platform")
}

/// Name of the interface carrying the default route, if the platform can
/// tell us. Used to bias capture-interface selection toward the NIC that
/// actually carries traffic — on multi-NIC machines enumeration order says
/// nothing about which port has the cable (issue #43).
pub fn default_route_interface() -> Option<String> {
    #[cfg(target_os = "linux")]
    return linux::default_route_interface();

    #[cfg(target_os = "macos")]
    return macos::default_route_interface();

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    None
}

pub fn collect_interface_info() -> Result<Vec<InterfaceInfo>> {
    #[cfg(target_os = "linux")]
    return linux::collect_interface_info();

    #[cfg(target_os = "macos")]
    return macos::collect_interface_info();

    #[cfg(target_os = "windows")]
    return windows::collect_interface_info();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    anyhow::bail!("Unsupported platform")
}
