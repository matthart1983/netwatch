#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
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
