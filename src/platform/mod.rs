#[cfg(target_os = "freebsd")]
pub mod freebsd;
/// Decoding for the records Windows' IP Helper API returns. Platform-neutral
/// so it is tested everywhere; only the calls that fill it are Windows-only.
pub mod ip_helper;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
/// Locating Npcap before the capture path needs it. Windows only, and called
/// from `main` before anything touches libpcap.
#[cfg(target_os = "windows")]
pub mod npcap;
/// Friendly-name -> Npcap device matching. Platform-neutral so the matching
/// is tested everywhere; only the Windows lookups that feed it are gated.
pub mod npcap_device;
#[cfg(target_os = "macos")]
pub mod pktap;
/// Kernel-derived process identity — every platform, including the fallback
/// that returns nothing so callers keep the name they already had.
pub mod procname;
/// Decoding of the Windows TCP and UDP socket tables. Platform-neutral so it
/// is tested everywhere; only the calls that read the tables are gated.
pub mod socket_table;
#[cfg(target_os = "windows")]
pub mod windows;

/// The `setcap` line the README, REFERENCE.md and the man page give for
/// capture without root on Linux. CAP_BPF and CAP_PERFMON are for eBPF
/// attribution (`sandbox/mod.rs`).
pub const LINUX_CAPTURE_FIX: &str =
    r#"sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$(which netwatch)""#;

/// What [`capture_fix`] says on Windows. Named so doctor's Npcap wording can
/// use it, and be tested, on every platform rather than only on Windows.
pub const WINDOWS_CAPTURE_FIX: &str =
    "install Npcap from https://npcap.com/#download, without \"restrict to administrators\"";

/// What lets netwatch capture on this OS when opening a capture was refused.
/// The one place it is written, so the error, the Dashboard banner and the
/// docs cannot drift apart.
pub const fn capture_fix() -> &'static str {
    if cfg!(target_os = "linux") {
        LINUX_CAPTURE_FIX
    } else if cfg!(target_os = "macos") {
        "run with sudo, or give your user read access to /dev/bpf* (Wireshark's ChmodBPF does this)"
    } else if cfg!(target_os = "windows") {
        WINDOWS_CAPTURE_FIX
    } else {
        "run with sudo, or give your user read access to /dev/bpf* in devfs.rules"
    }
}

use crate::ui::sanitize::display_owned;
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
    /// Signal level in dBm for an 802.11 interface, where the kernel reports
    /// one. `None` on wired links and on platforms without a source.
    pub signal_dbm: Option<i32>,
    /// Cumulative 802.11 transmit retries, same caveat. A rate is derived
    /// against `tx_packets` upstream.
    pub tx_retries: Option<u64>,
}

/// Whether `rx_drops` and `tx_drops` are counted on this platform. macOS
/// reads `netstat -ibn`, which has no drop column, so its drops are 0 by
/// construction rather than by measurement. `netstat -ibnd` does print one;
/// reading it is future work.
pub const IFACE_DROPS_COUNTED: bool = !cfg!(target_os = "macos");

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

/// Interface names are the host's to choose: Linux accepts any byte but `/`,
/// `:` and whitespace, ESC included, and a Windows alias is whatever an admin
/// typed. Each name is made safe to draw here, so every caller gets it that
/// way. The cost is that a name this changes no longer opens its device, and
/// only whoever named the interface can cause that.
pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    platform_interface_stats().map(displayable_stats)
}

fn displayable_stats(stats: HashMap<String, InterfaceStats>) -> HashMap<String, InterfaceStats> {
    stats
        .into_iter()
        .map(|(name, mut stats)| {
            stats.name = display_owned(stats.name);
            (display_owned(name), stats)
        })
        .collect()
}

fn platform_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    #[cfg(target_os = "linux")]
    return linux::collect_interface_stats();

    #[cfg(target_os = "macos")]
    return macos::collect_interface_stats();

    #[cfg(target_os = "freebsd")]
    return freebsd::collect_interface_stats();

    #[cfg(target_os = "windows")]
    return windows::collect_interface_stats();

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    anyhow::bail!("Unsupported platform")
}

/// Name of the interface carrying the default route, if the platform can
/// tell us. Used to bias capture-interface selection toward the NIC that
/// actually carries traffic — on multi-NIC machines enumeration order says
/// nothing about which port has the cable (issue #43).
///
/// Made safe to draw like [`collect_interface_stats`], so it still matches
/// the names [`collect_interface_info`] returns.
pub fn default_route_interface() -> Option<String> {
    platform_default_route_interface().map(display_owned)
}

fn platform_default_route_interface() -> Option<String> {
    #[cfg(target_os = "linux")]
    return linux::default_route_interface();

    #[cfg(target_os = "macos")]
    return macos::default_route_interface();

    #[cfg(target_os = "freebsd")]
    return freebsd::default_route_interface();

    #[cfg(target_os = "windows")]
    return windows::default_route_interface();

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    None
}

/// Negotiated link speed in bits per second, when the OS will tell us.
///
/// Feeds the Dense view's saturation meter: "51% of a 1 Gb link" is a fact
/// about your network, while "51% of the busiest second we've seen" is a fact
/// about our own sampling. Only the first is worth a red zone, so where this
/// returns `None` the meter re-labels itself rather than inventing a ceiling.
///
/// Two cfg'd definitions rather than one function with cfg'd blocks: the block
/// form leaves a `return` that is needless on exactly one platform, which is a
/// lint you only see on that platform's CI.
#[cfg(target_os = "linux")]
pub fn link_speed_bps(iface: &str) -> Option<u64> {
    // /sys/class/net/<if>/speed is in Mb/s, and reads -1 (or fails with
    // EINVAL) for virtual, down, or wireless interfaces that can't report one.
    let raw = std::fs::read_to_string(format!("/sys/class/net/{iface}/speed")).ok()?;
    let mbps: i64 = raw.trim().parse().ok()?;
    if mbps <= 0 {
        return None;
    }
    Some(mbps as u64 * 1_000_000)
}

/// macOS: `ifi_baudrate` from `getifaddrs`, which is the link's currently
/// negotiated rate — a real gigabit figure on Ethernet, and the live PHY rate
/// on Wi-Fi (it moves as the radio renegotiates, because the capacity really
/// does move).
///
/// `getifaddrs` is a syscall, deliberately: this is read on every refresh, and
/// the rest of this module already shells out to `netstat`/`ifconfig` per tick.
/// Adding a fourth fork to the tick path to fetch one integer would be a poor
/// trade.
#[cfg(target_os = "macos")]
pub fn link_speed_bps(iface: &str) -> Option<u64> {
    use std::ffi::CStr;

    let mut ifap: *mut nix::libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `ifap` with an owned list we free below; every
    // pointer is null-checked before it is read.
    if unsafe { nix::libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
        return None;
    }
    let mut speed = None;
    let mut cur = ifap;
    while !cur.is_null() {
        let entry = unsafe { &*cur };
        cur = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_data.is_null() {
            continue;
        }
        // Only the AF_LINK entry carries `if_data`; the AF_INET ones don't.
        if i32::from(unsafe { (*entry.ifa_addr).sa_family }) != nix::libc::AF_LINK {
            continue;
        }
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        if name.to_string_lossy() != iface {
            continue;
        }
        let data = unsafe { &*(entry.ifa_data as *const nix::libc::if_data) };
        if data.ifi_baudrate > 0 {
            speed = Some(u64::from(data.ifi_baudrate));
        }
        break;
    }
    // SAFETY: `ifap` came from a successful `getifaddrs` and is freed once.
    unsafe { nix::libc::freeifaddrs(ifap) };
    speed
}

/// FreeBSD: same `getifaddrs`/`AF_LINK`/`if_data.ifi_baudrate` approach as
/// macOS — the struct and field are shared BSD ABI. Lives in `freebsd.rs`
/// since that module also needs `getifaddrs` for nothing else, unlike macOS
/// where this function sits directly in this file.
#[cfg(target_os = "freebsd")]
pub fn link_speed_bps(iface: &str) -> Option<u64> {
    freebsd::link_speed_bps(iface)
}

/// Windows would come from `GetIfEntry2`'s `TransmitLinkSpeed`; not wired up
/// yet, so the saturation meter falls back to labelling itself against the
/// observed peak rather than inventing a ceiling.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
pub fn link_speed_bps(_iface: &str) -> Option<u64> {
    None
}

/// Names made safe to draw, as in [`collect_interface_stats`].
pub fn collect_interface_info() -> Result<Vec<InterfaceInfo>> {
    platform_interface_info().map(displayable_info)
}

fn displayable_info(infos: Vec<InterfaceInfo>) -> Vec<InterfaceInfo> {
    infos
        .into_iter()
        .map(|mut info| {
            info.name = display_owned(info.name);
            info
        })
        .collect()
}

fn platform_interface_info() -> Result<Vec<InterfaceInfo>> {
    #[cfg(target_os = "linux")]
    return linux::collect_interface_info();

    #[cfg(target_os = "macos")]
    return macos::collect_interface_info();

    #[cfg(target_os = "freebsd")]
    return freebsd::collect_interface_info();

    #[cfg(target_os = "windows")]
    return windows::collect_interface_info();

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    anyhow::bail!("Unsupported platform")
}

#[cfg(test)]
mod link_speed_tests {
    /// Talks to the running kernel, so it is environment-dependent and
    /// `#[ignore]`d. Run it to see what your link actually reports:
    /// `cargo test --lib link_speed -- --ignored --nocapture`
    ///
    /// A saturation meter is only worth drawing if this returns a real
    /// capacity; where it returns `None` the meter has to say so rather than
    /// invent a ceiling.
    #[test]
    #[ignore]
    fn live_link_speed_is_plausible() {
        for iface in ["en0", "eth0", "wlan0"] {
            if let Some(bps) = super::link_speed_bps(iface) {
                println!("{iface}: {bps} bps ({} Mb)", bps / 1_000_000);
                assert!(
                    (1_000_000..=800_000_000_000u64).contains(&bps),
                    "{iface} reported {bps} bps, which is not a link speed"
                );
            }
        }
    }
}

#[cfg(test)]
mod interface_name_tests {
    use super::*;

    const HOSTILE: &str = "eth\x1b]0;owned\x07\u{202E}0";

    /// `ip link add $'eth\e]0;owned\a0' type dummy` puts an escape sequence
    /// in every view that lists interfaces.
    #[test]
    fn interface_name_control_characters_are_replaced() {
        let stats = InterfaceStats {
            name: HOSTILE.into(),
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: 0,
            tx_errors: 0,
            rx_drops: 0,
            tx_drops: 0,
            signal_dbm: None,
            tx_retries: None,
        };
        let stats = displayable_stats(HashMap::from([(HOSTILE.to_string(), stats)]));
        assert_eq!(stats["eth·]0;owned··0"].name, "eth·]0;owned··0");

        let info = InterfaceInfo {
            name: HOSTILE.into(),
            ipv4: None,
            ipv6: None,
            mac: None,
            mtu: None,
            is_up: true,
            is_wireless: None,
        };
        assert_eq!(displayable_info(vec![info])[0].name, "eth·]0;owned··0");
    }
}

#[cfg(test)]
mod capture_fix_tests {
    use super::LINUX_CAPTURE_FIX;

    /// The line the banner prints is the line the docs give, and the
    /// packages grant the same capabilities.
    #[test]
    fn the_fix_line_matches_the_docs_and_packages() {
        for (doc, text) in [
            ("README.md", include_str!("../../README.md")),
            ("docs/REFERENCE.md", include_str!("../../docs/REFERENCE.md")),
            ("docs/netwatch.1", include_str!("../../docs/netwatch.1")),
        ] {
            assert!(
                text.contains(LINUX_CAPTURE_FIX),
                "{doc} gives another setcap line"
            );
        }
        let caps = LINUX_CAPTURE_FIX.split_whitespace().nth(2).unwrap();
        assert_eq!(caps, "'cap_net_raw,cap_bpf,cap_perfmon+eip'");
        for (file, text) in [
            (
                "debian/postinst",
                include_str!("../../packaging/debian/postinst"),
            ),
            (
                "rpm/netwatch.spec",
                include_str!("../../packaging/rpm/netwatch.spec"),
            ),
            (
                "rpm/post_install.sh",
                include_str!("../../packaging/rpm/post_install.sh"),
            ),
        ] {
            assert!(text.contains(caps), "{file} grants other capabilities");
        }
    }
}
