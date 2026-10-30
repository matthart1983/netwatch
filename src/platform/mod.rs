#[cfg(target_os = "freebsd")]
pub mod freebsd;
/// ICMP echo outcomes as Windows' ICMP API reports them. Platform-neutral so
/// the decoding is tested everywhere; only the calls are Windows-only.
pub mod icmp;
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

/// The command the capture error and the Dashboard banner give for capture
/// without root on Linux. CAP_BPF and CAP_PERFMON are for eBPF attribution
/// (`sandbox/mod.rs`). It restricts the binary to a group before granting it,
/// because file capabilities on a world-executable binary let every local
/// account capture. `setcap` comes last, as `chown` clears file capabilities.
///
/// It finds the binary once, first. Once `chmod` has taken it away from an
/// account not yet in the group, another `which netwatch` finds a different
/// netwatch further down `PATH`, or none, and `setcap` would grant that one.
/// Each `&&` stops the chain before a binary is granted anything unrestricted,
/// such as where a Nix store refuses the `chown`. REFERENCE.md has the longer
/// recipe that copies a binary like that one.
pub const LINUX_CAPTURE_FIX: &str = r#"b=$(readlink -f "$(which netwatch)") && sudo groupadd -f netwatch && sudo usermod -aG netwatch "$USER" && sudo chown root:netwatch "$b" && sudo chmod 0750 "$b" && sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$b""#;

/// What [`capture_fix`] says on Windows. Named so doctor's Npcap wording can
/// use it, and be tested, on every platform rather than only on Windows.
pub const WINDOWS_CAPTURE_FIX: &str =
    "install Npcap from https://npcap.com/#download, without \"restrict to administrators\"";

/// What lets netwatch capture on this OS when opening a capture was refused.
/// The one place it is written, so the error and the Dashboard banner cannot
/// drift apart.
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

/// macOS and FreeBSD: `ifi_baudrate` from `getifaddrs`, which is the link's
/// currently negotiated rate — a real gigabit figure on Ethernet, and the live
/// PHY rate on Wi-Fi (it moves as the radio renegotiates, because the capacity
/// really does move). FreeBSD's `<net/if.h>` has an `ifi_baudrate` in its
/// `struct if_data` too, but the layouts differ and the field is a u64 there
/// where macOS has a u32, so it is read by name from the target's own struct.
///
/// `getifaddrs` is a syscall, deliberately: this is read on every refresh, and
/// the rest of this module already shells out to `netstat`/`ifconfig` per tick.
/// Adding a fourth fork to the tick path to fetch one integer would be a poor
/// trade.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub fn link_speed_bps(iface: &str) -> Option<u64> {
    let mut ifap: *mut nix::libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `ifap` with an owned list we free below.
    if unsafe { nix::libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
        return None;
    }
    // SAFETY: `ifap` is the list `getifaddrs` just returned, not yet freed.
    let speed = unsafe { link_baudrate(ifap, iface) };
    // SAFETY: `ifap` came from a successful `getifaddrs` and is freed once.
    unsafe { nix::libc::freeifaddrs(ifap) };
    speed
}

/// `ifi_baudrate` from `iface`'s `AF_LINK` entry in a `getifaddrs` list, when
/// it reports one. Only the `AF_LINK` entry carries `if_data`; the `AF_INET`
/// ones don't.
///
/// # Safety
///
/// `list` is null or the head of a live list laid out as `getifaddrs` returns
/// it: every non-null `ifa_next`, `ifa_name` and `ifa_addr` points at an
/// entry, a NUL-terminated name and a `sockaddr`, and an `AF_LINK` entry's
/// non-null `ifa_data` points at its `if_data`.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
unsafe fn link_baudrate(list: *const nix::libc::ifaddrs, iface: &str) -> Option<u64> {
    use std::ffi::CStr;

    let mut cur = list;
    // SAFETY: `cur` is the head or an `ifa_next`, so null or a live entry.
    while let Some(entry) = unsafe { cur.as_ref() } {
        cur = entry.ifa_next;
        if entry.ifa_name.is_null() || entry.ifa_addr.is_null() || entry.ifa_data.is_null() {
            continue;
        }
        // SAFETY: checked non-null above, and a `sockaddr` by the contract.
        if i32::from(unsafe { (*entry.ifa_addr).sa_family }) != nix::libc::AF_LINK {
            continue;
        }
        // SAFETY: checked non-null above, and NUL-terminated by the contract.
        if unsafe { CStr::from_ptr(entry.ifa_name) }.to_string_lossy() != iface {
            continue;
        }
        let data = entry.ifa_data.cast::<nix::libc::if_data>();
        // SAFETY: checked non-null above, and this entry's `if_data` by the
        // contract. Only the one field is read, without a reference to the
        // whole struct, so nothing is assumed about the bytes around it.
        let baud = unsafe { std::ptr::addr_of!((*data).ifi_baudrate).read_unaligned() };
        // u32 on macOS, u64 on FreeBSD.
        #[cfg(target_os = "macos")]
        let baud = u64::from(baud);
        return (baud > 0).then_some(baud);
    }
    None
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

    /// The walk reads each entry's name as a C string, so a null one has to
    /// be passed over, not read.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn null_ifa_name_is_skipped() {
        use nix::libc::{if_data, ifaddrs, sa_family_t, sockaddr, AF_LINK};
        use std::ptr::addr_of_mut;

        let mut addr = sockaddr {
            sa_family: AF_LINK as sa_family_t,
            ..Default::default()
        };
        // libc has no `Default` for FreeBSD's `if_data`, whose timestamps
        // are unions.
        // SAFETY: `if_data` is integers and unions of integers and
        // timevals, for which all-zero bytes are a valid value.
        let mut data: if_data = unsafe { std::mem::zeroed() };
        data.ifi_baudrate = 1_000_000_000;
        let mut named = ifaddrs {
            ifa_name: c"en0".as_ptr().cast_mut(),
            ifa_addr: addr_of_mut!(addr),
            ifa_data: addr_of_mut!(data).cast(),
            ..Default::default()
        };
        // An AF_LINK entry with data but no name, ahead of the one we want.
        let unnamed = ifaddrs {
            ifa_next: addr_of_mut!(named),
            ifa_addr: addr_of_mut!(addr),
            ifa_data: addr_of_mut!(data).cast(),
            ..Default::default()
        };

        // SAFETY: both entries and everything they point at live on this
        // frame for the whole call, and the walk only reads them.
        let speed = unsafe { super::link_baudrate(&unnamed, "en0") };
        assert_eq!(speed, Some(1_000_000_000));
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

    const CAPS: &str = "'cap_net_raw,cap_bpf,cap_perfmon+eip'";

    /// The banner, the docs and the packages grant the same capabilities, and
    /// none of them to a binary every local account can run.
    #[test]
    fn the_fix_line_matches_the_docs_and_packages() {
        assert!(LINUX_CAPTURE_FIX.contains(CAPS));
        assert!(
            include_str!("../../docs/REFERENCE.md").contains(LINUX_CAPTURE_FIX),
            "REFERENCE.md does not give the line the capture error prints"
        );
        for (doc, text) in [
            ("README.md", include_str!("../../README.md")),
            ("docs/REFERENCE.md", include_str!("../../docs/REFERENCE.md")),
            ("docs/netwatch.1", include_str!("../../docs/netwatch.1")),
        ] {
            assert!(
                text.contains("cap_net_raw,cap_bpf,cap_perfmon+eip"),
                "{doc} gives another capability set"
            );
            assert!(
                !text.contains(r#"sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$(which"#),
                "{doc} grants capabilities to a world-executable binary"
            );
        }
    }

    /// Each post-install prints the steps in the order that works: `chown`
    /// clears file capabilities, so `setcap` has to come after it.
    #[test]
    fn the_packages_restrict_the_binary_before_granting_it() {
        for (file, text, bin) in [
            (
                "debian/postinst",
                include_str!("../../packaging/debian/postinst"),
                "/usr/bin/netwatch",
            ),
            (
                "rpm/post_install.sh",
                include_str!("../../packaging/rpm/post_install.sh"),
                "/usr/bin/netwatch",
            ),
            (
                "rpm/netwatch.spec %post",
                include_str!("../../packaging/rpm/netwatch.spec")
                    .split_once("%post")
                    .unwrap()
                    .1,
                "/usr/bin/netwatch",
            ),
            (
                "rpm/netwatch.spec %description",
                include_str!("../../packaging/rpm/netwatch.spec")
                    .split_once("%description")
                    .unwrap()
                    .1,
                "%{_bindir}/netwatch",
            ),
        ] {
            let at = |line: String| {
                text.find(&line)
                    .unwrap_or_else(|| panic!("{file} does not say {line:?}"))
            };
            let group = at("groupadd -f netwatch".to_string());
            let member = at(r#"usermod -aG netwatch "$USER""#.to_string());
            let owner = at(format!("chown root:netwatch {bin}"));
            let mode = at(format!("chmod 0750 {bin}"));
            let grant = at(format!("setcap {CAPS} {bin}"));
            assert!(
                group < member && member < owner && owner < mode && mode < grant,
                "{file} gives the steps out of order"
            );
        }
    }

    /// The line run by `sh` for an account not yet in the group, which is
    /// everyone the first time: once `chmod` has run, `which` cannot find the
    /// binary. A second, later `netwatch` on PATH stands in for the one
    /// another `which` would hand to `setcap`.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_fix_line_grants_the_binary_it_found_first() {
        use std::os::unix::fs::PermissionsExt;
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let scratch =
            Scratch(std::env::temp_dir().join(format!("netwatch-fix-{}", uuid::Uuid::new_v4())));
        let root = scratch.0.as_path();
        let tools = root.join("tools");
        std::fs::create_dir_all(&tools).unwrap();
        let dirs: Vec<_> = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        for tool in ["readlink", "chmod"] {
            let found = dirs
                .iter()
                .map(|dir: &std::path::PathBuf| dir.as_path())
                .chain([
                    std::path::Path::new("/usr/bin"),
                    std::path::Path::new("/bin"),
                ])
                .map(|dir| dir.join(tool))
                .find(|p| p.exists())
                .unwrap_or_else(|| panic!("no {tool}"));
            std::os::unix::fs::symlink(found, tools.join(tool)).unwrap();
        }
        const SHIMS: &str = r#"
which() {
  old=$IFS; IFS=:
  for dir in $PATH; do
    [ -x "$dir/$1" ] && { IFS=$old; echo "$dir/$1"; return 0; }
  done
  IFS=$old; return 1
}
sudo() {
  case $1 in
    groupadd | usermod) echo "$1" ;;
    chmod) chmod 0600 "$3"; echo "chmod $3" ;;
    chown | setcap) echo "$1 $3" ;;
  esac
}
"#;
        let run = || {
            let path = ["first", "second"]
                .map(|dir| root.join(dir).display().to_string())
                .join(":");
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("{SHIMS}{LINUX_CAPTURE_FIX}"))
                .env_clear()
                .env("PATH", format!("{path}:{}", tools.display()))
                .env("USER", "user")
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|l| l.replace(&format!("{}/", root.display()), ""))
                .collect::<Vec<_>>()
                .join(", ")
        };

        // With no netwatch on PATH nothing runs, group changes included.
        std::fs::create_dir(root.join("first")).unwrap();
        std::fs::create_dir(root.join("second")).unwrap();
        assert_eq!(run(), "");

        for dir in ["first", "second"] {
            let bin = root.join(dir).join("netwatch");
            std::fs::write(&bin, "").unwrap();
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(
            run(),
            "groupadd, usermod, chown first/netwatch, chmod first/netwatch, setcap first/netwatch"
        );
    }

    /// The group-restricted recipe in REFERENCE.md and the man page, run by
    /// `sh` in a scratch tree standing in for /usr/bin, /usr/local/bin, a
    /// cargo bin directory and a Nix store and profile. `sudo` records which
    /// file each command would change, and `stat` names the owner a real
    /// system would: root for package, store and profile files and for the
    /// copy `sudo install` makes, the user for a cargo build.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_setcap_recipe_grants_the_file_it_describes() {
        use std::path::Path;
        let reference = include_str!("../../docs/REFERENCE.md")
            .split_once("### Running without sudo")
            .and_then(|(_, rest)| rest.split_once("```bash\n"))
            .and_then(|(_, rest)| rest.split_once("```"))
            .unwrap()
            .0;
        let man = include_str!("../../docs/netwatch.1")
            .split_once(".SH PERMISSIONS")
            .and_then(|(_, rest)| rest.split_once(".nf\n"))
            .and_then(|(_, rest)| rest.split_once(".fi"))
            .unwrap()
            .0
            .replace("\\-", "-")
            .replace("\\e", "\\");
        // The man page leaves out the comments and the closing echo.
        let commands = |recipe: &str| {
            recipe
                .lines()
                .filter(|l| !l.trim_start().starts_with('#') && !l.starts_with("echo "))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(commands(reference), commands(&man), "the recipes differ");

        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let scratch =
            Scratch(std::env::temp_dir().join(format!("netwatch-recipe-{}", uuid::Uuid::new_v4())));
        std::fs::create_dir(&scratch.0).unwrap();
        let root = std::fs::canonicalize(&scratch.0).unwrap();
        // Only the tools the recipe needs, so a netwatch installed on this
        // machine cannot be found.
        let tools = root.join("tools");
        std::fs::create_dir(&tools).unwrap();
        // PATH first: the Nix build sandbox has them nowhere else.
        let dirs: Vec<_> = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        for tool in ["tr", "grep", "readlink", "cp"] {
            let found = dirs
                .iter()
                .map(|dir| dir.as_path())
                .chain([Path::new("/usr/bin"), Path::new("/bin")])
                .map(|dir| dir.join(tool))
                .find(|p| p.exists())
                .unwrap_or_else(|| panic!("no {tool}"));
            std::os::unix::fs::symlink(found, tools.join(tool)).unwrap();
        }
        const SHIMS: &str = r#"
sudo() {
  case $1 in
    install) shift $(($# - 2)); cp "$1" "$2"; echo "install $2" ;;
    chown | chmod | setcap) echo "$1 $3" ;;
  esac
}
stat() { case ${3#"$PWD"/} in usr/* | local/* | store/* | profile/*) echo root ;; *) echo user ;; esac; }
"#;
        for dir in ["usr", "local", "cargo", "store", "profile"] {
            std::fs::create_dir(root.join(dir)).unwrap();
        }
        // A new file each time, as an upgrade writes.
        let put = |path: &str, text: &str| {
            let path = root.join(path);
            let _ = std::fs::remove_file(&path);
            std::fs::write(&path, text).unwrap();
            let mode = std::os::unix::fs::PermissionsExt::from_mode(0o755);
            std::fs::set_permissions(&path, mode).unwrap();
        };
        // What the recipe changes, as "<command> <path under root>" lines,
        // and what the copy in /usr/local/bin then holds.
        let run = |recipe: &str, path: &[&str]| {
            let script = recipe
                .replace("/usr/local/bin", &root.join("local").display().to_string())
                .replace(
                    "/usr/bin/netwatch",
                    &root.join("usr/netwatch").display().to_string(),
                );
            let path = path
                .iter()
                .map(|dir| root.join(dir))
                .chain([tools.clone()])
                .map(|dir| dir.display().to_string())
                .collect::<Vec<_>>()
                .join(":");
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("{SHIMS}{script}"))
                .env_clear()
                .env("PATH", path)
                .env("USER", "user")
                .current_dir(&root)
                .output()
                .unwrap();
            let prefix = format!("{}/", root.display());
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let changed = stdout
                .lines()
                .filter(|l| !l.starts_with("After"))
                .chain(stderr.lines())
                .map(|l| l.replace(&prefix, ""))
                .collect::<Vec<_>>()
                .join(", ");
            let copy = std::fs::read_to_string(root.join("local/netwatch")).ok();
            (changed, copy)
        };
        let in_place = |file: &str| format!("chown {file}, chmod {file}, setcap {file}");
        let copied = format!("install local/netwatch, {}", in_place("local/netwatch"));

        for recipe in [reference, man.as_str()] {
            // A package: changed in place, so an upgrade resets it.
            put("usr/netwatch", "v1");
            assert_eq!(
                run(recipe, &["local", "usr"]),
                (in_place("usr/netwatch"), None)
            );
            std::fs::remove_file(root.join("usr/netwatch")).unwrap();

            // A cargo build, with /usr/local/bin ahead of the cargo bin
            // directory in PATH: copied, and after an upgrade the re-run
            // copies the new build, not the old copy onto itself.
            put("cargo/netwatch", "v1");
            let path = ["local", "usr", "cargo"];
            assert_eq!(run(recipe, &path), (copied.clone(), Some("v1".into())));
            put("cargo/netwatch", "v2");
            assert_eq!(run(recipe, &path), (copied.clone(), Some("v2".into())));
            std::fs::remove_file(root.join("cargo/netwatch")).unwrap();
            std::fs::remove_file(root.join("local/netwatch")).unwrap();

            // A Nix profile's symlink into the store: the store file is
            // copied, never changed.
            put("store/netwatch", "v1");
            std::os::unix::fs::symlink(root.join("store/netwatch"), root.join("profile/netwatch"))
                .unwrap();
            assert_eq!(
                run(recipe, &["profile", "local"]),
                (copied.clone(), Some("v1".into()))
            );
            std::fs::remove_file(root.join("profile/netwatch")).unwrap();
            std::fs::remove_file(root.join("store/netwatch")).unwrap();
            std::fs::remove_file(root.join("local/netwatch")).unwrap();
        }
    }
}
