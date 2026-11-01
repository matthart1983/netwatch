//! Resolver ownership and typed command boundary. No arbitrary target paths or
//! shell commands are accepted by the CLI. Managed resolvers remain instructions.
use std::{io, net::IpAddr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ownership {
    SystemdResolved,
    NetworkManager,
    OtherManaged,
    Symlink,
    UnconfirmedRegular,
    Unsupported,
}
impl Ownership {
    pub fn description(&self) -> &'static str {
        match self {
            Self::SystemdResolved => {
                "systemd-resolved owns resolver configuration; use its per-link settings"
            }
            Self::NetworkManager => {
                "NetworkManager owns resolver configuration; use its connection DNS settings"
            }
            Self::OtherManaged => {
                "resolver configuration is generated or managed; use its owning manager"
            }
            Self::Symlink => "resolver is a symlink; direct file editing is unsupported",
            Self::UnconfirmedRegular => {
                "regular resolver file; administrator must confirm unmanaged ownership"
            }
            Self::Unsupported => "resolver adapter is unavailable on this platform",
        }
    }
}

/// Classification is conservative. Plain text is not proof of unmanaged ownership.
#[cfg(any(target_os = "linux", test))]
fn classify(link: Option<&str>, contents: &str) -> Ownership {
    let evidence = format!("{}\n{contents}", link.unwrap_or("")).to_ascii_lowercase();
    if evidence.contains("systemd")
        || evidence.contains("127.0.0.53")
        || evidence.contains("127.0.0.54")
    {
        Ownership::SystemdResolved
    } else if evidence.contains("networkmanager") {
        Ownership::NetworkManager
    } else if evidence.contains("generated")
        || evidence.contains("resolvconf")
        || evidence.contains("dhclient")
        || evidence.contains("do not edit")
    {
        Ownership::OtherManaged
    } else if link.is_some() {
        Ownership::Symlink
    } else {
        Ownership::UnconfirmedRegular
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Request {
    Status,
    Set { address: IpAddr, seconds: u64 },
    Recover,
}
fn parse(args: &[String]) -> io::Result<Request> {
    let invalid = || {
        io::Error::new(io::ErrorKind::InvalidInput,
        "usage: netwatch resolver status | set <IP> --unmanaged [--seconds 1..3600] | recover --unmanaged")
    };
    match args.first().map(String::as_str) {
        Some("status") if args.len() == 1 => Ok(Request::Status),
        Some("recover") if args.len() == 2 && args[1] == "--unmanaged" => Ok(Request::Recover),
        Some("set") if (args.len() == 3 || args.len() == 5) && args[2] == "--unmanaged" => {
            let address: IpAddr = args[1].parse().map_err(|_| invalid())?;
            if address.is_unspecified()
                || address.is_multicast()
                || address.is_loopback()
                || matches!(address, IpAddr::V4(ip) if ip.is_broadcast())
                || matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local())
            {
                return Err(invalid());
            }
            let seconds = if args.len() == 5 {
                if args[3] != "--seconds" {
                    return Err(invalid());
                }
                args[4].parse::<u64>().map_err(|_| invalid())?
            } else {
                60
            };
            if !(1..=3600).contains(&seconds) {
                return Err(invalid());
            }
            Ok(Request::Set { address, seconds })
        }
        _ => Err(invalid()),
    }
}

#[cfg(target_os = "linux")]
mod linux;

pub fn ownership() -> io::Result<Ownership> {
    #[cfg(target_os = "linux")]
    {
        linux::ownership()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(Ownership::Unsupported)
    }
}

pub fn authority_notice() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        linux::authority_notice()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// For the log and `doctor`, when the kernel refuses this user the root-owned
/// store. Not a recovery notice: nothing here knows whether the store holds one.
pub fn authority_refusal() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        linux::authority_refusal()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// One line of a command's report. `println!` panics when stdout is closed or
/// full, and these commands must finish whatever happens to their output: by its
/// first line `set` has changed the resolver, and only it can put it back at the
/// deadline. What they did is in the exit status and the store, not in this text.
fn report(line: &str) {
    use std::io::Write;
    let _ = writeln!(io::stdout(), "{line}");
}

/// Called synchronously before the application's runtime, Npcap or workers start.
pub fn command(args: &[String]) -> anyhow::Result<()> {
    let request = parse(args)?;
    #[cfg(target_os = "linux")]
    {
        linux::command(request)
    }
    #[cfg(not(target_os = "linux"))]
    {
        match request {
            Request::Status => {
                report(Ownership::Unsupported.description());
                Ok(())
            }
            _ => anyhow::bail!("resolver changes are unavailable on this platform"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_and_unknown_resolvers_are_not_inferred_unmanaged() {
        assert_eq!(
            classify(Some("../run/systemd/resolve/stub-resolv.conf"), ""),
            Ownership::SystemdResolved
        );
        assert_eq!(
            classify(None, "# Generated by NetworkManager"),
            Ownership::NetworkManager
        );
        assert_eq!(
            classify(None, "# generated by DHCP"),
            Ownership::OtherManaged
        );
        assert_eq!(classify(Some("custom.conf"), ""), Ownership::Symlink);
        assert_eq!(
            classify(None, "nameserver 8.8.8.8\n"),
            Ownership::UnconfirmedRegular
        );
    }
    #[test]
    fn command_requires_typed_address_confirmation_and_bounded_lifetime() {
        let args = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert!(parse(&args("set 1.1.1.1")).is_err());
        assert!(parse(&args("set example.com --unmanaged")).is_err());
        assert!(parse(&args("set 0.0.0.0 --unmanaged")).is_err());
        assert!(parse(&args("set 1.1.1.1 --unmanaged --seconds 0")).is_err());
        assert!(parse(&args("set 1.1.1.1 --unmanaged --target /tmp/x")).is_err());
        assert!(parse(&args("recover")).is_err());
        assert!(matches!(
            parse(&args("set 2606:4700:4700::1111 --unmanaged --seconds 3")),
            Ok(Request::Set { seconds: 3, .. })
        ));
    }
}
