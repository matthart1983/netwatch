//! Which policy a thread enters with, looked up by the name it was spawned
//! under.
//!
//! Spawn sites pass only a name, so a name missing from the table is a
//! parser. A network worker left out loses its connections, which shows up in
//! `isolated_worker_boundaries`, rather than a parser keeping network it
//! should not have.

/// What a thread does, and so which policy it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The UI or daemon thread. It starts network workers after its own
    /// entry, and a thread keeps every layer it inherits, so it keeps the
    /// network.
    Main,
    /// Workers whose job is a lookup, a probe or a publish. The filesystem
    /// policy only.
    Network,
    /// Everything else: workers that read packets, files, kernel tables or
    /// subprocess output and have no reason to connect anywhere. On top of
    /// the filesystem policy they lose TCP bind and connect, Unix sockets and
    /// signals outside their domain where the kernel can deny them, and
    /// CAP_NET_RAW.
    Parser,
    /// The packet capture thread: the parser policy, with the read grants
    /// and none of the write grants.
    Capture,
    /// The ProcBroker, which never enters. It keeps CAP_SYS_PTRACE and
    /// CAP_DAC_READ_SEARCH and drops the rest (`worker::relinquish`). Were it
    /// ever to enter, it would take the parser policy.
    Broker,
}

impl Role {
    /// The Landlock layer stacked on the filesystem one, or `None` for the
    /// roles that keep the network.
    pub fn layer(self) -> Option<&'static str> {
        match self {
            Role::Main | Role::Network => None,
            Role::Parser | Role::Broker => Some("parser"),
            Role::Capture => Some("capture"),
        }
    }
}

/// The role of the worker spawned as `name`.
pub fn role_for(name: &str) -> Role {
    match name {
        // `host` retries a truncated answer over TCP, the traceroute binary
        // resolves names through NSS, and the runtime's blocking pool takes
        // any blocking job, a name lookup among them. The rest connect by
        // design.
        "tokio-blocking" | "reverse-dns" | "whois" | "geoip" | "health" | "traceroute"
        | "insights" | "remote" | "diagnose-active" | "diagnose-test" | "diagnose-targets" => {
            Role::Network
        }
        "capture" => Role::Capture,
        "proc-broker" => Role::Broker,
        // keylog, metrics-listener, metrics-client, ebpf, connections,
        // tcp-info, traffic, process-cpu, terminal, logging, capture-export,
        // policy-preflight and pktap, and any name added without a row here.
        _ => Role::Parser,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_worker_name_maps_to_its_role() {
        for (name, role) in [
            ("tokio-blocking", Role::Network),
            ("reverse-dns", Role::Network),
            ("whois", Role::Network),
            ("geoip", Role::Network),
            ("health", Role::Network),
            ("traceroute", Role::Network),
            ("insights", Role::Network),
            ("remote", Role::Network),
            ("diagnose-active", Role::Network),
            ("diagnose-test", Role::Network),
            ("diagnose-targets", Role::Network),
            ("capture", Role::Capture),
            ("proc-broker", Role::Broker),
            ("keylog", Role::Parser),
            ("metrics-listener", Role::Parser),
            ("metrics-client", Role::Parser),
            ("ebpf", Role::Parser),
            ("connections", Role::Parser),
            ("tcp-info", Role::Parser),
            ("traffic", Role::Parser),
            ("process-cpu", Role::Parser),
            ("terminal", Role::Parser),
            ("logging", Role::Parser),
            ("capture-export", Role::Parser),
            ("policy-preflight", Role::Parser),
            ("pktap", Role::Parser),
        ] {
            assert_eq!(role_for(name), role, "{name}");
        }
    }

    #[test]
    fn unknown_name_is_parser() {
        // Fails closed: a worker added without a row loses the network.
        for name in ["", "new-worker", "Capture", "whois ", "smoke"] {
            assert_eq!(role_for(name), Role::Parser, "{name:?}");
        }
    }

    #[test]
    fn only_main_and_network_keep_the_network() {
        assert_eq!(Role::Main.layer(), None);
        assert_eq!(Role::Network.layer(), None);
        assert_eq!(Role::Parser.layer(), Some("parser"));
        assert_eq!(Role::Broker.layer(), Some("parser"));
        assert_eq!(Role::Capture.layer(), Some("capture"));
    }
}
