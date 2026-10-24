//! Developer targets: hosts the user says matter, probed stage by stage.
//!
//! ```text
//!   resolve ──▶ connect ──▶ tls ──▶ http
//!   system       first addr   rustls   GET path, status, Date
//!   + each       + v4 and v6
//!   resolver
//! ```
//!
//! A failing request to `api.staging.internal` is only useful to diagnose if
//! we know *which stage* failed and *what else was true*: a VPN interface is
//! up but its routing domain isn't configured; the port refuses, so the host
//! is there and the service isn't; the certificate is "not yet valid" and the
//! server's clock disagrees with ours by an hour. The probe records the stage
//! outcomes and that context; the detectors in `detectors.rs` turn them into
//! issues.
//!
//! Some answers are not network faults at all — a name that doesn't exist, a
//! service that is stopped. Those are still reported, but as information, so
//! a developer isn't sent chasing the network for a typo.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// One `[[diagnose_targets]]` entry in config.toml.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Defaults to true on 443.
    #[serde(default)]
    pub tls: Option<bool>,
    /// Request `path` over HTTP(S). False for plain TCP services.
    #[serde(default = "default_true")]
    pub http: bool,
    #[serde(default = "default_path")]
    pub path: String,
    /// When set, any other status is an error.
    #[serde(default)]
    pub expect_status: Option<u16>,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
}

fn default_port() -> u16 {
    443
}
fn default_true() -> bool {
    true
}
fn default_path() -> String {
    "/".into()
}
fn default_interval() -> u64 {
    60
}

impl TargetConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty()
            || self.name.len() > 128
            || self.name.chars().any(char::is_control)
        {
            return Err("target name must contain 1–128 printable bytes".into());
        }
        if self.host.is_empty()
            || self.host.len() > 253
            || self
                .host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || "/?#@".contains(c))
        {
            return Err("target host must be a hostname or IP address without a URL scheme".into());
        }
        if self.port == 0 || !(10..=86400).contains(&self.interval_secs) {
            return Err("target port must be nonzero and interval_secs must be 10–86400".into());
        }
        if !self.path.starts_with('/')
            || self.path.len() > 2048
            || self
                .path
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(
                "target path must start with / and contain no whitespace or control characters"
                    .into(),
            );
        }
        if self
            .expect_status
            .is_some_and(|s| !(100..=599).contains(&s))
        {
            return Err("expected HTTP status must be 100–599".into());
        }
        Ok(())
    }

    pub fn baseline_key(&self) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, self.identity().as_bytes());
        format!(
            "target-config:{}",
            digest
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }

    fn identity(&self) -> String {
        serde_json::to_string(self).expect("target configuration serializes")
    }

    pub fn uses_tls(&self) -> bool {
        self.tls.unwrap_or(self.port == 443)
    }

    /// A result older than this is stale. Three missed probes, at least 3 min.
    pub fn stale_after_secs(&self) -> u64 {
        self.interval_secs.max(10).saturating_mul(3).max(180)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StageError {
    /// The name does not exist.
    NxDomain,
    /// The resolver couldn't answer: SERVFAIL, timeout, no resolver.
    ResolverFailed,
    Timeout,
    Refused,
    Unreachable,
    CertUntrusted,
    CertExpired,
    CertNotYetValid,
    CertNameMismatch,
    TlsAlert {
        alert: String,
    },
    HttpStatus {
        status: u16,
    },
    Other {
        message: String,
    },
}

impl StageError {
    pub fn label(&self) -> String {
        match self {
            StageError::NxDomain => "no such name".into(),
            StageError::ResolverFailed => "resolver could not answer".into(),
            StageError::Timeout => "timed out".into(),
            StageError::Refused => "connection refused".into(),
            StageError::Unreachable => "network unreachable".into(),
            StageError::CertUntrusted => "certificate from an untrusted issuer".into(),
            StageError::CertExpired => "certificate expired".into(),
            StageError::CertNotYetValid => "certificate not yet valid".into(),
            StageError::CertNameMismatch => "certificate is for a different name".into(),
            StageError::TlsAlert { alert } => format!("tls alert {alert}"),
            StageError::HttpStatus { status } => format!("http {status}"),
            StageError::Other { message } => message.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stage {
    pub ms: Option<f64>,
    pub error: Option<StageError>,
}

impl Stage {
    fn ok(ms: f64) -> Self {
        Self {
            ms: Some(ms),
            error: None,
        }
    }
    fn failed(ms: Option<f64>, error: StageError) -> Self {
        Self {
            ms,
            error: Some(error),
        }
    }
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupOutcome {
    Answered,
    NxDomain,
    ServFail,
    NoReply,
}

/// The name asked directly of one resolver, bypassing the system's choice.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lookup {
    pub resolver: String,
    /// The interface this resolver belongs to, from systemd-resolved.
    pub link: Option<String>,
    pub outcome: LookupOutcome,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TargetContext {
    /// GNOME proxy mode, when its settings are available. PAC mode does not
    /// prove that a proxy applies to any particular destination.
    #[serde(default)]
    pub system_proxy_mode: Option<String>,
    /// Local container bridges, for explaining which network was observed.
    #[serde(default)]
    pub container_bridges: Vec<String>,
    /// An HTTP(S)/ALL proxy is set for this process and the host isn't in
    /// NO_PROXY. Other processes may see a different environment.
    pub proxy_env: bool,
    /// tun, wg, tailscale and similar interfaces that are up.
    pub vpn_ifaces: Vec<String>,
    /// Routing domains configured per link, e.g. `("wg0", ["corp.internal"])`.
    pub link_domains: Vec<(String, Vec<String>)>,
    /// System clock minus the local NTP clock, when synchronised, in seconds.
    pub clock_offset_secs: Option<f64>,
}

/// One address tried during a probe, and what it returned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectAttempt {
    pub address: String,
    pub stage: Stage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetObs {
    #[serde(default)]
    pub baseline_key: Option<String>,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub http: bool,
    pub expect_status: Option<u16>,
    pub probed_at: String,
    pub resolve: Stage,
    pub addresses: Vec<String>,
    pub lookups: Vec<Lookup>,
    /// The first address, as a client would try it.
    pub connect: Option<Stage>,
    pub connect_v4: Option<Stage>,
    pub connect_v6: Option<Stage>,
    pub tls_stage: Option<Stage>,
    /// Time to the first byte of the response.
    pub http_stage: Option<Stage>,
    pub status: Option<u16>,
    /// Every address this probe tried, in order, with what each returned.
    /// The probe used to try only the first address: one dead address in a
    /// DNS answer made a working service look down.
    #[serde(default)]
    pub attempts: Vec<ConnectAttempt>,
    /// The address the later stages actually ran on.
    #[serde(default)]
    pub effective_endpoint: Option<String>,
    /// The name sent as SNI, when TLS was used.
    #[serde(default)]
    pub sni: Option<String>,
    /// The authority sent in the HTTP `Host` header, including the port when
    /// it is not the scheme's default and brackets around an IPv6 literal.
    #[serde(default)]
    pub http_authority: Option<String>,
    /// How long results for this target stay usable, from its configured
    /// probe interval. `None` in recordings made before the engine scoped
    /// staleness per target; those fall back to the global default.
    #[serde(default)]
    pub stale_after_secs: Option<u64>,
    pub context: TargetContext,
}

impl TargetObs {
    pub fn baseline_subject(&self) -> &str {
        self.baseline_key.as_deref().unwrap_or(&self.name)
    }
    /// The lookup a finding about this target records as its route: the
    /// first resolver that answered, else the first one asked. Suppression
    /// and `diagnose run --target` read the resolver and its link from it.
    pub fn route_lookup(&self) -> Option<&Lookup> {
        self.lookups
            .iter()
            .find(|l| l.outcome == LookupOutcome::Answered)
            .or_else(|| self.lookups.first())
    }
    /// Stage timings for the baseline store, as `(metric, ms)`.
    pub fn stage_readings(&self) -> Vec<(&'static str, f64)> {
        let mut out = Vec::new();
        let mut push = |metric, stage: Option<&Stage>| {
            if let Some(ms) = stage.filter(|s| s.is_ok()).and_then(|s| s.ms) {
                out.push((metric, ms));
            }
        };
        push("target.resolve_ms", Some(&self.resolve));
        push("target.connect_ms", self.connect.as_ref());
        push("target.tls_ms", self.tls_stage.as_ref());
        push("target.ttfb_ms", self.http_stage.as_ref());
        out
    }
}

/// What the probe needs from the host, gathered on the app thread.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProbeEnv {
    pub resolvers: Vec<IpAddr>,
    pub vpn_ifaces: Vec<String>,
}

pub const VPN_PREFIXES: &[&str] = &[
    "tun",
    "tap",
    "wg",
    "tailscale",
    "utun",
    "ppp",
    "zt",
    "nordlynx",
];

pub fn is_vpn_iface(name: &str) -> bool {
    VPN_PREFIXES.iter().any(|p| name.starts_with(p))
}

// ------------------------------------------------------------------ probe

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Addresses tried before giving up, so a long DNS answer cannot turn one
/// target into a minute of probing.
const MAX_ADDRESS_ATTEMPTS: usize = 4;
/// Total wall clock one target may spend connecting, across every address and
/// the extra per-family attempt. One unreachable target must not starve the
/// targets queued behind it.
const TARGET_BUDGET: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub fn probe(cfg: &TargetConfig, env: &ProbeEnv, now: impl Fn() -> String) -> TargetObs {
    probe_cancel(cfg, env, now, &super::probe_io::Cancel::default())
}

fn probe_cancel(
    cfg: &TargetConfig,
    env: &ProbeEnv,
    now: impl Fn() -> String,
    cancel: &super::probe_io::Cancel,
) -> TargetObs {
    let link_domains = link_domains();
    let mut obs = TargetObs {
        baseline_key: Some(cfg.baseline_key()),
        stale_after_secs: Some(cfg.stale_after_secs()),
        name: cfg.name.clone(),
        host: cfg.host.clone(),
        port: cfg.port,
        tls: cfg.uses_tls(),
        http: cfg.http,
        expect_status: cfg.expect_status,
        probed_at: String::new(),
        resolve: Stage::ok(0.0),
        addresses: vec![],
        lookups: vec![],
        connect: None,
        connect_v4: None,
        connect_v6: None,
        tls_stage: None,
        http_stage: None,
        status: None,
        attempts: vec![],
        effective_endpoint: None,
        sni: None,
        http_authority: None,
        context: TargetContext {
            system_proxy_mode: system_proxy_mode(),
            container_bridges: container_bridges(),
            proxy_env: proxy_applies(&cfg.host, |k| std::env::var(k).ok()),
            vpn_ifaces: env.vpn_ifaces.clone(),
            link_domains: link_domains
                .iter()
                .map(|l| (l.link.clone(), l.domains.clone()))
                .collect(),
            clock_offset_secs: local_clock_offset(),
        },
    };

    // ── resolve ──
    let addrs: Vec<SocketAddr> = if let Ok(ip) = cfg.host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, cfg.port)]
    } else {
        let started = Instant::now();
        let result = super::probe_io::resolve(&cfg.host, cfg.port, cancel);
        let ms = started.elapsed().as_secs_f64() * 1000.0;
        let mut servers: Vec<(IpAddr, Option<String>)> =
            env.resolvers.iter().map(|r| (*r, None)).collect();
        for l in &link_domains {
            for s in &l.servers {
                if !servers.iter().any(|(ip, _)| ip == s) {
                    servers.push((*s, Some(l.link.clone())));
                }
            }
        }
        obs.lookups = servers
            .into_iter()
            .take(4)
            .take_while(|_| !cancel.cancelled())
            .map(|(ip, link)| Lookup {
                resolver: ip.to_string(),
                link,
                outcome: direct_lookup(ip, &cfg.host),
            })
            .collect();
        match result {
            Ok(it) => {
                obs.resolve = Stage::ok(ms);
                it
            }
            Err(e) => {
                obs.resolve = Stage::failed(Some(ms), resolve_error(&e));
                vec![]
            }
        }
    };
    obs.addresses = addrs.iter().map(|a| a.ip().to_string()).collect();

    connect_stages(cfg, &addrs, cancel, &mut obs);
    obs.probed_at = now();
    obs
}

fn connect_stages(
    cfg: &TargetConfig,
    addrs: &[SocketAddr],
    cancel: &super::probe_io::Cancel,
    obs: &mut TargetObs,
) {
    // ── connect ──
    //
    // Every address in turn, not just the first: a DNS answer that leads with
    // a dead address used to make a working service look down, because the
    // first failure ended the probe and TLS and HTTP never ran. Attempts are
    // bounded and share one budget, so a target with a long address list
    // cannot hold up the targets queued behind it.
    let Some(first) = addrs.first().copied() else {
        return;
    };
    let deadline = Instant::now() + TARGET_BUDGET;
    let cancelled_stage = || {
        Stage::failed(
            None,
            StageError::Other {
                message: "probe cancelled".into(),
            },
        )
    };
    let budget_stage = || {
        Stage::failed(
            None,
            StageError::Other {
                message: "probe budget spent before this address was tried".into(),
            },
        )
    };
    let mut selected: Option<(SocketAddr, TcpStream, Stage)> = None;
    for addr in addrs.iter().copied().take(MAX_ADDRESS_ATTEMPTS) {
        if cancel.cancelled() {
            obs.attempts.push(ConnectAttempt {
                address: addr.to_string(),
                stage: cancelled_stage(),
            });
            break;
        }
        if Instant::now() >= deadline {
            obs.attempts.push(ConnectAttempt {
                address: addr.to_string(),
                stage: budget_stage(),
            });
            break;
        }
        let (stage, stream) = connect(addr);
        obs.attempts.push(ConnectAttempt {
            address: addr.to_string(),
            stage: stage.clone(),
        });
        if let Some(stream) = stream {
            selected = Some((addr, stream, stage));
            break;
        }
    }

    // Per-family results, from the attempts already made. A family nothing
    // tried is probed once more if the budget allows, because "v6 fails while
    // v4 works" is evidence a cause depends on.
    let attempted = |want_v6: bool| -> Option<Stage> {
        obs.attempts
            .iter()
            .find(|a| {
                a.address
                    .parse::<SocketAddr>()
                    .is_ok_and(|s| s.is_ipv6() == want_v6)
            })
            .map(|a| a.stage.clone())
    };
    let family = |want_v6: bool, obs_attempts: &[ConnectAttempt]| -> Option<Stage> {
        let addr = addrs.iter().find(|a| a.is_ipv6() == want_v6).copied()?;
        if let Some(stage) = obs_attempts
            .iter()
            .find(|a| a.address == addr.to_string())
            .map(|a| a.stage.clone())
        {
            return Some(stage);
        }
        if cancel.cancelled() {
            return Some(cancelled_stage());
        }
        if Instant::now() >= deadline {
            return Some(budget_stage());
        }
        Some(connect(addr).0)
    };
    obs.connect_v4 = attempted(false).or_else(|| family(false, &obs.attempts));
    obs.connect_v6 = attempted(true).or_else(|| family(true, &obs.attempts));

    let Some((addr, stream, stage)) = selected else {
        // Nothing connected. The headline stage is the first address's
        // result, which is what the rules read, and `attempts` holds the rest.
        obs.connect = Some(
            obs.attempts
                .first()
                .map(|a| a.stage.clone())
                .unwrap_or_else(cancelled_stage),
        );
        let _ = first;
        return;
    };
    obs.connect = Some(stage);
    obs.effective_endpoint = Some(addr.to_string());

    let mut stream =
        match super::probe_io::Stream::new(stream, Instant::now() + IO_TIMEOUT, cancel.clone()) {
            Ok(s) => s,
            Err(e) => {
                obs.connect = Some(Stage::failed(None, connect_error(&e)));
                return;
            }
        };

    // ── tls + http ──
    if obs.tls {
        obs.sni = Some(cfg.host.clone());
        let started = Instant::now();
        match tls_handshake(&cfg.host, &mut stream) {
            Ok(mut conn) => {
                obs.tls_stage = Some(Stage::ok(started.elapsed().as_secs_f64() * 1000.0));
                if cfg.http {
                    let mut tls = rustls::Stream::new(&mut conn, &mut stream);
                    http_exchange(cfg, &mut tls, obs);
                }
            }
            Err(error) => {
                obs.tls_stage = Some(Stage::failed(
                    Some(started.elapsed().as_secs_f64() * 1000.0),
                    error,
                ));
            }
        }
    } else if cfg.http {
        http_exchange(cfg, &mut stream, obs);
    }
}

/// Probe stages against a fixed address list, with no DNS of its own.
///
/// The seam the address-fallback tests use: resolution is the one part of a
/// probe that cannot be made deterministic in a unit test.
#[cfg(test)]
fn probe_addresses(
    cfg: &TargetConfig,
    env: &ProbeEnv,
    addrs: &[SocketAddr],
    cancel: &super::probe_io::Cancel,
) -> TargetObs {
    let mut obs = probe(cfg, env, String::new);
    obs.attempts.clear();
    obs.connect = None;
    obs.connect_v4 = None;
    obs.connect_v6 = None;
    obs.tls_stage = None;
    obs.http_stage = None;
    obs.status = None;
    obs.effective_endpoint = None;
    obs.resolve = Stage::ok(0.0);
    obs.addresses = addrs.iter().map(|a| a.ip().to_string()).collect();
    connect_stages(cfg, addrs, cancel, &mut obs);
    obs
}

/// The `Host` header for a target: the port when it is not the scheme's
/// default, and brackets around an IPv6 literal.
///
/// Sending a bare `host` reached the wrong virtual host on any non-default
/// port, and an unbracketed IPv6 literal is not a valid authority at all, so
/// the server's reply described something other than the configured target.
pub fn http_authority(host: &str, port: u16, tls: bool) -> String {
    let host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let default = if tls { 443 } else { 80 };
    if port == default {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn connect(addr: SocketAddr) -> (Stage, Option<TcpStream>) {
    let started = Instant::now();
    match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
        Ok(s) => (Stage::ok(started.elapsed().as_secs_f64() * 1000.0), Some(s)),
        Err(e) => (
            Stage::failed(
                Some(started.elapsed().as_secs_f64() * 1000.0),
                connect_error(&e),
            ),
            None,
        ),
    }
}

pub fn connect_error(e: &std::io::Error) -> StageError {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => StageError::Refused,
        TimedOut | WouldBlock => StageError::Timeout,
        HostUnreachable | NetworkUnreachable => StageError::Unreachable,
        _ => StageError::Other {
            message: e.to_string(),
        },
    }
}

/// getaddrinfo's errors arrive as text; these are glibc's and macOS's words.
pub fn resolve_error(e: &std::io::Error) -> StageError {
    if matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        return StageError::Timeout;
    }
    let text = e.to_string().to_ascii_lowercase();
    if text.contains("name or service not known")
        || text.contains("no address associated")
        || text.contains("nodename nor servname")
        || text.contains("no such host")
    {
        StageError::NxDomain
    } else if text.contains("temporary failure") || text.contains("try again") {
        StageError::ResolverFailed
    } else {
        StageError::Other {
            message: e.to_string(),
        }
    }
}

fn direct_lookup(resolver: IpAddr, host: &str) -> LookupOutcome {
    use crate::collectors::health::{build_dns_query, dns_exchange, dns_socket};
    let Some(sock) = dns_socket(resolver) else {
        return LookupOutcome::NoReply;
    };
    let id = (uuid::Uuid::new_v4().as_u128() & 0xffff) as u16;
    let query = build_dns_query(id, host, 1, false);
    match dns_exchange(&sock, SocketAddr::new(resolver, 53), &query, id) {
        None => LookupOutcome::NoReply,
        Some((reply, _)) if reply.rcode == 3 => LookupOutcome::NxDomain,
        Some((reply, _)) if reply.rcode != 0 => LookupOutcome::ServFail,
        // NOERROR with only AAAA or a CNAME chain still means the name exists.
        Some(_) => LookupOutcome::Answered,
    }
}

/// Shared with the diagnostic load upload, so both trust the same roots.
pub(super) fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            Arc::new(
                rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .expect("ring supports the default protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
            )
        })
        .clone()
}

fn tls_handshake(
    host: &str,
    stream: &mut super::probe_io::Stream,
) -> Result<rustls::ClientConnection, StageError> {
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| {
        StageError::Other {
            message: e.to_string(),
        }
    })?;
    let mut conn = rustls::ClientConnection::new(tls_config(), name).map_err(|e| tls_error(&e))?;
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(stream) {
            return Err(
                match e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
                    Some(inner) => tls_error(inner),
                    None => connect_error(&e),
                },
            );
        }
    }
    Ok(conn)
}

pub fn tls_error(e: &rustls::Error) -> StageError {
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            C::UnknownIssuer => StageError::CertUntrusted,
            C::Expired | C::ExpiredContext { .. } => StageError::CertExpired,
            C::NotValidYet | C::NotValidYetContext { .. } => StageError::CertNotYetValid,
            C::NotValidForName | C::NotValidForNameContext { .. } => StageError::CertNameMismatch,
            other => StageError::Other {
                message: format!("invalid certificate: {other:?}"),
            },
        },
        rustls::Error::AlertReceived(alert) => StageError::TlsAlert {
            alert: format!("{alert:?}"),
        },
        other => StageError::Other {
            message: other.to_string(),
        },
    }
}

fn http_exchange(cfg: &TargetConfig, stream: &mut impl ReadWrite, obs: &mut TargetObs) {
    let authority = http_authority(&cfg.host, cfg.port, cfg.uses_tls());
    obs.http_authority = Some(authority.clone());
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: netwatch-diagnose\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        cfg.path
    );
    let started = Instant::now();
    if let Err(e) = stream.write_all(request.as_bytes()) {
        obs.http_stage = Some(Stage::failed(None, connect_error(&e)));
        return;
    }
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    let mut ttfb = None;
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                ttfb.get_or_insert_with(|| started.elapsed().as_secs_f64() * 1000.0);
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16_384 {
                    break;
                }
            }
            Err(e) => {
                if ttfb.is_none() {
                    obs.http_stage = Some(Stage::failed(None, connect_error(&e)));
                    return;
                }
                break;
            }
        }
    }
    match parse_head(&buf) {
        Some((status, _date)) => {
            obs.status = Some(status);
            // A server's Date is not an independent check of our clock.
            // Use local NTP status, available even when TLS cannot complete.
            let bad = match cfg.expect_status {
                Some(want) => status != want,
                None => status >= 400,
            };
            obs.http_stage = Some(if bad {
                Stage::failed(ttfb, StageError::HttpStatus { status })
            } else {
                Stage::ok(ttfb.unwrap_or_default())
            });
        }
        None => {
            obs.http_stage = Some(Stage::failed(
                ttfb,
                StageError::Other {
                    message: "no http response".into(),
                },
            ))
        }
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// Status and `Date` from a response head.
pub fn parse_head(buf: &[u8]) -> Option<(u16, Option<chrono::DateTime<chrono::Utc>>)> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    resp.parse(buf).ok()?;
    let status = resp.code?;
    let date = resp
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("date"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|v| chrono::DateTime::parse_from_rfc2822(v.trim()).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    Some((status, date))
}

/// Whether an HTTP(S)_PROXY/ALL_PROXY applies to `host` given NO_PROXY.
pub fn proxy_applies(host: &str, var: impl Fn(&str) -> Option<String>) -> bool {
    let set = [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .iter()
    .any(|k| var(k).is_some_and(|v| !v.trim().is_empty()));
    if !set {
        return false;
    }
    let no_proxy = var("NO_PROXY")
        .or_else(|| var("no_proxy"))
        .unwrap_or_default();
    !no_proxy
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .any(|p| {
            p == "*"
                || host == p.trim_start_matches('.')
                || host.ends_with(&format!(".{}", p.trim_start_matches('.')))
        })
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinkDns {
    pub link: String,
    pub servers: Vec<IpAddr>,
    pub domains: Vec<String>,
}

fn system_proxy_mode() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let value = context_command("gsettings", &["get", "org.gnome.system.proxy", "mode"])?;
        let mode = value.trim().trim_matches('\'');
        matches!(mode, "none" | "manual" | "auto").then(|| mode.to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn container_bridges() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/sys/class/net")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name == "docker0" || name.starts_with("br-"))
            .collect()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// Signed system-clock error from chrony's local monitoring report.
/// https://chrony-project.org/doc/4.8/chronyc.html#tracking
#[cfg(any(target_os = "linux", test))]
fn parse_clock_offset(report: &str) -> Option<f64> {
    let field = |key: &str| {
        report
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(k, _)| k.trim() == key)
            .map(|(_, v)| v.trim())
    };
    if field("Leap status")? != "Normal" {
        return None;
    }
    if field("Reference ID").is_some_and(|id| id.starts_with("7F7F0101")) {
        return None;
    }
    let system = field("System time")?;
    let value: f64 = system.split_whitespace().next()?.parse().ok()?;
    if !value.is_finite() {
        return None;
    }
    if system.contains("slow of NTP time") {
        Some(-value)
    } else if system.contains("fast of NTP time") {
        Some(value)
    } else {
        None
    }
}

fn local_clock_offset() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        parse_clock_offset(&context_command("chronyc", &["-n", "tracking"])?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Optional local context must not stall all target probes if a service hangs.
#[cfg(target_os = "linux")]
fn context_command(program: &str, args: &[&str]) -> Option<String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < Duration::from_secs(2) => {
                std::thread::sleep(Duration::from_millis(10))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let output = child.wait_with_output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Per-link DNS servers and routing domains from `resolvectl status`, when
/// systemd-resolved is in use. Empty anywhere else.
fn link_domains() -> Vec<LinkDns> {
    #[cfg(target_os = "linux")]
    {
        context_command("resolvectl", &["status"])
            .map(|text| parse_resolvectl(&text))
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// Per-link DNS servers and domains from `resolvectl status`, which only
/// Linux runs.
#[cfg(any(target_os = "linux", test))]
pub fn parse_resolvectl(text: &str) -> Vec<LinkDns> {
    let mut out: Vec<LinkDns> = Vec::new();
    let mut key = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Link ") {
            let link = rest
                .split_once('(')
                .and_then(|(_, r)| r.split_once(')'))
                .map(|(n, _)| n.to_string())
                .unwrap_or_default();
            out.push(LinkDns {
                link,
                servers: vec![],
                domains: vec![],
            });
            continue;
        }
        let Some(link) = out.last_mut() else {
            continue;
        };
        let trimmed = line.trim();
        // `Field Name: value` starts a field; anything else continues the
        // last one. IPv6 continuation lines contain colons too, but never
        // letters-and-spaces followed by ": ".
        let (field, value) = match trimmed.split_once(':') {
            Some((f, v))
                if !f.is_empty()
                    && f.chars().all(|c| c.is_ascii_alphabetic() || c == ' ')
                    && (v.is_empty() || v.starts_with(' ')) =>
            {
                key = f.to_string();
                (f.to_string(), v.trim().to_string())
            }
            _ => (key.clone(), trimmed.to_string()),
        };
        match field.as_str() {
            "DNS Servers" => link.servers.extend(
                value
                    .split_whitespace()
                    .filter_map(|s| s.parse::<IpAddr>().ok()),
            ),
            "DNS Domain" => link.domains.extend(
                value
                    .split_whitespace()
                    .map(|d| d.trim_start_matches('~').to_string()),
            ),
            _ => {}
        }
    }
    out.retain(|l| !l.servers.is_empty() || !l.domains.is_empty());
    out
}

// ------------------------------------------------------------------ prober

pub fn validation_errors(targets: &[TargetConfig]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut names = std::collections::HashSet::new();
    if targets.len() > 16 {
        errors.push("at most 16 diagnose targets are supported".into());
    }
    for t in targets {
        if !names.insert(&t.name) {
            errors.push(format!("duplicate target name: {}", t.name));
        }
        if let Err(error) = t.validate() {
            errors.push(format!("{}: {error}", t.name));
        }
    }
    errors
}

/// Probes due targets on a worker and keeps the latest result per target.
#[derive(Default)]
pub struct TargetProber {
    latest: Arc<RwLock<Vec<(Instant, TargetConfig, TargetObs)>>>,
    busy: Arc<AtomicBool>,
    cancel: Mutex<super::probe_io::Cancel>,
    configuration: Mutex<String>,
    started: Mutex<std::collections::HashMap<String, Instant>>,
}

impl TargetProber {
    pub fn cancel(&self) {
        self.cancel.lock().unwrap().cancel();
        self.latest.write().unwrap().clear();
        self.started.lock().unwrap().clear();
    }
    /// Start a probe cycle for every target whose interval has elapsed.
    pub fn probe_due(&self, targets: &[TargetConfig], env: ProbeEnv) {
        let current = serde_json::to_string(targets).unwrap_or_default();
        {
            let mut old = self.configuration.lock().unwrap();
            if *old != current {
                self.cancel();
                *old = current;
            }
        }
        if targets.is_empty() || self.busy.load(Ordering::SeqCst) {
            return;
        }
        if !validation_errors(targets).is_empty() {
            return;
        }
        let now = Instant::now();
        let due: Vec<TargetConfig> = {
            let mut started = self.started.lock().unwrap();
            started.retain(|key, _| targets.iter().any(|t| t.identity() == *key));
            let due: Vec<TargetConfig> = targets
                .iter()
                .filter(|t| t.enabled)
                .filter(|t| {
                    started.get(&t.identity()).is_none_or(|at| {
                        now.duration_since(*at).as_secs() >= t.interval_secs.max(10)
                    })
                })
                .cloned()
                .collect();
            for t in &due {
                started.insert(t.identity(), now);
            }
            due
        };
        if due.is_empty() {
            return;
        }
        self.busy.store(true, Ordering::SeqCst);
        let cancel = super::probe_io::Cancel::default();
        *self.cancel.lock().unwrap() = cancel.clone();
        let (latest, busy) = (Arc::clone(&self.latest), Arc::clone(&self.busy));
        crate::sandbox::worker::spawn("diagnose-targets", move || {
            for cfg in due {
                if cancel.cancelled() {
                    break;
                }
                let obs = probe_cancel(
                    &cfg,
                    &env,
                    || super::engine::format_ts(chrono::Local::now()),
                    &cancel,
                );
                if cancel.cancelled() {
                    break;
                }
                let mut guard = latest.write().unwrap();
                if cancel.cancelled() {
                    break;
                }
                guard.retain(|(_, old, _)| old.name != cfg.name);
                guard.push((Instant::now(), cfg, obs));
            }
            busy.store(false, Ordering::SeqCst);
        });
    }

    /// Queue fresh measurements without retaining old configuration results.
    pub fn probe_now(&self, targets: &[TargetConfig], env: ProbeEnv) -> Result<(), String> {
        if targets.iter().all(|t| !t.enabled) {
            return Err("no enabled targets; enable a target before probing".into());
        }
        let errors = validation_errors(targets);
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        if self.busy.load(Ordering::SeqCst) {
            return Err("target probes are already running".into());
        }
        self.started.lock().unwrap().clear();
        self.probe_due(targets, env);
        Ok(())
    }

    /// Fresh results for configured targets, and when the newest completed.
    pub fn fresh(&self, targets: &[TargetConfig]) -> (Vec<(Instant, TargetObs)>, Option<Instant>) {
        if !validation_errors(targets).is_empty() {
            return (vec![], None);
        }
        let guard = self.latest.read().unwrap();
        let fresh: Vec<(Instant, TargetObs)> = guard
            .iter()
            .filter(|(at, cfg, _)| {
                targets
                    .iter()
                    .find(|t| t.enabled && *t == cfg)
                    .is_some_and(|t| at.elapsed().as_secs() <= t.stale_after_secs())
            })
            .map(|(at, _, obs)| (*at, obs.clone()))
            .collect();
        let newest = fresh.iter().map(|(at, _)| *at).max();
        (fresh, newest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(host: &str, port: u16) -> TargetConfig {
        TargetConfig {
            enabled: true,
            name: "t".into(),
            host: host.into(),
            port,
            tls: Some(false),
            http: true,
            path: "/healthz".into(),
            expect_status: None,
            interval_secs: 60,
        }
    }

    fn serve_once(response: &'static [u8]) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            // The probe connects once per family plus once for the request.
            for stream in listener.incoming().take(3).flatten() {
                let mut s = stream;
                let mut buf = [0u8; 1024];
                let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
                if s.read(&mut buf).is_ok_and(|n| n > 0) {
                    let _ = s.write_all(response);
                }
            }
        });
        port
    }

    #[test]
    fn the_host_header_carries_the_port_and_brackets_a_v6_literal() {
        // A bare host on a non-default port reaches whatever virtual host the
        // server defaults to, and an unbracketed v6 literal is not a valid
        // authority at all — either way the reply describes something other
        // than the configured target.
        assert_eq!(http_authority("example.com", 443, true), "example.com");
        assert_eq!(http_authority("example.com", 80, false), "example.com");
        assert_eq!(
            http_authority("example.com", 8443, true),
            "example.com:8443"
        );
        assert_eq!(
            http_authority("example.com", 8080, false),
            "example.com:8080"
        );
        assert_eq!(http_authority("::1", 443, true), "[::1]");
        assert_eq!(http_authority("::1", 8443, true), "[::1]:8443");
        assert_eq!(http_authority("127.0.0.1", 8080, false), "127.0.0.1:8080");
    }

    #[test]
    fn a_dead_first_address_does_not_hide_a_working_service() {
        // The probe used to try `addrs.first()` only. One stale AAAA or a
        // dead round-robin member therefore reported the whole service down,
        // with TLS and HTTP never attempted.
        let port = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead); // nothing is listening on this port now

        let cfg = TargetConfig {
            http: true,
            ..cfg("127.0.0.1", port)
        };
        let cancel = super::super::probe_io::Cancel::default();
        let addrs = vec![
            SocketAddr::from(([127, 0, 0, 1], dead_port)),
            SocketAddr::from(([127, 0, 0, 1], port)),
        ];
        let obs = probe_addresses(&cfg, &ProbeEnv::default(), &addrs, &cancel);

        assert_eq!(obs.attempts.len(), 2, "both addresses were tried in order");
        assert!(!obs.attempts[0].stage.is_ok());
        assert!(obs.attempts[1].stage.is_ok());
        assert_eq!(
            obs.effective_endpoint.as_deref(),
            Some(addrs[1].to_string().as_str())
        );
        assert_eq!(obs.status, Some(200), "http ran on the address that worked");
        assert!(obs.connect.as_ref().is_some_and(|s| s.is_ok()));
    }

    #[test]
    fn disabled_targets_do_not_start_workers() {
        let mut target = cfg("127.0.0.1", 80);
        target.enabled = false;
        let prober = TargetProber::default();
        prober.probe_due(&[target.clone()], ProbeEnv::default());
        assert!(!prober.busy.load(Ordering::SeqCst));
        assert!(prober.fresh(&[target.clone()]).0.is_empty());
        assert!(prober.probe_now(&[target], ProbeEnv::default()).is_err());
    }

    #[test]
    fn target_configuration_changes_invalidate_baseline_identity() {
        let cfg = TargetConfig {
            enabled: true,
            name: "api".into(),
            host: "127.0.0.1".into(),
            port: 80,
            tls: Some(false),
            http: true,
            path: "/health".into(),
            expect_status: Some(200),
            interval_secs: 60,
        };
        let mut changed = cfg.clone();
        changed.path = "/new-health".into();
        assert_ne!(cfg.baseline_key(), changed.baseline_key());
        changed = cfg.clone();
        changed.host = "127.0.0.2".into();
        assert_ne!(cfg.baseline_key(), changed.baseline_key());
        changed = cfg.clone();
        changed.expect_status = Some(204);
        assert_ne!(cfg.baseline_key(), changed.baseline_key());
        assert!(!cfg.baseline_key().contains("health"));
    }

    #[test]
    fn edited_configuration_does_not_reuse_old_results() {
        let original = cfg("localhost", 443);
        let prober = TargetProber::default();
        let obs = TargetObs {
            stale_after_secs: None,
            attempts: vec![],
            effective_endpoint: None,
            sni: None,
            http_authority: None,
            baseline_key: None,
            name: original.name.clone(),
            host: original.host.clone(),
            port: original.port,
            tls: true,
            http: true,
            expect_status: None,
            probed_at: "now".into(),
            resolve: Stage::ok(1.0),
            addresses: vec![],
            lookups: vec![],
            connect: None,
            connect_v4: None,
            connect_v6: None,
            tls_stage: None,
            http_stage: None,
            status: None,
            context: TargetContext::default(),
        };
        prober
            .latest
            .write()
            .unwrap()
            .push((Instant::now(), original.clone(), obs));
        assert_eq!(prober.fresh(std::slice::from_ref(&original)).0.len(), 1);
        let mut edited = original.clone();
        edited.path = "/changed".into();
        assert!(prober.fresh(&[edited]).0.is_empty());
        let mut edited = original;
        edited.expect_status = Some(204);
        assert!(prober.fresh(&[edited]).0.is_empty());
    }

    #[test]
    fn target_validation_rejects_ambiguous_and_injected_requests() {
        let original = cfg("localhost", 80);
        assert!(original.validate().is_ok());
        assert!(!validation_errors(&[original.clone(), original.clone()]).is_empty());
        let mut injected = original.clone();
        injected.path = "/ HTTP/1.1\r\nHost: other".into();
        assert!(injected.validate().is_err());
        let mut url = original;
        url.host = "https://example.com".into();
        assert!(url.validate().is_err());
    }

    #[test]
    fn a_healthy_http_target_passes_every_stage() {
        let port = serve_once(
            b"HTTP/1.1 200 OK\r\nDate: Tue, 15 Sep 2026 10:00:00 GMT\r\nContent-Length: 0\r\n\r\n",
        );
        let obs = probe(&cfg("127.0.0.1", port), &ProbeEnv::default(), || {
            "now".into()
        });
        assert!(obs.resolve.is_ok());
        assert!(obs.connect.as_ref().unwrap().is_ok());
        assert!(
            obs.http_stage.as_ref().unwrap().is_ok(),
            "{:?}",
            obs.http_stage
        );
        assert_eq!(obs.status, Some(200));
        // NTP status may be absent; the HTTP Date must not manufacture it.
        assert_eq!(obs.stage_readings().len(), 3);
    }

    #[test]
    fn a_5xx_or_unexpected_status_fails_the_http_stage() {
        let port = serve_once(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");
        let obs = probe(&cfg("127.0.0.1", port), &ProbeEnv::default(), || {
            "now".into()
        });
        assert_eq!(
            obs.http_stage.unwrap().error,
            Some(StageError::HttpStatus { status: 503 })
        );
        let port = serve_once(b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n");
        let mut c = cfg("127.0.0.1", port);
        c.expect_status = Some(200);
        let obs = probe(&c, &ProbeEnv::default(), || "now".into());
        assert!(!obs.http_stage.unwrap().is_ok());
    }

    #[test]
    fn proxy_authentication_failure_is_an_http_error_by_default() {
        let port =
            serve_once(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n");
        let obs = probe(&cfg("127.0.0.1", port), &ProbeEnv::default(), || {
            "now".into()
        });
        assert_eq!(
            obs.http_stage.unwrap().error,
            Some(StageError::HttpStatus { status: 407 })
        );
    }

    #[test]
    fn a_closed_port_is_refused_not_timed_out() {
        // A port is free once its listener drops, and a test running in
        // parallel can bind it before the probe connects; the connect then
        // succeeds (macOS CI, PR #73). That outcome says nothing about a
        // closed port, so try a fresh one. A bound socket that does not
        // listen is no fix: macOS drops the SYN and the probe times out.
        for _ in 0..5 {
            let port = {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                l.local_addr().unwrap().port()
            };
            let obs = probe(&cfg("127.0.0.1", port), &ProbeEnv::default(), || {
                "now".into()
            });
            match obs.connect.unwrap().error {
                None => continue,
                error => {
                    assert_eq!(error, Some(StageError::Refused));
                    assert!(obs.http_stage.is_none());
                    return;
                }
            }
        }
        panic!("every freed port was taken before the probe connected");
    }

    #[test]
    fn tls_against_a_plaintext_server_fails_the_tls_stage() {
        let port = serve_once(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        let mut c = cfg("localhost", port);
        c.tls = Some(true);
        let obs = probe(&c, &ProbeEnv::default(), || "now".into());
        if obs.connect.as_ref().is_some_and(|s| s.is_ok()) {
            assert!(!obs.tls_stage.unwrap().is_ok());
        }
    }

    #[test]
    fn certificate_errors_map_to_their_classes() {
        use rustls::CertificateError as C;
        let e = |c| tls_error(&rustls::Error::InvalidCertificate(c));
        assert_eq!(e(C::UnknownIssuer), StageError::CertUntrusted);
        assert_eq!(e(C::Expired), StageError::CertExpired);
        assert_eq!(e(C::NotValidYet), StageError::CertNotYetValid);
        assert_eq!(e(C::NotValidForName), StageError::CertNameMismatch);
    }

    #[test]
    fn resolver_and_connect_errors_map_to_their_classes() {
        let io = |s: &str| std::io::Error::other(s.to_string());
        assert_eq!(
            resolve_error(&io(
                "failed to lookup address information: Name or service not known"
            )),
            StageError::NxDomain
        );
        assert_eq!(
            resolve_error(&io(
                "failed to lookup address information: Temporary failure in name resolution"
            )),
            StageError::ResolverFailed
        );
        assert_eq!(
            connect_error(&std::io::Error::from(std::io::ErrorKind::TimedOut)),
            StageError::Timeout
        );
        assert_eq!(
            connect_error(&std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            StageError::Refused
        );
    }

    #[test]
    fn ntp_status_is_signed_and_must_be_synchronised() {
        let slow = "System time : 3600.0 seconds slow of NTP time\nLeap status : Normal";
        assert_eq!(parse_clock_offset(slow), Some(-3600.0));
        assert_eq!(
            parse_clock_offset(&slow.replace("slow", "fast")),
            Some(3600.0)
        );
        assert_eq!(
            parse_clock_offset(&slow.replace("Normal", "Not synchronised")),
            None
        );
        assert_eq!(parse_clock_offset(&slow.replace("3600.0", "NaN")), None);
    }

    #[test]
    fn proxy_respects_no_proxy() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert!(!proxy_applies("api.corp", env(&[])));
        assert!(proxy_applies(
            "api.corp",
            env(&[("HTTPS_PROXY", "http://proxy:3128")])
        ));
        assert!(!proxy_applies(
            "api.corp",
            env(&[("HTTPS_PROXY", "http://p"), ("NO_PROXY", "localhost,.corp")])
        ));
        assert!(!proxy_applies(
            "corp",
            env(&[("https_proxy", "http://p"), ("no_proxy", "corp")])
        ));
        assert!(proxy_applies(
            "api.other",
            env(&[("ALL_PROXY", "socks5://p"), ("NO_PROXY", ".corp")])
        ));
    }

    #[test]
    fn resolvectl_links_parse_servers_and_routing_domains() {
        let text = "Global\n       Protocols: +LLMNR\n\nLink 2 (wlp192s0)\n    Current Scopes: DNS\n         Protocols: +DefaultRoute\nCurrent DNS Server: 192.168.0.1\n       DNS Servers: 192.168.0.1\n                    fe80::1%2\n        DNS Domain: lan\n     Default Route: yes\n\nLink 5 (wg0)\n    Current Scopes: DNS\n       DNS Servers: 10.8.0.1\n                    10.8.0.2\n        DNS Domain: ~corp.internal\n                    ~svc.corp.internal\n     Default Route: no\n";
        let links = parse_resolvectl(text);
        assert_eq!(links.len(), 2);
        assert_eq!(links[1].link, "wg0");
        assert_eq!(links[1].servers.len(), 2);
        assert_eq!(links[1].domains, vec!["corp.internal", "svc.corp.internal"]);
        assert_eq!(links[0].domains, vec!["lan"]);
    }

    #[test]
    fn config_defaults_are_sensible() {
        let c: TargetConfig = toml::from_str("name = \"api\"\nhost = \"api.example.com\"").unwrap();
        assert_eq!(c.port, 443);
        assert!(c.uses_tls() && c.http);
        assert_eq!(c.path, "/");
        assert_eq!(c.stale_after_secs(), 180);
        assert!(is_vpn_iface("wg0") && is_vpn_iface("tailscale0") && !is_vpn_iface("wlp192s0"));
    }
}
