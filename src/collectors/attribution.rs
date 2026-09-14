//! Per-match evidence, distinct from backend readiness.
use serde::Serialize;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_MATCH_AGE: Duration = Duration::from_secs(5);
pub fn session_id() -> &'static str {
    static SESSION: OnceLock<String> = OnceLock::new();
    SESSION.get_or_init(|| uuid::Uuid::new_v4().to_string())
}
pub fn utc_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ProcessIdentity {
    pub session: String,
    pub pid: u32,
    pub start_token: String,
    pub executable: Option<String>,
    pub network_namespace: Option<String>,
}
/// Whether a fresh observation is the process `expected` describes. The start
/// token (from `/proc/<pid>/stat`, readable everywhere) rules out PID reuse;
/// executable and namespace are compared only when this thread could read
/// them, since a sandboxed worker cannot see them for other processes.
pub fn same_process(observed: Option<&ProcessIdentity>, expected: &ProcessIdentity) -> bool {
    let Some(observed) = observed else {
        return false;
    };
    observed.session == expected.session
        && observed.pid == expected.pid
        && observed.start_token == expected.start_token
        && (observed.executable.is_none() || observed.executable == expected.executable)
        && (observed.network_namespace.is_none()
            || observed.network_namespace == expected.network_namespace)
}
/// Read start identity on both sides of executable discovery. No persistent PID cache.
#[cfg(target_os = "linux")]
pub fn process_identity(pid: u32) -> Option<ProcessIdentity> {
    use std::os::unix::fs::MetadataExt;
    let root = format!("/proc/{pid}");
    let before = start_token(&std::fs::read_to_string(format!("{root}/stat")).ok()?)?;
    let executable = std::fs::metadata(format!("{root}/exe")).ok().map(|m| {
        format!(
            "{}:{}:{}:{}:{}",
            m.dev(),
            m.ino(),
            m.len(),
            m.ctime(),
            m.ctime_nsec()
        )
    });
    let namespace = std::fs::read_link(format!("{root}/ns/net"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let after = start_token(&std::fs::read_to_string(format!("{root}/stat")).ok()?)?;
    (before == after).then(|| ProcessIdentity {
        session: session_id().into(),
        pid,
        start_token: before,
        executable,
        network_namespace: namespace,
    })
}
#[cfg(not(target_os = "linux"))]
pub fn process_identity(_pid: u32) -> Option<ProcessIdentity> {
    None
}
#[cfg(any(target_os = "linux", test))]
fn start_token(stat: &str) -> Option<String> {
    // comm may contain spaces and closing parentheses. Field 22 follows state.
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)
        .map(str::to_owned)
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    #[default]
    NoSocketOwner,
    IdentityUnavailable,
    IdentityChanged,
    StaleSnapshot,
    AmbiguousEndpoint,
    IncompleteEventKey,
}
#[derive(Debug, Clone, Serialize)]
pub struct MatchEvidence {
    pub observed_at_utc_ms: Option<u64>,
    pub process: Option<ProcessIdentity>,
    pub corroborated_by: Option<String>,
    pub event_age_at_match_ms: Option<u64>,
    pub unknown_reason: Option<UnknownReason>,
    pub flow: Option<FlowIdentity>,
    #[serde(skip)]
    pub observed_at: Option<Instant>,
}
impl Default for MatchEvidence {
    fn default() -> Self {
        Self {
            observed_at_utc_ms: None,
            process: None,
            corroborated_by: None,
            event_age_at_match_ms: None,
            unknown_reason: Some(UnknownReason::NoSocketOwner),
            flow: None,
            observed_at: None,
        }
    }
}
impl MatchEvidence {
    pub fn fresh(&self) -> bool {
        self.observed_at
            .is_some_and(|t| t.elapsed() <= MAX_MATCH_AGE)
    }
    pub fn verified(&self) -> bool {
        self.fresh() && self.process.is_some() && self.unknown_reason.is_none()
    }
    pub fn observe(&mut self) {
        self.observed_at = Some(Instant::now());
        self.observed_at_utc_ms = Some(utc_ms());
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct FlowIdentity {
    pub session: String,
    pub generation: u64,
    pub capture_generation: Option<u32>,
    pub protocol: String,
    pub local: String,
    pub remote: String,
    pub network_namespace: Option<String>,
}
#[derive(Default)]
pub struct FlowRegistry {
    next: u64,
    previous: HashMap<(String, String, String), (Option<ProcessIdentity>, u64)>,
}
impl FlowRegistry {
    pub fn reconcile(&mut self, connections: &mut [super::connections::Connection]) {
        let mut current = HashMap::new();
        for c in connections {
            let key = (
                c.protocol.clone(),
                c.local_addr.clone(),
                c.remote_addr.clone(),
            );
            let identity = c.evidence.process.clone();
            let generation = self
                .previous
                .get(&key)
                .filter(|(old, _)| old == &identity)
                .map(|(_, generation)| *generation)
                .unwrap_or_else(|| {
                    self.next += 1;
                    self.next
                });
            c.evidence.flow = Some(FlowIdentity {
                session: session_id().into(),
                generation,
                capture_generation: None,
                protocol: c.protocol.clone(),
                local: c.local_addr.clone(),
                remote: c.remote_addr.clone(),
                network_namespace: identity.as_ref().and_then(|p| p.network_namespace.clone()),
            });
            current.insert(key, (identity, generation));
        }
        self.previous = current;
    }
}
/// Coverage denominator: captured TCP/UDP streams with payload increments in the
/// latest completed polling interval. It includes flows missing from socket polling.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct Coverage {
    pub eligible_flows: u64,
    pub attributed_flows: u64,
    pub eligible_payload_bytes: u64,
    pub attributed_payload_bytes: u64,
    pub completed_at_utc_ms: Option<u64>,
    pub capture_drops: Option<u64>,
    #[serde(skip)]
    pub completed_at: Option<Instant>,
}
impl Coverage {
    pub fn summary(&self) -> String {
        if self
            .completed_at
            .is_none_or(|t| t.elapsed() > MAX_MATCH_AGE)
        {
            return "attribution coverage: not measured (no fresh snapshot)".into();
        }
        if self.eligible_flows == 0 {
            return "attribution coverage: not measured (no captured payload)".into();
        }
        format!(
            "attributed flows {}/{} · payload bytes {}/{} (latest capture interval)",
            self.attributed_flows,
            self.eligible_flows,
            self.attributed_payload_bytes,
            self.eligible_payload_bytes
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stat_name_does_not_shift_start_identity() {
        let fields = (0..20).map(|i| i.to_string()).collect::<Vec<_>>().join(" ");
        assert_eq!(
            start_token(&format!("42 (name ) with spaces) {fields}")),
            Some("19".into())
        );
    }
    #[test]
    fn empty_and_stale_coverage_are_not_perfect() {
        assert!(Coverage::default().summary().contains("not measured"));
        let c = Coverage {
            completed_at: Some(Instant::now()),
            ..Default::default()
        };
        assert!(c.summary().contains("not measured"));
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn live_process_identity_is_stable_and_missing_pid_is_unknown() {
        let first = process_identity(std::process::id()).unwrap();
        assert_eq!(Some(first), process_identity(std::process::id()));
        assert!(process_identity(u32::MAX).is_none());
    }
}

#[cfg(test)]
mod same_process_tests {
    use super::*;
    fn identity() -> ProcessIdentity {
        ProcessIdentity {
            session: "s".into(),
            pid: 7,
            start_token: "100".into(),
            executable: Some("exe".into()),
            network_namespace: Some("net:[1]".into()),
        }
    }
    #[test]
    fn sandboxed_observer_verifies_by_start_token_but_never_accepts_reuse() {
        let expected = identity();
        let sandboxed = ProcessIdentity {
            executable: None,
            network_namespace: None,
            ..identity()
        };
        assert!(same_process(Some(&sandboxed), &expected));
        assert!(same_process(Some(&identity()), &expected));
        let reused = ProcessIdentity {
            start_token: "200".into(),
            ..sandboxed.clone()
        };
        assert!(!same_process(Some(&reused), &expected));
        let other_exe = ProcessIdentity {
            executable: Some("other".into()),
            ..identity()
        };
        assert!(!same_process(Some(&other_exe), &expected));
        assert!(!same_process(None, &expected));
    }
}
