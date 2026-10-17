use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// User-facing persistent configuration, stored as `netwatch/config.toml`
/// under the platform config directory (`dirs::config_dir()`): `~/.config` on
/// Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on Windows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetwatchConfig {
    /// Which tab to show on launch (dashboard, connections, interfaces,
    /// packets, stats, topology, timeline, insights)
    pub default_tab: String,

    /// Tick / refresh rate in milliseconds (100–5000)
    pub refresh_rate_ms: u64,

    /// Preferred capture interface (e.g. "en0"). Empty = auto-detect.
    pub capture_interface: String,

    /// Show GeoIP column in Connections tab
    pub show_geo: bool,

    /// Default timeline window (1m, 5m, 15m, 30m, 1h)
    pub timeline_window: String,

    /// Auto-follow new packets in the Packets tab
    pub packet_follow: bool,

    /// Default BPF capture filter (e.g. "tcp port 443")
    pub bpf_filter: String,

    /// Path to MaxMind GeoLite2-City or GeoLite2-Country .mmdb file
    /// (empty = no offline lookups; see `geoip_online` for the fallback)
    pub geoip_db: String,

    /// Path to MaxMind GeoLite2-ASN .mmdb file (optional, for AS numbers)
    pub geoip_asn_db: String,

    /// Allow falling back to ip-api.com when no local `geoip_db` is
    /// configured, or the one configured fails to open. Off by default:
    /// without an mmdb, enabling this sends every public peer IP a
    /// connection or packet touches to a third party, in cleartext HTTP,
    /// with no per-host opt-out. ip-api.com has no HTTPS on its free tier,
    /// so this cannot be made private. Install a MaxMind database for
    /// offline lookups, or opt into this explicitly.
    pub geoip_online: bool,

    /// Network intelligence alert settings
    pub alerts: AlertConfig,

    /// Enable the AI Insights tab (opt-in — off by default)
    pub insights_enabled: bool,

    /// AI insights model name (for Ollama / local LLM or cloud)
    pub insights_model: String,

    /// AI insights endpoint: "local" → http://localhost:11434, or a full base URL
    pub insights_endpoint: String,

    /// Color theme (dark, light, ocean, solarized, dracula, nord)
    pub theme: String,

    /// Which view starts: `full` (the tabbed TUI), `lite` (one 80×24 screen),
    /// or `dense` (the four-box 130×44 screen). `full` stays the default —
    /// the other two are opt-in, and `--view` overrides this for one run.
    #[serde(default = "default_view")]
    pub view: String,

    /// Chart style for every sparkline in the app (`dots` or `bars`) —
    /// hero tiles, in-row connection lines, RTT history, timeline layers and
    /// Lite's charts all route through `graph::render`.
    ///
    /// `dots` is the default and is the braille area plot the Dense view and
    /// the Dashboard's throughput graph draw: two samples per cell column, so
    /// a sparkline carries twice the history in the same width. `bars` is the
    /// pre-v0.21 block look, kept for terminals whose font has no braille
    /// coverage — there the area plot renders as empty boxes.
    pub graph_style: String,

    /// The magnitude gradient. When `true`, every chart colours each cell by
    /// how high it sits — dim at the baseline, the series colour in the
    /// middle, lightened at the peak.
    ///
    /// On by default: it is what makes a filled area read as depth rather
    /// than as a block. Under the `terminal` theme it steps from each series
    /// colour to its bright palette variant instead of blending, so no colour
    /// is invented.
    #[serde(default = "default_graph_fade")]
    pub graph_fade: bool,

    /// Sandbox enforcement mode — `"on"` (best-effort, default),
    /// `"strict"` (refuse to start if the platform backend can't apply),
    /// or `"off"` (skip sandboxing entirely). CLI flags `--no-sandbox`
    /// and `--sandbox-strict` still override. Changes apply on next
    /// netwatch start — Landlock and dropped capabilities can't be undone
    /// at runtime, so the live process keeps whatever mode it launched
    /// with.
    #[serde(default = "default_sandbox")]
    pub sandbox: String,

    /// Path to an NSS `SSLKEYLOGFILE` containing per-connection TLS
    /// secrets exported by a cooperating client (Chrome, Firefox, Node,
    /// curl with `--ssl-no-revoke` etc.). When non-empty, netwatch
    /// reads this file and uses the secrets to decrypt observed TLS
    /// 1.3 Application Data records — same trick Wireshark uses.
    ///
    /// Empty (default) = no decryption. Decryption only works when:
    ///   - You control the client process (it must export its secrets).
    ///   - The client sets `SSLKEYLOGFILE=<this-path>` before launch.
    ///   - The connection is TLS 1.3 (TLS 1.2 / QUIC application data /
    ///     0-RTT not in scope for the initial implementation).
    #[serde(default)]
    pub tls_keylog_path: String,

    /// How long (seconds) before the same violating flow — one
    /// (process, destination, port) — re-warns on egress policy drift.
    /// 0 warns on every connection refresh. Default 300 (5 minutes).
    #[serde(default = "default_egress_cooldown")]
    pub egress_violation_cooldown_secs: u64,

    /// Whether the grouped tables (Connections, Egress) open with every group
    /// folded. Default true: a folded screen answers "what is on this machine"
    /// in one glance, and expanding is one keystroke. Set false to open with
    /// everything visible, which is closer to the old flat tables.
    #[serde(default = "default_groups_collapsed")]
    pub groups_start_collapsed: bool,

    /// Record Diagnose episodes: the ten minutes before an issue opens through
    /// ten minutes after it closes, plus one quiet 15-minute sample a day.
    /// Stored locally under `~/.local/state/netwatch/episodes`, kept 90 days
    /// or 300 MB. Nothing is uploaded. Default true.
    #[serde(default = "default_record_episodes")]
    pub diagnose_record_episodes: bool,

    /// Hosts Diagnose probes stage by stage (DNS, TCP, TLS, HTTP), e.g.
    ///
    /// ```toml
    /// [[diagnose_targets]]
    /// name = "staging api"
    /// host = "api.staging.example.internal"
    /// port = 443
    /// path = "/healthz"
    /// expect_status = 200
    /// ```
    #[serde(default)]
    pub diagnose_probes: crate::diagnose::active::Config,
    pub diagnose_targets: Vec<crate::diagnose::targets::TargetConfig>,

    /// The Diagnose engine's thresholds, e.g.
    ///
    /// ```toml
    /// [diagnose_thresholds]
    /// dns_ceiling_ms = 30
    /// ```
    ///
    /// A missing key keeps its default. A value that cannot mean anything
    /// (σ multiple ≤ 0, a negative σ or delta floor, `consecutive_n` = 0, a
    /// share outside 0–100, NaN, a close σ multiple not below the open one)
    /// is logged and replaced by its default. Read at startup: an episode
    /// records the thresholds it ran with, so they do not change mid-run.
    ///
    /// Saved only once it differs from the defaults. `--generate-config` and
    /// the Settings editor write the whole config, and a table of today's
    /// defaults in the file would hold them there when a release retunes one.
    #[serde(default, skip_serializing_if = "is_default_thresholds")]
    pub diagnose_thresholds: crate::diagnose::detectors::Thresholds,
}

fn is_default_thresholds(t: &crate::diagnose::detectors::Thresholds) -> bool {
    *t == crate::diagnose::detectors::Thresholds::default()
}

fn default_record_episodes() -> bool {
    true
}

fn default_groups_collapsed() -> bool {
    true
}

fn default_view() -> String {
    "full".into()
}

/// The braille area plot. `bars` remains selectable for terminals whose font
/// has no braille coverage.
fn default_graph_style() -> String {
    "dots".into()
}

/// On: the gradient is what makes a filled area read as depth.
fn default_graph_fade() -> bool {
    true
}

fn default_sandbox() -> String {
    "on".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertConfig {
    /// Bandwidth alert threshold in bytes/sec (0 = disabled)
    pub bandwidth_threshold: u64,

    /// Minimum distinct ports within window to flag a port scan
    pub port_scan_threshold: usize,

    /// Port-scan detection window in seconds
    pub port_scan_window_secs: u64,
}

// ── Defaults ───────────────────────────────────────────────

impl Default for NetwatchConfig {
    fn default() -> Self {
        Self {
            default_tab: "dashboard".into(),
            refresh_rate_ms: 1000,
            capture_interface: String::new(),
            show_geo: true,
            timeline_window: "5m".into(),
            packet_follow: true,
            bpf_filter: String::new(),
            geoip_db: String::new(),
            geoip_asn_db: String::new(),
            geoip_online: false,
            alerts: AlertConfig::default(),
            insights_enabled: false,
            insights_model: "llama3.2".into(),
            insights_endpoint: "local".into(),
            theme: "dark".into(),
            view: default_view(),
            graph_style: default_graph_style(),
            graph_fade: default_graph_fade(),
            diagnose_record_episodes: default_record_episodes(),
            diagnose_probes: Default::default(),
            diagnose_targets: Vec::new(),
            diagnose_thresholds: Default::default(),
            sandbox: default_sandbox(),
            tls_keylog_path: String::new(),
            egress_violation_cooldown_secs: default_egress_cooldown(),
            groups_start_collapsed: default_groups_collapsed(),
        }
    }
}

fn default_egress_cooldown() -> u64 {
    300
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            bandwidth_threshold: 100_000_000, // 100 MB/s
            port_scan_threshold: 20,
            port_scan_window_secs: 30,
        }
    }
}

// ── Persistence ────────────────────────────────────────────

impl NetwatchConfig {
    /// Path to `netwatch/config.toml` under the platform config dir
    /// (`~/.config` on Linux, `~/Library/Application Support` on macOS,
    /// `%APPDATA%` on Windows).
    pub fn path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("netwatch").join("config.toml"))
    }

    /// Load from disk, falling back to defaults for any missing field.
    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            return Self::default();
        };
        let Ok(contents) = fs::read_to_string(&path) else {
            return Self::default();
        };
        let mut cfg: Self = toml::from_str(&contents).unwrap_or_default();
        cfg.validate();
        cfg
    }

    /// Clamp and normalise fields that may arrive out of range from a hand-edited
    /// config file. Called automatically by `load()`; also useful in tests.
    pub fn validate(&mut self) {
        self.refresh_rate_ms = self.refresh_rate_ms.clamp(100, 5000);
        if self.theme.is_empty() {
            self.theme = "dark".into();
        }
        if self.graph_style.is_empty() {
            self.graph_style = default_graph_style();
        }
        // An unknown view name falls back to `full` rather than refusing to
        // start: a typo in a config file must not cost you the tool.
        if !crate::app::VIEW_MODE_NAMES.contains(&self.view.as_str()) {
            self.view = default_view();
        }
        if self.default_tab.is_empty() {
            self.default_tab = "dashboard".into();
        }
        if self.timeline_window.is_empty() {
            self.timeline_window = "5m".into();
        }
        if self.insights_model.is_empty() {
            self.insights_model = "llama3.2".into();
        }
        if self.insights_endpoint.is_empty() {
            self.insights_endpoint = "local".into();
        }
    }

    /// Write current config to disk, creating parent directories as needed.
    pub fn save(&self) -> anyhow::Result<()> {
        let path =
            Self::path().ok_or_else(|| anyhow::anyhow!("cannot determine config directory"))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(self)?;
        fs::write(&path, contents)?;
        Ok(())
    }
}

// ── Helpers to map string ↔ app types ──────────────────────

use crate::app::{Tab, TimelineWindow};

impl NetwatchConfig {
    pub fn tab(&self) -> Tab {
        match self.default_tab.to_lowercase().as_str() {
            "connections" => Tab::Connections,
            "interfaces" => Tab::Interfaces,
            "packets" => Tab::Packets,
            "stats" => Tab::Stats,
            "topology" => Tab::Topology,
            "timeline" => Tab::Timeline,
            "processes" => Tab::Processes,
            // Kept as an alias: the Insights tab folded into Diagnose,
            // and a config naming it should land somewhere sensible.
            "diagnose" | "insights" => Tab::Diagnose,
            "egress" => Tab::Egress,
            _ => Tab::Dashboard,
        }
    }

    pub fn timeline_window_enum(&self) -> TimelineWindow {
        match self.timeline_window.as_str() {
            "1m" => TimelineWindow::Min1,
            "15m" => TimelineWindow::Min15,
            "30m" => TimelineWindow::Min30,
            "1h" => TimelineWindow::Hour1,
            _ => TimelineWindow::Min5,
        }
    }
}

// ── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cfg = NetwatchConfig::default();
        assert_eq!(cfg.default_tab, "dashboard");
        assert_eq!(cfg.refresh_rate_ms, 1000);
        assert!(cfg.show_geo);
        assert!(cfg.packet_follow);
        assert_eq!(cfg.timeline_window, "5m");
        assert_eq!(cfg.alerts.bandwidth_threshold, 100_000_000);
    }

    #[test]
    fn partial_toml_fills_defaults() {
        let toml_str = r#"
default_tab = "packets"
show_geo = false
"#;
        let cfg: NetwatchConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.default_tab, "packets");
        assert!(!cfg.show_geo);
        // un-specified fields get defaults
        assert_eq!(cfg.refresh_rate_ms, 1000);
        assert!(cfg.packet_follow);
        assert_eq!(cfg.alerts.port_scan_threshold, 20);
    }

    #[test]
    fn full_roundtrip() {
        let cfg = NetwatchConfig {
            default_tab: "topology".into(),
            refresh_rate_ms: 500,
            capture_interface: "en1".into(),
            show_geo: false,
            timeline_window: "15m".into(),
            packet_follow: false,
            bpf_filter: "tcp port 443".into(),
            geoip_db: "/path/to/GeoLite2-City.mmdb".into(),
            geoip_asn_db: "/path/to/GeoLite2-ASN.mmdb".into(),
            geoip_online: true,
            alerts: AlertConfig {
                bandwidth_threshold: 50_000_000,
                port_scan_threshold: 10,
                port_scan_window_secs: 60,
            },
            insights_enabled: true,
            insights_model: "llama3:8b".into(),
            insights_endpoint: "local".into(),
            theme: "dark".into(),
            view: "dense".into(),
            graph_style: "bars".into(),
            graph_fade: false,
            sandbox: "strict".into(),
            tls_keylog_path: "/tmp/sslkeylog.txt".into(),
            egress_violation_cooldown_secs: 120,
            groups_start_collapsed: false,
            diagnose_record_episodes: false,
            diagnose_probes: Default::default(),
            diagnose_targets: vec![],
            diagnose_thresholds: Default::default(),
        };
        let serialized = toml::to_string_pretty(&cfg).unwrap();
        let deserialized: NetwatchConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.default_tab, "topology");
        assert_eq!(deserialized.refresh_rate_ms, 500);
        assert_eq!(deserialized.capture_interface, "en1");
        assert!(!deserialized.show_geo);
        assert_eq!(deserialized.timeline_window, "15m");
        assert!(!deserialized.packet_follow);
        assert_eq!(deserialized.bpf_filter, "tcp port 443");
        assert_eq!(deserialized.alerts.bandwidth_threshold, 50_000_000);
        assert_eq!(deserialized.alerts.port_scan_threshold, 10);
        assert_eq!(deserialized.alerts.port_scan_window_secs, 60);
        assert_eq!(deserialized.insights_model, "llama3:8b");
        assert_eq!(deserialized.sandbox, "strict");
    }

    #[test]
    fn sandbox_field_defaults_when_missing() {
        // Pre-v0.21.5 configs don't have a `sandbox` key — they must
        // continue to load cleanly and pick up the default ("on").
        let toml_str = r#"
default_tab = "dashboard"
"#;
        let cfg: NetwatchConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.sandbox, "on");
    }

    #[test]
    fn tab_parsing() {
        let mut cfg = NetwatchConfig::default();
        assert_eq!(cfg.tab(), Tab::Dashboard);

        cfg.default_tab = "Connections".into();
        assert_eq!(cfg.tab(), Tab::Connections);

        cfg.default_tab = "PACKETS".into();
        assert_eq!(cfg.tab(), Tab::Packets);

        cfg.default_tab = "nonsense".into();
        assert_eq!(cfg.tab(), Tab::Dashboard);
    }

    #[test]
    fn timeline_window_parsing() {
        let mut cfg = NetwatchConfig::default();
        assert_eq!(cfg.timeline_window_enum(), TimelineWindow::Min5);

        cfg.timeline_window = "1m".into();
        assert_eq!(cfg.timeline_window_enum(), TimelineWindow::Min1);

        cfg.timeline_window = "1h".into();
        assert_eq!(cfg.timeline_window_enum(), TimelineWindow::Hour1);

        cfg.timeline_window = "bad".into();
        assert_eq!(cfg.timeline_window_enum(), TimelineWindow::Min5);
    }

    #[test]
    fn empty_toml_gives_defaults() {
        let cfg: NetwatchConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.default_tab, "dashboard");
        assert_eq!(cfg.refresh_rate_ms, 1000);
        assert!(cfg.show_geo);
    }

    #[test]
    fn alerts_section_partial() {
        let toml_str = r#"
[alerts]
bandwidth_threshold = 50000000
"#;
        let cfg: NetwatchConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.alerts.bandwidth_threshold, 50_000_000);
        assert_eq!(cfg.alerts.port_scan_threshold, 20); // default
        assert_eq!(cfg.alerts.port_scan_window_secs, 30); // default
    }

    #[test]
    fn diagnose_thresholds_parse_from_toml_and_default_when_absent() {
        use crate::diagnose::detectors::Thresholds;
        let cfg: NetwatchConfig = toml::from_str(
            r#"
[diagnose_thresholds]
dns_ceiling_ms = 30
consecutive_n = 5
"#,
        )
        .unwrap();
        // A whole number is read as a float, and the keys left out keep
        // their defaults.
        assert_eq!(
            cfg.diagnose_thresholds,
            Thresholds {
                dns_ceiling_ms: 30.0,
                consecutive_n: 5,
                ..Thresholds::default()
            }
        );

        let cfg: NetwatchConfig = toml::from_str("default_tab = \"diagnose\"").unwrap();
        assert_eq!(cfg.diagnose_thresholds, Thresholds::default());

        // A save leaves the table out while it holds the defaults, so a
        // later retune still reaches this file, and keeps it once changed.
        let saved = toml::to_string_pretty(&NetwatchConfig::default()).unwrap();
        assert!(!saved.contains("diagnose_thresholds"), "{saved}");
        let saved = toml::to_string_pretty(&NetwatchConfig {
            diagnose_thresholds: Thresholds {
                sigma_k: 4.0,
                ..Thresholds::default()
            },
            ..Default::default()
        })
        .unwrap();
        let back: NetwatchConfig = toml::from_str(&saved).unwrap();
        assert_eq!(back.diagnose_thresholds.sigma_k, 4.0);
    }

    /// DIAGNOSE.md lists the table with every default, so a threshold added
    /// or retuned without the doc fails here.
    #[test]
    fn the_documented_thresholds_are_the_defaults() {
        // A Windows checkout rewrites the doc to CRLF, and the search below
        // spans a line break.
        let doc = include_str!("../docs/DIAGNOSE.md").replace("\r\n", "\n");
        let start = doc
            .find("```toml\n[diagnose_thresholds]\n")
            .expect("DIAGNOSE.md shows the thresholds table")
            + "```toml\n".len();
        let block = &doc[start..][..doc[start..].find("```").unwrap()];
        let documented: toml::Table = toml::from_str(block).unwrap();
        assert_eq!(
            documented["diagnose_thresholds"],
            toml::Value::try_from(crate::diagnose::detectors::Thresholds::default()).unwrap()
        );
    }

    #[test]
    fn config_path_exists() {
        // Just verify it returns Some on normal systems
        let path = NetwatchConfig::path();
        assert!(path.is_some());
        let p = path.unwrap();
        assert!(p.to_string_lossy().contains("netwatch"));
        assert!(p.to_string_lossy().ends_with("config.toml"));
    }

    #[test]
    fn save_and_load_tempdir() {
        // Test save/load with a temp file
        let dir = std::env::temp_dir().join("netwatch_test_config");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");

        let cfg = NetwatchConfig {
            default_tab: "stats".into(),
            refresh_rate_ms: 750,
            ..Default::default()
        };
        let contents = toml::to_string_pretty(&cfg).unwrap();
        fs::write(&path, &contents).unwrap();

        let loaded: NetwatchConfig = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.default_tab, "stats");
        assert_eq!(loaded.refresh_rate_ms, 750);
        assert!(loaded.show_geo); // default

        let _ = fs::remove_dir_all(&dir);
    }
}
