use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

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

    /// Path to a City or Country .mmdb file, DB-IP's or MaxMind's. Empty uses
    /// what `netwatch geoip update` downloaded, if anything; see
    /// [`geoip_paths`](Self::geoip_paths).
    pub geoip_db: String,

    /// Path to an ASN .mmdb file, DB-IP's or MaxMind's, for organisation
    /// names. Empty uses what `netwatch geoip update` downloaded, if anything.
    pub geoip_asn_db: String,

    /// Removed in 0.39, when it sent every public peer address to a third party
    /// in cleartext. Still read, so a config that sets it loads, and
    /// [`warn_removed_keys`](Self::warn_removed_keys) can say so, but nothing
    /// acts on it and a save drops it from the file.
    #[serde(default, skip_serializing)]
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

    /// Ask before `q` quits. Off by default. Ctrl+C always quits at once.
    #[serde(default)]
    pub confirm_quit: bool,

    /// Record Diagnose episodes: the ten minutes before an issue opens through
    /// ten minutes after it closes, plus one quiet 15-minute sample a day.
    /// Stored locally under `~/.local/state/netwatch/episodes`, kept 90 days
    /// or 300 MB. Nothing is uploaded. Default true.
    #[serde(default = "default_record_episodes")]
    pub diagnose_record_episodes: bool,

    /// Keep the uptime log `netwatch uptime` reports from: a heartbeat a
    /// minute and a line when the gateway, internet or DNS hop goes down or
    /// comes back. Stored locally under `~/.local/state/netwatch/uptime`,
    /// kept 90 days, about 80 KB a day. Nothing is uploaded. Default true.
    #[serde(default = "default_record_uptime")]
    pub record_uptime: bool,

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

fn default_record_uptime() -> bool {
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
            record_uptime: default_record_uptime(),
            diagnose_probes: Default::default(),
            diagnose_targets: Vec::new(),
            diagnose_thresholds: Default::default(),
            sandbox: default_sandbox(),
            tls_keylog_path: String::new(),
            egress_violation_cooldown_secs: default_egress_cooldown(),
            groups_start_collapsed: default_groups_collapsed(),
            confirm_quit: false,
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

/// Why a config.toml that exists was not loaded. A missing file is not an
/// error: it means the defaults.
#[derive(Debug)]
pub enum ConfigError {
    /// The file is there but could not be read: no permission, a directory,
    /// a symlink to nothing, or bytes that are not UTF-8.
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Not valid TOML, or a value of the wrong type. `source` names the line,
    /// column and key and quotes the line. `position` is the 1-based line and
    /// column alone, for a report that must not echo the file. Boxed, as
    /// toml's error would make every `Result` holding this one large.
    Parse {
        path: PathBuf,
        position: Option<(usize, usize)>,
        source: Box<toml::de::Error>,
    },
}

impl ConfigError {
    pub fn path(&self) -> &Path {
        match self {
            ConfigError::Read { path, .. } | ConfigError::Parse { path, .. } => path,
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Read { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            // toml's message ends in a newline.
            ConfigError::Parse { path, source, .. } => write!(
                f,
                "invalid config {}: {}",
                path.display(),
                source.to_string().trim_end()
            ),
        }
    }
}

// The message already carries the cause, so `source()` stays `None`: anyhow
// would otherwise print it twice.
impl std::error::Error for ConfigError {}

/// The 1-based line and column of byte `at`, counting characters as toml does.
fn line_column(text: &str, at: usize) -> (usize, usize) {
    let before = text.get(..at).unwrap_or(text);
    let line = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
    (line, column)
}

impl NetwatchConfig {
    /// Path to `netwatch/config.toml` under the platform config dir
    /// (`~/.config` on Linux, `~/Library/Application Support` on macOS,
    /// `%APPDATA%` on Windows).
    pub fn path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("netwatch").join("config.toml"))
    }

    /// Load from disk. No file means the defaults, and a key the file leaves
    /// out keeps its default. A file that is there but cannot be read or
    /// parsed is an error rather than the defaults: falling back would drop
    /// every setting in it, `sandbox = "strict"` and `record_uptime = false`
    /// included, over one bad value.
    pub fn load() -> Result<Self, ConfigError> {
        match Self::path() {
            Some(path) => Self::load_from(&path),
            None => Ok(Self::default()),
        }
    }

    /// [`load`](Self::load) from `path` rather than the platform location.
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            // Nothing at the path at all. A symlink to a missing file is
            // something, and an error.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && fs::symlink_metadata(path).is_err() =>
            {
                return Ok(Self::default());
            }
            Err(source) => {
                return Err(ConfigError::Read {
                    path: path.into(),
                    source,
                })
            }
        };
        let mut cfg: Self = toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.into(),
            position: source.span().map(|span| line_column(&contents, span.start)),
            source: Box::new(source),
        })?;
        cfg.validate();
        Ok(cfg)
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
        self.save_to(&path)
    }

    /// [`save`](Self::save) to `path`. A file already there that does not
    /// load is left alone, by Settings and `--generate-config` alike: it holds
    /// settings nothing has read, such as a hand edit made while netwatch ran.
    pub fn save_to(&self, path: &Path) -> anyhow::Result<()> {
        if let Err(e) = Self::load_from(path) {
            return Err(anyhow::Error::new(e).context(format!(
                "{} does not load; not overwriting it",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }
}

// ── GeoIP database locations ───────────────────────────────

impl NetwatchConfig {
    /// Log a warning for each key a config still sets that no longer does
    /// anything. For the session's start, once the log exists: `main` loads
    /// the config before it installs the logger, and a session loads it again
    /// after that and on every save, so this cannot live in [`Self::load_from`].
    pub fn warn_removed_keys(&self) {
        if self.geoip_online {
            tracing::warn!(
                target: "netwatch::config",
                "geoip_online was removed in 0.39: it sent peer addresses to a third party in cleartext. Run `netwatch geoip update` for offline lookups."
            );
        }
    }

    /// The City or Country database and the ASN database a session opens, each
    /// empty when there is none. A path in the config wins; an empty one means
    /// what `netwatch geoip update` downloaded, City ahead of Country.
    pub fn geoip_paths(&self) -> (String, String) {
        // What a test finds must not depend on who runs it, or on whether they
        // have run the command.
        #[cfg(test)]
        let downloaded: Option<PathBuf> = None;
        #[cfg(not(test))]
        let downloaded = crate::geoip_update::downloaded_dir();
        self.geoip_paths_in(downloaded.as_deref())
    }

    fn geoip_paths_in(&self, downloaded: Option<&Path>) -> (String, String) {
        use crate::geoip_update::Database;
        let found = |db: Database| {
            downloaded
                .map(|dir| dir.join(db.file_name()))
                .filter(|path| path.is_file())
                .map(|path| path.to_string_lossy().into_owned())
        };
        let or_downloaded = |set: &str, downloaded: Option<String>| {
            if set.trim().is_empty() {
                downloaded.unwrap_or_default()
            } else {
                set.to_owned()
            }
        };
        (
            or_downloaded(
                &self.geoip_db,
                found(Database::City).or_else(|| found(Database::Country)),
            ),
            or_downloaded(&self.geoip_asn_db, found(Database::Asn)),
        )
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
        assert!(!cfg.confirm_quit);
        assert!(cfg.record_uptime);
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
        assert!(!cfg.confirm_quit);
        assert_eq!(cfg.alerts.port_scan_threshold, 20);
    }

    /// A config from before 0.39 still loads and is told about the key, once,
    /// and the key does not survive a save.
    #[test]
    fn geoip_online_true_parses_and_is_ignored() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tracing_subscriber::layer::{Context, SubscriberExt};

        struct Count(Arc<AtomicUsize>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Count {
            fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
                assert_eq!(*event.metadata().level(), tracing::Level::WARN);
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let dir = std::env::temp_dir().join(format!("nw-geoip-online-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        fs::write(&path, "geoip_online = true\ntheme = \"nord\"\n").unwrap();

        let events = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(Count(Arc::clone(&events)));
        tracing::subscriber::with_default(subscriber, || {
            // Loading and saving say nothing. A session does both repeatedly.
            let cfg = NetwatchConfig::load_from(&path).unwrap();
            assert!(cfg.geoip_online);
            assert_eq!(cfg.theme, "nord");
            cfg.save_to(&path).unwrap();
            assert_eq!(events.load(Ordering::Relaxed), 0);

            cfg.warn_removed_keys();
            assert_eq!(events.load(Ordering::Relaxed), 1);

            // The save dropped it, so the next start has nothing to say.
            let saved = fs::read_to_string(&path).unwrap();
            assert!(!saved.contains("geoip_online"), "{saved}");
            let cfg = NetwatchConfig::load_from(&path).unwrap();
            assert!(!cfg.geoip_online);
            assert_eq!(cfg.theme, "nord");
            cfg.warn_removed_keys();
            assert_eq!(events.load(Ordering::Relaxed), 1);
        });
        let _ = fs::remove_dir_all(&dir);
    }

    /// An empty key means the downloaded file where there is one, a path in
    /// the config always wins, and each key is decided on its own.
    #[test]
    fn empty_geoip_paths_use_the_downloaded_files() {
        let dir = std::env::temp_dir().join(format!("nw-geoip-paths-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let text = |name: &str| dir.join(name).to_str().unwrap().to_owned();
        let empty = NetwatchConfig::default();
        let paths = |cfg: &NetwatchConfig| cfg.geoip_paths_in(Some(&dir));

        assert_eq!(paths(&empty), (String::new(), String::new()));
        assert_eq!(
            empty.geoip_paths_in(None),
            (String::new(), String::new()),
            "no cache directory"
        );

        fs::write(dir.join("dbip-country-lite.mmdb"), "x").unwrap();
        fs::write(dir.join("dbip-asn-lite.mmdb"), "x").unwrap();
        assert_eq!(
            paths(&empty),
            (text("dbip-country-lite.mmdb"), text("dbip-asn-lite.mmdb"))
        );

        // City ahead of Country.
        fs::write(dir.join("dbip-city-lite.mmdb"), "x").unwrap();
        assert_eq!(paths(&empty).0, text("dbip-city-lite.mmdb"));

        let own_db = NetwatchConfig {
            geoip_db: "/geo/own.mmdb".into(),
            ..Default::default()
        };
        assert_eq!(
            paths(&own_db),
            ("/geo/own.mmdb".to_owned(), text("dbip-asn-lite.mmdb"))
        );
        let own_asn = NetwatchConfig {
            geoip_asn_db: "/geo/asn.mmdb".into(),
            ..Default::default()
        };
        assert_eq!(
            paths(&own_asn),
            (text("dbip-city-lite.mmdb"), "/geo/asn.mmdb".to_owned())
        );
        // A set path that is not there is reported, not quietly replaced.
        let missing = NetwatchConfig {
            geoip_db: "/nonexistent.mmdb".into(),
            ..Default::default()
        };
        assert_eq!(paths(&missing).0, "/nonexistent.mmdb");

        // Only a file counts.
        let empty_dir = dir.join("empty");
        fs::create_dir(&empty_dir).unwrap();
        fs::create_dir(empty_dir.join("dbip-country-lite.mmdb")).unwrap();
        assert_eq!(empty.geoip_paths_in(Some(&empty_dir)).0, "");
        let _ = fs::remove_dir_all(&dir);
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
            confirm_quit: true,
            diagnose_record_episodes: false,
            record_uptime: false,
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
        assert!(deserialized.confirm_quit);
        assert!(!deserialized.record_uptime);
        assert_eq!(deserialized.bpf_filter, "tcp port 443");
        assert_eq!(deserialized.alerts.bandwidth_threshold, 50_000_000);
        assert_eq!(deserialized.alerts.port_scan_threshold, 10);
        assert_eq!(deserialized.alerts.port_scan_window_secs, 60);
        assert_eq!(deserialized.insights_model, "llama3:8b");
        assert_eq!(deserialized.sandbox, "strict");
    }

    /// config.toml is a file people edit by hand and keep in their dotfiles,
    /// and `--generate-config` writes the one they start from. A toml release
    /// that laid it out differently (tables inlined, strings quoted another
    /// way, a float losing its `.0`) would show up as a rewrite of that file
    /// on the next Settings save. This pins what toml decides about the
    /// layout rather than the list of keys, so adding a key does not fail it.
    #[test]
    fn saved_config_layout_is_stable() {
        let text = toml::to_string_pretty(&NetwatchConfig::default()).unwrap();
        let first_table = text.find("\n[").expect("a table");
        // Top-level keys first, one `key = value` line each.
        for line in [
            "default_tab = \"dashboard\"\n",
            "refresh_rate_ms = 1000\n",
            "capture_interface = \"\"\n",
            "show_geo = true\n",
            "diagnose_targets = []\n",
        ] {
            let at = text
                .find(line)
                .unwrap_or_else(|| panic!("{line:?} in\n{text}"));
            assert!(at < first_table, "{line:?} after a table in\n{text}");
        }
        // Then each nested struct as its own table and each list of them as
        // an array of tables, never inline.
        for block in [
            "\n\n[alerts]\nbandwidth_threshold = 100000000\n",
            "\n\n[diagnose_probes]\ntrace_target = \"1.1.1.1\"\n",
            "\n\n[[diagnose_probes.ipv6_pairs]]\nv4 = \"1.1.1.1:443\"\nv6 = \"[2606:4700:4700::1111]:443\"\n",
            "\n\n[[diagnose_probes.portal_endpoints]]\nurl = \"http://cp.cloudflare.com/generate_204\"\nexpect_status = 204\n",
        ] {
            assert!(text.contains(block), "{block:?} in\n{text}");
        }
        assert!(!text.contains('{'), "an inline table in\n{text}");

        let text = toml::to_string_pretty(&NetwatchConfig {
            bpf_filter: "host \"a\"".into(),
            geoip_db: r"C:\GeoIP\City.mmdb".into(),
            tls_keylog_path: "/tmp/a\nb".into(),
            diagnose_targets: vec![toml::from_str("name = \"api\"\nhost = \"a.example\"").unwrap()],
            diagnose_thresholds: crate::diagnose::detectors::Thresholds {
                sigma_k: 3.5,
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        for line in [
            // A string a basic string would need escapes for is written as a
            // literal string, and one with a newline as a multi-line string.
            "\nbpf_filter = 'host \"a\"'\n",
            "\ngeoip_db = 'C:\\GeoIP\\City.mmdb'\n",
            "\ntls_keylog_path = \"\"\"\n/tmp/a\nb\"\"\"\n",
            "\n\n[[diagnose_targets]]\nenabled = true\nname = \"api\"\nhost = \"a.example\"\nport = 443\n",
            // Floats keep their decimal point, whole or not.
            "\n\n[diagnose_thresholds]\nsigma_k = 3.5\nsigma_close_k = 2.0\n",
        ] {
            assert!(text.contains(line), "{line:?} in\n{text}");
        }
    }

    /// toml 1.x reads TOML 1.1: an inline table may span lines and end in a
    /// comma, and strings take `\e` and `\xHH` escapes. A file written that
    /// way loads rather than falling back to the defaults.
    #[test]
    fn toml_1_1_syntax_loads() {
        let cfg: NetwatchConfig = toml::from_str(
            "bpf_filter = \"\\x74cp\"\nalerts = {\n    bandwidth_threshold = 5,\n    port_scan_threshold = 6,\n}\n",
        )
        .unwrap();
        assert_eq!(cfg.bpf_filter, "tcp");
        assert_eq!(cfg.alerts.bandwidth_threshold, 5);
        assert_eq!(cfg.alerts.port_scan_threshold, 6);
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

    /// A directory of its own for one test, so tests running in parallel
    /// never share a config file and none of them sets an env var.
    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "netwatch_config_{name}_{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn load_from_a_missing_file_gives_the_defaults() {
        let dir = scratch("missing");
        let cfg = NetwatchConfig::load_from(&dir.join("config.toml")).unwrap();
        assert_eq!(cfg.sandbox, "on");
        assert!(cfg.record_uptime);
        // Nor does a missing parent directory make it an error.
        NetwatchConfig::load_from(&dir.join("absent/config.toml")).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_a_partial_file_keeps_the_other_defaults() {
        let dir = scratch("partial");
        let path = dir.join("config.toml");
        fs::write(&path, "sandbox = 'strict'\nrefresh_rate_ms = 50\n").unwrap();
        let cfg = NetwatchConfig::load_from(&path).unwrap();
        assert_eq!(cfg.sandbox, "strict");
        // Clamped by `validate`, as before.
        assert_eq!(cfg.refresh_rate_ms, 100);
        assert!(cfg.record_uptime);
        assert_eq!(cfg.default_tab, "dashboard");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_invalid_toml_names_the_path_line_and_column() {
        let dir = scratch("syntax");
        let path = dir.join("config.toml");
        fs::write(&path, "sandbox = 'strict'\nshow_geo = tru\n").unwrap();
        let err = NetwatchConfig::load_from(&path).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Parse {
                    position: Some((2, 12)),
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(err.path(), path);
        let message = err.to_string();
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(message.contains("line 2, column 12"), "{message}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The case the review reproduced: one value of the wrong type used to
    /// discard the whole file, so a strict sandbox came up best-effort and
    /// uptime recording came back on.
    #[test]
    fn load_from_a_wrong_type_is_an_error_not_the_defaults() {
        let dir = scratch("wrong_type");
        let path = dir.join("config.toml");
        fs::write(
            &path,
            "sandbox = 'strict'\nrecord_uptime = false\nrefresh_rate_ms = 'oops'\n",
        )
        .unwrap();
        let err = NetwatchConfig::load_from(&path).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Parse {
                    position: Some((3, 19)),
                    ..
                }
            ),
            "{err:?}"
        );
        let message = err.to_string();
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(message.contains("refresh_rate_ms"), "{message}");
        assert!(message.contains("expected u64"), "{message}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_an_unreadable_file_is_an_error() {
        let dir = scratch("unreadable");
        // A directory where the file should be is unreadable on every
        // platform, root included, where a mode of 000 is not.
        let path = dir.join("config.toml");
        fs::create_dir(&path).unwrap();
        let err = NetwatchConfig::load_from(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }), "{err:?}");
        assert!(
            err.to_string()
                .starts_with(&format!("cannot read {}: ", path.display())),
            "{err}"
        );

        let path = dir.join("latin1.toml");
        fs::write(&path, b"theme = \"caf\xe9\"\n").unwrap();
        let err = NetwatchConfig::load_from(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }), "{err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A dotfiles manager's link to a file that has gone is a config the user
    /// meant to have, not a missing one.
    #[cfg(unix)]
    #[test]
    fn load_from_a_dangling_symlink_is_an_error() {
        let dir = scratch("dangling");
        let path = dir.join("config.toml");
        std::os::unix::fs::symlink(dir.join("gone.toml"), &path).unwrap();
        let err = NetwatchConfig::load_from(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }), "{err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_to_leaves_a_file_that_does_not_load_alone() {
        let dir = scratch("save");
        let path = dir.join("netwatch/config.toml");
        let cfg = NetwatchConfig {
            theme: "nord".into(),
            ..Default::default()
        };

        // No file yet: written, parent directory included.
        cfg.save_to(&path).unwrap();
        assert_eq!(NetwatchConfig::load_from(&path).unwrap().theme, "nord");

        // A valid file is replaced, as Settings has always done.
        fs::write(&path, "theme = 'ocean'\n").unwrap();
        cfg.save_to(&path).unwrap();
        assert_eq!(NetwatchConfig::load_from(&path).unwrap().theme, "nord");

        // One that does not load is not.
        let broken = "sandbox = 'strict'\nrefresh_rate_ms = 'oops'\n";
        fs::write(&path, broken).unwrap();
        let err = NetwatchConfig::default().save_to(&path).unwrap_err();
        assert!(err.to_string().contains("not overwriting"), "{err:#}");
        assert!(format!("{err:#}").contains("refresh_rate_ms"), "{err:#}");
        assert_eq!(fs::read_to_string(&path).unwrap(), broken);
        let _ = fs::remove_dir_all(&dir);
    }
}
