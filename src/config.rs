use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// User-facing persistent configuration, stored at
/// `~/.config/netwatch/config.toml`.
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
    /// (empty = fall back to online ip-api.com lookups)
    pub geoip_db: String,

    /// Path to MaxMind GeoLite2-ASN .mmdb file (optional, for AS numbers)
    pub geoip_asn_db: String,

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
            alerts: AlertConfig::default(),
            insights_enabled: false,
            insights_model: "llama3.2".into(),
            insights_endpoint: "local".into(),
            theme: "dark".into(),
        }
    }
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
    /// Returns `~/.config/netwatch/config.toml`
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
            "insights" => Tab::Insights,
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
            alerts: AlertConfig {
                bandwidth_threshold: 50_000_000,
                port_scan_threshold: 10,
                port_scan_window_secs: 60,
            },
            insights_enabled: true,
            insights_model: "llama3:8b".into(),
            insights_endpoint: "local".into(),
            theme: "dark".into(),
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
