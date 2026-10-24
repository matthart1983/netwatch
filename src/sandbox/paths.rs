//! Dedicated application paths and exact input files for a prepared policy.
//! Directory preparation happens before restriction; Linux pins opened objects
//! in a ruleset reused by workers. File replacement requires a new session.

use crate::config::NetwatchConfig;
use std::path::PathBuf;

/// Paths the sandbox needs to know about. All optional — empty entries
/// are skipped at apply time rather than treated as `/` allow-all.
#[derive(Debug, Clone, Default)]
pub struct SandboxPaths {
    /// `~/.cache/netwatch/` — log files + Flight Recorder bundles + any
    /// other transient output the TUI writes.
    pub cache_dir: Option<PathBuf>,
    /// `~/.config/netwatch/` — config.toml read at startup and on
    /// settings-overlay edits.
    pub config_dir: Option<PathBuf>,
    /// Exact City database file (legacy field name retained).
    pub geoip_db_dir: Option<PathBuf>,
    /// Exact ASN database file (legacy field name retained).
    pub geoip_asn_db_dir: Option<PathBuf>,
    /// Exact keylog file; no parent-directory grant. Missing files are not granted.
    pub keylog_dir: Option<PathBuf>,
    /// Dedicated cache/netwatch/exports directory (legacy field name retained).
    pub cwd: Option<PathBuf>,
    /// `~/.local/state/netwatch/` (Linux) — the learned egress baseline
    /// (`egress-profiles.json`) persists here on a rate-limited tick and
    /// at quit, both after the sandbox is applied. Read-only would lose
    /// the baseline every session.
    pub state_dir: Option<PathBuf>,
}

impl SandboxPaths {
    /// Derive the sandbox path set from runtime config and dirs.
    ///
    /// All filesystem ops here are read-only (existence checks via
    /// `dirs::*` + `parent()`). No directories are created — the
    /// sandbox just needs to *permit* the directory if the app later
    /// chooses to write there. Missing dirs are silently skipped.
    pub fn from_config(cfg: &NetwatchConfig) -> Self {
        let cache_dir = dirs::cache_dir().map(|c| c.join("netwatch"));
        let config_dir = dirs::config_dir().map(|c| c.join("netwatch"));

        let geoip_db_dir = file_if_set(&cfg.geoip_db);
        let geoip_asn_db_dir = file_if_set(&cfg.geoip_asn_db);
        let keylog_dir = file_if_set(&cfg.tls_keylog_path);

        let cwd = cache_dir.as_ref().map(|p| p.join("exports"));

        // Derive from the same helper that decides where the baseline is
        // written, so the sandbox rule can't drift from the writer.
        let state_dir = crate::collectors::egress::default_profiles_path()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));

        Self {
            cache_dir,
            config_dir,
            geoip_db_dir,
            geoip_asn_db_dir,
            keylog_dir,
            cwd,
            state_dir,
        }
    }
}

fn file_if_set(path: &str) -> Option<PathBuf> {
    (!path.trim().is_empty()).then(|| PathBuf::from(path))
}

impl SandboxPaths {
    /// Create owned application directories before restriction. Reject symlinks
    /// and broad existing directory targets rather than silently widening access.
    pub fn prepare(&self) -> std::io::Result<()> {
        for dir in [
            &self.cache_dir,
            &self.config_dir,
            &self.state_dir,
            &self.cwd,
        ]
        .into_iter()
        .flatten()
        {
            prepare_directory(dir)?;
        }
        if let Some(cache) = &self.cache_dir {
            prepare_directory(&cache.join("scratch"))?;
        }
        for file in [&self.geoip_db_dir, &self.geoip_asn_db_dir, &self.keylog_dir]
            .into_iter()
            .flatten()
        {
            if file.exists() && !file.is_file() {
                return Err(std::io::Error::other(format!(
                    "expected a file: {}",
                    file.display()
                )));
            }
        }
        Ok(())
    }
}
fn prepare_directory(path: &std::path::Path) -> std::io::Result<()> {
    if path.parent().is_none() || path.file_name().is_none() {
        return Err(std::io::Error::other("broad sandbox directory rejected"));
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::other("symlink sandbox directory rejected"));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;
    let canonical = path.canonicalize()?;
    if [
        "/", "/tmp", "/var/tmp", "/usr", "/etc", "/run", "/home", "/root",
    ]
    .iter()
    .any(|p| canonical == std::path::Path::new(p))
        || dirs::home_dir().is_some_and(|h| h == canonical)
    {
        return Err(std::io::Error::other("home/root sandbox grant rejected"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(path)?;
        if directory.metadata()?.uid() != unsafe { nix::libc::geteuid() } {
            return Err(std::io::Error::other(
                "sandbox directory is owned by a different user",
            ));
        }
        directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn shared_tmp_is_rejected_without_changing_its_permissions() {
        let before = std::fs::metadata("/tmp").unwrap().permissions();
        assert!(prepare_directory(std::path::Path::new("/tmp")).is_err());
        assert_eq!(std::fs::metadata("/tmp").unwrap().permissions(), before);
    }

    /// Where netwatch keeps its config, cache and state is part of its
    /// compatibility promise: a `dirs` release that moved one would strand a
    /// user's config.toml, baselines and episodes where the new build never
    /// looks. `dirs` reads the locations from `HOME` and the XDG variables
    /// (on Windows, from the known folders), and changing those here would
    /// race every other test, so each case runs in a child process given its
    /// own environment.
    #[test]
    fn config_cache_and_state_stay_where_earlier_releases_put_them() {
        const EXPECT: [&str; 3] = [
            "NETWATCH_PATHS_TEST_CONFIG",
            "NETWATCH_PATHS_TEST_CACHE",
            "NETWATCH_PATHS_TEST_STATE",
        ];
        if let [Some(config), Some(cache), Some(state)] = EXPECT.map(std::env::var_os) {
            let [config, cache, state] =
                [config, cache, state].map(|d| PathBuf::from(d).join("netwatch"));
            assert_eq!(NetwatchConfig::path(), Some(config.join("config.toml")));
            assert_eq!(
                crate::collectors::egress::default_policy_path(),
                Some(config.join("egress-policy.toml"))
            );
            assert_eq!(crate::logging::log_dir(), Some(cache.clone()));
            assert_eq!(
                crate::diagnose::baseline::BaselineStore::default_path(),
                cache.join("baselines.json")
            );
            assert_eq!(
                crate::diagnose::remediation::Journal::default_path(),
                cache.join("applied.json")
            );
            assert_eq!(crate::app::export_dir(), cache.join("exports"));
            assert_eq!(
                crate::collectors::egress::default_profiles_path(),
                Some(state.join("egress-profiles.json"))
            );
            assert_eq!(
                crate::diagnose::episode::default_dir(),
                Some(state.join("episodes"))
            );
            assert_eq!(crate::uptime::default_dir(), Some(state.join("uptime")));
            assert_eq!(
                crate::diagnose::remediation::store::default_directory(),
                Some(state.join("recovery-v2"))
            );
            let paths = SandboxPaths::from_config(&NetwatchConfig::default());
            assert_eq!(paths.config_dir, Some(config));
            assert_eq!(paths.cache_dir, Some(cache));
            assert_eq!(paths.state_dir, Some(state));
            return;
        }

        let home = std::env::temp_dir().join(format!("netwatch-paths-{}", uuid::Uuid::new_v4()));
        for (env, expected) in path_cases(&home) {
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args([
                "--exact",
                "sandbox::paths::tests::config_cache_and_state_stay_where_earlier_releases_put_them",
                "--nocapture",
            ]);
            for (var, value) in &env {
                match value {
                    Some(v) => cmd.env(var, v),
                    None => cmd.env_remove(var),
                };
            }
            for (var, dir) in EXPECT.iter().zip(&expected) {
                cmd.env(var, dir);
            }
            let out = cmd.output().unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && stdout.contains("1 passed"),
                "{env:?}\n{stdout}\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// The environment a case runs under, and the config, cache and state
    /// directories `dirs` must resolve from it.
    type PathCase = (Vec<(&'static str, Option<PathBuf>)>, [PathBuf; 3]);

    #[cfg(all(unix, not(target_os = "macos")))]
    fn path_cases(home: &std::path::Path) -> Vec<PathCase> {
        let defaults = [".config", ".cache", ".local/state"].map(|d| home.join(d));
        let with = |xdg: [Option<PathBuf>; 3]| {
            let mut env = vec![("HOME", Some(home.to_path_buf()))];
            env.extend(
                ["XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"]
                    .into_iter()
                    .zip(xdg),
            );
            env
        };
        let own = ["xdg-config", "xdg-cache", "xdg-state"].map(|d| home.join(d));
        vec![
            // The XDG variables win over HOME.
            (with(own.clone().map(Some)), own),
            // Unset, the XDG defaults under HOME.
            (with([None, None, None]), defaults.clone()),
            // A relative value is ignored, as the XDG spec requires.
            (
                with(["config", "cache", "state"].map(|d| Some(PathBuf::from(d)))),
                defaults,
            ),
        ]
    }

    #[cfg(target_os = "macos")]
    fn path_cases(home: &std::path::Path) -> Vec<PathCase> {
        // macOS has no state directory, so state falls back to the local data
        // directory, which is Application Support.
        let support = home.join("Library/Application Support");
        vec![(
            vec![("HOME", Some(home.to_path_buf()))],
            [support.clone(), home.join("Library/Caches"), support],
        )]
    }

    #[cfg(windows)]
    fn path_cases(_home: &std::path::Path) -> Vec<PathCase> {
        // The known folders, which no environment variable redirects. Windows
        // sets APPDATA and LOCALAPPDATA to the same two folders at logon, so
        // they say where the folders are. There is no state directory, so
        // state falls back to the local data directory.
        let folder = |var: &str| {
            PathBuf::from(std::env::var_os(var).unwrap_or_else(|| panic!("{var} is unset")))
        };
        vec![(
            Vec::new(),
            [
                folder("APPDATA"),
                folder("LOCALAPPDATA"),
                folder("LOCALAPPDATA"),
            ],
        )]
    }

    #[test]
    fn exports_use_the_dedicated_cache_directory() {
        let paths = SandboxPaths::from_config(&NetwatchConfig::default());
        assert_eq!(paths.cwd, paths.cache_dir.map(|p| p.join("exports")));
    }

    #[test]
    fn empty_geoip_paths_resolve_to_none() {
        let cfg = NetwatchConfig {
            geoip_db: String::new(),
            geoip_asn_db: String::new(),
            ..Default::default()
        };
        let paths = SandboxPaths::from_config(&cfg);
        assert!(paths.geoip_db_dir.is_none());
        assert!(paths.geoip_asn_db_dir.is_none());
    }

    #[test]
    fn absolute_geoip_path_extracts_parent() {
        let cfg = NetwatchConfig {
            geoip_db: "/usr/share/GeoIP/GeoLite2-City.mmdb".to_string(),
            ..Default::default()
        };
        let paths = SandboxPaths::from_config(&cfg);
        assert_eq!(
            paths.geoip_db_dir.as_deref(),
            Some(std::path::Path::new("/usr/share/GeoIP/GeoLite2-City.mmdb"))
        );
    }

    #[test]
    fn bare_filename_geoip_remains_an_exact_file() {
        let cfg = NetwatchConfig {
            geoip_db: "city.mmdb".to_string(),
            ..Default::default()
        };
        let paths = SandboxPaths::from_config(&cfg);
        assert_eq!(
            paths.geoip_db_dir.as_deref(),
            Some(std::path::Path::new("city.mmdb"))
        );
    }
}
