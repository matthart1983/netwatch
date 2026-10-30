//! `netwatch geoip update`: download DB-IP's free databases for offline
//! lookups. Nothing else in netwatch fetches them, and nothing here runs
//! unless asked.
//!
//! The main thread only moves bytes. Undoing the gzip, reading the database
//! and writing the file happen on a `geoip-update` worker, a parser by role
//! ([`crate::sandbox::roles`]), so hostile gzip or database bytes meet those
//! parsers with TCP denied and the filesystem policy applied.
//!
//! The command name, `--city` and the exit codes are stable. The provider,
//! its URLs and the file locations are not, which leaves room to move if
//! DB-IP changes them.
use crate::collectors::geo::epoch_date;
use crate::config::NetwatchConfig;
use crate::sandbox::{worker, Mode, SandboxPaths};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Datelike, Utc};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Where the databases come from; [`Database::url`] adds the file name.
pub const DOWNLOAD_BASE: &str = "https://download.db-ip.com/free/";

/// The City database is about 60 MiB compressed, the others under 6 MiB.
const MAX_COMPRESSED: u64 = 80 * 1024 * 1024;
const MAX_DECOMPRESSED: u64 = crate::collectors::geo::MAX_DATABASE_BYTES;
/// DB-IP publishes monthly, and the month's file can be a day late, so a good
/// download can be two months old. Past this the provider has stopped
/// publishing or someone is replaying an old file.
const MAX_BUILD_AGE: Duration = Duration::from_secs(70 * 86_400);
/// Slower than this a download is not going to finish. The shared agent's 30 s
/// is for small JSON replies; the per-read timeout still catches a stall.
const BODY_TIMEOUT: Duration = Duration::from_secs(600);

/// One of DB-IP's three free databases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Database {
    Country,
    Asn,
    City,
}

impl Database {
    fn slug(self) -> &'static str {
        match self {
            Database::Country => "country",
            Database::Asn => "asn",
            Database::City => "city",
        }
    }

    /// What the file's own `database_type` must start with.
    fn database_type(self) -> &'static str {
        match self {
            Database::Country => "DBIP-Country-Lite",
            Database::Asn => "DBIP-ASN-Lite",
            Database::City => "DBIP-City-Lite",
        }
    }

    pub fn file_name(self) -> String {
        format!("dbip-{}-lite.mmdb", self.slug())
    }

    fn url(self, month: &str) -> String {
        format!("{DOWNLOAD_BASE}dbip-{}-lite-{month}.mmdb.gz", self.slug())
    }
}

/// Where the command puts its files. An empty `geoip_db` or `geoip_asn_db`
/// looks here ([`NetwatchConfig::geoip_paths`]).
pub fn downloaded_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|cache| cache.join("netwatch").join("geoip"))
}

/// What one request came back with.
#[derive(Debug)]
enum Fetched {
    /// 404: the month's file is not there.
    Missing,
    NotModified,
    Body {
        gzip: Vec<u8>,
        last_modified: Option<SystemTime>,
    },
}

/// A database file that passed [`validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct Checked {
    database_type: String,
    build_epoch: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Updated(Checked),
    AlreadyCurrent(Checked),
}

/// Run `netwatch geoip update`. Any database that could not be brought up to
/// date is an error, so the process exits 1, and the file it would have
/// replaced stays as it was.
pub fn command(city: bool) -> Result<()> {
    // A config that does not load could be hiding `sandbox = "strict"`, so
    // this stops the same way a live session does.
    let config = NetwatchConfig::load()?;
    let dir = downloaded_dir().context("cannot determine the cache directory")?;
    // A session takes database paths as text, so it could never open a file
    // saved here, and running this again would not help.
    if dir.to_str().is_none() {
        bail!(
            "the cache directory {} is not valid UTF-8, so netwatch could not load a \
             database saved there; use another cache directory, or set geoip_db to a \
             database you downloaded yourself",
            dir.display()
        );
    }
    let mode = Mode::from_config(&config.sandbox);
    let paths = SandboxPaths::from_config(&config);
    if !matches!(mode, Mode::Disabled) {
        paths.prepare()?;
    }
    worker::install(mode, paths).map_err(anyhow::Error::msg)?;
    let _session = worker::SessionGuard;
    worker::preflight().map_err(anyhow::Error::msg)?;

    crate::owner_only::create_dir_all(&dir)
        .with_context(|| format!("cannot create {}", dir.display()))?;
    let _lock = take_lock(&dir)?;
    remove_stale_partials(&dir);

    let agent = crate::http::agent();
    let mut over_https = |url: &str, since: Option<SystemTime>| fetch(agent, true, url, since);
    run(city, &dir, Utc::now(), &mut over_https, &config)
}

/// Update each database in turn and report on them. One that fails does not
/// stop the next.
fn run(
    city: bool,
    dir: &Path,
    now: DateTime<Utc>,
    fetch: &mut impl FnMut(&str, Option<SystemTime>) -> Result<Fetched>,
    config: &NetwatchConfig,
) -> Result<()> {
    let mut wanted = vec![Database::Country, Database::Asn];
    // City wins over Country once it is there, so a file left to go stale
    // would hide the Country file this run refreshes.
    if city || dir.join(Database::City.file_name()).is_file() {
        wanted.push(Database::City);
    }
    let (mut updated, mut failed) = (0, 0);
    for db in &wanted {
        let path = dir.join(db.file_name());
        match update_one(*db, dir, now, fetch) {
            Ok(Outcome::Updated(checked)) => {
                updated += 1;
                say(&format!("updated {}", describe(&path, &checked)));
            }
            Ok(Outcome::AlreadyCurrent(checked)) => {
                say(&format!("already current {}", describe(&path, &checked)));
            }
            Err(error) => {
                failed += 1;
                complain(&format!("{}: {error:#}", db.file_name()));
            }
        }
    }
    if let Some(partly) = worker::snapshot()
        .get("geoip-update")
        .and_then(|worker| worker.error.clone())
    {
        complain(&format!("note: {partly}"));
    }
    if failed < wanted.len() {
        say(crate::collectors::geo::DBIP_ATTRIBUTION);
    }
    if updated > 0 {
        say("restart netwatch to load it");
        for (key, value) in [
            ("geoip_db", &config.geoip_db),
            ("geoip_asn_db", &config.geoip_asn_db),
        ] {
            if !value.trim().is_empty() {
                say(&format!(
                    "{key} in config.toml still takes precedence: {value}"
                ));
            }
        }
    }
    if failed > 0 {
        bail!("{failed} of {} databases not updated", wanted.len());
    }
    Ok(())
}

/// Write a line of the report. A closed pipe or a full disk must not cost the
/// run its remaining downloads or its exit status, and the print macros panic
/// on both.
fn say(line: &str) {
    let _ = writeln!(std::io::stdout(), "{line}");
}

/// [`say`] for stderr, whose print macro panics the same way.
fn complain(line: &str) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// Hold this for the run. Two runs would write the same partial file, and the
/// first to rename would publish what the second had written so far.
fn take_lock(dir: &Path) -> Result<std::fs::File> {
    let path = dir.join(".update.lock");
    let lock = crate::owner_only::create(&path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    lock_outcome(lock.try_lock(), &path)?;
    Ok(lock)
}

/// A lock that could not be taken at all, on a filesystem without them say, is
/// a refusal too: it says nothing about whether another run is writing.
fn lock_outcome(result: Result<(), std::fs::TryLockError>, path: &Path) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => {
            bail!("another netwatch geoip update is running")
        }
        Err(std::fs::TryLockError::Error(error)) => {
            bail!("cannot lock {}: {error}", path.display())
        }
    }
}

/// A run stopped partway leaves its partial file, and a first `--city` that
/// never finishes would otherwise leave 127 MB that no later run looks at. Only
/// call this holding the lock. What cannot be removed shows when the write to
/// that path fails.
fn remove_stale_partials(dir: &Path) {
    for db in [Database::Country, Database::Asn, Database::City] {
        let _ = std::fs::remove_file(partial_of(&dir.join(db.file_name())));
    }
}

/// Where a database is written before it replaces `path`.
fn partial_of(path: &Path) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!(".{name}.partial"))
}

fn describe(path: &Path, checked: &Checked) -> String {
    let built = epoch_date(checked.build_epoch)
        .map_or_else(|| "?".into(), |at| at.format("%Y-%m-%d").to_string());
    format!(
        "{} ({}, built {built})",
        path.display(),
        checked.database_type
    )
}

/// Bring one file up to date: this month's database, or last month's when
/// this month's is not out yet.
fn update_one(
    db: Database,
    dir: &Path,
    now: DateTime<Utc>,
    fetch: &mut impl FnMut(&str, Option<SystemTime>) -> Result<Fetched>,
) -> Result<Outcome> {
    let path = dir.join(db.file_name());
    // Read in the worker too: this file is about to decide whether a download
    // happens at all. One that does not validate is fetched again, or the server
    // would call it current. That catches the wrong database, a file cut short
    // and one past its age, but the data check is one lookup: damage anywhere
    // 8.8.8.8 does not reach still reads as current, until next month's file
    // replaces it.
    let present = {
        let path = path.clone();
        confined(move || read_and_validate(db, &path, now))?.ok()
    };
    let mtime = present
        .as_ref()
        .and_then(|_| std::fs::metadata(&path).and_then(|m| m.modified()).ok());
    let held = present
        .as_ref()
        .and_then(|checked| epoch_date(checked.build_epoch))
        .map(|built| built.format("%Y-%m").to_string());

    let months = [month(now), previous_month(now)];
    for month in &months {
        let url = db.url(month);
        // An mtime says nothing about which month a file holds: `cp` without
        // `-p` makes October's file newer than November's, and the server would
        // answer 304 for November. So only the month the file was built in is
        // asked conditionally. DB-IP builds a file on the first of its month; if
        // that ever slips, the cost is a download, not a stale file.
        let since = mtime.filter(|_| held.as_ref() == Some(month));
        match fetch(&url, since).with_context(|| url.clone())? {
            Fetched::Missing => continue,
            Fetched::NotModified => {
                return present
                    .filter(|_| since.is_some())
                    .map(Outcome::AlreadyCurrent)
                    .ok_or_else(|| anyhow!("{url}: 304 to a request that was not conditional"));
            }
            Fetched::Body {
                gzip,
                last_modified,
            } => {
                let path = path.clone();
                let checked = confined(move || install(db, &path, &gzip, last_modified, now))?
                    .with_context(|| url.clone())?;
                return Ok(Outcome::Updated(checked));
            }
        }
    }
    bail!(
        "{}: no database for {} or {}",
        DOWNLOAD_BASE,
        months[0],
        months[1]
    )
}

fn month(now: DateTime<Utc>) -> String {
    now.format("%Y-%m").to_string()
}

fn previous_month(now: DateTime<Utc>) -> String {
    match now.month() {
        1 => format!("{}-12", now.year() - 1),
        month => format!("{}-{:02}", now.year(), month - 1),
    }
}

/// One GET. `https_only` is off only for tests, which have no certificate.
fn fetch(
    agent: &ureq::Agent,
    https_only: bool,
    url: &str,
    since: Option<SystemTime>,
) -> Result<Fetched> {
    let mut request = agent
        .get(url)
        .config()
        .https_only(https_only)
        .max_redirects(0)
        .timeout_recv_body(Some(BODY_TIMEOUT))
        .build()
        .header("Accept-Encoding", "identity");
    if let Some(since) = since.and_then(http_date) {
        request = request.header("If-Modified-Since", since);
    }
    let response = match request.call() {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(404)) => return Ok(Fetched::Missing),
        Err(error) => return Err(error.into()),
    };
    match response.status().as_u16() {
        200 => {}
        304 => return Ok(Fetched::NotModified),
        // With no redirects followed, a 3xx is returned as it is.
        status => bail!("unexpected status {status}"),
    }
    // Not asked for, but a server can send one anyway: ureq gunzips a body
    // marked gzip as it is read, here on the main thread, and removes both
    // headers from the response so nothing shows it will. A plain .gz has a
    // length and no coding, so anything else is refused without reading it.
    let headers = response.headers();
    let length = headers
        .get("Content-Length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let Some(length) = length.filter(|_| !headers.contains_key("Content-Encoding")) else {
        bail!("the response has a content coding, or no length");
    };
    if length > MAX_COMPRESSED {
        bail!("{length} bytes is over the {MAX_COMPRESSED} byte limit");
    }
    let last_modified = headers
        .get("Last-Modified")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| DateTime::parse_from_rfc2822(value).ok())
        .and_then(|at| {
            let secs = u64::try_from(at.timestamp()).ok()?;
            UNIX_EPOCH.checked_add(Duration::from_secs(secs))
        });
    let gzip = response
        .into_body()
        .into_with_config()
        .limit(MAX_COMPRESSED)
        .read_to_vec()?;
    Ok(Fetched::Body {
        gzip,
        last_modified,
    })
}

/// A file's mtime as an HTTP date, or `None` where chrono cannot represent it:
/// some filesystems hold a date its `From<SystemTime>` panics on.
fn http_date(at: SystemTime) -> Option<String> {
    let secs = at.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let at = epoch_date(secs)?;
    Some(at.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
}

/// Run `work` on a `geoip-update` worker and return what it returned. Strict
/// refusing the thread, or a panic on a hostile file, is an error here.
fn confined<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let handle = worker::spawn("geoip-update", move || {
        let _ = tx.send(work());
    });
    let answer = rx.recv();
    let _ = handle.join();
    answer.map_err(|_| {
        let why = worker::snapshot()
            .get("geoip-update")
            .and_then(|worker| worker.error.clone());
        anyhow!(
            "the parsing worker stopped: {}",
            why.as_deref().unwrap_or("it panicked")
        )
    })
}

/// Undo the gzip, check the database and replace the file. Runs on the worker.
fn install(
    db: Database,
    path: &Path,
    gzip: &[u8],
    last_modified: Option<SystemTime>,
    now: DateTime<Utc>,
) -> Result<Checked> {
    let bytes = gunzip(gzip)?;
    let checked = validate(db, &bytes, now)?;
    // The server's own date, not the time of this write. The next run sends
    // it back as If-Modified-Since, and a write time could be later than the
    // next month's file: Cloudflare keeps a 404 for hours after DB-IP
    // publishes, so a run can fetch October after November's Last-Modified,
    // and then November would answer 304 until December.
    let modified = last_modified.unwrap_or(UNIX_EPOCH + Duration::from_secs(checked.build_epoch));
    replace_file(path, &bytes, modified)?;
    Ok(checked)
}

fn gunzip(gzip: &[u8]) -> Result<Vec<u8>> {
    debug_assert_eq!(std::thread::current().name(), Some("geoip-update"));
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(gzip)
        .take(MAX_DECOMPRESSED + 1)
        .read_to_end(&mut bytes)
        .context("not a complete gzip file")?;
    if bytes.len() as u64 > MAX_DECOMPRESSED {
        bail!("decompresses past the {MAX_DECOMPRESSED} byte limit");
    }
    Ok(bytes)
}

fn read_and_validate(db: Database, path: &Path, now: DateTime<Utc>) -> Result<Checked> {
    validate(db, &crate::collectors::geo::read_database(path)?, now)
}

/// Is this the database that was asked for, recent, and able to answer?
fn validate(db: Database, bytes: &[u8], now: DateTime<Utc>) -> Result<Checked> {
    debug_assert_eq!(std::thread::current().name(), Some("geoip-update"));
    use crate::ui::sanitize::display_owned;
    let reader = maxminddb::Reader::from_source(bytes).context("not a MaxMind database")?;
    let metadata = reader.metadata();
    if !metadata.database_type.starts_with(db.database_type()) {
        bail!(
            "expected {}, found {}",
            db.database_type(),
            display_owned(metadata.database_type.clone())
        );
    }
    match SystemTime::from(now).duration_since(metadata.build_time()?) {
        Ok(age) if age > MAX_BUILD_AGE => {
            bail!("built {} days ago", age.as_secs() / 86_400)
        }
        Ok(_) => {}
        // A clock a little behind is not the file's fault, and a date far
        // ahead would never read as stale.
        Err(ahead) if ahead.duration() > Duration::from_secs(86_400) => {
            bail!(
                "built {} days from now",
                ahead.duration().as_secs() / 86_400
            )
        }
        Err(_) => {}
    }
    let found = reader.lookup(std::net::IpAddr::from([8, 8, 8, 8]))?;
    let answers = match db {
        Database::Asn => found
            .decode::<maxminddb::geoip2::Asn>()?
            .is_some_and(|asn| {
                asn.autonomous_system_organization
                    .is_some_and(|org| !org.is_empty())
            }),
        Database::Country | Database::City => found
            .decode::<maxminddb::geoip2::Country>()?
            .is_some_and(|record| record.country.iso_code.is_some_and(|c| !c.is_empty())),
    };
    if !answers {
        bail!("no answer for 8.8.8.8");
    }
    Ok(Checked {
        database_type: display_owned(metadata.database_type.clone()),
        build_epoch: metadata.build_epoch,
    })
}

/// Replace `path` so a reader sees the old file or the whole new one, and a
/// failure leaves the old one. `modified` becomes the new file's mtime.
fn replace_file(path: &Path, bytes: &[u8], modified: SystemTime) -> Result<()> {
    let partial = partial_of(path);
    let replaced = write_synced(&partial, bytes, modified).and_then(|()| rename(&partial, path));
    if replaced.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    replaced.with_context(|| format!("cannot write {}", path.display()))
}

fn write_synced(path: &Path, bytes: &[u8], modified: SystemTime) -> std::io::Result<()> {
    let mut file = crate::owner_only::create(path)?;
    file.write_all(bytes)?;
    file.set_modified(modified)?;
    file.sync_all()
}

/// On Windows a scanner or indexer holding the old file open fails the rename
/// for as long as it looks, so it gets a few tries.
fn rename(from: &Path, to: &Path) -> std::io::Result<()> {
    let tries = if cfg!(windows) { 3 } else { 1 };
    let mut tried = 1;
    loop {
        match std::fs::rename(from, to) {
            Err(_) if tried < tries => {
                tried += 1;
                std::thread::sleep(Duration::from_millis(200));
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::geo::test_db;
    use chrono::TimeZone;
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;

    fn at(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).unwrap()
    }

    fn gz(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn built(now: DateTime<Utc>, days_ago: i64) -> u64 {
        (now.timestamp() - days_ago * 86_400) as u64
    }

    fn country(now: DateTime<Utc>) -> Vec<u8> {
        test_db::city("DBIP-Country-Lite", built(now, 10))
    }

    fn body(bytes: &[u8]) -> Fetched {
        Fetched::Body {
            gzip: gz(bytes),
            last_modified: None,
        }
    }

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("nw-geoip-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn file(&self, db: Database) -> PathBuf {
            self.0.join(db.file_name())
        }
        fn names(&self) -> Vec<String> {
            let mut names: Vec<_> = std::fs::read_dir(&self.0)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// DB-IP publishes during the first of the month, so before that this
    /// month's URL is a 404 and last month's is the newest there is.
    #[test]
    fn month_falls_back_on_404() {
        let dir = TestDir::new();
        let now = at(2026, 11, 1);
        let mut urls = Vec::new();
        let outcome = update_one(Database::Country, &dir.0, now, &mut |url: &str, since| {
            assert_eq!(since, None, "nothing on disk to compare");
            urls.push(url.to_owned());
            Ok(if urls.len() == 1 {
                Fetched::Missing
            } else {
                body(&country(now))
            })
        })
        .unwrap();
        assert!(matches!(outcome, Outcome::Updated(_)));
        assert_eq!(
            urls,
            [
                "https://download.db-ip.com/free/dbip-country-lite-2026-11.mmdb.gz",
                "https://download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz",
            ]
        );
        assert_eq!(previous_month(at(2027, 1, 2)), "2026-12");
        assert_eq!(previous_month(at(2026, 10, 2)), "2026-09");
    }

    #[test]
    fn two_missing_months_are_a_failure() {
        let dir = TestDir::new();
        let error = update_one(Database::Asn, &dir.0, at(2026, 11, 1), &mut |_: &str, _| {
            Ok(Fetched::Missing)
        })
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("2026-11 or 2026-10"),
            "{error:#}"
        );
        assert!(dir.names().is_empty());
    }

    /// 256 MiB of zeros is about 256 KiB of gzip, well under the limit on the
    /// download, so only the limit on what it decompresses to can stop it.
    #[test]
    fn gzip_over_cap_is_rejected() {
        let dir = TestDir::new();
        let now = at(2026, 11, 2);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let chunk = vec![0u8; 1 << 20];
        for _ in 0..=(MAX_DECOMPRESSED >> 20) {
            encoder.write_all(&chunk).unwrap();
        }
        let gzip = encoder.finish().unwrap();
        assert!((gzip.len() as u64) < MAX_COMPRESSED);
        let error = update_one(Database::Country, &dir.0, now, &mut |_: &str, _| {
            Ok(Fetched::Body {
                gzip: gzip.clone(),
                last_modified: None,
            })
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("limit"), "{error:#}");
        assert!(dir.names().is_empty());
    }

    #[test]
    fn truncated_gzip_is_rejected() {
        let dir = TestDir::new();
        let now = at(2026, 11, 2);
        let mut gzip = gz(&country(now));
        gzip.truncate(gzip.len() - 9);
        let error = update_one(Database::Country, &dir.0, now, &mut |_: &str, _| {
            Ok(Fetched::Body {
                gzip: gzip.clone(),
                last_modified: None,
            })
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("gzip"), "{error:#}");
        assert!(dir.names().is_empty());
    }

    /// A City file served at the Country URL, or anything else that is not
    /// what was asked for, never reaches the path a session opens.
    #[test]
    fn wrong_database_type_keeps_old_file() {
        let dir = TestDir::new();
        let now = at(2026, 11, 2);
        let old = country(now);
        let path = dir.file(Database::Country);
        std::fs::write(&path, b"old database").unwrap();
        for (wrong, expect) in [
            (
                test_db::city("DBIP-City-Lite", built(now, 1)),
                "found DBIP-City-Lite",
            ),
            (
                test_db::city("GeoLite2-City", built(now, 1)),
                "found GeoLite2-City",
            ),
            (b"not a database".to_vec(), "not a MaxMind database"),
        ] {
            let error = update_one(Database::Country, &dir.0, now, &mut |_: &str, _| {
                Ok(body(&wrong))
            })
            .unwrap_err();
            assert!(format!("{error:#}").contains(expect), "{error:#}");
            assert_eq!(std::fs::read(&path).unwrap(), b"old database");
            assert_eq!(dir.names(), [Database::Country.file_name()]);
        }
        update_one(Database::Country, &dir.0, now, &mut |_: &str, _| {
            Ok(body(&old))
        })
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), old);
    }

    /// A date this far out fits `SystemTime` but not chrono. It is a file that
    /// fails its checks, not a panic on the worker.
    #[test]
    fn an_out_of_range_build_epoch_is_rejected() {
        let dir = TestDir::new();
        let now = at(2026, 11, 2);
        for epoch in [9_000_000_000_000, u64::MAX] {
            let db = test_db::city("DBIP-Country-Lite", epoch);
            let error = update_one(Database::Country, &dir.0, now, &mut |_: &str, _| {
                Ok(body(&db))
            })
            .unwrap_err();
            assert!(!format!("{error:#}").contains("panicked"), "{error:#}");
            assert!(dir.names().is_empty());
        }
    }

    /// Some filesystems keep an mtime chrono cannot represent, and chrono's
    /// conversion panicked on the main thread for it.
    #[test]
    fn an_mtime_chrono_cannot_represent_is_not_sent() {
        assert_eq!(
            http_date(UNIX_EPOCH + Duration::from_secs(1_790_818_572)).as_deref(),
            Some("Thu, 01 Oct 2026 01:36:12 GMT")
        );
        assert_eq!(
            http_date(UNIX_EPOCH + Duration::from_secs(9_000_000_000_000)),
            None
        );
        assert_eq!(http_date(UNIX_EPOCH - Duration::from_secs(1)), None);
    }

    /// A Last-Modified from a hostile server is not converted unchecked, and a
    /// missing date is the same as none: the file takes its build date.
    #[test]
    fn an_unusable_last_modified_is_ignored() {
        for date in ["Fri, 01 Jan 1960 00:00:00 GMT", "not a date"] {
            let (url, server) = serve(response(
                &format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nLast-Modified: {date}"),
                b"ok",
            ));
            let fetched = fetch(crate::http::agent(), false, &url, None).unwrap();
            let Fetched::Body { last_modified, .. } = fetched else {
                panic!("{fetched:?}");
            };
            assert_eq!(last_modified, None, "{date}");
            server.join().unwrap();
        }
    }

    /// A FIFO left where a database goes held the update forever, as it did
    /// doctor. It does not validate, so the download replaces it.
    #[cfg(unix)]
    #[test]
    fn a_fifo_in_place_of_a_database_is_replaced() {
        let dir = TestDir::new();
        let now = at(2026, 11, 2);
        let path = dir.file(Database::Country);
        assert!(std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success());
        let (tx, rx) = std::sync::mpsc::channel();
        let target = dir.0.clone();
        std::thread::spawn(move || {
            let outcome = update_one(Database::Country, &target, now, &mut |_: &str, since| {
                assert_eq!(since, None);
                Ok(body(&country(now)))
            });
            let _ = tx.send(outcome.map_err(|error| format!("{error:#}")));
        });
        let outcome = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the update did not return");
        assert!(matches!(outcome, Ok(Outcome::Updated(_))), "{outcome:?}");
        assert!(std::fs::metadata(&path).unwrap().is_file());
    }

    /// A database with nothing to say about 8.8.8.8 has the wrong shape.
    #[test]
    fn a_database_that_cannot_answer_is_rejected() {
        let dir = TestDir::new();
        let now = at(2026, 11, 2);
        // A City-shaped record has no autonomous_system_organization.
        let error = update_one(Database::Asn, &dir.0, now, &mut |_: &str, _| {
            Ok(body(&test_db::city("DBIP-ASN-Lite", built(now, 1))))
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("no answer"), "{error:#}");
        // The ASN shape is what the ASN database has to be.
        update_one(Database::Asn, &dir.0, now, &mut |_: &str, _| {
            Ok(body(&test_db::asn("DBIP-ASN-Lite", built(now, 1))))
        })
        .unwrap();
    }

    #[test]
    fn stale_build_epoch_rejected() {
        let dir = TestDir::new();
        let now = at(2026, 11, 2);
        let path = dir.file(Database::Country);
        for (days_ago, accepted) in [(71, false), (-3, false), (69, true)] {
            let db = test_db::city("DBIP-Country-Lite", built(now, days_ago));
            let result = update_one(Database::Country, &dir.0, now, &mut |_: &str, _| {
                Ok(body(&db))
            });
            assert_eq!(result.is_ok(), accepted, "{days_ago}: {result:?}");
            assert_eq!(path.exists(), accepted, "{days_ago}");
        }
    }

    /// A reader sees the old file or the whole new one, however the two are
    /// timed, and a write that cannot start leaves the old file alone.
    #[test]
    fn replace_is_atomic() {
        let dir = TestDir::new();
        let path = dir.file(Database::Country);
        let (a, b) = (vec![b'a'; 1 << 20], vec![b'b'; 1 << 20]);
        let modified = UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        replace_file(&path, &a, modified).unwrap();

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let (path, a, b, stop) = (path.clone(), a.clone(), b.clone(), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut reads = 0;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    // Windows can refuse the open while the rename runs.
                    if let Ok(read) = std::fs::read(&path) {
                        assert!(read == a || read == b, "a torn read: {} bytes", read.len());
                        reads += 1;
                    }
                }
                reads
            })
        };
        for round in 0..100 {
            let bytes = if round % 2 == 0 { &b } else { &a };
            replace_file(&path, bytes, modified).unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(reader.join().unwrap() > 0);
        assert_eq!(std::fs::read(&path).unwrap(), a);
        assert_eq!(dir.names(), [Database::Country.file_name()]);

        // A directory where the partial file goes: the write fails first.
        let blocker = dir
            .0
            .join(format!(".{}.partial", Database::Country.file_name()));
        std::fs::create_dir(&blocker).unwrap();
        assert!(replace_file(&path, &b, modified).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), a);
    }

    /// The server's date is what the next request sends back, and the file
    /// is readable only by its owner, like everything else netwatch saves.
    #[test]
    fn the_file_keeps_the_servers_date() {
        let dir = TestDir::new();
        let now = at(2026, 11, 2);
        let served = at(2026, 10, 1);
        update_one(Database::Country, &dir.0, now, &mut |_: &str, _| {
            Ok(Fetched::Body {
                gzip: gz(&country(now)),
                last_modified: Some(served.into()),
            })
        })
        .unwrap();
        let meta = std::fs::metadata(dir.file(Database::Country)).unwrap();
        assert_eq!(meta.modified().unwrap(), SystemTime::from(served));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn not_modified_is_success() {
        let dir = TestDir::new();
        let now = at(2026, 11, 2);
        let db = test_db::city("DBIP-Country-Lite", built(now, 1));
        let served = at(2026, 11, 1);
        update_one(Database::Country, &dir.0, now, &mut |_: &str, _| {
            Ok(Fetched::Body {
                gzip: gz(&db),
                last_modified: Some(served.into()),
            })
        })
        .unwrap();
        let before = std::fs::read(dir.file(Database::Country)).unwrap();
        let outcome = update_one(Database::Country, &dir.0, now, &mut |_: &str, since| {
            assert_eq!(since, Some(served.into()));
            Ok(Fetched::NotModified)
        })
        .unwrap();
        let Outcome::AlreadyCurrent(checked) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(checked.database_type, "DBIP-Country-Lite");
        assert_eq!(std::fs::read(dir.file(Database::Country)).unwrap(), before);
    }

    /// `cp` without `-p` gave last month's file a date later than this month's,
    /// so asking with it got a 304 and the old data read as current for up to
    /// 70 days. The date goes only to the URL for the month the file holds.
    #[test]
    fn since_goes_only_with_the_month_the_file_holds() {
        let dir = TestDir::new();
        let now = at(2026, 11, 21);
        let path = dir.file(Database::Country);
        let october = Utc.with_ymd_and_hms(2026, 10, 1, 1, 36, 12).unwrap();
        std::fs::write(
            &path,
            test_db::city("DBIP-Country-Lite", october.timestamp() as u64),
        )
        .unwrap();
        // As `cp` leaves it: written yesterday, so later than November's file.
        let rewritten = SystemTime::from(at(2026, 11, 20));
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(rewritten)
            .unwrap();

        // November comes down, because it is not asked conditionally.
        let mut asked = Vec::new();
        let november = test_db::city("DBIP-Country-Lite", built(now, 20));
        let outcome = update_one(Database::Country, &dir.0, now, &mut |url: &str, since| {
            asked.push((url.to_owned(), since));
            // What Cloudflare answers for a date later than its file.
            Ok(if since.is_some() {
                Fetched::NotModified
            } else {
                body(&november)
            })
        })
        .unwrap();
        assert!(matches!(outcome, Outcome::Updated(_)), "{outcome:?}");
        assert_eq!(
            asked,
            [(Database::Country.url("2026-11"), None)],
            "only this month, unconditionally"
        );
        assert_eq!(std::fs::read(&path).unwrap(), november);
    }

    /// With this month's file not out yet, the month the file does hold is the
    /// one asked conditionally, and that is what "already current" rests on.
    #[test]
    fn the_previous_month_is_asked_conditionally_when_the_file_holds_it() {
        let dir = TestDir::new();
        let now = at(2026, 11, 1);
        let path = dir.file(Database::Country);
        let october = Utc.with_ymd_and_hms(2026, 10, 1, 1, 36, 12).unwrap();
        std::fs::write(
            &path,
            test_db::city("DBIP-Country-Lite", october.timestamp() as u64),
        )
        .unwrap();
        let served = SystemTime::from(at(2026, 10, 1));
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(served)
            .unwrap();
        let mut asked = Vec::new();
        let outcome = update_one(Database::Country, &dir.0, now, &mut |url: &str, since| {
            asked.push((url.to_owned(), since));
            Ok(if url.contains("2026-11") {
                Fetched::Missing
            } else {
                Fetched::NotModified
            })
        })
        .unwrap();
        assert!(matches!(outcome, Outcome::AlreadyCurrent(_)), "{outcome:?}");
        assert_eq!(
            asked,
            [
                (Database::Country.url("2026-11"), None),
                (Database::Country.url("2026-10"), Some(served)),
            ]
        );
    }

    /// A file two months old is asked about under neither month, so it cannot
    /// read as current however recent its date looks.
    #[test]
    fn a_file_older_than_both_months_is_never_asked_conditionally() {
        let dir = TestDir::new();
        let now = at(2026, 11, 1);
        let september = Utc.with_ymd_and_hms(2026, 9, 1, 1, 32, 45).unwrap();
        std::fs::write(
            dir.file(Database::Country),
            test_db::city("DBIP-Country-Lite", september.timestamp() as u64),
        )
        .unwrap();
        let mut asked = Vec::new();
        let outcome = update_one(Database::Country, &dir.0, now, &mut |url: &str, since| {
            asked.push((url.to_owned(), since));
            Ok(if url.contains("2026-11") {
                Fetched::Missing
            } else {
                body(&test_db::city("DBIP-Country-Lite", built(now, 20)))
            })
        })
        .unwrap();
        assert!(matches!(outcome, Outcome::Updated(_)), "{outcome:?}");
        assert!(asked.iter().all(|(_, since)| since.is_none()), "{asked:?}");
    }

    /// A 304 to a request that named no date says nothing about this file, even
    /// a valid one.
    #[test]
    fn a_304_to_an_unconditional_request_is_a_failure() {
        let dir = TestDir::new();
        let now = at(2026, 11, 21);
        // Built in October, so November goes out with no date.
        let october = Utc.with_ymd_and_hms(2026, 10, 1, 1, 36, 12).unwrap();
        std::fs::write(
            dir.file(Database::Country),
            test_db::city("DBIP-Country-Lite", october.timestamp() as u64),
        )
        .unwrap();
        let error = update_one(Database::Country, &dir.0, now, &mut |_: &str, _| {
            Ok(Fetched::NotModified)
        })
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("not conditional"),
            "{error:#}"
        );
    }

    /// A damaged file with a good date is not asked after, or the server would
    /// call it current and doctor would keep calling it unreadable.
    #[test]
    fn a_file_that_no_longer_validates_is_fetched_again() {
        let dir = TestDir::new();
        let now = at(2026, 11, 2);
        let path = dir.file(Database::Country);
        for bad in [
            b"junk".to_vec(),
            test_db::city("DBIP-Country-Lite", built(now, 200)),
        ] {
            std::fs::write(&path, bad).unwrap();
            let outcome = update_one(Database::Country, &dir.0, now, &mut |_: &str, since| {
                assert_eq!(since, None);
                Ok(body(&country(now)))
            })
            .unwrap();
            assert!(matches!(outcome, Outcome::Updated(_)));
        }
        // Answering 304 to a question that was not asked is not success.
        std::fs::write(&path, b"junk").unwrap();
        assert!(
            update_one(Database::Country, &dir.0, now, &mut |_: &str, _| {
                Ok(Fetched::NotModified)
            })
            .is_err()
        );
    }

    /// Answer one connection with `response`, and hand back the request head.
    fn serve(response: Vec<u8>) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/db.mmdb.gz", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let head = read_head(&mut stream);
            let _ = stream.write_all(&response);
            head
        });
        (url, handle)
    }

    fn read_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
            head.push(byte[0]);
        }
        String::from_utf8(head).unwrap()
    }

    fn response(head: &str, body: &[u8]) -> Vec<u8> {
        let mut bytes = format!("{head}\r\nConnection: close\r\n\r\n").into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    /// The agent's 30 s is for small replies, and the City database takes
    /// longer than that on a slow link. Shown with an agent whose limit is
    /// far shorter than the body takes, which a plain request does hit.
    #[test]
    fn body_timeout_is_overridden() {
        let agent = ureq::Agent::config_builder()
            .timeout_recv_body(Some(Duration::from_millis(100)))
            .proxy(None)
            .build()
            .new_agent();
        let slow_server = || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/db.mmdb.gz", listener.local_addr().unwrap());
            std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                read_head(&mut stream);
                let head = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n";
                stream.write_all(head).unwrap();
                stream.write_all(b"a").unwrap();
                stream.flush().unwrap();
                std::thread::sleep(Duration::from_millis(600));
                let _ = stream.write_all(b"b");
            });
            url
        };
        let plain = agent
            .get(slow_server())
            .call()
            .and_then(|response| response.into_body().read_to_vec());
        assert!(
            matches!(plain, Err(ureq::Error::Timeout(ureq::Timeout::RecvBody))),
            "{plain:?}"
        );
        let fetched = fetch(&agent, false, &slow_server(), None).unwrap();
        assert!(matches!(fetched, Fetched::Body { gzip, .. } if gzip == b"ab"));
    }

    #[test]
    fn plain_http_is_refused() {
        // Nothing listens here, and nothing has to: the scheme fails first.
        let error = fetch(crate::http::agent(), true, "http://127.0.0.1:1/x", None).unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<ureq::Error>(),
                Some(ureq::Error::RequireHttpsOnly(_))
            ),
            "{error:#}"
        );
    }

    /// A redirect could point anywhere, and every URL this command fetches is
    /// listed in the threat model.
    #[test]
    fn a_redirect_is_not_followed() {
        let (url, server) = serve(response(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0",
            b"",
        ));
        let error = fetch(crate::http::agent(), false, &url, None).unwrap_err();
        assert!(error.to_string().contains("302"), "{error:#}");
        server.join().unwrap();
    }

    #[test]
    fn statuses_mean_what_the_update_expects() {
        for (status, want_missing) in [("404 Not Found", true), ("500 Oops", false)] {
            let (url, server) = serve(response(
                &format!("HTTP/1.1 {status}\r\nContent-Length: 0"),
                b"",
            ));
            let fetched = fetch(crate::http::agent(), false, &url, None);
            assert_eq!(
                matches!(fetched, Ok(Fetched::Missing)),
                want_missing,
                "{fetched:?}"
            );
            assert_eq!(fetched.is_err(), !want_missing, "{fetched:?}");
            server.join().unwrap();
        }
    }

    /// The request names the file's date and the response's date comes back,
    /// and the request asks for the bytes as they are stored.
    #[test]
    fn dates_go_out_and_come_back_as_http_dates() {
        let (url, server) = serve(response(
            "HTTP/1.1 304 Not Modified\r\nLast-Modified: Thu, 01 Oct 2026 06:29:26 GMT",
            b"",
        ));
        let since = SystemTime::from(Utc.with_ymd_and_hms(2026, 10, 1, 6, 29, 26).unwrap());
        let fetched = fetch(crate::http::agent(), false, &url, Some(since)).unwrap();
        assert!(matches!(fetched, Fetched::NotModified), "{fetched:?}");
        let head = server.join().unwrap().to_lowercase();
        assert!(
            head.contains("if-modified-since: thu, 01 oct 2026 06:29:26 gmt\r\n"),
            "{head}"
        );
        assert!(head.contains("accept-encoding: identity\r\n"), "{head}");

        let (url, server) = serve(response(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nLast-Modified: Thu, 01 Oct 2026 06:29:26 GMT",
            b"ok",
        ));
        let fetched = fetch(crate::http::agent(), false, &url, None).unwrap();
        let Fetched::Body { last_modified, .. } = fetched else {
            panic!("{fetched:?}");
        };
        assert_eq!(last_modified, Some(since));
        assert!(!server
            .join()
            .unwrap()
            .to_lowercase()
            .contains("if-modified-since"));
    }

    /// A body marked gzip would be undone by ureq on this thread, the main
    /// thread in the real command, with nothing left on the response to show
    /// it. It is refused before a byte of it is read.
    #[test]
    fn a_coded_body_is_refused_unread() {
        for head in [
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2",
            "HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: 2",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked",
            "HTTP/1.1 200 OK",
        ] {
            let (url, server) = serve(response(head, b"ok"));
            let error = fetch(crate::http::agent(), false, &url, None).unwrap_err();
            assert!(error.to_string().contains("coding"), "{head}: {error:#}");
            server.join().unwrap();
        }
    }

    #[test]
    fn a_body_over_the_download_limit_is_refused() {
        // By its declared length, unread.
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}", MAX_COMPRESSED + 1);
        let (url, server) = serve(response(&head, b""));
        let error = fetch(crate::http::agent(), false, &url, None).unwrap_err();
        assert!(error.to_string().contains("limit"), "{error:#}");
        server.join().unwrap();
    }

    /// The real sequence on a real parser thread, in a child process because
    /// the policy can be installed once per process. The hostile bytes never
    /// meet a thread that can connect, and the thread doing the download can.
    #[test]
    #[cfg(target_os = "linux")]
    fn parse_runs_in_parser_role() {
        const CHILD: &str = "NETWATCH_GEOIP_PARSER_TEST";
        let Ok(root) = std::env::var(CHILD) else {
            let dir = TestDir::new();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "geoip_update::tests::parse_runs_in_parser_role",
                    "--nocapture",
                ])
                .env(CHILD, &dir.0)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        };
        let root = PathBuf::from(root);
        let paths = SandboxPaths {
            cache_dir: Some(root.join("cache")),
            config_dir: Some(root.join("config")),
            state_dir: Some(root.join("state")),
            cwd: Some(root.join("exports")),
            ..Default::default()
        };
        paths.prepare().unwrap();
        worker::install(Mode::BestEffort, paths).unwrap();
        let dir = root.join("cache").join("geoip");
        std::fs::create_dir(&dir).unwrap();

        let now = at(2026, 11, 2);
        let outcome = update_one(Database::Country, &dir, now, &mut |_: &str, _| {
            Ok(body(&country(now)))
        })
        .unwrap();
        assert!(matches!(outcome, Outcome::Updated(_)));
        assert!(dir.join(Database::Country.file_name()).is_file());

        let report = worker::snapshot()["geoip-update"].report.clone().unwrap();
        assert_eq!(report.platform.landlock_layer, Some("parser"));
        if !report.platform.landlock_network_blocked {
            eprintln!("skipped: denying TCP needs Landlock ABI 4 (Linux 6.7)");
            return;
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Outside the grants, so the filesystem policy shows as well.
        let outside = root.join("secret");
        std::fs::write(&outside, b"sentinel").unwrap();
        let (errno, read) = confined(move || {
            let errno = TcpStream::connect(addr)
                .err()
                .and_then(|error| error.raw_os_error());
            (errno, std::fs::read(outside).map_err(|e| e.kind()))
        })
        .unwrap();
        assert_eq!(errno, Some(nix::libc::EACCES));
        assert_eq!(read, Err(std::io::ErrorKind::PermissionDenied));
        assert!(
            TcpStream::connect(addr).is_ok(),
            "the main thread downloads"
        );
    }

    /// The print macros panic on a closed pipe or a full disk, which took the
    /// process down with exit 101 before ASN was downloaded. Assembled, so this
    /// test does not match itself.
    #[test]
    fn nothing_here_prints_with_a_macro_that_panics() {
        let source = include_str!("geoip_update.rs");
        let (code, _tests) = source.split_once(concat!("#[cfg(", "test)]")).unwrap();
        for printing in [concat!("print", "ln!"), concat!("print", "!(")] {
            assert!(!code.contains(printing), "{printing}");
        }
    }

    #[test]
    fn a_second_run_is_refused_while_the_first_holds_the_lock() {
        let dir = TestDir::new();
        let held = take_lock(&dir.0).unwrap();
        let error = take_lock(&dir.0).unwrap_err();
        assert_eq!(
            error.to_string(),
            "another netwatch geoip update is running"
        );
        drop(held);
        take_lock(&dir.0).unwrap();
    }

    /// Only `WouldBlock` used to stop a run. Every other failure carried on
    /// unlocked, with concurrent runs sharing one partial file.
    #[test]
    fn a_lock_that_cannot_be_taken_fails_closed() {
        let path = Path::new("/cache/.update.lock");
        let error = lock_outcome(
            Err(std::fs::TryLockError::Error(std::io::Error::other(
                "no locks here",
            ))),
            path,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("no locks here"), "{message}");
        assert!(message.contains(".update.lock"), "{message}");
        assert!(lock_outcome(Ok(()), path).is_ok());
    }

    /// Each kind's, whichever this run wants: an orphan from an interrupted
    /// `--city` is no use to a run without the flag.
    #[test]
    fn stale_partials_of_every_kind_are_removed() {
        let dir = TestDir::new();
        let keep = dir.file(Database::Country);
        std::fs::write(&keep, b"database").unwrap();
        for db in [Database::Country, Database::Asn, Database::City] {
            std::fs::write(partial_of(&dir.file(db)), b"partial").unwrap();
        }
        remove_stale_partials(&dir.0);
        assert_eq!(dir.names(), [Database::Country.file_name()]);
        assert_eq!(std::fs::read(&keep).unwrap(), b"database");
        // Nothing to remove is not a failure.
        remove_stale_partials(&dir.0);
    }

    /// City is preferred when present, so a junk City file hides a good Country
    /// file. Doctor reports it, and a plain update, with no `--city`, repairs it
    /// and leaves Country alone.
    #[test]
    fn a_junk_city_file_is_repaired_by_an_update_without_the_flag() {
        use crate::collectors::geo::{DbFile, DbStatus};
        let dir = TestDir::new();
        let now = at(2026, 11, 2);
        let country = test_db::city("DBIP-Country-Lite", built(now, 1));
        std::fs::write(dir.file(Database::Country), &country).unwrap();
        let city_path = dir.file(Database::City);
        std::fs::write(&city_path, b"junk").unwrap();

        let config = NetwatchConfig::default();
        let (selected, _) = config.geoip_paths_in(Some(&dir.0));
        assert_eq!(selected, city_path.to_str().unwrap());
        assert!(matches!(
            DbStatus::open(&selected, "").city,
            DbFile::Unreadable { .. }
        ));

        let city = test_db::city("DBIP-City-Lite", built(now, 1));
        let asn = test_db::asn("DBIP-ASN-Lite", built(now, 1));
        run(
            false,
            &dir.0,
            now,
            &mut |url: &str, since| {
                if url.contains("-city-") {
                    assert_eq!(since, None, "a junk file is not asked after");
                    Ok(body(&city))
                } else if url.contains("-asn-") {
                    Ok(body(&asn))
                } else {
                    assert!(since.is_some());
                    Ok(Fetched::NotModified)
                }
            },
            &config,
        )
        .unwrap();

        let (selected, _) = config.geoip_paths_in(Some(&dir.0));
        assert_eq!(selected, city_path.to_str().unwrap());
        let DbFile::Loaded { database_type, .. } = DbStatus::open(&selected, "").city else {
            panic!("the City file was not repaired");
        };
        assert_eq!(database_type, "DBIP-City-Lite");
        assert_eq!(std::fs::read(dir.file(Database::Country)).unwrap(), country);
    }

    /// One failure is exit 1, and it does not cost the databases after it.
    #[test]
    fn a_failed_database_does_not_stop_the_next() {
        let dir = TestDir::new();
        let now = at(2026, 11, 2);
        let asn = test_db::asn("DBIP-ASN-Lite", built(now, 1));
        let error = run(
            false,
            &dir.0,
            now,
            &mut |url: &str, _| {
                if url.contains("-country-") {
                    bail!("no route to host");
                }
                Ok(body(&asn))
            },
            &NetwatchConfig::default(),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "1 of 2 databases not updated");
        assert_eq!(dir.names(), [Database::Asn.file_name()]);
    }

    /// A panic on a hostile file is a failed update, not a hung command.
    #[test]
    fn a_panicking_parser_is_an_error() {
        let error = confined::<()>(|| panic!("hostile file")).unwrap_err();
        assert!(error.to_string().contains("panicked"), "{error:#}");
    }
}
