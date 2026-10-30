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
use crate::config::NetwatchConfig;
use crate::sandbox::{worker, Mode, SandboxPaths};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Datelike, Utc};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Where the databases come from; [`Database::url`] adds the file name.
pub const DOWNLOAD_BASE: &str = "https://download.db-ip.com/free/";
/// The attribution CC BY 4.0 asks for.
const ATTRIBUTION: &str = "IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0";

/// The City database is about 60 MiB compressed, the others under 6 MiB.
const MAX_COMPRESSED: u64 = 80 * 1024 * 1024;
const MAX_DECOMPRESSED: u64 = 256 * 1024 * 1024;
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
    let mode = Mode::from_config(&config.sandbox);
    let paths = SandboxPaths::from_config(&config);
    if !matches!(mode, Mode::Disabled) {
        paths.prepare()?;
    }
    worker::install(mode, paths).map_err(anyhow::Error::msg)?;
    let _session = worker::SessionGuard;
    worker::preflight().map_err(anyhow::Error::msg)?;

    let dir = downloaded_dir().context("cannot determine the cache directory")?;
    crate::owner_only::create_dir_all(&dir)
        .with_context(|| format!("cannot create {}", dir.display()))?;
    // Both runs would write the same partial file, and the first to rename
    // would publish what the second had written so far.
    let lock = crate::owner_only::create(&dir.join(".update.lock"))?;
    if let Err(std::fs::TryLockError::WouldBlock) = lock.try_lock() {
        bail!("another netwatch geoip update is running");
    }

    let mut wanted = vec![Database::Country, Database::Asn];
    // City wins over Country once it is there, so a file left to go stale
    // would hide the Country file this run refreshes.
    if city || dir.join(Database::City.file_name()).is_file() {
        wanted.push(Database::City);
    }
    let now = Utc::now();
    let agent = crate::http::agent();
    let mut over_https = |url: &str, since: Option<SystemTime>| fetch(agent, true, url, since);
    let (mut updated, mut failed) = (0, 0);
    for db in &wanted {
        let path = dir.join(db.file_name());
        match update_one(*db, &dir, now, &mut over_https) {
            Ok(Outcome::Updated(checked)) => {
                updated += 1;
                println!("updated {}", describe(&path, &checked));
            }
            Ok(Outcome::AlreadyCurrent(checked)) => {
                println!("already current {}", describe(&path, &checked));
            }
            Err(error) => {
                failed += 1;
                eprintln!("{}: {error:#}", db.file_name());
            }
        }
    }
    if let Some(partly) = worker::snapshot()
        .get("geoip-update")
        .and_then(|worker| worker.error.clone())
    {
        eprintln!("note: {partly}");
    }
    if failed < wanted.len() {
        println!("{ATTRIBUTION}");
    }
    if updated > 0 {
        println!("restart netwatch to load it");
        for (key, value) in [
            ("geoip_db", &config.geoip_db),
            ("geoip_asn_db", &config.geoip_asn_db),
        ] {
            if !value.trim().is_empty() {
                println!("{key} in config.toml still takes precedence: {value}");
            }
        }
    }
    if failed > 0 {
        bail!("{failed} of {} databases not updated", wanted.len());
    }
    Ok(())
}

fn describe(path: &Path, checked: &Checked) -> String {
    let built = i64::try_from(checked.build_epoch)
        .ok()
        .and_then(|epoch| DateTime::from_timestamp(epoch, 0))
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
    // happens at all. One that no longer validates is not asked after, or
    // the server would call it current until next month.
    let present = {
        let path = path.clone();
        confined(move || read_and_validate(db, &path, now))?.ok()
    };
    let since = present
        .as_ref()
        .and_then(|_| std::fs::metadata(&path).and_then(|m| m.modified()).ok());

    let months = [month(now), previous_month(now)];
    for month in &months {
        let url = db.url(month);
        match fetch(&url, since).with_context(|| url.clone())? {
            Fetched::Missing => continue,
            Fetched::NotModified => {
                return present
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
    if let Some(since) = since {
        let since = DateTime::<Utc>::from(since).format("%a, %d %b %Y %H:%M:%S GMT");
        request = request.header("If-Modified-Since", since.to_string());
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
        .map(SystemTime::from);
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
    if std::fs::metadata(path)?.len() > MAX_DECOMPRESSED {
        bail!("over the {MAX_DECOMPRESSED} byte limit");
    }
    validate(db, &std::fs::read(path)?, now)
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
    let name = path
        .file_name()
        .context("a database path has a file name")?
        .to_string_lossy();
    let partial = path.with_file_name(format!(".{name}.partial"));
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

    fn built(now: DateTime<Utc>, days_ago: i64) -> u32 {
        (now.timestamp() - days_ago * 86_400) as u32
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
        let db = country(now);
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

    /// A panic on a hostile file is a failed update, not a hung command.
    #[test]
    fn a_panicking_parser_is_an_error() {
        let error = confined::<()>(|| panic!("hostile file")).unwrap_err();
        assert!(error.to_string().contains("panicked"), "{error:#}");
    }
}
