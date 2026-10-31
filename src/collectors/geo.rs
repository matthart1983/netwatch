use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::lru::BoundedLru;

/// More than the 10,000 connections netwatch is sized for. The egress view
/// looks up every public peer on every tick, and an LRU smaller than the set
/// it cycles through evicts each entry before it is asked for again.
const GEO_CACHE_MAX: usize = 16_384;

#[derive(Clone, Debug)]
pub struct GeoInfo {
    pub country_code: String,
    pub country: String,
    pub city: String,
    pub org: String,
}

impl GeoInfo {
    /// Every field comes from a database file we did not write, so each is
    /// made safe to draw on the way in.
    fn new(country_code: String, country: String, city: String, org: String) -> Self {
        use crate::ui::sanitize::display_owned;
        Self {
            country_code: display_owned(country_code),
            country: display_owned(country),
            city: display_owned(city),
            org: display_owned(org),
        }
    }
}

#[derive(Clone, Debug)]
enum GeoEntry {
    Resolved(GeoInfo),
    Failed,
}

// ── MaxMind offline reader ─────────────────────────────────

/// The largest file read from where `netwatch geoip update` saves them. DB-IP's
/// largest free database is 127 MiB.
pub(crate) const MAX_DOWNLOADED_DATABASE_BYTES: u64 = 256 * 1024 * 1024;

/// The largest file read from a path in the config. A commercial database can be
/// far larger than a free one, and any size loaded before this limit existed.
/// This only bounds what doctor and a session hold in memory.
const MAX_CONFIGURED_DATABASE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The attribution CC BY 4.0 asks of whatever shows DB-IP's data.
pub const DBIP_ATTRIBUTION: &str = "IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0";

/// What became of one database path. The database type and the error come
/// from a file we did not write, so they are made safe to draw.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum DbFile {
    /// No path to open.
    #[default]
    NotConfigured,
    Loaded {
        path: String,
        database_type: String,
        build_epoch: u64,
    },
    Unreadable {
        path: String,
        error: String,
    },
}

/// The databases a lookup can use, for doctor and Settings: a path that does
/// not open otherwise looks the same as no path at all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DbStatus {
    pub city: DbFile,
    pub asn: DbFile,
}

impl DbFile {
    /// By the file's own `database_type`, because a path says nothing: a DB-IP
    /// file can live anywhere, and a MaxMind one can have any name.
    fn is_dbip(&self) -> bool {
        matches!(self, DbFile::Loaded { database_type, .. } if database_type.starts_with("DBIP-"))
    }
}

impl DbStatus {
    /// Open both files to see what a session would make of them. Reads each
    /// whole, so this is for a report, not for every frame.
    pub fn open(city_path: &str, asn_path: &str) -> Self {
        MaxMindReader::open(city_path, asn_path).1
    }

    /// The line to show beside these databases, if lookups answer with DB-IP's
    /// data. A lookup starts from the Country or City file, so an ASN file with
    /// none beside it shows nothing, and beside a MaxMind one it fills the
    /// organisation names.
    pub fn attribution(&self) -> Option<&'static str> {
        let answers = matches!(self.city, DbFile::Loaded { .. });
        (answers && (self.city.is_dbip() || self.asn.is_dbip())).then_some(DBIP_ATTRIBUTION)
    }
}

/// Seconds since the epoch as a date, or `None` where chrono cannot represent
/// them. A `build_epoch` is a u64 from a file we did not write, and chrono's
/// `From<SystemTime>` panics on one that `SystemTime` holds and it does not.
pub(crate) fn epoch_date(secs: u64) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(i64::try_from(secs).ok()?, 0)
}

/// The size limit for a database at `path`, given where downloads are saved.
fn database_limit(path: &Path, downloaded: Option<&Path>) -> u64 {
    if downloaded.is_some_and(|dir| path.parent() == Some(dir)) {
        MAX_DOWNLOADED_DATABASE_BYTES
    } else {
        MAX_CONFIGURED_DATABASE_BYTES
    }
}

/// Read a database file whole. Only a regular file under `limit` is read:
/// opening a FIFO blocks until something writes to it, and `/dev/zero` never
/// ends, on a path taken from the config or the cache directory.
pub(crate) fn read_database(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let over =
        |bytes: u64| std::io::Error::other(format!("{bytes} bytes is over the {limit} byte limit"));
    if metadata.len() > limit {
        return Err(over(metadata.len()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(over(bytes.len() as u64));
    }
    Ok(bytes)
}

fn open_database(path: &str) -> (Option<maxminddb::Reader<Vec<u8>>>, DbFile) {
    use crate::ui::sanitize::display_owned;
    if path.is_empty() {
        return (None, DbFile::NotConfigured);
    }
    let limit = database_limit(
        Path::new(path),
        crate::geoip_update::downloaded_dir().as_deref(),
    );
    let opened = read_database(Path::new(path), limit)
        .map_err(|error| error.to_string())
        .and_then(|bytes| maxminddb::Reader::from_source(bytes).map_err(|error| error.to_string()))
        .and_then(|reader| {
            let epoch = reader.metadata().build_epoch;
            epoch_date(epoch)
                .map(|_| reader)
                .ok_or_else(|| format!("build_epoch {epoch} is out of range"))
        });
    match opened {
        Ok(reader) => {
            let file = DbFile::Loaded {
                path: path.to_owned(),
                database_type: display_owned(reader.metadata().database_type.clone()),
                build_epoch: reader.metadata().build_epoch,
            };
            (Some(reader), file)
        }
        Err(error) => (
            None,
            DbFile::Unreadable {
                path: path.to_owned(),
                error: display_owned(error),
            },
        ),
    }
}

struct MaxMindReader {
    city_reader: Option<maxminddb::Reader<Vec<u8>>>,
    asn_reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl MaxMindReader {
    fn open(city_path: &str, asn_path: &str) -> (Self, DbStatus) {
        let (city_reader, city) = open_database(city_path);
        let (asn_reader, asn) = open_database(asn_path);
        (
            Self {
                city_reader,
                asn_reader,
            },
            DbStatus { city, asn },
        )
    }

    fn lookup(&self, addr: IpAddr) -> Option<GeoInfo> {
        // Try the City/Country DB first
        // `?` rather than `if let ... else { return None }`: no City/Country
        // database configured means no lookup is possible, which is the same
        // early return every other failure here takes.
        let reader = self.city_reader.as_ref()?;
        let (country_code, country, city) = {
            let result = reader.lookup(addr).ok()?;
            // Try City decode first (superset of Country)
            if let Some(city_rec) = result.decode::<maxminddb::geoip2::City>().ok().flatten() {
                let cc = city_rec.country.iso_code.unwrap_or_default().to_string();
                let cn = city_rec
                    .country
                    .names
                    .english
                    .unwrap_or_default()
                    .to_string();
                let ct = city_rec.city.names.english.unwrap_or_default().to_string();
                (cc, cn, ct)
            } else {
                let result = reader.lookup(addr).ok()?;
                let country_rec = result
                    .decode::<maxminddb::geoip2::Country>()
                    .ok()
                    .flatten()?;
                let cc = country_rec.country.iso_code.unwrap_or_default().to_string();
                let cn = country_rec
                    .country
                    .names
                    .english
                    .unwrap_or_default()
                    .to_string();
                (cc, cn, String::new())
            }
        };

        // Enrich with ASN/org if available
        let org = if let Some(ref reader) = self.asn_reader {
            reader
                .lookup(addr)
                .ok()
                .and_then(|r| r.decode::<maxminddb::geoip2::Asn>().ok().flatten())
                .and_then(|asn| asn.autonomous_system_organization.map(|s| s.to_string()))
                .unwrap_or_default()
        } else {
            String::new()
        };

        Some(GeoInfo::new(country_code, country, city, org))
    }
}

// ── GeoCache ───────────────────────────────────────────────

#[derive(Clone)]
pub struct GeoCache {
    /// Keyed by [`lookup_addr`]'s canonical address.
    cache: Arc<Mutex<BoundedLru<IpAddr, GeoEntry>>>,
    mmdb: Arc<Option<MaxMindReader>>,
    db_status: Arc<DbStatus>,
}

impl Default for GeoCache {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoCache {
    /// No database, so no lookup answers. Used by tests.
    pub fn new() -> Self {
        Self::with_mmdb("", "")
    }

    /// Lookups answered from these files and nowhere else. An address no file
    /// answers for has no geo info. Empty or unreadable paths are in
    /// [`Self::db_status`].
    pub fn with_mmdb(city_path: &str, asn_path: &str) -> Self {
        let (reader, status) = MaxMindReader::open(city_path, asn_path);
        Self::with_reader(reader, status)
    }

    fn with_reader(reader: MaxMindReader, status: DbStatus) -> Self {
        let has_db = reader.city_reader.is_some();
        Self {
            cache: Arc::new(Mutex::new(BoundedLru::new(GEO_CACHE_MAX))),
            mmdb: Arc::new(if has_db { Some(reader) } else { None }),
            db_status: Arc::new(status),
        }
    }

    pub fn has_offline_db(&self) -> bool {
        self.mmdb.is_some()
    }

    /// What this session opened when it started.
    pub fn db_status(&self) -> &DbStatus {
        &self.db_status
    }

    pub fn lookup(&self, ip: &str) -> Option<GeoInfo> {
        let addr = lookup_addr(ip)?;

        // Fast path: check cache first
        {
            let mut cache = self.cache.lock().unwrap();
            match cache.get(&addr) {
                Some(GeoEntry::Resolved(info)) => return Some(info.clone()),
                Some(GeoEntry::Failed) => return None,
                None => {}
            }
        }

        // No database, no answer. Nothing leaves this machine for a lookup.
        let reader = (*self.mmdb).as_ref()?;
        let result = reader.lookup(addr);
        let mut cache = self.cache.lock().unwrap();
        match result {
            Some(info) => {
                cache.put(addr, GeoEntry::Resolved(info.clone()));
                Some(info)
            }
            None => {
                cache.put(addr, GeoEntry::Failed);
                None
            }
        }
    }
}

/// The address a GeoIP or WHOIS lookup is made for, or None when `ip` should
/// not be looked up at all. Brackets and a `%zone` are dropped and a
/// v4-mapped address becomes the IPv4 one it carries, so `[::ffff:8.8.8.8]`,
/// `::ffff:8.8.8.8` and `8.8.8.8` share a cache entry. Anything that is not
/// global unicast is None: a multicast address, or one the IANA
/// special-purpose registries mark not globally reachable, such as a
/// private, shared, documentation or benchmarking address. It has no
/// location or owner worth showing, and asking a remote service about one
/// tells it about the local network.
///
/// Stricter than [`is_private_ip`], which stays as it is: topology, egress,
/// beacon detection and diagnose use it to decide what counts as local, and
/// widening it would change what they report.
pub(crate) fn lookup_addr(ip: &str) -> Option<IpAddr> {
    let ip = ip
        .strip_prefix('[')
        .and_then(|ip| ip.strip_suffix(']'))
        .unwrap_or(ip);
    let ip = ip.split_once('%').map_or(ip, |(addr, _zone)| addr);
    let addr = ip.parse::<IpAddr>().ok()?.to_canonical();
    let global = match addr {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    };
    global.then_some(addr)
}

/// IPv4 networks that are not global unicast: those the IANA special-purpose
/// registry (RFC 6890 and its updates) marks not globally reachable, as
/// std's unstable `Ipv4Addr::is_global` does, and multicast.
const NON_GLOBAL_V4: [(Ipv4Addr, u32); 15] = [
    (Ipv4Addr::new(0, 0, 0, 0), 8),       // "this network"
    (Ipv4Addr::new(10, 0, 0, 0), 8),      // private
    (Ipv4Addr::new(100, 64, 0, 0), 10),   // shared: carrier-grade NAT, Tailscale
    (Ipv4Addr::new(127, 0, 0, 0), 8),     // loopback
    (Ipv4Addr::new(169, 254, 0, 0), 16),  // link-local
    (Ipv4Addr::new(172, 16, 0, 0), 12),   // private
    (Ipv4Addr::new(192, 0, 0, 0), 24),    // IETF protocol assignments, but see GLOBAL_V4
    (Ipv4Addr::new(192, 0, 2, 0), 24),    // documentation
    (Ipv4Addr::new(192, 88, 99, 2), 32),  // 6a44 relay anycast
    (Ipv4Addr::new(192, 168, 0, 0), 16),  // private
    (Ipv4Addr::new(198, 18, 0, 0), 15),   // benchmarking
    (Ipv4Addr::new(198, 51, 100, 0), 24), // documentation
    (Ipv4Addr::new(203, 0, 113, 0), 24),  // documentation
    (Ipv4Addr::new(224, 0, 0, 0), 4),     // multicast
    (Ipv4Addr::new(240, 0, 0, 0), 4),     // reserved, and 255.255.255.255
];

/// Addresses inside [`NON_GLOBAL_V4`] that the registry marks globally
/// reachable.
const GLOBAL_V4: [(Ipv4Addr, u32); 2] = [
    (Ipv4Addr::new(192, 0, 0, 9), 32),  // PCP anycast
    (Ipv4Addr::new(192, 0, 0, 10), 32), // TURN anycast
];

/// IPv6 networks that are not global unicast: those the IANA special-purpose
/// registry marks not globally reachable, as std's unstable
/// `Ipv6Addr::is_global` does, multicast and deprecated site-local. NAT64
/// and 6to4 addresses are left to [`is_global_v6`], which judges them by the
/// IPv4 address inside.
const NON_GLOBAL_V6: [(Ipv6Addr, u32); 12] = [
    (Ipv6Addr::UNSPECIFIED, 127),                         // :: and ::1
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),      // unique local
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),     // link-local
    (Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10),     // site-local, deprecated
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),      // multicast
    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32), // documentation
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),     // documentation
    (Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0), 64),      // discard-only
    (Ipv6Addr::new(0x100, 0, 0, 1, 0, 0, 0, 0), 64),      // dummy prefix
    // Local-use NAT64. Its prefix can be any length from /48 to /96, so the
    // IPv4 address inside is not always in the last 32 bits.
    (Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48),
    // IETF protocol assignments, Teredo and benchmarking among them, but
    // see GLOBAL_V6.
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16), // SRv6 segment IDs
];

/// Blocks inside [`NON_GLOBAL_V6`] that the registry marks globally
/// reachable.
const GLOBAL_V6: [(Ipv6Addr, u32); 7] = [
    (Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 1), 128), // PCP anycast
    (Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 2), 128), // TURN anycast
    (Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 3), 128), // DNS-SD SRP anycast
    (Ipv6Addr::new(0x2001, 3, 0, 0, 0, 0, 0, 0), 32),  // AMT
    (Ipv6Addr::new(0x2001, 4, 0x112, 0, 0, 0, 0, 0), 48), // AS112
    (Ipv6Addr::new(0x2001, 0x20, 0, 0, 0, 0, 0, 0), 28), // ORCHIDv2
    (Ipv6Addr::new(0x2001, 0x30, 0, 0, 0, 0, 0, 0), 28), // drone remote ID tags
];

fn in_v4(ip: Ipv4Addr, nets: &[(Ipv4Addr, u32)]) -> bool {
    let bits = u32::from(ip);
    nets.iter()
        .any(|&(net, len)| bits >> (32 - len) == u32::from(net) >> (32 - len))
}

fn in_v6(ip: Ipv6Addr, nets: &[(Ipv6Addr, u32)]) -> bool {
    let bits = u128::from(ip);
    nets.iter()
        .any(|&(net, len)| bits >> (128 - len) == u128::from(net) >> (128 - len))
}

fn is_global_v4(ip: Ipv4Addr) -> bool {
    in_v4(ip, &GLOBAL_V4) || !in_v4(ip, &NON_GLOBAL_V4)
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    let embedded = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    // A NAT64 address (64:ff9b::/96) ends in the IPv4 peer, and a 6to4 one
    // (2002::/16) carries the site's IPv4 address after the prefix.
    if seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_global_v4(embedded(seg[6], seg[7]));
    }
    if seg[0] == 0x2002 {
        return is_global_v4(embedded(seg[1], seg[2]));
    }
    in_v6(ip, &GLOBAL_V6) || !in_v6(ip, &NON_GLOBAL_V6)
}

pub fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.")
        || ip.starts_with("172.16.")
        || ip.starts_with("172.17.")
        || ip.starts_with("172.18.")
        || ip.starts_with("172.19.")
        || ip.starts_with("172.20.")
        || ip.starts_with("172.21.")
        || ip.starts_with("172.22.")
        || ip.starts_with("172.23.")
        || ip.starts_with("172.24.")
        || ip.starts_with("172.25.")
        || ip.starts_with("172.26.")
        || ip.starts_with("172.27.")
        || ip.starts_with("172.28.")
        || ip.starts_with("172.29.")
        || ip.starts_with("172.30.")
        || ip.starts_with("172.31.")
        || ip.starts_with("192.168.")
        || ip.starts_with("127.")
        || ip == "0.0.0.0"
        || ip == "::"
        || ip == "::1"
        || ip.starts_with("fe80:")
        || ip.starts_with("fc")
        || ip.starts_with("fd")
        || ip.starts_with("ff") // multicast
        || ip.starts_with("169.254.") // link-local
        || ip.starts_with("224.")
        || ip.starts_with("239.") // multicast v4
}

#[cfg(test)]
impl GeoCache {
    /// A cache whose database puts every address in Ashburn, United States,
    /// for tests outside this module.
    pub(crate) fn every_address_us_for_test() -> Self {
        Self::with_reader(tests::every_address_us(), DbStatus::default())
    }
}

/// Small databases in the MaxMind format, for tests here and of the code that
/// downloads them: one search-tree node whose two records both point at the
/// only data record, so every address, v4 or v6, finds it.
#[cfg(test)]
pub(crate) mod test_db {
    /// A UTF-8 string: type 2 in the top three bits, then its length.
    fn text(s: &str) -> Vec<u8> {
        let mut out = if s.len() < 29 {
            vec![0x40 | s.len() as u8]
        } else {
            vec![0x40 | 29, (s.len() - 29) as u8]
        };
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn build(data: &[u8], database_type: &str, build_epoch: u64) -> Vec<u8> {
        // One node, 24-bit records. A record past the node count points into
        // the data section, which starts 16 bytes after the tree:
        // 1 + 16 + offset 0.
        let mut db = vec![0, 0, 17, 0, 0, 17];
        db.extend_from_slice(&[0; 16]);
        db.extend_from_slice(data);
        db.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
        let epoch = [&[0x08, 0x02][..], &build_epoch.to_be_bytes()].concat(); // uint64
        let database_type = text(database_type);
        let metadata: [(&str, &[u8]); 9] = [
            ("binary_format_major_version", &[0xA1, 2]), // uint16
            ("binary_format_minor_version", &[0xA0]),
            ("build_epoch", &epoch),
            ("database_type", &database_type),
            ("description", &[0xE0]), // empty map
            ("ip_version", &[0xA1, 6]),
            ("languages", b"\x01\x04\x42en"), // array of one string
            ("node_count", &[0xC1, 1]),       // uint32
            ("record_size", &[0xA1, 24]),
        ];
        db.push(0xE0 | metadata.len() as u8);
        for (key, value) in metadata {
            db.extend(text(key));
            db.extend_from_slice(value);
        }
        db
    }

    /// Every address is in Ashburn, United States.
    pub(crate) fn city(database_type: &str, build_epoch: u64) -> Vec<u8> {
        // {city: {names: {en: "Ashburn"}},
        //  country: {iso_code: "US", names: {en: "United States"}}}
        let mut data = vec![0xE2];
        data.extend(text("city"));
        data.push(0xE1);
        data.extend(text("names"));
        data.push(0xE1);
        data.extend(text("en"));
        data.extend(text("Ashburn"));
        data.extend(text("country"));
        data.push(0xE2);
        data.extend(text("iso_code"));
        data.extend(text("US"));
        data.extend(text("names"));
        data.push(0xE1);
        data.extend(text("en"));
        data.extend(text("United States"));
        build(&data, database_type, build_epoch)
    }

    /// Every address is in AS 42, "Test Org".
    pub(crate) fn asn(database_type: &str, build_epoch: u64) -> Vec<u8> {
        let mut data = vec![0xE2];
        data.extend(text("autonomous_system_number"));
        data.extend_from_slice(&[0xC1, 42]); // uint32
        data.extend(text("autonomous_system_organization"));
        data.extend(text("Test Org"));
        build(&data, database_type, build_epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_class_a() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("10.255.255.255"));
    }

    #[test]
    fn private_class_b() {
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("172.31.255.255"));
    }

    #[test]
    fn not_private_class_b_boundary() {
        assert!(!is_private_ip("172.15.0.1"));
        assert!(!is_private_ip("172.32.0.1"));
    }

    #[test]
    fn private_class_c() {
        assert!(is_private_ip("192.168.1.1"));
    }

    #[test]
    fn not_private_192() {
        assert!(!is_private_ip("192.169.1.1"));
    }

    #[test]
    fn loopback_v4() {
        assert!(is_private_ip("127.0.0.1"));
    }

    #[test]
    fn all_zeros() {
        assert!(is_private_ip("0.0.0.0"));
    }

    #[test]
    fn public_ips() {
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
    }

    #[test]
    fn ipv6_unspecified_and_loopback() {
        assert!(is_private_ip("::"));
        assert!(is_private_ip("::1"));
    }

    #[test]
    fn ipv6_link_local() {
        assert!(is_private_ip("fe80::1"));
    }

    #[test]
    fn ipv6_ula() {
        assert!(is_private_ip("fc00::1"));
        assert!(is_private_ip("fd00::1"));
    }

    #[test]
    fn ipv6_multicast() {
        assert!(is_private_ip("ff02::1"));
    }

    #[test]
    fn link_local_v4() {
        assert!(is_private_ip("169.254.1.1"));
    }

    #[test]
    fn multicast_v4() {
        assert!(is_private_ip("224.0.0.1"));
        assert!(is_private_ip("239.255.255.255"));
    }

    #[test]
    fn ipv6_documentation_prefix_not_caught() {
        assert!(!is_private_ip("2001:db8::1"));
    }

    #[test]
    fn empty_and_invalid() {
        assert!(!is_private_ip(""));
        assert!(!is_private_ip("not-an-ip"));
    }

    #[test]
    fn geocache_skips_private() {
        let cache = GeoCache::new();
        assert!(cache.lookup("10.0.0.1").is_none());
        assert!(cache.lookup("192.168.1.1").is_none());
        assert!(cache.lookup("127.0.0.1").is_none());
        assert!(cache.lookup("").is_none());
        assert!(cache.lookup("—").is_none());
    }

    /// Without a database an address has no geo info, and nothing is recorded
    /// or sent for it. There is no worker, queue or other path off this machine
    /// to send it down, and this file holds no client to build one with.
    #[test]
    fn lookup_never_queues_online() {
        for cache in [GeoCache::new(), GeoCache::with_mmdb("", "")] {
            assert!(cache.lookup("8.8.8.8").is_none());
            assert_eq!(cache.cache.lock().unwrap().len(), 0);
        }
        let unreadable = GeoCache::with_mmdb("/nonexistent/path.mmdb", "");
        assert!(unreadable.lookup("8.8.8.8").is_none());
        assert_eq!(unreadable.cache.lock().unwrap().len(), 0);
        // Assembled, so this test does not match itself.
        let source = include_str!("geo.rs");
        for client in [concat!("crate::", "http"), concat!("ureq", "::")] {
            assert!(!source.contains(client), "{client}");
        }
    }

    #[test]
    fn has_offline_db_without_db() {
        let cache = GeoCache::new();
        assert!(!cache.has_offline_db());
    }

    #[test]
    fn has_offline_db_with_bad_path() {
        let cache = GeoCache::with_mmdb("/nonexistent/path.mmdb", "");
        assert!(!cache.has_offline_db());
    }

    /// `open_readfile(..).ok()` threw the reason away, so a wrong path looked
    /// the same as none to everything that could have reported it.
    #[test]
    fn a_database_that_does_not_open_says_why() {
        let status = DbStatus::open("/nonexistent/path.mmdb", "");
        assert_eq!(status.asn, DbFile::NotConfigured);
        let DbFile::Unreadable { path, error } = &status.city else {
            panic!("{status:?}");
        };
        assert_eq!(path, "/nonexistent/path.mmdb");
        assert!(!error.is_empty());
        assert_eq!(
            *GeoCache::with_mmdb("/nonexistent/path.mmdb", "").db_status(),
            status
        );
        assert_eq!(DbStatus::open("", ""), DbStatus::default());
    }

    /// A file in a fresh directory, for the status a session would make of it.
    fn status_of(write: impl FnOnce(&Path)) -> DbFile {
        let dir = std::env::temp_dir().join(format!("nw-geo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.mmdb");
        write(&path);
        let status = DbStatus::open(path.to_str().unwrap(), "");
        let _ = std::fs::remove_dir_all(&dir);
        status.city
    }

    /// The date fits `SystemTime` but not chrono, whose conversion panics. That
    /// took doctor and every session down with exit 101 on one hand-made file.
    #[test]
    fn an_out_of_range_build_epoch_is_unreadable() {
        for epoch in [9_000_000_000_000, i64::MAX as u64, u64::MAX] {
            let file = status_of(|path| {
                std::fs::write(path, test_db::city("DBIP-Country-Lite", epoch)).unwrap()
            });
            let DbFile::Unreadable { error, .. } = &file else {
                panic!("{epoch}: {file:?}");
            };
            assert!(error.contains("build_epoch"), "{epoch}: {error}");
        }
        // Far off but representable is only a strange date. Windows' SystemTime
        // stops at about 9e11 seconds, well short of chrono's limit.
        let far = status_of(|path| {
            std::fs::write(path, test_db::city("DBIP-Country-Lite", 100_000_000_000)).unwrap()
        });
        assert!(matches!(far, DbFile::Loaded { .. }), "{far:?}");
    }

    /// Opening a FIFO blocks until something writes to it, which held doctor
    /// forever, and `/dev/zero` never ends. The thread is so a regression fails
    /// here rather than hanging the run.
    #[cfg(unix)]
    #[test]
    fn a_file_that_is_not_regular_is_unreadable_without_being_read() {
        let opened = |path: String| {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(DbStatus::open(&path, "").city);
            });
            rx.recv_timeout(std::time::Duration::from_secs(10))
                .expect("reading it did not return")
        };
        let dir = std::env::temp_dir().join(format!("nw-geo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("fifo.mmdb");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        for path in [fifo.to_str().unwrap(), "/dev/zero", dir.to_str().unwrap()] {
            let file = opened(path.to_owned());
            let DbFile::Unreadable { error, .. } = &file else {
                panic!("{path}: {file:?}");
            };
            assert_eq!(error, "not a regular file", "{path}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The limit is the file's place, not its name: a path in the config has
    /// room for a commercial database, and only the download directory is held
    /// to what the update writes.
    #[test]
    fn the_limit_depends_on_where_the_file_is() {
        let downloads = Path::new("/cache/netwatch/geoip");
        for (path, limit) in [
            (
                "/cache/netwatch/geoip/dbip-city-lite.mmdb",
                MAX_DOWNLOADED_DATABASE_BYTES,
            ),
            ("/geo/GeoIP2-Enterprise.mmdb", MAX_CONFIGURED_DATABASE_BYTES),
            ("/geo/dbip-city-lite.mmdb", MAX_CONFIGURED_DATABASE_BYTES),
            (
                "/cache/netwatch/geoip/sub/db.mmdb",
                MAX_CONFIGURED_DATABASE_BYTES,
            ),
        ] {
            assert_eq!(
                database_limit(Path::new(path), Some(downloads)),
                limit,
                "{path}"
            );
        }
        assert_eq!(
            database_limit(Path::new("/geo/db.mmdb"), None),
            MAX_CONFIGURED_DATABASE_BYTES
        );
    }

    /// Sparse, so this costs nothing, and too big to read by accident.
    #[test]
    fn a_file_over_the_limit_is_unreadable_without_being_read() {
        let file = status_of(|path| {
            std::fs::File::create(path)
                .unwrap()
                .set_len(MAX_CONFIGURED_DATABASE_BYTES + 1)
                .unwrap()
        });
        let DbFile::Unreadable { error, .. } = &file else {
            panic!("{file:?}");
        };
        assert!(error.contains("limit"), "{error}");

        let dir = std::env::temp_dir().join(format!("nw-geo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.mmdb");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_DOWNLOADED_DATABASE_BYTES + 1)
            .unwrap();
        let error = read_database(&path, MAX_DOWNLOADED_DATABASE_BYTES).unwrap_err();
        assert!(error.to_string().contains("limit"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A commercial database larger than anything the update writes loaded at
    /// any size before there was a limit, and still does. Padded inside the data
    /// section, which nothing refers to, and sparse on disk.
    #[test]
    fn a_configured_database_over_the_download_limit_still_loads() {
        use std::io::{Seek, Write};
        let dir = std::env::temp_dir().join(format!("nw-geo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("commercial.mmdb");
        let db = test_db::city("GeoIP2-Enterprise", 1_790_000_000);
        let marker = db
            .windows(14)
            .rposition(|window| window == b"\xab\xcd\xefMaxMind.com")
            .unwrap();
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&db[..marker]).unwrap();
        file.seek(std::io::SeekFrom::Start(MAX_DOWNLOADED_DATABASE_BYTES + 1))
            .unwrap();
        file.write_all(&db[marker..]).unwrap();
        drop(file);
        assert!(std::fs::metadata(&path).unwrap().len() > MAX_DOWNLOADED_DATABASE_BYTES);

        let cache = GeoCache::with_mmdb(path.to_str().unwrap(), "");
        assert!(
            matches!(cache.db_status().city, DbFile::Loaded { .. }),
            "{:?}",
            cache.db_status().city
        );
        assert_eq!(cache.lookup("8.8.8.8").unwrap().country_code, "US");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_loaded_database_reports_its_type_and_date() {
        let dir = std::env::temp_dir().join(format!("nw-geo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let (city, asn) = (dir.join("city.mmdb"), dir.join("asn.mmdb"));
        std::fs::write(&city, test_db::city("Ctrl\x1b-City", 1_790_000_000)).unwrap();
        std::fs::write(&asn, test_db::asn("Test-ASN", 1_790_000_001)).unwrap();
        let cache = GeoCache::with_mmdb(city.to_str().unwrap(), asn.to_str().unwrap());
        assert_eq!(
            cache.db_status().city,
            DbFile::Loaded {
                path: city.to_str().unwrap().to_owned(),
                database_type: "Ctrl·-City".into(),
                build_epoch: 1_790_000_000,
            }
        );
        assert!(matches!(
            cache.db_status().asn,
            DbFile::Loaded {
                build_epoch: 1_790_000_001,
                ..
            }
        ));
        // And the ASN shape reaches a lookup.
        let info = cache.lookup("8.8.8.8").unwrap();
        assert_eq!(
            (info.country_code.as_str(), info.org.as_str()),
            ("US", "Test Org")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only what a file says about itself counts. Its name does not, and an
    /// ASN file that no lookup reaches puts nothing on screen to attribute.
    #[test]
    fn attribution_follows_the_database_type() {
        let file = |database_type: &str| DbFile::Loaded {
            path: "/geo/dbip-country-lite.mmdb".into(),
            database_type: database_type.into(),
            build_epoch: 1_790_000_000,
        };
        let status = |city, asn| DbStatus { city, asn };
        let (dbip, asn_dbip) = (
            file("DBIP-City-Lite"),
            file("DBIP-ASN-Lite (compat=GeoLite2-ASN)"),
        );
        let maxmind = file("GeoLite2-City");
        for attributed in [
            status(dbip.clone(), DbFile::NotConfigured),
            status(dbip.clone(), maxmind.clone()),
            status(maxmind.clone(), asn_dbip.clone()),
        ] {
            assert_eq!(
                attributed.attribution(),
                Some(DBIP_ATTRIBUTION),
                "{attributed:?}"
            );
        }
        let unreadable = DbFile::Unreadable {
            path: "/geo/dbip-city-lite.mmdb".into(),
            error: "bad".into(),
        };
        for not in [
            DbStatus::default(),
            status(maxmind.clone(), DbFile::NotConfigured),
            status(maxmind.clone(), file("GeoLite2-ASN")),
            status(file("dbip-lowercase"), DbFile::NotConfigured),
            status(DbFile::NotConfigured, asn_dbip.clone()),
            status(unreadable, asn_dbip),
        ] {
            assert_eq!(not.attribution(), None, "{not:?}");
        }
    }

    #[test]
    fn with_mmdb_bad_path_falls_back() {
        let cache = GeoCache::with_mmdb("/nonexistent.mmdb", "/also-bad.mmdb");
        assert!(!cache.has_offline_db());
        assert!(cache.lookup("192.168.1.1").is_none()); // private
    }

    #[test]
    fn control_characters_are_replaced() {
        let info = GeoInfo::new(
            "AU".into(),
            "Aus\u{202E}tralia".into(),
            "Syd\u{1b}]52;c;AAAA\u{7}".into(),
            "Evil\u{FEFF}Net".into(),
        );
        assert_eq!(info.country_code, "AU");
        assert_eq!(info.country, "Aus·tralia");
        assert_eq!(info.city, "Syd·]52;c;AAAA·");
        assert_eq!(info.org, "Evil·Net");
    }

    /// A reader that puts every address, v4 or v6, in Ashburn, United States.
    /// Enough to drive the offline path without a database file.
    pub(super) fn every_address_us() -> MaxMindReader {
        MaxMindReader {
            city_reader: Some(
                maxminddb::Reader::from_source(test_db::city("Test-City", 1_760_016_128)).unwrap(),
            ),
            asn_reader: None,
        }
    }

    /// The offline path inserted with no eviction at all, so a long-running
    /// host with a database kept every distinct peer it ever saw.
    #[test]
    fn offline_cache_stays_bounded() {
        let cache = GeoCache::with_reader(every_address_us(), DbStatus::default());
        assert!(cache.has_offline_db());
        for i in 0..100_000u32 {
            let ip = Ipv4Addr::from(0x0800_0000 + i).to_string();
            assert_eq!(cache.lookup(&ip).unwrap().country_code, "US");
            assert!(cache.cache.lock().unwrap().len() <= GEO_CACHE_MAX);
        }
    }

    /// netwatch is sized for 10,000 connections, and the egress view looks
    /// up every public peer on every tick. With fewer entries than peers,
    /// each tick evicted the ones the next would ask for, so every lookup
    /// went back to the database.
    #[test]
    fn ten_thousand_peers_stay_cached() {
        let cache = GeoCache::with_reader(every_address_us(), DbStatus::default());
        let peers: Vec<IpAddr> = (0..10_000u32)
            .map(|i| IpAddr::from(Ipv4Addr::from(0x0800_0000 + i)))
            .collect();
        for peer in &peers {
            assert!(cache.lookup(&peer.to_string()).is_some());
        }
        let c = cache.cache.lock().unwrap();
        assert!(peers.iter().all(|peer| c.contains_key(peer)));
    }

    #[test]
    fn v4_mapped_and_plain_share_one_entry() {
        let cache = GeoCache::with_reader(every_address_us(), DbStatus::default());
        assert!(cache.lookup("8.8.8.8").is_some());
        assert!(cache.lookup("::ffff:8.8.8.8").is_some());
        assert!(cache.lookup("[::ffff:8.8.8.8]").is_some());
        assert_eq!(cache.cache.lock().unwrap().len(), 1);
    }

    #[test]
    fn non_global_addresses_are_never_looked_up() {
        // Every address is in the fake database, so None means skipped.
        let offline = GeoCache::with_reader(every_address_us(), DbStatus::default());
        for ip in [
            "::ffff:192.168.1.5",
            "::ffff:10.0.0.1",
            "100.64.0.1",
            "100.100.100.100",
            "192.0.2.1",
            "198.18.0.1",
            "2001:db8::1",
            "fe90::1",
            "64:ff9b::a00:1",
            "255.255.255.255",
            // The edges of the same networks, and the rest of the tables.
            "0.0.0.0",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.0.170",
            "192.88.99.2",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "fd00::1",
            "fe80::1%eth0",
            "fec0::1",
            "ff02::1",
            "3fff::1",
            "100::1",
            // 6to4 for 192.168.1.1.
            "2002:c0a8:101::1",
            // The rest of the registry: local-use NAT64, whatever the
            // prefix length, the dummy prefix, SRv6, and the IETF block
            // with Teredo and benchmarking in it.
            "64:ff9b:1::a00:1",
            "64:ff9b:1:c0a8:1:500::",
            "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
            "100:0:0:1::1",
            "5f00::1",
            "2001::1",
            "2001:1::5",
            "2001:2::1",
            "2001:5::1",
            "2001:10::1",
            "2001:1ff:ffff::1",
            // A connection row's host, as Linux prints a dual-stack peer.
            "[::ffff:192.168.1.5]",
            "[fe80::1%eth0]",
            "",
            "—",
            "not-an-ip",
        ] {
            assert!(offline.lookup(ip).is_none(), "{ip}");
        }
        assert_eq!(offline.cache.lock().unwrap().len(), 0);

        for ip in [
            "8.8.8.8",
            "2606:4700:4700::1111",
            "2606:4700:4700::1111%eth0",
            "100.63.255.255",
            "100.128.0.0",
            "172.32.0.1",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "[::ffff:8.8.8.8]",
            "[2606:4700:4700::1111]",
            // Blocks inside the ones above that IANA marks global.
            "192.0.0.9",
            "192.0.0.10",
            "2001:1::1",
            "2001:1::2",
            "2001:1::3",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:3f::1",
            "2001:200::1",
        ] {
            assert!(offline.lookup(ip).is_some(), "{ip}");
        }
    }
}
