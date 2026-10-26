//! Flood soak driver: the real App capturing on a lab interface, drawn ten
//! times a second, one JSON line a second.
//!
//! `flood_soak --interface NAME --seconds N [--stop-file FILE]
//!             [--geoip-db PATH] [--geoip-asn-db PATH]`
//! `flood_soak --replay DIR --seconds N`
//!
//! Live, it starts a daemon session with capture on NAME, ticks the App as
//! often as `refresh_rate_ms` asks, and every 100 ms draws the next view in
//! [`VIEWS`] into a 200x50 terminal that writes to `io::sink`. The frame
//! time so includes the diff and the escape encoding a real terminal costs,
//! without a tty. Each line carries libpcap's totals, what the packet ring,
//! the stream tracker and the detectors hold, the process's memory, threads
//! and CPU time from /proc, the longest tick, every frame time by view, the
//! capture error, whether any thread panicked, and the GeoIP databases
//! loaded. `--stop-file` ends the run after the line on which FILE first
//! exists. `--geoip-db` and `--geoip-asn-db` load offline GeoIP databases, as
//! a release candidate's soak runs with Country and ASN loaded. A database
//! that does not load stops the run; netwatch reads ASN only beside Country,
//! so `--geoip-asn-db` needs `--geoip-db`.
//!
//! Run by `tests/soak/flood_soak.py` inside its namespaces, never by hand
//! against a real home: live, it refuses to start unless every directory the
//! App writes resolves inside a temp home the lab created (see
//! `netwatch::diagnose::lab::check_home`).
//!
//! `--replay` builds no App and needs no namespace or home. It loops the
//! classic pcap files in DIR through the capture thread's decode path
//! (`packets::Replay`) for N seconds, changing every address on each pass so
//! that each pass is new flows, and prints the decode rate. It runs on any
//! platform.
use anyhow::{bail, ensure, Context, Result};
use netwatch::{
    app::{draw_frame, App, Tab},
    collectors::packets::Replay,
    config::NetwatchConfig,
    diagnose::lab,
    runtime::bootstrap::{self, SessionKind},
};
use ratatui::{backend::CrosstermBackend, layout::Rect, Terminal, TerminalOptions, Viewport};
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        PoisonError,
    },
    time::{Duration, Instant},
};

// As the netwatch binary allocates, so RSS reads as it would there.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// What each frame draws, in turn: the tab, a Packets filter, and the name
/// the line files the frame's time under. The filter is a bare word that
/// matches nothing, so every frame searches every packet's payload.
const VIEWS: [(Tab, Option<&str>, &str); 6] = [
    (Tab::Dashboard, None, "dashboard"),
    (Tab::Connections, None, "connections"),
    (Tab::Packets, None, "packets"),
    (Tab::Packets, Some("zzz"), "packets_filtered"),
    (Tab::Stats, None, "stats"),
    (Tab::Timeline, None, "timeline"),
];

/// One frame per slot.
const FRAME_EVERY: Duration = Duration::from_millis(100);

/// The size of the terminal frames are drawn into.
const SCREEN: Rect = Rect {
    x: 0,
    y: 0,
    width: 200,
    height: 50,
};

/// How long capture may take to open before the run is refused.
const CAPTURE_WAIT: Duration = Duration::from_secs(10);

/// /proc reports CPU time in clock ticks of USER_HZ, which is 100 on every
/// architecture netwatch builds for.
const USER_HZ: f64 = 100.0;

/// Set by the panic hook. A panic in a capture step is caught and stops
/// capture with an error, but the hook still sees it first, so this counts
/// it as the daemon's degraded flag does.
static PANICKED: AtomicBool = AtomicBool::new(false);

struct Options {
    seconds: u64,
    interface: Option<String>,
    replay: Option<PathBuf>,
    stop_file: Option<PathBuf>,
    geoip_db: Option<String>,
    geoip_asn_db: Option<String>,
}

fn parse() -> Result<Options> {
    let mut opts = Options {
        seconds: 0,
        interface: None,
        replay: None,
        stop_file: None,
        geoip_db: None,
        geoip_asn_db: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .with_context(|| format!("{arg} requires a value"))
        };
        match arg.as_str() {
            "--seconds" => opts.seconds = value()?.parse().context("--seconds")?,
            "--interface" => opts.interface = Some(value()?),
            "--replay" => opts.replay = Some(value()?.into()),
            "--stop-file" => opts.stop_file = Some(value()?.into()),
            "--geoip-db" => opts.geoip_db = Some(value()?),
            "--geoip-asn-db" => opts.geoip_asn_db = Some(value()?),
            other => bail!("unknown option: {other}"),
        }
    }
    ensure!(
        (1..=86_400).contains(&opts.seconds),
        "--seconds must be 1..86400"
    );
    ensure!(
        opts.replay.is_some() != opts.interface.is_some(),
        "give --interface NAME for a live run or --replay DIR, not both"
    );
    for path in [&opts.geoip_db, &opts.geoip_asn_db].into_iter().flatten() {
        // A typo would otherwise run without GeoIP and measure the wrong thing.
        ensure!(Path::new(path).is_file(), "{path} is not a file");
    }
    ensure!(
        opts.geoip_asn_db.is_none() || opts.geoip_db.is_some(),
        "--geoip-asn-db needs --geoip-db: netwatch loads ASN only beside a Country database"
    );
    Ok(opts)
}

fn main() -> Result<()> {
    let opts = parse()?;
    match &opts.replay {
        Some(dir) => replay(dir, opts.seconds),
        None => live(&opts),
    }
}

/// The numbers /proc keeps for this process. All zero where there is no
/// /proc, so the driver still runs there and says nothing about memory.
#[derive(Default)]
struct Usage {
    rss_kib: u64,
    hwm_kib: u64,
    threads: u64,
    utime_s: f64,
    stime_s: f64,
}

fn usage() -> Usage {
    let mut usage = Usage::default();
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        let mut words = line.split_whitespace();
        let (Some(key), Some(Ok(value))) = (words.next(), words.next().map(str::parse::<u64>))
        else {
            continue;
        };
        match key {
            "VmRSS:" => usage.rss_kib = value,
            "VmHWM:" => usage.hwm_kib = value,
            "Threads:" => usage.threads = value,
            _ => {}
        }
    }
    // utime and stime are fields 14 and 15, counted from the pid; the command
    // name before them is in parentheses and may hold spaces.
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    if let Some((_, rest)) = stat.rsplit_once(')') {
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let ticks = |i: usize| fields.get(i).and_then(|f| f.parse::<f64>().ok());
        if let (Some(utime), Some(stime)) = (ticks(11), ticks(12)) {
            usage.utime_s = utime / USER_HZ;
            usage.stime_s = stime / USER_HZ;
        }
    }
    usage
}

fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1e6).round() / 1e3
}

/// The `p`th percentile of sorted `values`, by nearest rank.
fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let rank = (p * values.len() as f64).ceil() as usize;
    values[rank.clamp(1, values.len()) - 1]
}

/// The newest packet id in the ring and the largest frame among the packets
/// newer than `after` that are still there. Under a flood the ring turns
/// over many times a second, so this sees the last few thousand packets of
/// each second, not all of them.
fn newest_packets(app: &App, after: u64) -> (u64, usize, usize) {
    let ring = app.packet_collector.get_packets();
    let newest = ring.last().map_or(after, |p| p.id);
    let largest = ring
        .iter()
        .rev()
        .take_while(|p| p.id > after)
        .map(|p| p.raw_bytes.len())
        .max()
        .unwrap_or(0);
    (newest, largest, ring.len())
}

fn flag_panics() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        PANICKED.store(true, Ordering::Relaxed);
        previous(info);
    }));
}

fn live(opts: &Options) -> Result<()> {
    // Before anything resolves a path: the App loads baselines, the recovery
    // journal and the config as it is built.
    let home = lab::check_home(
        |name| std::env::var_os(name).map(PathBuf::from),
        &std::env::temp_dir(),
        &[
            ("cache", dirs::cache_dir()),
            ("config", dirs::config_dir()),
            ("state", dirs::state_dir().or_else(dirs::data_local_dir)),
        ],
    )
    .map_err(anyhow::Error::msg)?;
    eprintln!("lab home: {}", home.display());
    // `load` falls back to defaults on a parse error, which would run the
    // soak on settings the lab did not write.
    let path = NetwatchConfig::path().context("no config directory")?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("the lab writes {}", path.display()))?;
    toml::from_str::<NetwatchConfig>(&text).with_context(|| format!("{}", path.display()))?;
    let mut config = NetwatchConfig::load();
    let interface = opts.interface.clone().unwrap_or_default();
    config.capture_interface = interface.clone();
    if let Some(db) = &opts.geoip_db {
        config.geoip_db = db.clone();
    }
    if let Some(db) = &opts.geoip_asn_db {
        // The App keeps no sign of whether this one opened, so open it here as
        // the App does, and drop it before the App opens its own.
        maxminddb::Reader::open_readfile(db)
            .with_context(|| format!("--geoip-asn-db: {db} did not load"))?;
        config.geoip_asn_db = db.clone();
    }
    flag_panics();

    let _session = netwatch::sandbox::worker::SessionGuard;
    let mode = netwatch::sandbox::Mode::from_config(&config.sandbox);
    let mut app = App::prepare_with_config(config);
    if opts.geoip_db.is_some() && !app.geo_cache.has_offline_db() {
        bail!("--geoip-db: the database did not load");
    }
    // What the App holds, by config key: the ASN database opened above, and
    // the App keeps it only beside a Country one.
    let country = app.geo_cache.has_offline_db();
    let geoip: Vec<&str> = [
        ("geoip_db", country),
        ("geoip_asn_db", country && opts.geoip_asn_db.is_some()),
    ]
    .into_iter()
    .filter_map(|(key, loaded)| loaded.then_some(key))
    .collect();
    bootstrap::start(&mut app, SessionKind::Daemon, mode)?;
    bootstrap::prime_collectors(&mut app);
    let waited = Instant::now();
    while !app.packet_collector.is_capturing() {
        if let Some(error) = app.packet_collector.get_error() {
            bail!("capture on {interface}: {error}");
        }
        ensure!(
            waited.elapsed() < CAPTURE_WAIT,
            "capture on {interface} did not start in {CAPTURE_WAIT:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!("capturing on {interface}");

    let mut terminal = Terminal::with_options(
        CrosstermBackend::new(std::io::sink()),
        TerminalOptions {
            viewport: Viewport::Fixed(SCREEN),
        },
    )?;
    let tick_every = Duration::from_millis(app.user_config.refresh_rate_ms.clamp(100, 5000));
    // Every frame time of the run, by view, for the summary at the end.
    let mut run_frames: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    // This second's: frame times by view and the longest tick.
    let mut frames: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    let mut tick_ms: Option<f64> = None;
    let mut newest_id = 0;
    let mut view = 0;
    let mut written = 0;
    let started = Instant::now();
    let mut next_tick = started;
    let mut slot = 0u32;
    loop {
        std::thread::sleep(
            (started + FRAME_EVERY * slot).saturating_duration_since(Instant::now()),
        );
        // A line for the second just ended. A stall writes one line for the
        // seconds it covers, so the lab sees the gap rather than a burst.
        let second = started.elapsed().as_secs();
        if second > written {
            written = second;
            let (received, dropped, decoded) = app.packet_collector.capture_totals();
            let (newest, max_frame, ring_len) = newest_packets(&app, newest_id);
            newest_id = newest;
            let (streams, held_bytes, stream_budget, dropped_flows) = {
                let tracker = app
                    .packet_collector
                    .stream_tracker
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                (
                    tracker.all_streams.len(),
                    tracker.held_bytes(),
                    tracker.byte_budget(),
                    tracker.dropped_flows(),
                )
            };
            let usage = usage();
            let line = json!({
                "t": second,
                "geoip": geoip,
                "capturing": app.packet_collector.is_capturing(),
                "capture_error": app.packet_collector.get_error(),
                "panicked": PANICKED.load(Ordering::Relaxed),
                "received": received,
                "dropped": dropped,
                "decoded": decoded,
                "ring_len": ring_len,
                "ring_bytes": app.packet_collector.ring_bytes(),
                "max_frame": max_frame,
                "streams": streams,
                "held_bytes": held_bytes,
                "stream_budget": stream_budget,
                "dropped_flows": dropped_flows,
                "scan_states": app.network_intel.scan_states_len(),
                "beacon_states": app.network_intel.beacon_states_len(),
                "alerts": app.network_intel.alert_history_len(),
                "connections": app.connection_collector.connections().len(),
                "rss_kib": usage.rss_kib,
                "hwm_kib": usage.hwm_kib,
                "threads": usage.threads,
                "utime_s": usage.utime_s,
                "stime_s": usage.stime_s,
                "tick_ms": tick_ms,
                "frame_ms": frames,
            });
            println!("{line}");
            for (name, times) in std::mem::take(&mut frames) {
                run_frames.entry(name).or_default().extend(times);
            }
            tick_ms = None;
            if written >= opts.seconds || opts.stop_file.as_ref().is_some_and(|f| f.exists()) {
                break;
            }
        }
        if Instant::now() >= next_tick {
            let tick = Instant::now();
            app.tick();
            tick_ms = Some(tick_ms.unwrap_or(0.0).max(ms(tick.elapsed())));
            // A tick that overran starts the next interval, as the daemon's
            // ticker skips missed ticks rather than bursting.
            next_tick = (next_tick + tick_every).max(Instant::now());
        }
        let (tab, filter, name) = VIEWS[view % VIEWS.len()];
        view += 1;
        app.ui.current_tab = tab;
        app.ui.packet_filter_active = filter.map(str::to_string);
        let frame = Instant::now();
        terminal.draw(|f| draw_frame(f, &mut app))?;
        frames.entry(name).or_default().push(ms(frame.elapsed()));
        // The next slot after now: a frame that overran skips the slots it
        // covered instead of drawing them back to back.
        slot = (started.elapsed().as_millis() / FRAME_EVERY.as_millis()) as u32 + 1;
    }
    app.packet_collector.stop_capture();
    app.shutdown_diagnose();

    let (received, dropped, decoded) = app.packet_collector.capture_totals();
    eprintln!("{written} s: received {received}, dropped {dropped}, decoded {decoded}");
    for (name, mut times) in run_frames {
        times.sort_by(f64::total_cmp);
        eprintln!(
            "  {name:<17} {:>5} frames  p50 {:>7.3} ms  p99 {:>7.3} ms  max {:>7.3} ms",
            times.len(),
            percentile(&times, 0.50),
            percentile(&times, 0.99),
            times.last().copied().unwrap_or(0.0),
        );
    }
    Ok(())
}

/// The frames of a classic pcap file, in either byte order and either time
/// resolution. Only Ethernet captures: that is the one framing `Replay`
/// decodes.
fn pcap_frames(path: &Path) -> Result<Vec<Vec<u8>>> {
    let file = std::fs::read(path).with_context(|| format!("{}", path.display()))?;
    ensure!(file.len() >= 24, "{}: no pcap header", path.display());
    let little = match file[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => bail!("{}: not a classic pcap file", path.display()),
    };
    let field = |at: usize| -> Option<usize> {
        let bytes: [u8; 4] = file.get(at..at + 4)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        } as usize)
    };
    ensure!(field(20) == Some(1), "{}: not Ethernet", path.display());
    let mut frames = Vec::new();
    let mut at = 24;
    while at < file.len() {
        let frame = field(at + 8)
            .and_then(|caplen| file.get(at + 16..at + 16 + caplen))
            .with_context(|| format!("{}: truncated at byte {at}", path.display()))?;
        at += 16 + frame.len();
        frames.push(frame.to_vec());
    }
    Ok(frames)
}

/// Give `frame` the addresses of pass `pass`: the low three bytes of both
/// IPv4 addresses, or of both IPv6 addresses, XORed with it. Both ends
/// change the same way, so a conversation stays one conversation, as
/// tcpreplay's --unique-ip keeps it. Checksums are left as they were;
/// nothing on the decode path checks them.
fn readdress(frame: &mut [u8], pass: u32) {
    let ethertype = frame.get(12..14).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let ends: &[usize] = match ethertype {
        Some(0x0800) => &[30, 34],
        Some(0x86dd) => &[38, 54],
        _ => return,
    };
    let mask = pass.to_be_bytes();
    for &end in ends {
        if let Some(low) = frame.get_mut(end - 3..end) {
            for (byte, m) in low.iter_mut().zip(&mask[1..]) {
                *byte ^= m;
            }
        }
    }
}

fn replay(dir: &Path, seconds: u64) -> Result<()> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("{}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "pcap"))
        .collect();
    paths.sort();
    let mut fixture = Vec::new();
    for path in &paths {
        fixture.extend(pcap_frames(path)?);
    }
    ensure!(!fixture.is_empty(), "{}: no pcap frames", dir.display());
    eprintln!(
        "replaying {} frames from {} files in {}",
        fixture.len(),
        paths.len(),
        dir.display()
    );

    let replay = Replay::new();
    let mut frames = fixture.clone();
    let (mut offered, mut decoded, mut bytes, mut passes) = (0u64, 0u64, 0u64, 0u32);
    let mut last = (0u64, 0u64);
    let mut written = 0;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    'run: loop {
        passes += 1;
        for (frame, original) in frames.iter_mut().zip(&fixture) {
            frame.copy_from_slice(original);
            readdress(frame, passes);
        }
        for frame in &frames {
            offered += 1;
            bytes += frame.len() as u64;
            if replay.frame(frame).is_some() {
                decoded += 1;
            }
            // The clock is read every so often rather than for every frame.
            if offered % 1024 != 0 {
                continue;
            }
            let second = started.elapsed().as_secs();
            if second > written {
                written = second;
                let usage = usage();
                let line = json!({
                    "t": second,
                    "offered": offered,
                    "decoded": decoded,
                    "bytes": bytes,
                    "passes": passes,
                    "decoded_per_s": decoded - last.0,
                    "mb_per_s": (bytes - last.1) as f64 / 1e6,
                    "rss_kib": usage.rss_kib,
                    "hwm_kib": usage.hwm_kib,
                    "threads": usage.threads,
                    "utime_s": usage.utime_s,
                    "stime_s": usage.stime_s,
                });
                println!("{line}");
                last = (decoded, bytes);
            }
            if Instant::now() >= deadline {
                break 'run;
            }
        }
    }
    let wall = started.elapsed().as_secs_f64();
    let usage = usage();
    let cpu = usage.utime_s + usage.stime_s;
    eprintln!(
        "{offered} frames in {wall:.1} s over {passes} passes: {:.0} frames/s decoded, \
         {:.1} MB/s, CPU {:.0}% of one core, VmHWM {} MiB",
        decoded as f64 / wall,
        bytes as f64 / wall / 1e6,
        if wall > 0.0 { cpu / wall * 100.0 } else { 0.0 },
        usage.hwm_kib / 1024,
    );
    Ok(())
}
