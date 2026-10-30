# Changelog

All notable changes to NetWatch will be documented in this file.

## [Unreleased]

### Added
- **`netwatch daemon --metrics` exports the capture's packet counts.**
  `netwatch_capture_packets_received_total` and
  `netwatch_capture_packets_dropped_total` count the packets libpcap
  received and dropped since the capture opened, and
  `netwatch_capture_packets_decoded_total` the ones netwatch decoded. Frames
  in a framing netwatch does not decode, the `Raw` rows in Packets, are not
  counted as decoded, so on a Linux `any` capture or a tunnel that counter
  stays at 0. Until now only the TUI showed capture drops, so on a dashboard
  a daemon losing packets to a full kernel buffer looked the same as one
  that saw every packet. The counters are 64-bit and keep counting past
  libpcap's 32-bit wrap. While no capture is running, for example when the
  daemon lacks permission to capture, they have no sample rather than a
  zero. docs/observability-export.md lists them, and puts its table of
  metric names, types and labels under the 1.0 compatibility promise.
- **`third_party_probes = false` stops netwatch's automatic probes to public
  servers.** Every TUI and daemon run sends STUN to Google and Cloudflare
  about once a minute, asks 1.1.1.1 for `dns.google` and probes 1.1.1.1 with
  ICMP and TCP 443 every probe cycle, and each TUI start traces 1.1.1.1.
  Nothing could turn these off, which ruled netwatch out on an air-gapped or
  privacy-minded host. The key defaults to `true`, so nothing changes unless
  you set it. Set to `false`, none of those go out, and that holds across a
  network change. What they measured reads as not measured, never as failed.
  The internet RTT reads `—`, and `netwatch uptime` reports the connection as
  unknown with no uptime percentage, though a gateway or DNS outage still
  counts. Topology's ISP box stays empty until you press `T`. In Diagnose,
  `dns.hijack_suspect`, `nat.symmetric` and `gateway.unreachable` show as not
  measured and cannot open, so a router that answers nothing no longer raises
  a critical on a probe that was never sent. The cost is that a dead gateway
  shows up as a failing resolver or a down link instead. The three tests that
  ask 1.1.1.1 do not run: `t` on an issue picks another, and `t` on the
  coverage row refuses the load test, which also uploads to
  speed.cloudflare.com. Your resolver and gateway are still probed, and what
  else you start yourself still runs: `T`, `W`, `t` on the other coverage rows
  and periodic traces. docs/REFERENCE.md lists them.

### Changed
- **Less `unsafe` code, and the raw-pointer reads this change touches check
  what they assume.** Six places that read the effective user ID, and three
  in tests, call nix's safe wrapper instead of libc inside an `unsafe`
  block. The sandbox's Landlock write-grant check still calls libc. On
  Windows, the Npcap loader and doctor's query of the Npcap driver service
  call the windows-sys declarations instead of hand-written ones, and on
  macOS the process path lookup uses libc's declaration of `proc_pidpath`.
  Reading the Windows socket tables now checks that the buffer holds the
  whole table struct, a header and one row, before it reads the row count,
  which only the caller guaranteed before, and the build fails if the
  alignment the socket table, adapter and ICMP buffers rely on stops
  holding. macOS and FreeBSD share one walk of the `getifaddrs` list for the
  link speed. It skips an entry with no name instead of reading a null
  pointer, and reads only the speed field rather than borrowing the whole
  `if_data` record. Every `unsafe` site now has a comment saying what it
  relies on and why that holds there. Nothing netwatch shows changes, and no
  new crate is compiled.
- **The stream tracker's budget is an eighth of the host's memory, up to
  256 MiB.** It was 256 MiB on every host, half the memory of a 512 MiB
  board. netwatch reads the host's memory once at start, `MemTotal` on Linux
  and the physical memory the system reports on macOS, Windows and FreeBSD,
  so a 512 MiB host gets 64 MiB, a 1 GiB host 128 MiB, and a host with 2 GiB
  or more keeps 256 MiB. In a Linux container the budget follows the host's
  memory, not the container's limit. Past the budget the tracker drops the
  least recently seen streams, as before, so a small host keeps payloads for
  fewer flows under heavy traffic. One decrypted HTTP/3 flow can hold about
  69 MiB on its own, and the tracker does not drop a flow while that flow is
  the one growing. With an SSLKEYLOGFILE on a host under about 550 MiB, the
  tracker can pass its budget by the difference, about 5 MiB on a 512 MiB
  host, until another flow's traffic drops that one.
- **The `M` overlay shows the bytes the packet list and the stream tracker
  hold, in MiB, against their budgets.** It also took the packet list's
  count cap from a copy of 5000, and now reads the constant the list uses.
- **`CapturedPacket` no longer has `raw_hex` and `raw_ascii`.** Library
  callers can build the same text from `raw_bytes` with
  `collectors::packets::hex_dump` and `ascii_dump`. `PacketCollector::ring_bytes`
  and the hidden `StreamTracker::held_bytes`, `byte_budget` and
  `dropped_flows` are new. The library is not a stable interface.
- **`--sandbox-strict` and `sandbox = "strict"` need Linux 6.7 or newer.**
  Strict mode now requires the parser threads' TCP deny described under
  Security, which needs Landlock ABI 4. On Linux 6.2 to 6.6, which passed strict
  before, netwatch now refuses to start in strict mode and says the kernel
  cannot deny TCP. Older kernels already failed strict. Best-effort runs on
  any kernel as before and logs one line when the deny is unavailable.
  `netwatch doctor --check-capture` now checks under the capture thread's
  policy, so on those kernels it reports capture as unavailable in strict
  mode, where it used to report it ready.
- **The Timeline keeps every open connection and the last 2,000 that
  closed.** Its limit of 2,000 counted open connections too, but dropped only
  closed ones. On a host with 2,000 or more open connections, each one left
  the Timeline on the tick it closed, so the tab showed no closed
  connections at all. With fewer open, the closed ones to go first were the
  ones that opened first, however recently they had closed. The limit now
  counts closed connections alone and drops the ones that closed longest
  ago. Open connections are never dropped. It drops at least 256 at a time,
  so the Timeline is not reindexed on every tick that something closes, and
  right after a drop it can hold as few as 1,745 closed connections. The
  `M` overlay shows the closed count against 2,000. Library callers lose
  `ConnectionTimeline::tracked_len` and `tracked_cap`, and gain
  `ConnectionTimeline::closed_len`, `closed_trimmed` and `first_seen`, and
  `ConnectionCollector::connections_with_generation`.

### Fixed
- **One bad value in config.toml no longer throws the whole file away.** A
  file that was not valid TOML, or gave a key a value of the wrong type, was
  replaced by the defaults without a word. With `refresh_rate_ms = 'oops'` in
  a file that also set `sandbox = "strict"` and `record_uptime = false`,
  netwatch started with a best-effort sandbox and recorded uptime. A file it
  could not read, or a symlink to one that had gone, was treated the same
  way. `netwatch` and `netwatch daemon` now print the file, line and column
  and exit 1 before anything starts or is written. `diagnose run` exits 3,
  its status for no session, and `diagnose coverage` exits 1, with the same
  message. `netwatch doctor` names the file, line and column in its `config`
  entry, still without quoting the file, and `--check-capture` no longer
  opens capture on the defaults in its place. `--generate-config` and the
  Settings save no longer overwrite a file that does not load. With no file
  at all the defaults apply as before, and keys a file leaves out keep
  theirs. In the library, `NetwatchConfig::load` returns a `Result`, and
  `load_from` and `save_to` are new.
- Dense view's connection and process sparklines now use their full width,
  including on wide terminals. Their time labels reflect the retained history
  and refresh interval instead of always saying `60s`.
- **Dense view's interface sparklines fill their whole row.** The `60s` plot
  gave each sample half a cell, so when the row had more room than the last
  minute had samples, its left side stayed empty. At the default 1-second
  refresh that happened on terminals wider than about 160 columns and in the
  zoomed `ifaces` box. At a 5-second refresh it happened on every terminal.
  In the first minute after start, the samples so far were also stretched
  across the plot as if they covered all 60 seconds. The plot now spreads
  the last 60 seconds across the row at every width and refresh rate, and a
  short history fills in from the right.
- **`--remote` backs off up to its 60-second cap when the backend keeps
  failing.** The retry delay is a random point below a ceiling that doubles
  from 0.5 s with each failure, but the randomness came from the clock's
  sub-second nanoseconds, so every delay stayed under one second, and a
  backend that answered every POST with an error got one about every 0.6 s
  for as long as it was down. The delay now reaches across the whole
  ceiling, and the wait counts from when the failed POST ends rather than
  when it started, so a POST that took its whole timeout no longer used up
  the wait after it.
- **The Connections and Processes detail graphs fill their width, and their
  labels name the window they draw.** The Connections detail graph drew its
  30 samples at the right edge, one or two to a column, so in a wider pane
  the rest stayed empty, and its label said `RX 30s` at every refresh rate.
  The Processes RX chart did the same with its 60 samples under a fixed
  `RX 60s`, and a bar chart narrower than 60 columns dropped the oldest
  samples it claimed to show. Both graphs now spread their whole history
  across the chart, and the label follows the refresh interval: at 500 ms
  they read `RX 15s` and `RX 30s`, and at 5000 ms `RX 150s` and `RX 5m`.
- **Dense view's process header rows draw the traffic their DOWN column
  reports.** A process with several sockets summed its sockets' sparklines,
  but every socket to the same host carries that host's whole history, so a
  host with five open sockets was counted five times. The sparkline
  overstated whichever hosts had the most sockets, and its newest point
  disagreed with DOWN. Each host is now counted once.
- **Chart window labels between two and ten minutes give the exact number
  of seconds.** A window of two minutes or more was rounded to the nearest
  minute, so 148 seconds read `2m` and 150 seconds `3m`. At the default
  1-second refresh, Dense's throughput axis was off at nearly every terminal
  size (80 columns plot 148 seconds), and so was Lite's axis on terminals
  wider than about 120 columns. Lite's connection sparkline label was off at
  refresh intervals above 4 seconds. Those windows now read
  `148s` and `150s`. A whole number of minutes still reads `2m` or `5m`, and
  a window of ten minutes or more is given to the nearest minute.
- **With `x` on, the Packets detail pane stops showing a packet the list
  hides.** Turning `x` on with a packet selected that is not an expert
  finding left that packet decoded in the detail pane, while the list showed
  only the findings and the stream pane beside it asked for a selection. The
  detail pane now asks for a selection too, as it already did when the
  display filter hid the packet. `W` (WHOIS), `s` (stream), `m` (bookmark)
  and `y` (copy) now act only on a packet the list shows, where they used to
  act on the hidden one whether `x` or the display filter hid it. Turning `x`
  off shows the packet again.
- **Worker threads carry their names.** They were started unnamed, so the
  log recorded a panic in any of them as `thread="unnamed"`, and `top -H`
  or `ps -L` listed every worker as `netwatch`. Each now has its worker's
  name (`capture`, `connections`, `health`, `reverse-dns` and so on), which
  the kernel shortens to 15 characters.
- **The terminal is restored on a TUI panic or shutdown signal.** SIGTERM,
  SIGINT and SIGHUP save the session and exit cleanly on Unix, the hangup
  from closing the terminal window or losing the SSH connection included.
  A terminal that has stopped reading output, as a frozen SSH session does,
  cannot be restored. If the connection then drops, netwatch still saves
  the session and exits cleanly; a signal that comes while the session is
  frozen ends netwatch after 5 seconds, the way it used to. Windows handles
  Ctrl+C and console close notifications. Raw mode, mouse capture and the
  alternate screen are undone before a fatal panic report is printed, with
  the backtrace `RUST_BACKTRACE` asks for and any terminal control
  characters replaced. Background panics stay in the log. Bare mouse
  motion no longer redraws the screen, and queued input is processed in
  bounded batches.
- **A packet from before the stream indices ran out no longer shows a newer
  flow's stream.** Once a capture had numbered 2^32 flows the numbers began
  again, and a packet still in the list from before could show the stream
  details, handshake time, HTTP/3 bodies, conversation ladder and stream
  view of the newer flow that took its number; a `stream N` filter listed
  both flows. Such a packet now shows no stream, and `stream N` matches only
  the flow numbered N now. Packets from before a capture restart or an
  interface switch still show theirs, as numbering carries on across those.
- **The drop count and packet rate stay right past four billion packets.**
  libpcap counts received and dropped packets in 32 bits, which wrap within
  the hour at 1.2 million packets a second. netwatch showed libpcap's count
  as it stood, so after a wrap the drops in the Packets header and in an
  incident bundle's `last_capture_status` fell back towards zero, and the
  rate read 0 pkt/s for a second. Each poll now adds the change since the
  last one to 64-bit totals.
- **A stream index names one flow per capture session, even after four
  billion flows.** Capture numbers each flow with a 32-bit index. After
  2^32 flows, about seven hours of new connections at full decode speed, the
  numbering wrapped to 0, and one index in one `capture_session` could name
  two flows, so two flows' packets could carry the same `capture_generation`
  in a PCAPNG export. netwatch now forgets every stream, numbers from 0
  again and starts a new `capture_session`. The drops in an incident
  bundle's `last_capture_status` still count from the capture start.
- **A port scan or a flood of DNS names no longer swells the detectors'
  memory.** The port-scan detector kept every port each source touched in
  its 30-second window, up to all 65,536 for each of 1,000 sources, about
  400 MB, and kept that memory after the window ended. Query counts per
  domain were trimmed every 30 seconds, so a flood of unique names added an
  entry per query until then. Each source now keeps at most 256 ports, well
  past the 20 that raise the alert, and each window starts with an empty
  set. Domain counts are cut to the 500 most queried as soon as a new name
  would take them past 1,000.
- **With a GeoIP database configured, the GeoIP cache stops growing at
  16,384 addresses.** Each address the database answered for got a cache
  entry that was never removed, so a TUI or daemon left running kept one
  for every public address it had looked up. On a public server that is
  every client. Every GeoIP lookup now goes through one cache of 16,384
  entries, room for the 10,000 connections netwatch is sized for, that
  drops the least recently used quarter when it fills, as reverse DNS
  already did. The WHOIS cache of 2,048 entries and the online GeoIP cache
  dropped whichever quarter their map listed first, which could include the
  address on screen. They now drop the least recently used too. A
  v4-mapped address such as `::ffff:8.8.8.8` and its IPv4 form share one
  entry and are looked up as the IPv4 address. With `geoip_online` on, the
  queue of addresses waiting for ip-api.com, which is asked about one every
  1.4 seconds, had no limit, and with more peers than the cache held it
  grew by hundreds a second. It now holds 256, and an address that finds
  it full is asked for again on a later lookup.
- **The Connections GEO column shows a location for IPv6 peers.** The
  column looked up the address with its brackets on, as in
  `[2606:4700:4700::1111]`, which the lookup could not parse, so every IPv6
  row showed a dash. So did an IPv4 peer of a dual-stack socket, which
  Linux shows as `[::ffff:8.8.8.8]`. The lookup now drops the brackets.
- **Dense shows the org and city of a peer that sent a server name.** The
  line under the selected connection looked up the TLS or QUIC server name
  instead of the address, and a GeoIP database knows only addresses, so
  those rows never showed one. It now looks up the address.
- **A bulk transfer no longer fills memory through the packet list.** Every
  captured packet carried a hex and an ASCII dump of its frame, built with a
  `format!` per byte. The dumps took about five times the frame's size and
  most of the capture thread's decode time, and the list of the last 5,000
  packets had no byte limit. A local bulk transfer, whose segmentation
  offload hands libpcap 64 KB frames, left the list holding 1.8 GB, and
  5,000 full-size Ethernet frames held 53 MB. Only the selected packet's dump
  is ever drawn, so the Packets tab now builds it from the frame as it
  draws, and only as many lines as the pane has rows. The list keeps 5,000
  packets or 32 MiB of them, whichever is fewer. That is about 500 of those
  64 KB frames, or 5,000 full-size ones in 18 MB. Each packet's copy of its
  flow's DPI label counts too, since a peer chooses how long it is: a few
  QUIC Initials of ordinary size can name a 15,000-byte SNI, which every
  later datagram on the flow then carries. The capture strip said
  `ring 5000` whatever the list held. It now measures the list against the
  cap it is nearer, `ring 3120/5000`, or `ring 494 · 31.9/32 MiB` under
  large frames. The drop count moves to the front of those figures, since
  the strip is cut off at the terminal's edge: at 80 columns, with a long
  interface name or filter, the end of the line was lost, and the drop
  count with it. Decoding full-size frames went from about 13,000 to about
  150,000 a second on the development machine.
- **The stream tracker charges each segment its full cost, and charges the
  QUIC CRYPTO buffer and each flow's DPI label.** The tracker charged each
  stored segment its payload and its own size, but not the `Arc` it lives in
  or its slot in the stream's list, 24 bytes a segment on a 64-bit host. It
  did not charge a QUIC flow's CRYPTO reassembly buffer at all, up to
  16 KiB, or the flow's label, whose SNI a peer can make 15,000 bytes long.
  Small UDP payloads over a thousand flows filled 300 MiB against the
  256 MiB budget. The tracker charges all three now and stays under its
  budget, and it takes the CRYPTO buffer's charge back when it frees the
  buffer.
- **A text filter on the Packets tab no longer slows every frame.** A bare
  word or a `contains` filter lowercased a copy of each packet's info,
  addresses, host names and payload text to search them. It did that for
  every packet in the list on every frame, while holding the list's lock.
  With 5,000 text packets and the filter `zzz`, a Packets frame took 11 ms,
  17.6 ms at the 99th percentile, against 0.4 ms unfiltered. It now takes
  4 ms, or 6.3 ms at the 99th percentile. The search compares in place and
  finds the same packets.
- **An armed flight recorder no longer grows to gigabytes on a busy host.**
  It kept up to 20,000 packets whatever their size, and a copy of the whole
  connection table at every refresh for five minutes. Under bulk TCP, where
  one GSO frame can be 64 KiB, each recorded frame held about 380 KB with
  its hex and text, so 20,000 could reach 7 GB. A host with 10,000
  connections reached 3 million rows, about 3.3 GB. The recorder now also
  stops at 64 MiB of packets, dropping the oldest first. That counts the
  text decoded from them as well as their bytes, including the SNI or
  request path that every packet of a flow carries, which a peer can make
  kilobytes long. Connection snapshots stop at 50,000 rows or 64 MiB in
  all, whichever comes first, and past that the recorder leaves out whole
  older snapshots. Each row carries its flow's SNI or request path too, so
  1,024 connections each carrying an 8 KB name held about 2.7 GB over the
  window; they now keep seven snapshots. With rows of the usual size, up
  to 16,666 connections the rest stay spread across the window at a longer
  interval. From there to 25,000 only one older snapshot fits beside the
  newest, and past 25,000 the recorder keeps only the newest. That one is
  always whole. A new manifest key, `connection_rows_dropped`, and a line
  in `summary.md` give the number of rows left out, and `connections.json`
  keeps its shape. The bundle's JSON files are also written through a
  buffer now; 50,000 rows took about 12 million write calls before.
- **A connection poll on a busy Linux host takes about a quarter of the
  time.** Each poll ran `ss -tunap`. The `-p` walks every process's open
  files to name each socket's owner, and netwatch threw that name away for
  the owner its own `/proc` scan found. Naming owners then read each
  process's identity from `/proc` twice per socket, so a process holding
  10,000 sockets was read 20,000 times a poll. With 10,000 loopback sockets
  a poll took about 300 ms at the median on a 24-thread host, and now takes
  about 80 ms. netwatch runs `ss -tuna`, and `netwatch doctor` names that
  command. Each poll reads a process's identity once before looking up its
  name and once after, and a socket recorded for an earlier process with
  the same PID still loses its owner. A UDP socket with no peer is matched to
  its captured stream through an index built once per poll, where each one
  searched every stream before.
- **Diagnose's socket check no longer takes 100 ms a tick on a busy host.**
  In the Dense view and during `netwatch diagnose run`, Diagnose matches
  each kernel TCP flow to its connection once a tick. It searched the whole
  connection table for each flow, then checked every socket it remembered
  against a list of the live ones, so its cost grew with the square of the
  connection count. At 10,000 connections a pass took about 100 ms, and now
  takes about 11 ms.
- **Diagnose matches IPv6 sockets to their connections.** The kernel's TCP
  flows spell an IPv6 endpoint `2001:db8::1:443` and the connection table
  `[2001:db8::1]:443`, and Diagnose compared the two as text, so no IPv6
  socket found its connection. It lost its process name, and its send and
  receive rates read as zero, which classified a busy IPv6 socket as idle
  and kept it from ever counting as bufferbloat. IPv4-mapped addresses such
  as `[::ffff:192.0.2.1]:443` failed the same way. Both now match. A socket
  that matches no connection, or whose connection has no rate yet, now has
  unknown rates rather than zero: it is neither idle nor sending, and the
  bufferbloat check that needs its rate says it was not measured. Episodes
  record unknown rates as `null`.
- **The tick does less work per connection.** Every read of the connection
  table checked each row's age, and once any row was more than five seconds
  old, it copied the whole table to blank the stale owners. A tick
  and a frame each read the table several times. Now the table is checked
  once per poll and copied at most once each time another row goes stale.
  The Timeline also stopped building a set of every connection's key on
  each tick. At 10,000 connections the tick's connection work fell from
  about 50 ms to about 35 ms at the median.
- **Names with emoji or halfwidth katakana stay inside their column.** Lite
  and Dense measured a name with unicode-width and cut it one character at
  a time, and both disagree with what ratatui draws. A halfwidth sound mark
  (ﾞ or ﾟ) takes a column on screen but counted as none: in Lite, a process
  named with eight `ﾊﾟ` filled its 15-column field and the gap after it,
  with no ellipsis. An emoji with its presentation selector, such as `❤️`
  or `#️⃣`, counted as one column and drew two, so eight hearts were cut one
  heart late and the ellipsis fell in the host column. A skin-tone emoji
  such as `👍🏽` counted as four columns and drew two, so the name was cut
  short, and the last hand could lose its skin tone. In the top border of
  Dense's net box, an interface name with sound marks lost its end under
  the `├` that closes it. Text is now measured and cut between the
  graphemes ratatui lays out, by the columns it gives each one. That covers
  Lite, Dense, the cuts in the full view's tables and labels and in the
  footer's status message, which counted characters, and the check that
  drops a box's right-hand text when it would cover the title. Plain ASCII
  text is cut as before. A CJK or emoji name that a full-view table used to
  clip at its column edge now ends in `…`, and a status message naming a
  CJK process no longer runs off the right of the footer. Full-view tables
  that pad their columns with spaces, such as Connections and Processes,
  still count characters for the padding, so a CJK name there still pushes
  the columns after it right. ratatui itself still places right-aligned
  text one column too far right for each sound mark, and cuts off what
  passes the edge.
- **An emoji sequence that reached the screen unreplaced no longer hides
  the text after it.** The last pass over each frame drops the characters
  that could control the terminal or disguise text, the zero-width joiner
  among them. A family emoji is three emoji joined into one 2-column cell.
  With the joiners gone that cell held three emoji, 6 columns wide, and the
  four cells after it were never sent to the terminal. The cell now keeps
  the first emoji and its width. Names from packets, peers and other
  processes have their joiners replaced with `·` before layout, so this
  only hit text that missed that step.
- **`diagnose run --budget` rejects a huge minute count instead of
  panicking.** `--budget 18446744073709551615m` overflowed the conversion to
  seconds. A debug build panicked, and a release build wrapped around, so
  some huge values landed back inside the 5 s to 10 min range and were
  accepted. Every out-of-range budget now exits 3 with "budget must be
  between 5s and 10m", including numbers too large to read at all.
- **The packet decoder stops at the length each header gives, and no longer
  reads an IPv4 fragment as if it started with a UDP or TCP header.** The
  UDP or TCP segment ran to the end of the captured frame instead of the
  length in the IPv4, IPv6 or UDP header, so netwatch read the Ethernet
  padding after a short packet as payload. A pure ACK from a peer that does
  not use TCP timestamps arrives padded from 54 to 60 bytes. Each one added
  6 bytes to its stream, and in a run of them every ACK after the first
  counted as out of order, which the Connections tab shows as `↹N`. The
  protocol classifiers and the stream view saw the padding too. netwatch
  read the payload of an IPv4 fragment after the first as a UDP or TCP
  header, which gave the fragment ports, and so a stream, from bytes that
  were not a header. It classified the first fragment and added it to its
  stream as if it held the whole message. The Packets tab now lists a later
  fragment as `IPv4`, with the protocol, the datagram's ID and the
  fragment's offset in the Info column, and no ports or stream. A first
  fragment shows its ports and `[first fragment, ID 0x…]`, but netwatch does
  not classify it or add it to a stream. netwatch does not reassemble
  fragments. The Info column now names an IPv4 header length under 20 bytes,
  a total length shorter than the header, a TCP data offset under 20 bytes
  and a UDP length under 8, as in `TCP (bad header length 16)`, and a TCP or
  UDP header cut short, as in `TCP (truncated)`. None of these gets ports or
  a stream. netwatch used to decode them from the wrong bytes. With an IPv4
  header length of 16 it read the ports out of the destination address. The
  DNS timing and the QUIC breakdown in the detail pane read the same bounded
  payload.

### Security
- **Selecting a packet or a connection no longer sends its addresses to
  rdap.org. Only `W` does.** Since 0.8.0 the Packets detail pane, and since
  0.16.1 the Connections detail strip, started a WHOIS lookup themselves the
  first time they drew an address. Stepping through a capture sent the
  source and destination of each packet you landed on to rdap.org over
  HTTPS, and on to the regional registry it redirects to. Moving down the
  Connections table, or leaving the cursor on a row while the live table
  changed under it, did the same with each remote address. Addresses in the
  private ranges WHOIS skips were not sent. The panes now show only what a
  `W` press has already fetched.
- **`W` in Packets no longer sends the addresses of a packet the list is
  hiding.** Since 0.24.0, when the display filter hides the selected packet,
  the detail pane stops showing it and asks for a selection. `W` still found
  that packet in the whole capture and sent its source and destination to
  rdap.org. `W` now looks up a packet only while its row is in the list.
- **Run as root, the sandbox now takes the capabilities netwatch does not
  need from every confined thread.** It removes capabilities by a
  deny-list, and the list held only CAP_BPF, CAP_PERFMON and CAP_SYS_ADMIN.
  Under sudo, every confined thread, the packet parser included, kept 38 of
  root's 41 capabilities (37 with `--sandbox-strict`). One was
  CAP_SYS_RAWIO, which with the sandbox's `/proc` grant can read kernel
  memory, page cache included, through `/proc/kcore`, past every filesystem
  rule. Confined threads now also drop CAP_SYS_RAWIO, CAP_SYS_MODULE,
  CAP_SYS_PTRACE, CAP_SETUID, CAP_SETGID and 23 more. In the TUI, main and
  the network workers keep 10: file access in the user's directories,
  resource limits and scheduling, a metrics port below 1024, and CAP_NET_RAW
  to reopen capture. Parser and capture threads keep 9, without CAP_NET_RAW,
  and so does every confined thread in strict mode, the daemon and the
  Diagnose CLI. Root still owns most files, so under sudo the sandbox
  remains defence in depth, not containment. Losing CAP_SYS_PTRACE costs
  something under sudo on a kernel where Landlock does not enforce (older
  than 5.13, or Landlock missing from `lsm=`): confined threads can no
  longer read `/proc/<pid>/exe` or the socket links in `/proc/<pid>/fd` of
  almost any process but netwatch itself. Without CAP_SYS_PTRACE the kernel
  allows those reads of another process only if it runs as root, is dumpable
  and holds no capability the reading thread lacks. That rules out your
  processes and other users', and also most root daemons, systemd among
  them, because they hold capabilities a confined thread has dropped. Such a
  process is named by the kernel's 15-character `comm` rather than its
  executable, and its connections have no owner on a poll that finds the
  latest process-attribution scan more than 5 seconds old. Where Landlock
  enforces, it already refused those reads. Runs without elevation drop what
  they did before, and so do runs with the documented `setcap` line or under
  the systemd unit, apart from the CAP_NET_RAW change below.
- **The process-attribution thread no longer keeps every capability
  netwatch started with.** It reads other processes' socket fds in `/proc`
  to name each connection's owner, so it runs outside the sandbox, and it
  never dropped anything: in every mode, `--sandbox-strict` included, it
  held CAP_NET_RAW, CAP_BPF and CAP_PERFMON under the `setcap` line and all
  41 of root's capabilities under sudo. Strict mode's promise to drop
  CAP_NET_RAW was therefore untrue of the process. Before its first scan the
  thread now drops everything except CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH,
  the two it needs to read another user's sockets under root, so its scans
  attribute connections as before.
- **netwatch.log no longer records credentials from the `--remote` URL.**
  When a POST to the remote backend failed, the warning carried the whole
  ingest URL, so a user name and password in it, or a token in its query
  string, went into a file that outlives the session and gets attached to
  bug reports. The log now names the backend by scheme, host, port and path.
- **`netwatch diagnose` prints a shared episode as plain text.** `episodes`,
  `replay`, `features` and the `export` preview printed ids, times, issue
  keys, causes and lab scenario names as the file had them, so an episode
  someone sent you could carry escape sequences that retitle the terminal or
  write the clipboard through OSC 52. Those characters now print as `·`, as
  in the TUI, and so do the same characters in file names and in load
  errors, which can quote the file. `features --out` writes the `·` to its
  CSV file too. `replay --json` escaped C0 controls only; it now writes DEL,
  C1 controls and bidi overrides as `\u` escapes as well, which decode to
  the same strings. `diagnose episodes` and the `export` preview no longer
  panic on an id with a multi-byte character across its eighth byte. Replay
  no longer panics when the first frame's time does not parse, as happened
  to any recording that began in the hour a clock goes back. Nor do
  `replay` and `features` on a frame time or probe age hundreds of billions
  of years out, which only a crafted file holds: they skip that frame, and
  that probe counts as one that has not answered.
- **An episode stops loading past 84,000 frames or 820 MiB uncompressed.**
  `diagnose episodes`, `replay`, `features` and `export` inflated a gzipped
  episode in full before parsing it, so a gzip of zeros a few megabytes long
  could take all the memory there was, and a 100 KB file of a million empty
  frames took 2.6 GB. Loading now stops at either limit with an error that
  says which. A recording holds at most 72,000 frames, one per 100 ms tick
  for two hours, which inflate to about 650 MB on a busy host. The limits
  bound the input, not the memory: a crafted episode under both can still
  take gigabytes to parse. `netwatch uptime` likewise skips a log line
  longer than 64 KiB and warns how many it skipped, where it used to read a
  line of any length. A line that is not valid UTF-8 now costs that line
  only; it used to end the rest of that day's file.
- **`netwatch diagnose` no longer follows a link into another directory.**
  Given a directory, `episodes`, `replay`, `features` and `export` walked
  every link in it, so two links back up the tree, as an archive someone
  sends you can hold, kept them walking until killed, and a link out of it
  listed episodes from elsewhere. netwatch cleans its own episode directory
  the same way after each recording, deleting what is past 90 days or
  300 MiB, so a link there could keep that cleanup running for good or
  offer it files from outside. They now list a linked file but do not
  descend into a linked directory.
- **WHOIS and online GeoIP look up global unicast addresses only.** Their
  private-address check compared the start of the text against a short
  list, so it let through local addresses written another way or in ranges
  the list left out. Among them were a LAN peer in the `::ffff:192.168.1.5`
  form Linux gives a dual-stack socket's peer, the 100.64.0.0/10 range that
  carrier-grade NAT and Tailscale use, the documentation and benchmarking
  ranges, link-local addresses outside `fe80::/16`, multicast groups
  outside 224/8 and 239/8, 255.255.255.255, local-use NAT64 addresses in
  `64:ff9b:1::/48` and SRv6 addresses in `5f00::/16`. `W` sent such an
  address to rdap.org, and with `geoip_online` on, netwatch sent it to
  ip-api.com in cleartext. Both now skip any address that is not global
  unicast: multicast, and every address the IANA special-purpose
  registries mark as not globally reachable. A NAT64 address in
  `64:ff9b::/96` or a 6to4 address in `2002::/16` counts as global only if
  the IPv4 address inside it does.
- **Dense no longer sends server names to ip-api.com.** With
  `geoip_online` on, the line under the selected connection sent
  ip-api.com, in cleartext, the server name a TLS or QUIC connection had
  sent instead of its address. It now sends the address.
- **The threat model states the limits of the Linux sandbox.** The 0.17.0
  release notes overstated protection by saying a compromised parser cannot
  read SSH keys, exfiltrate arbitrary files or pivot via new raw sockets.
  Threads share memory and descriptors, the proc broker is outside Landlock,
  and outbound networking was unrestricted. From this release parser threads
  cannot connect or bind TCP sockets on Linux 6.7 or newer, which still
  leaves them UDP and the other ways out listed below. Under the `setcap`
  line or sudo, the default best-effort mode left CAP_NET_RAW on every
  confined thread, the parser included, so capture could reopen, and only
  `--sandbox-strict` dropped it. Parser and capture threads now drop it in
  every mode, but that does not close a descriptor already open, and every
  thread shares the open capture descriptor, so a compromised parser can
  still capture and inject through it. Root operation has limited
  containment.
  The preferred Linux setup restricts a capability-enabled binary to a
  dedicated group; policy and endpoint tables are checked in tests, and the
  outbound inventory lists the trace to 1.1.1.1 that every TUI session runs
  at startup. `netwatch doctor` said eBPF was disabled by the sandbox
  policy, untrue since 0.32.2; it now says eBPF loads under the policy and
  its reader keeps the load capabilities.
- **Parser threads can no longer call `connect` or `bind` on a TCP
  socket.** On Linux 6.7 or newer, the workers that read packets, files,
  kernel tables or subprocess output now stack a second Landlock layer that
  denies TCP bind and connect. Capture, the TLS keylog reader, the metrics
  endpoint, eBPF and connections are among them. Before, a parser bug that
  ran code could connect anywhere or listen on any port, as every confined
  thread could. The metrics endpoint still answers scrapes, because
  accepting a connection is neither. Where the kernel supports it, the same
  layer also stops these threads connecting to abstract Unix sockets from
  Linux 6.12 and to pathname Unix sockets such as D-Bus or nscd from 7.1.
  From 6.12, on a kernel with the fix for Landlock erratum 2, it stops them
  signalling processes outside their domain. Main keeps the network, and so
  do the workers whose job is a connection: reverse DNS, WHOIS, GeoIP,
  health, traceroute, Insights, remote publishing and the Diagnose probes.
  A worker missing from the role table counts as a parser. UDP, ICMP and
  MPTCP stay open to parser threads, and MPTCP falls back to TCP. Two TCP
  calls also get past the deny, because Landlock checks only `connect` and
  `bind`: a TCP Fast Open send (`sendto` with `MSG_FASTOPEN`) opens a
  connection, and `listen` on an unbound socket takes a random port on
  every address and accepts connections on it. So this makes sending data
  out after code execution harder without preventing it. On older kernels
  best-effort logs `parser network deny unavailable` once and runs as
  before.
- **Parser and capture threads drop CAP_NET_RAW in best-effort mode too.**
  Under the `setcap` line or sudo, every confined thread kept CAP_NET_RAW
  unless `--sandbox-strict` was given, so a compromised parser could open
  raw and packet sockets and inject frames. Those threads now drop it
  whenever the sandbox is on. Capture opens its device before it drops the
  capability, and `c`, `i` and `Shift+R` reopen capture on a new thread, so
  they keep working. Main and the network workers keep CAP_NET_RAW in a
  best-effort TUI. The capture thread still holds the device it opened,
  which can capture and inject on its interface.
- **The capture thread can no longer write files.** It had every write
  grant the other confined threads have, so a parser bug in it could
  rewrite `config.toml`, for example to turn the sandbox off for the next
  start. Its Landlock layer now allows reading only. Nothing in the capture
  loop writes a file; exports and incident bundles are written by other
  threads. The other confined threads can still write the configuration.
- **With the sandbox on, the daemon and the Diagnose CLI hold no raw-socket
  capability once capture has opened, and no thread keeps CAP_NET_ADMIN.**
  Under the `setcap` line, sudo or the systemd unit, `netwatch daemon`,
  `diagnose run` and `diagnose coverage` kept CAP_NET_RAW on the main
  thread and the network workers for the whole session, though none of
  them ever reopens capture. A thread running injected code could open raw
  sockets, set `IP_TRANSPARENT` or `SO_MARK`, and hand the capability to
  the commands it started through the Ambient set the systemd unit grants.
  Run as root, every thread also kept CAP_NET_ADMIN, which nothing in
  netwatch uses. Promiscuous capture opens with CAP_NET_RAW alone. Those
  sessions now drop CAP_NET_RAW from main and the network workers after
  capture opens, and in best-effort and strict mode every thread drops
  CAP_NET_ADMIN, so `netwatch doctor --check-capture --json` under sudo no
  longer lists it in `caps_retained`. The TUI keeps CAP_NET_RAW on main and
  the network workers in best-effort mode, so `c`, `i` and `Shift+R` still
  reopen capture. In strict mode they fail, as before. Once startup is
  done, netwatch reads every thread's capability sets. If a thread still
  holds CAP_NET_ADMIN, or CAP_NET_RAW in a session that drops it, netwatch
  names the thread in a warning, and with `--sandbox-strict` refuses to
  start. With `--no-sandbox` or `sandbox = "off"`, main and the workers
  keep both capabilities, as before, and the audit warns about nothing.
  None of this revokes the capture descriptor already open, which every
  thread shares and which can still capture and inject on any interface in
  its network namespace. In the daemon and the Diagnose CLI, on a host
  whose `net.ipv4.ping_group_range` leaves out the user netwatch runs as,
  the `ping` that health falls back to and the Diagnose PMTU probe now
  fail, and health measures over TCP instead.
- **Insights now says when it sends in cleartext to another machine.** With
  `insights_endpoint` set to an `http://` URL on another host, every request
  carries DNS names, peer addresses and packet summaries across the network
  unencrypted, and only docs/INSIGHTS.md said so. `--remote` refuses the same
  setup unless told otherwise. The Diagnose page now carries a `cleartext,
  off-host` line while Insights is on, whether or not an issue is open, the AI
  Endpoint row in Settings leads with the same words, and `netwatch doctor`
  reports `insights` as degraded with reason `cleartext_off_host`. netwatch
  still sends: there is no new key, and Insights stays experimental. A
  loopback address, `localhost` and `https://` carry no mark.
- **The capture error and the package install messages restrict the binary to
  a group before granting it capture.** They printed a bare `setcap`, which on
  a 0755 binary lets every local account capture. The README, REFERENCE.md and
  the man page already put a `netwatch` group first, but anyone following the
  error or the post-install message did not get that. The `.deb` and `.rpm`
  messages now give `groupadd`, `usermod`, `chown root:netwatch`, `chmod 0750`
  and `setcap`, in that order. On Linux the capture error gives the same steps
  as one command, which finds the binary once, before `chmod` takes it away
  from an account not yet in the group. The header on Dashboard and Packets
  wraps that command between its steps instead of cutting it off. netwatch
  changes no file itself, so a binary you already granted stays open to every
  account until you run the steps. The README now leads with this recipe and
  the systemd unit, and the container docs drop `--cap-add=NET_ADMIN`, which
  nothing in netwatch uses.

### Dependencies
- **landlock 0.4.7 at minimum.** The parser layer's rule for pathname Unix
  sockets is Landlock ABI 9, which earlier releases of the crate do not
  know. Cargo.lock already had 0.4.7, so nothing new is compiled.

### CI
- **A Diagnose load test unit test no longer fails on a slow runner.**
  `loaded_samples_are_taken_only_while_the_body_goes_out` slept on the real
  clock and needed its first sample before a 900 ms cut-off, which a busy
  macOS runner sometimes missed, failing the run and cancelling the Linux
  and Windows jobs with it. The sampler now takes its clock as an argument,
  and the test gives it one that moves only when it is slept on.
- **The sandbox tests catch a worker whose role changes by accident.** They
  read the name every worker spawn site in `src` uses and fail on one the
  role table does not list, so renaming a network worker can no longer turn
  it into a parser unnoticed. A child test hides Landlock behind a seccomp
  filter and checks that strict mode refuses a parser thread because it
  cannot deny TCP. Another enters the capture role through the installed
  policy and checks that it cannot write the configuration. The list of
  capabilities each role drops is also checked without a user namespace,
  which CI's runners refuse, so CI fails if CAP_NET_RAW leaves the parser
  and capture threads' list.
- **`cargo test` still passes on Linux 6.2 to 6.6.** Strict mode now refuses
  parser threads there, so the strict worker acceptance test skips on those
  kernels with a message, and the `/proc/net` fallback test, which needs no
  TCP deny, runs in best-effort mode. Older kernels, and kernels without
  Landlock, fail both tests as before.
- **The capability tests cover capture authority.** Which capabilities
  each role drops in each session and how the startup audit reads a
  thread's status file are checked on the Linux runner, and which session
  keeps CAP_NET_RAW on every runner. Where a user namespace can be made,
  tests run as root in one: they enter each role, start a capture on a
  missing interface, audit a thread holding CAP_NET_RAW, enter a network
  worker before and after the session sets its capture authority, run
  main's entry beside a thread that kept CAP_NET_RAW in best-effort and
  strict mode, and check what the shutdown-deadline thread and the other
  threads that never enter keep. CI's runners refuse user namespaces, so
  those skip there.
- **CI checks the connection table at 10,000 rows.** A generator builds
  connection tables shaped like a busy host's. In every run, a 10,000-row
  table must show its true count and scroll to its last row, and the
  Timeline must keep every active connection when 10,000 are open. Timed
  tests for frames, the scroll key, the tick's connection consumers and
  Diagnose's socket join at 2,000, 10,000 and 50,000 rows, and for a real
  poll of up to 50,000 loopback sockets, run in a new weekly perf workflow
  that gates nothing yet. `scripts/scale-bench.sh` prints their numbers as
  a table and fails on any budget not met. The workflow sets
  `NW_PERF_STRICT=0`, so budgets that wait on later 0.39 changes are
  printed there and do not fail the run.
- **The terminal signal tests no longer fail at random on FreeBSD.**
  FreeBSD's openpty(3) finds the slave's path with ptsname(3), which keeps
  it in one buffer for the whole process. The four tests in
  `tests/tui_signals.rs` allocate their ptys at the same moment on parallel
  threads, so a test could open another test's slave. Its netwatch then drew
  where nothing was reading, and the test failed, mostly with `no first
  frame: ""`: 23 of 120 runs on a FreeBSD 15.1 VM. The pty tests in
  `src/ui/tty.rs` had the same race and failed 3 of 100. Both now allocate
  one pty at a time. The signal tests then passed 200 runs in a row, and the
  tty tests 100.
- **A flood soak checks netwatch's memory, capture caps and frame time
  under load.** `tests/soak/flood_soak.py` joins two unprivileged
  namespaces with a veth. `tests/soak/flood.py` floods one end with six
  kinds of traffic, two cycles of each, then two paced rates, while
  `examples/flood_soak` runs the real App on the other end, capturing and
  drawing ten frames a second. The second cycle sends new addresses, so
  a table that grows by address shows up as growth between the cycles.
  The real `netwatch daemon` runs last, under the mix of traffic and then
  under full-size TCP that fills its stream budget. The soak fails on a
  peak RSS over 512 MiB, memory that grows between the cycles, a packet
  ring, stream tracker or thread count past its cap, a phase in which
  nothing was sent or decoded, a capture error, a panic in the App or the
  daemon, a daemon that lost its packet socket, a run with no
  segmentation-offload frames, or a view whose p99 frame time passes
  33 ms. It records decode rate, drops and CPU for every phase. A full run
  takes 75 minutes and `--smoke` five. No workflow runs it yet.
- **The 10,000-socket poll and Diagnose's socket join are held to their
  budgets.** `scale_poll_real_sockets` fails past 150 ms at the median,
  times `NW_PERF_SLACK`, instead of printing it as pending.
  `scale_diagnose_join` times the join of kernel flows to connection rows on
  its own against the 2 ms budget, about 0.6 ms at 10,000 rows. It timed
  Diagnose's whole socket pass against that budget before, which no change
  to the join could meet; the pass is still printed, with no budget. The
  Timeline churn test now expects the last 2,000 closed connections to stay.
- **A test checks the metrics table in docs/observability-export.md
  against the exporter.** It fails when a metric is added, renamed or given
  another type without the table.

## [0.38.0] - 2026-10-25

### Added
- **`netwatch uptime`**: outage history for an ISP ticket. One row per
  outage with start, end, duration and the hop that failed (gateway,
  internet or DNS), then the outage count, total downtime, uptime and the
  time nothing was monitored. `--since 7d`, `--json` and `--csv`. The TUI
  and `netwatch daemon` keep the log it reads under
  `~/.local/state/netwatch/uptime/` (about 80 KB a day, kept 90 days, owner
  only). `record_uptime = false` turns it off. A hop is down after three
  probe cycles in a row with no reply, and time when netwatch was not
  running is "not monitored", never up (#76).
- **Topology shows how long the connection has been up**: a connection
  box under the router and ISP reads "up 3h 12m since netwatch started",
  or "since 14:02 (internet, 3m 00s)" after an outage, and "down 45s,
  gateway not answering" during one. The router box says "down" when the
  gateway is the hop that failed, rather than "up" regardless.
- **`confirm_quit`** (Settings → Confirm Quit, off by default): `q` asks
  "Quit netwatch?" first, and `y`, `q` or `Enter` confirms. `Ctrl+C` still
  quits at once (#94).
- **`netwatch doctor` says where the Linux connection table will come
  from.** A new `connections` entry reads `ready` (`ss_found`, with the path)
  when `ss` is on `PATH`, and `degraded` (`proc_net_fallback`) when it is
  not, naming the `/proc/net` tables a live session reads instead. When
  `/proc/net/tcp` cannot be read either, it reads `unavailable`
  (`no_connection_table`), because the table will be empty. The JSON gains
  that one capability and nothing else changes.
- **PCAPNG export, with the owning process in each packet's comment.** `w`
  in Packets and `Shift+E` for an incident now open a preview that freezes
  the selection, counts what will be written and what will be left out, and
  warns that packet bytes are not redacted. `w` takes the packets the list
  shows, so with `x` on only the expert findings. `Enter` writes in the
  background, `f` picks PCAPNG (the default) or classic PCAP, `a` turns
  comments off, and `Esc` cancels. Each PCAPNG packet's comment is a JSON
  object Wireshark shows under "Packet comments": the process, PID and
  direction when two checks of the socket's owner, one finished before the
  packet and one begun after it, agree on it (Linux), else `unknown_owner`,
  plus the DPI classification, SNI and JA4. One file can hold packets from several
  interfaces and link types. The format and every comment key are specified
  in REFERENCE.md, "Capture export".

### Changed
- **`q` closes the help, settings and memory overlays** instead of quitting
  netwatch, as `Esc` does. Pressed on an overlay, it nearly always meant
  "close this" (#94). `Ctrl+C` still quits from anywhere.
- **Windows reads connections through IP Helper, not netstat and
  tasklist.** Each socket and its owning PID come from
  `GetExtendedTcpTable` and `GetExtendedUdpTable`, and process names from
  one process snapshot, where every refresh used to start two commands. The
  names are the `chrome.exe` names tasklist gave. A listener's peer reads
  `*:*` instead of `0.0.0.0:0`. An IPv6 link-local address no longer carries
  its `%12` scope suffix, in the views and in the JSON and CSV exports. A
  TIME_WAIT connection reads "unattributed" instead of "System Idle
  Process", since no process owns it any more. The connection detail's
  Match line says `IpHelper`. netstat and tasklist are used only if those
  calls fail.
- **Windows: interface counters, the default route and adapter GUIDs come
  from the IP Helper API.** The Interfaces tab and traffic graphs read
  `GetIfTable2` each tick, where netwatch used to start PowerShell for
  Get-NetAdapterStatistics on every tick, at 300-800 ms a call. The default
  capture interface and the gateway come from the routing table
  (`GetIpForwardTable2`), ranked by route plus interface metric as Windows
  ranks them, instead of from Get-NetRoute and `route print`. Capture finds
  an adapter's Npcap device by the GUID `GetAdaptersAddresses` reports
  rather than by asking Get-NetAdapter. Counters cover the adapters the
  Interfaces tab lists and, as Get-NetAdapterStatistics did, NICs with IP
  unbound, such as a capture-only NIC or the physical NIC under a Hyper-V
  external switch. Packet counts now include broadcast and multicast, as
  they do on Linux and macOS, from the API and its fallbacks alike.
  PowerShell and `route print` remain only as fallbacks for when an API
  call fails. `netstat -e`, the last fallback for counters, is no longer
  run. It gave one machine-wide row that matched no interface, and only on
  an English install.
- **Incident bundles hold `packets.pcapng`, and `manifest.json` is version
  2.** `packets.pcap` is still written when every packet shares one link
  type and is dated before 2106. The manifest lists the packet files
  present, how many packets were written, left out and annotated, and the
  capture's last drop count. The
  bundle directory name ends in a short random suffix, so exporting the same
  incident twice gives two bundles instead of overwriting one.
- **Frames from interfaces that are not Ethernet appear in Packets as
  `Raw`**, undecoded, instead of being fed to the Ethernet parser, which
  dropped most of them and misread the rest. A VPN tunnel's raw IP and BSD
  or Windows loopback are the usual cases.
- **Exports never overwrite a file or leave a partial one.** Captures and
  bundles are written under a temporary name and moved into place when
  complete; a cancelled or failed export removes them. The exports directory
  must be on a filesystem with hard links.

### Fixed
- **Exported captures carry the real capture time and wire length.** PCAP
  export rebuilt each timestamp from the time of day shown in the packet
  list, so every packet was dated 1 January 1970 and a capture across
  midnight went backwards, and it recorded the captured length as the
  length on the wire. Times now come from libpcap, in UTC to the
  microsecond. `--demo` packets, which were never captured, are left out
  and counted instead of written with an invented time.
- **Lite view: keys no longer overflow in a terminal smaller than its
  grid.** The key handler sized its layout from the last frame without the
  80×24 check the renderer makes, so in a terminal under about 40 columns
  every key overflowed.
- **`netwatch doctor` on Windows says whether Npcap is installed, and where
  to get it.** Without Npcap, the `capture_library` entry now says Npcap is
  not installed, and its next step gives the https://npcap.com/#download
  link that the capture error and the Dashboard banner already give. With
  Npcap installed, doctor asks Windows whether the Npcap driver is running.
  If it is not, the reason is `npcap_driver_stopped` and the next step is
  `sc.exe start npcap` as administrator (`.exe`, because in Windows
  PowerShell `sc` is Set-Content). A `wpcap.dll` with no Npcap driver
  behind it, as WinPcap or a partial uninstall leaves, is
  `npcap_driver_missing`. Both now report state `unavailable`; in 0.37 they
  were `not_checked [npcap_present_unloaded]`. Before, doctor said "DLL and
  driver not loaded" either way, and told a user who had Npcap to install
  it.
- **Linux: the connection table is no longer empty without `ss`.** When
  `ss` is missing (minimal containers, some NAS distributions), cannot
  start, or fails, netwatch reads the kernel's
  `/proc/net/{tcp,tcp6,udp,udp6}` tables instead, so Connections, Processes
  and Egress fill as they do with `ss`, and processes are attributed the
  same way. The rows read the same with two exceptions: a socket bound to
  a device loses the `%lo`-style suffix `ss` adds, and a dual-stack
  wildcard reads `[::]:port` where `ss` prints `*:port`. While the fallback
  is in use, Settings shows a `connections: degraded` row with the reason.
  The log notes each switch once rather than every poll, and warns when a
  poll can read no table at all, from the first poll on.
- **Windows: connection states read the same in every display language.**
  netstat translates its state column: German Windows showed `HERGESTELLT`
  and `ABHÖREN`, which matched no state filter, colour or counter,
  including the TIME_WAIT and CLOSE_WAIT counts behind the Prometheus
  metrics, and English showed `LISTENING`, so the listen filter found
  nothing. The state now arrives as a number and is named as on Linux
  (`ESTABLISHED`, `LISTEN`, `TIME-WAIT`), in the views and in the JSON and
  CSV exports.
- **Processes view: SOCKET STATES counts CLOSE-WAIT, FIN-WAIT and SYN
  sockets on Linux.** It knew only lsof's spelling (`CLOSE_WAIT`), so it
  counted Linux's `CLOSE-WAIT` as other.
- **Linux: the Dense view dims closing sockets, and the Connections view
  flags CLOSE-WAIT.** Both knew only lsof's spellings (`TIME_WAIT`,
  `CLOSE_WAIT`), not the `TIME-WAIT` and `CLOSE-WAIT` that Linux, and now
  Windows, report. A closing row in the Dense view drew as live, with its
  state cut to `TIME-WA…`, and a `CLOSE-WAIT` or `FIN-WAIT` row in the
  Connections view was muted instead of drawn in the error colour.
- **Windows: DNS servers are found on non-English Windows, and IPv6 ones
  are read whole.** They came from `ipconfig /all` by its English label, so
  on a French ("Serveurs DNS") or Russian ("DNS-серверы") install none were
  found and the Health widget had no resolver to probe. An IPv6 server such
  as `2001:db8::53%12` was cut at its last colon to `53%12`, further IPv6
  servers were skipped, and another adapter's gateway could be listed as a
  DNS server. They now come from `GetAdaptersAddresses` in any display
  language: the default-route adapter's first, and without the
  `fec0:0:0:ffff::1` placeholders Windows reports when no IPv6 resolver is
  set. A link-local server keeps its zone index (`fe80::1%12`), as on Linux
  and macOS, and the probes pass it over as they do there rather than send
  to whichever link Windows picks. The ipconfig fallback reads IPv6 servers
  correctly as well.
- **Windows: the gateway is an address with a VPN up.** `route print` lists
  default routes unsorted, and a VPN's on-link default shows "On-link" in the
  gateway column, which the Health widget could then try to probe as the
  gateway. The gateway is now the next hop of the lowest-metric default route
  that has one. Where either old parse went wrong, the gateway or resolvers
  in the network's Diagnose baseline key change with these two fixes, so
  Diagnose relearns that network's baselines once after the upgrade.
- **Windows: gateway and internet latency on any display language.** The
  probes ran `ping.exe` and read its English summary. On a German, Russian
  or other non-English install that summary never matched, so the probes
  got no ICMP figure and fell back to timing a TCP connect, or showed
  "unmeasured" where nothing answered that either. netwatch now sends the
  echoes itself through the Windows ICMP API (`IcmpSendEcho2`, IPv4 and
  IPv6), which needs no administrator rights and answers with a status code
  instead of text. A reply under a millisecond shows its measured fraction,
  not 0. netwatch no longer starts `ping.exe` at all. It needs the same
  ICMP API, so it could not help where netwatch's own call fails.
- **Windows: traceroute works.** Since 0.32 the trace subprocess refused to
  start off Unix, so `T` ended in an error on Windows. Windows now traces
  natively through the ICMP API, IPv4 and IPv6, with three probes a hop up
  to 30 hops, and records whether the destination itself answered, which
  Diagnose's path rules read. A target that rejects pings with an
  unreachable of its own (an iptables REJECT, a firewalld icmp-block) counts
  as answered, as it does on Linux. `tracert` remains the fallback for a
  target that is not an address, and netwatch now reads its output
  correctly. `<1 ms` is under a millisecond rather than a hop named "<1",
  `*` is a probe with no answer, a hop's address comes only from a token
  that parses as one, so "Request timed out." no longer leaves "out." as
  the address, and "Transmit error: code 1231." is no hop rather than a
  1231 ms one. The tests cover English, German and Russian output.
- **Diagnose: the PMTU experiment is "unsupported" on Windows.** It
  confirms a black hole by repeating a transfer at a reduced TCP MSS, and
  Windows cannot set the MSS of one socket, so the experiment could never
  find a black hole there. The coverage row now says why and no longer
  suggests `t`, and both `t` and `diagnose coverage --test pmtu.blackhole`
  refuse it, before asking for a `pmtu_url`, as the IPv6 experiment does
  off Linux.
- **IPv6 connections show their protocol, rates and packets.** Packet
  capture wrote IPv6 addresses with every group spelled out
  (`2001:db8:0:0:0:0:0:1`) while the connection table compresses them
  (`2001:db8::1`), so no IPv6 connection ever found its capture stream. The
  Connections and Dense views showed no protocol, SNI or JA4 for it, and no
  live rate, retransmits or handshake time; its packets got no owner in a
  PCAPNG export; and `Enter` on the row opened an empty Packets list, as it
  also did for a dual-stack socket's `::ffff:192.0.2.1` peer. Capture now
  writes IPv6 in the standard compressed form (RFC 5952) in the packet list
  and details, copied packets, the timeline and alerts, and puts an IPv6
  address followed by a port in brackets, `[2001:db8::1]:443`, as the
  Connections tab does: unbracketed, `2001:db8::1:443` is a different
  address. Rows also join when `ss` adds a `%dev` zone and when macOS
  `lsof` writes the interface into a link-local address. Display filters
  take an address in any of those spellings, and `ip.addr == X` as Wireshark
  writes it; a whole address now matches only itself, so `10.0.0.1` no
  longer also shows `10.0.0.10`. IPv6 loopback traffic no longer reaches the
  beaconing detector as if it were external. The Egress tab and its NDJSON
  export now see SNI and byte counts for IPv6 destinations too, so policy
  verdicts, `netwatch_policy_violations_total` and Diagnose's egress check
  can change after upgrading: an `allow_sni` list stops flagging allowed
  IPv6 traffic that had no name before, and a `deny_sni` list now catches
  IPv6 traffic it used to miss.

### Dependencies
- **toml 0.8 → 1.1, so the tree carries one TOML parser rather than two.**
  toml 0.8 parsed through its own copy of toml_edit 0.22, next to the
  toml_edit 0.25 the egress policy writer uses; toml 1.x needs neither.
  config.toml and the egress policy are written byte for byte as before,
  `--generate-config` included. config.toml and egress-policy.toml can now
  also use TOML 1.1: an inline table may span lines and end in a comma, and
  strings take `\e` and `\xHH` escapes. netwatch 0.37 and earlier can't read
  a file that does. They run on defaults in place of such a config.toml, and
  they skip such an egress policy and enforce none of it, which shows only as
  a log warning and in Diagnose coverage. Keep a file shared across machines,
  such as a distributed egress policy, to TOML 1.0 until every host runs
  0.38. Parse errors are worded a little differently.
- **dirs 5 → 7.** Config, cache and state stay where they were on every
  platform. The one location dirs 7 moved, `preference_dir` on Windows, is
  not one netwatch uses.
- **ureq 2 → 3.5 and webpki-roots 0.26 → 1.** The remote publisher, the geo
  and whois lookups and AI insights behave as before. They keep their
  timeouts, connect directly even when `HTTPS_PROXY` is set, which ureq 3
  would otherwise honour, follow at most four redirects and send compact
  JSON. A reply is still capped at 10 MiB once gzip is undone. The remote
  URL is still sent as the url crate reads it, so a trailing newline from a
  secret file, a space in the path or a non-ASCII host works as it did, and
  a URL ureq 3 cannot send to is refused at start-up. Three things differ.
  An ingest POST answered with a 307 or 308 is now retried, where ureq 2
  counted it as delivered and dropped the batch. A response body now has
  30 s to arrive, a redirect's included, since ureq 3 reads a redirect's
  body before following it where ureq 2 dropped it unread. AI insights now
  use the shared client, so the Ollama endpoint gets 5 s to accept the
  connection and still 30 s to answer. The diagnose load test no longer
  uploads through ureq, because ureq 3 takes a custom resolver only through
  an API outside semver. It sends the same 25 MB over the cancellable
  lookup and sockets the other probes use, and still never follows a
  redirect. It times connections under load only once the upload's body is
  going out, so an upload that loses its first seconds to addresses that
  never answer gives no verdict from idle samples. Only one webpki-roots
  remains in the build.
- **windows-sys 0.61, on Windows only.** The IP Helper and ICMP calls that
  replace `netstat`, `tasklist`, `ping`, `tracert`, `ipconfig`, `route print`
  and the per-tick PowerShell query take their struct layouts from
  Microsoft's metadata through windows-sys rather than hand-written
  declarations. tokio, mio and socket2 already built it there, so no new
  crate is compiled.
- **ratatui 0.27 → 0.30, crossterm 0.27 → 0.29 and unicode-width 0.1 →
  0.2.** Every tab of the full view, Lite and Dense draw as before at
  80×24, 120×40 and 200×60, in every theme and with `NO_COLOR`, CJK and
  emoji names included. Three things differ. A box too narrow for both its
  title and the text at the right of its top border now shows the
  right-hand text over the title rather than under it. Most tabs of the
  full view have such boxes, and they start to overlap below about 53
  columns, as in a tmux window split in half; by 38 columns some boxes
  lose their name entirely. A halfwidth katakana sound mark (ﾞ or ﾟ) now
  has a column of its own, as terminals draw it, so a name holding one no
  longer pushes the rest of its row right; in Lite and Dense the name
  instead loses a column at its end for each mark. On Windows the second
  click of a double-click now counts, as it already did elsewhere, so
  double-clicking a group header folds it and opens it again. paste, the
  unmaintained crate ratatui 0.27 built with, is gone from the tree.

### CI
- **The Nix flake is built in CI.** A new workflow runs `nix build`, test
  suite included, on every change and once a week, evaluates the flake for
  every system it declares, and checks that the built binary reports the
  Cargo.toml version. The flake had stopped building without anyone
  noticing until #105, from @kashw2, fixed it and made it read its version
  from Cargo.toml. The flake now lists x86_64-linux, aarch64-linux and
  aarch64-darwin only: nixpkgs dropped Intel Macs in 26.11, and listing
  them made the flake fail to evaluate.
- **CI fails when Windows code compares English command output.** A test
  reads the source as a Windows build compiles it and fails on any
  comparison with English that ping, tracert, ipconfig, netstat, netsh or
  another Windows tool prints, such as `Average =` or `LISTENING`, because
  a translated install prints something else and the match finds nothing.
  The only code allowed to read English is a fallback that runs after its
  IP Helper call has failed: ipconfig for the interface list and for DNS
  servers, and netstat's connection states. Each is listed in the test and
  marked in the source. The netsh MTU fallback no longer looks for the
  English header row; it reads only rows that start with a number.
- **Windows CI runs the binary it builds.** On a runner with no Npcap,
  `netwatch --version` must print the Cargo.toml version, and
  `netwatch doctor --json` must report `npcap_missing` with the download
  link. Nothing started the built binary on Windows before. The release
  workflow runs the same check on the Windows binary before packaging it.

## [0.37.0] - 2026-10-22

### Dependencies
- nix 0.29 → 0.31, brotli 8 → 9, maxminddb 0.27 → 0.32, toml_edit 0.22 →
  0.25, and every semver-compatible update (`cargo update`). These are the
  Dependabot updates #86-#90 in one change.

### CI
- Tests run under cargo-nextest. Only the tests whose outcome depends on the
  runner (procfs attribution, local ports, probe timeouts) are retried, and a
  pass on retry is reported as flaky, with a warning on the run, not hidden.
- The FreeBSD VM and armv5te jobs moved to their own workflow, so as Tier 3
  platforms they no longer hold a release. Every Tier 1 and 2 job still does.
- The Windows jobs fetch the Npcap SDK through `scripts/npcap-sdk.ps1`,
  which checks a pinned SHA-256 and, if TLS to npcap.com fails, retries
  without certificate validation. npcap.com's certificate expired on
  2026-10-18 and failed every Windows CI job and would have failed a release.
- A pcap replay test runs saved captures (DNS, TLS, HTTP, SSH over IPv6,
  QUIC, ARP, ICMP, NTP, DHCP and truncated frames) through the capture
  thread's decode and stream tracking, and compares the result with
  checked-in golden output. The captures are generated by
  `tests/fixtures/pcap/generate.py` from documentation addresses.

### Release
- Each release attaches a CycloneDX SBOM (`netwatch-X.Y.Z.cdx.json`) built
  from `Cargo.lock` and attests it against every artifact. The GHCR image
  gets signed build provenance, stored in the registry. REFERENCE.md shows
  how to verify both.
- Release binaries are built with `cargo auditable`, which embeds the
  resolved dependency list, so `cargo audit bin` and other scanners can
  check an installed binary. The release fails if any binary lacks it.

### Security
- **rustls-webpki 0.103.15 → 0.103.16 and webpki-roots 1.0.9 → 1.0.10**,
  for RUSTSEC-2026-0382 (certificate verification could accept distrusted
  intermediates) and RUSTSEC-2026-0381 (bundled roots trusted the
  distrusted emSign intermediates).
- **rustls 0.23.40 → 0.23.46**, for RUSTSEC-2026-0285, -0346, -0348 and
  -0349 (handshake messages accepted across encryption levels, secrets in
  `Debug` output, a 1 GiB Brotli certificate allocation before
  authentication, and a ServerHello key-exchange downgrade). netwatch uses
  rustls for its own outbound HTTPS lookups. **anyhow 1.0.102 → 1.0.104**
  for RUSTSEC-2026-0190.
- CI now runs `cargo deny check` (advisories, licenses, sources) on every
  change, and Dependabot proposes weekly Cargo and GitHub Actions updates.

### Fixed
- **Shell completions and the man page now cover `diagnose run`, `diagnose
  corpus` and `diagnose features`**, with `run`'s `--budget`, `--target` and
  `--format` and its exit statuses. The usage message for an unknown
  `diagnose` subcommand lists all seven. A test keeps all three in step with
  the subcommands netwatch routes.
- **Help (`?`) lists every key the full view handles.** It was missing
  Connections `f` (state filter) and `G` (grouping), Interfaces `f`,
  Timeline `f`, Stats `t`, Egress `H`, Packets `d` and `y`, Diagnose `t`,
  `d` and `c`, the whole coverage view (`t`, `[`/`]`, `d`, `r`, `x`), `M`
  and `v`, and it printed the Dashboard section twice. Help is now a table,
  and a test reads the key handler and fails on any key without a help line.
- **`default_tab = "egress"` opens the Egress tab.** It fell back to
  Dashboard. Settings now offers all ten startup tabs; it was missing
  Processes, Diagnose and Egress.

- **A refused capture shows on the Dashboard, with the fix.** Without
  capture privileges the failure appeared only on the Packets tab, as
  "Capture failed: libpcap error: … CAP_NET_RAW may be required", and the
  "run with sudo" hint matched only the BSD wording. The Dashboard header now
  gains a row, "capture off: not permitted —" followed by the fix for the
  OS: on Linux the `setcap` line the README gives, on macOS and FreeBSD
  `/dev/bpf` access, on Windows Npcap. The fix is one constant, and a test
  checks the README, REFERENCE.md, the man page and the packages against it.

- **Diagnose: the IPv6 experiment is "unsupported" off Linux, not
  "failed".** It reads its route context from `/proc`, so on macOS, Windows
  and FreeBSD it showed a red collector-failed row and offered `t` to run
  it. The coverage row now says "IPv6 route context is read only on Linux"
  and `t` refuses with the same text. On Linux with IPv6 disabled in the
  kernel it is "not applicable"; other read errors still fail.

### Added
- **`NO_COLOR`.** Set to any non-empty value, the TUI draws no colour in any
  view. The selection, highlighted rows and filled bars switch to reverse
  video, so what was marked stays visible. REFERENCE.md gains a section
  listing the environment variables netwatch reads.

- **Coverage-guided fuzzing.** `fuzz/` holds six cargo-fuzz targets for the
  input netwatch takes from the network: frame decode, every DPI classifier,
  TLS handshakes, QUIC Initial frames, HTTP/3 frames and body decompression,
  and the display-filter language. CI fuzzes each for 60 s on pull requests
  and 10 min weekly, keeping the corpus between runs.

### Documentation
- README gains "Without the TUI": `doctor`, `diagnose run` and its exit
  statuses, `daemon --metrics`, `--demo`, and `--remote` marked experimental.
- REFERENCE.md gains a Command line section listing every command and flag.
- CAPABILITIES.md gains a FreeBSD column and a draft of the platform tiers 1.0
  would promise. WIKI.md no longer describes a 9-tab TUI with one CLI helper.

### Changed
- **Diagnose rules without a reviewed contract are beta.** 22 of the 30
  rules have detectors but no written statement of the evidence they need
  and the healthy lookalikes they must rule out. Their issues are still
  shown, now tagged `beta` in the issue list, the detail pane, `diagnose run`'s
  text output and its JSON (`"beta": true` on the issue). **`diagnose run`
  no longer exits 1 for a beta issue alone**; pass `--include-beta` for the
  old behaviour. The JSON report gains `"include_beta"`. The 8 contracted
  rules are unchanged. `docs/diagnostic-coverage.md` lists which is which.
- Every GitHub Action in CI and the release workflow is pinned to a commit
  SHA, with its version in a comment, so a moved or compromised tag cannot
  change what builds a release. Workflow tokens are read-only by default;
  only the release, container and apt jobs, which publish, get write scopes.
- **Minimum supported Rust version: 1.95**, declared in `Cargo.toml` and
  checked by CI. It will be raised only in a minor release, with a changelog
  entry.

## [0.35.4] - 2026-10-17

### Fixed
- **Windows: no interfaces and no capture on non-English Windows.** Interface
  discovery parsed `ipconfig /all`, whose labels are translated and written
  in the console's OEM code page. On a Russian install every adapter came out
  named after its mangled header line ("Адаптер Ethernet Ethernet") with no
  address, so the dashboard showed "no interfaces up" and packet capture
  failed with "No Npcap adapter matches …". Interfaces now come from
  `GetAdaptersAddresses`, which reports names in UTF-16 and status and media
  type as numbers in any display language; ipconfig remains the fallback.
  PowerShell lookups (adapter GUIDs, statistics, default route) now ask for
  UTF-8 output, so non-ASCII adapter names such as "Беспроводная сеть" match
  across all of them.
- **Interfaces tab: the list now scrolls.** With more interfaces than rows
  (many VLANs or NICs), the selection moved off the bottom of the table and
  the list stayed put. The table now scrolls to keep the selection in view,
  like the other lists, and the cursor stops at the last row the current
  filter shows instead of running past it (#66).

## [0.35.3] - 2026-10-05

### Fixed
- FreeBSD: an interface's up-state now comes from the kernel's `IFF_UP`
  flag rather than a substring match on `ifconfig` output, and a failed or
  empty `ifconfig` falls back to `getifaddrs` instead of an empty list.
  Interfaces wrongly marked down left the dashboard's Interfaces panel at
  "no interfaces up" and its throughput chart empty, while the Stats tab
  (which reads `netstat` only) was fine (#63). Not reproduced on a stock
  FreeBSD 14.4 VM, so this hardens the likely cause.

## [0.35.2] - 2026-10-04

### Fixed
- The FreeBSD release binary is now built on FreeBSD 13.5 against the base
  system's libpcap, so it runs on FreeBSD 13 and later. It was built on the
  newest release against ports libpcap, which failed on older hosts with
  `version FBSD_1.9 required ... not found` (#63). Best-effort: FreeBSD
  older than 13 is not covered.

## [0.35.1] - 2026-10-03

### Fixed
- A connection-attribution test that intermittently failed on a loaded CI
  runner. It asserted on a single live `/proc` scan instead of polling, the
  same race the existing `proc_broker_publishes_fresh_snapshots_and_stops_with_its_owner`
  test already guards against; brought in line with that precedent.
- `packaging/rpm/netwatch.spec`'s `Version:` left at 0.34.0 in the 0.35.0
  release commit.

0.35.0 was tagged but never published: the release guard caught both issues
on the tagged commit before anything built. 0.35.1 is 0.35.0 with both
fixed; everything under 0.35.0 below ships in this release.

## [0.35.0] - 2026-10-03

NetWatch now builds and runs on FreeBSD. Interfaces, the default route, link
speed, process attribution, clipboard, and gateway/DNS all have real FreeBSD
backends instead of the silent empty fallback every other unsupported
platform got before. Verified end to end on a real FreeBSD 15.1 VM, not
cross-compiled blind: that caught a real bug in the connection-attribution
parser before it shipped.

### Added
- FreeBSD support: interface stats and info (`netstat`/`ifconfig`), default
  route detection, link speed (`getifaddrs`), process-path resolution via
  `sysctl(KERN_PROC_PATHNAME)` (FreeBSD has no `/proc` by default), clipboard
  (shares Linux's `wl-copy`/`xclip`/`xsel`), gateway/DNS, and connection
  attribution via `sockstat`.
- A `freebsd` CI job and release artifact, built and tested inside a real
  FreeBSD VM (`vmactions/freebsd-vm`), since no cross-compile path safely
  links this crate's C/asm dependencies (`pcap`, `mimalloc`, `ring`) for this
  target.

### Known gaps
- `tcp_info` (cwnd/ssthresh/rwnd) isn't implemented on FreeBSD yet; those
  columns show `--`, same as Windows today.
- Wi-Fi interface detection is implemented but unverified on real wireless
  hardware — the CI VM has none to test against.
- Not submitted to the FreeBSD ports tree, and no Capsicum sandboxing yet.

## [0.34.0] - 2026-10-01

Diagnose issues now end when they should, and moves nobody can feel no
longer start them. A slow resolver on a home router can close. An issue whose
subject went away closes as expired instead of waiting for a recovery that
cannot come, and a muted fault stays one issue. A gateway hovering at its line
stays one open issue instead of a string of recoveries. `diagnose run` exits 1
only on an issue, and its JSON is now schema 2, which breaks scripts that read
info findings or `passed`. The gap 0.33 listed is closed: every rule whose
open or close changed since 0.32 has a pinned episode in which it opens and
closes, apart from `iface.errors` on Wi-Fi.

### Changed
- **Breaking:** `diagnose run --format json` is now schema 2. `issues` holds
  issues only, a new `observations` array holds the rest, and each finding
  carries a `kind` of `issue` or `observation`. Checks carry `state`, and
  `why_not` when they did not run. `passed` is no longer written anywhere,
  including recordings and exports. Scripts that read info findings from
  `issues`, or `passed` from checks, need updating. Older recordings still
  load, but 0.33 and earlier cannot read one made by this release.
- Info findings are now Observations: a symmetric NAT, a route change that
  added 20 ms or less, a receiver-limited socket, or a target that fails for
  reasons that are not the network's. Diagnose still lists them, but the
  status line on every tab counts only issues. A host whose only findings are
  Observations reads "no issues" (learning or limited) instead of "1 issue",
  and the report's summary counts observations separately instead of calling
  the host "nominal with notes".
- `diagnose run` exits 1 only on an issue. An observation is listed under its
  own heading and leaves the exit status at 0.
- `diagnose run --target api` now exits 1 when the target's service fails: an
  HTTP 503, a refused port or a name that does not exist. It reports this as a
  medium issue marked "service, not network", and the Diagnose tab still
  lists it as an observation. The run also keeps the gateway, interface and
  resolver issues that could lie on the target's route, so a gateway failure
  that hides the target's own finding no longer exits 0. `--target` can
  therefore exit 1 while the target itself is healthy, if an issue such as
  weak Wi-Fi, a gateway RTT spike or local bufferbloat is open. A script that
  uses it as a service health check should look at which subject is in
  `issues`. A target on loopback keeps only an issue that hides its own
  finding, and a target never probed inside the budget still exits 2.
- Diagnose no longer calls a move nobody can feel a deviation. Every
  baseline's σ is now at least 0.5 ms, or 5% of its mean if larger. A
  resolver that answers from cache in 1.2 ms, give or take 0.05 ms, now needs
  2.7 ms to reach 3σ, where 1.35 ms did before. The Dashboard's latency tiles
  and Diagnose evidence show the floored σ, so a slow target stage no longer
  reports its baseline as "σ0". Baselines also learn against it, so ordinary
  jitter on a quiet link is no longer held out as an outlier. Setting
  `sigma_floor_ms` and `sigma_floor_pct` to 0 restores the raw σ.
- DNS and gateway issues open later. `gateway.rtt_spike` also needs the
  gateway at least 10 ms slower than its baseline, and `dns.slow_resolver`'s
  baseline test needs the median at least 5 ms slower than its baseline and
  at least twice it. A LAN resolver going from 1.2 to 2.7 ms, or a wired
  gateway from 2 to 9 ms, no longer opens an issue. Its Dashboard tile can
  still turn red, and says no issue was raised. The 100 ms DNS ceiling still
  opens with or without a baseline.
- `gateway.rtt_spike`, `path.rtt_spike` and `target.slow_stage` still open at
  3σ, but now close only once the metric has stayed under 2σ
  (`sigma_close_k`) for the verify hold. Noisy links take longer to close. A
  `sigma_close_k` at or above `sigma_k` is replaced and logged, and a
  `sigma_k` of 2 or less brings the default close line down to two thirds of
  it, with a warning.
- An issue keeps the close condition it opened or reopened with, so a close
  line worked out from the metric no longer moves with the value it judges.
- The engine setting `auto_close_secs`, which nothing ever read, is now
  `expire_after_secs`, default 60 s: how long what an issue is about must
  stay gone before the issue expires. Recordings that use the old name still
  load.
- Recordings now store the configuration each sample ran with: the system
  resolvers, the enabled targets and their revisions, the trace target and
  interval, and the interfaces. A resolver or interface list the platform
  returned empty is recorded as unknown, not as "none". `diagnose run`
  records periodic tracing as off, because it never traces on a timer. Older
  recordings load as "configuration unknown", and redacted exports hide
  target names and revisions.
- The coverage document no longer says `gateway.unreachable` fires on a
  failed ARP or ICMP probe. netwatch sends no ARP, and the rule needs ICMP and
  the TCP fallback to the gateway to fail, and the internet probe too.
  `link.down` now says where each OS's "down" comes from. On macOS it is the
  admin `UP` flag, so an unplugged cable on an interface still configured up
  is not reported yet.

### Added
- Diagnose thresholds can be set in `config.toml` under
  `[diagnose_thresholds]`, for example `dns_ceiling_ms = 30`. Keys left out
  keep their defaults. The engine used to ignore anything set there and
  always ran on the built-in numbers. A value that cannot mean anything, such
  as a σ multiple of 0 or less, `consecutive_n = 0`, a percentage outside
  0 to 100, a negative σ floor, `nan` or `inf`, falls back to its default
  with a warning in the log, and `diagnose run` and `diagnose coverage` print
  the warning to stderr too. The keys new in this release are `sigma_close_k`,
  `sigma_floor_ms`, `sigma_floor_pct`, `gateway_delta_floor_ms`,
  `dns_delta_floor_ms` and `dns_delta_multiple`. A recording made before a
  threshold existed replays with that threshold at its default, so one from
  0.33 is judged against floors it ran without.
- A closed state, `expired`, for an issue whose subject went away. Diagnose
  closes an issue as "expired, evidence gone" only after what it was about
  has been gone for 60 s: the socket closed, the target left the config or
  its entry changed, the resolver left the system list, the periodic trace
  moved to another target, or the platform stopped listing the interface and
  the collector no longer reads it. An expiry is never a recovery. A step
  carried out before one reads "closed without a measurement", not
  "recovered". An expired condition that returns within 30 minutes reopens
  the same issue with its count.
- "stale since HH:MM:SS" on an open issue whose evidence stopped arriving, in
  the tab and the report. The issue stays open, so a gateway that can't be
  probed because ICMP is blocked no longer risks closing a real outage.
  netwatch reads sockets only in the Dense view and under `diagnose run`, so
  socket issues expire there; in the Full and Lite views they go stale
  instead, until a later release reads sockets in every view. `diagnose run
  --format json` findings carry an optional `stale_since`, and a socket issue
  whose socket closed a minute or more before the run ended no longer counts
  toward the exit code.
- The pinned replay corpus lists its episodes in
  `tests/diagnose/corpus/manifest.toml`, and `netwatch diagnose corpus --only
  ID` regenerates one. It now pins an open→close episode for each rule whose
  open or close changed since 0.32: a router resolver, a gateway spike and a
  gateway hovering at its line, a lost carrier, a weak Wi-Fi signal, a path
  RTT spike and a slow target stage that close only under the 2σ line, and
  three socket issues that expire a minute after their socket closes. An
  unknown carrier is pinned too, and opens nothing. A test fails unless every
  such rule opens and closes in a pinned episode or is listed with the reason
  it can't close yet, and another fails when a synthetic episode is no longer
  what its scenario in `fixture.rs` records.
- Pinned decisions record why each issue left the list (`close_reason`):
  auto-closed, expired, resolved, muted, suppressed, or pruned when the
  history limit dropped it on the tick it closed. An expiry, a suppression
  and a verified fix no longer pin the same way. Decision files without the
  field still load.
- A test that fails when a rule's trigger text quotes a number its detector
  does not judge with, or leaves out one it does.

### Fixed
- Enter in Settings loads the row you are on again. Since 0.29 added the
  View row, the edit box filled with the next row's value, so accepting GeoIP
  DB Path unchanged saved the ASN database path as `geoip_db`.
- A slow-resolver issue on a router never closed. It needed the median under
  a flat 5 ms, which a router answering in 10 ms never reaches, so the issue
  stayed open until netwatch restarted. It now closes against a line set when
  it opens: 0.8 of the line it opened on, or 2σ above the resolver's mean if
  that is higher, held for 60 s. With no baseline it closes under 0.8 of
  `dns_ceiling_ms`, which is 80 ms by default. On a resolver whose normal
  range reaches the ceiling, the issue closes once the median has stayed
  under the ceiling for 60 s.
- Muting a Diagnose issue (`m`) filed a second, identical issue while the
  fault continued, and the muted one was drawn and reported as fixed. A muted
  issue now stays one issue, and the mute ends on time an hour later,
  including when that hour is the one the clocks go back. The chronology
  shows `◌ muted until 07:48` in the muted colour, the verdict row and the
  report summary add "· 1 muted", the report lists it under Muted findings
  instead of Retained closed findings, and the status after `m` names the
  time the mute ends. A muted issue can still auto-close or expire, and a step
  marked done before the mute is no longer credited with a recovery.
- Muting a root cause let its consequences out from under it, so a symptom
  such as a slow resolver headed the verdict for the hour. They now stay
  under it. A mute that ends while the fault continues is recorded as one
  incident and replays as one, not two.
- An Observation no longer hides an issue. A route change that added 20 ms or
  less used to take a path RTT spike on the same path out of the list. A
  route change that adds more than 20 ms is still an issue and still explains
  the spike.
- Recorded episodes serialize the same way on every run. Issue snapshots and
  baseline metrics came out in a different order each time, so regenerating
  the corpus changed its files even when no decision had changed.
- Recordings and `baselines.json` read their numbers back exactly. A replay
  used to start from a baseline up to one bit off the one the live engine
  judged against.
- Editing a `[[diagnose_targets]]` entry while the target kept failing the
  same way left the old issue open for good. The new result merged into it
  and replaced the revision it was found under, so it never expired. It also
  kept its mute, its applied steps and its close condition, now pointing at
  an endpoint nobody had diagnosed. A target's issue now belongs to the
  revision it was found under. The old issue expires 60 s after the edit.
  The edited entry opens its own issue once its own probes confirm the
  fault, unmuted and with no history. Changing the entry back within 30
  minutes of that expiry reopens the old issue with its count. Recordings
  now name a target's issue by rule, name and revision. A recording made
  before this change gets the same names when it loads, so its labels, test
  results and actions still find their issue. The exception is an issue it
  recorded under two revisions, which is this bug. That issue keeps its old
  name, `diagnose replay` shows it as divergent, and its labels and test
  results drop out of `diagnose features` and the history.

### Known gaps
- `iface.errors` can open on a Wi-Fi driver's background drops, 70 a minute
  in the pinned episode, and then never close, because it closes only under
  one error or drop a minute combined. It is the one rule changed since 0.32
  whose pinned episode stays open.
- The close line of a slow-resolver issue does not follow the baseline. An
  issue whose median settles between its close and open lines stays open
  until netwatch restarts or the resolver leaves the config.

## [0.33.0] - 2026-09-29

Diagnose stops reading what it did not measure as evidence. A check that
could not run now says why instead of passing, a probe that sent nothing no
longer counts as an answer, and nothing Diagnose draws is green until it has
earned it. A lab that runs the real engine against a network it controls now
checks, in CI, that DNS, gateway and path findings open and close when they
should.

### Changed
- Diagnose checks that could not run now say why. Each carries a `why_not`
  from the words the coverage view already uses: `not_measured`,
  `not_implemented`, `awaiting_test`, `not_applicable`, `unsupported` or
  `learning`. Each also has a `state` of `passed`, `failed` or `not_run` next
  to `passed`. `diagnose run --format json` only gains fields, and older
  recordings still load.
- The Diagnose tab's check lines, the text output of `diagnose run` and the
  Markdown report give that reason in place of a blanket "not measured"
  ("awaiting test: link-level bufferbloat test passed"). A test nobody has
  run, a probe netwatch has never had and a sample that has not arrived no
  longer read the same. Redacted exports keep the reason even though they
  clear the detail.
- A timing stage a target does not have, such as TLS on an `http://` target,
  reads as not applicable rather than waiting forever for a baseline. So does
  a reference resolver's answer that came back without AD. The clock-offset
  check reads as unsupported on macOS and Windows, where netwatch does not
  read the NTP status.
- The resolver step no longer promises a write. It said netwatch "writes
  resolv.conf, keeps a backup, and puts it back on quit", but live ↵ wrote
  nothing and recorded "not applied". The step now appears only for an
  alternate resolver that was measured: for a slow resolver, one that
  answered in under a quarter of its median, and for a failing one, one that
  answered at all. It gives the measured time and the command to run (`sudo
  netwatch resolver set <alt> --unmanaged`, or `resolvectl dns <iface>
  <alt>`). netwatch does not time an alternate resolver on a live host yet, so
  for now only the demo shows the step. Live mode no longer offers ↵ at all,
  and Enter says to run the command shown. The demo still offers and
  simulates the switch. The unused `apply_file_edit` and `make_permanent`
  helpers are gone.
- An incomplete verdict is no longer drawn with the green ● of health. The
  Diagnose tab reads `◌ no issues found · …` in muted text, the header shows a
  muted `◌ no issues`, and `y` copies the words on screen. No verdict
  Diagnose can reach today earns green, so nothing is drawn green.
- The feature schema hash changed from `a3141086556720b1` to
  `e476c3f5ae717da6`. `ml/schema.json` gained two check columns,
  `check.dns.slow_resolver.local_udp_path.local_drop_counters` and
  `check.tcp.retrans_burst.packet_loss.socket_rtt_below_queueing_line`, so
  `netwatch_ml.load` refuses feature files exported by 0.32. Export them again
  with `netwatch diagnose features`.

### Added
- A headless lab driver, `examples/diagnose_lab`, runs the real `App::tick`
  once a second and prints one JSON line per tick: the verdict, what each
  health probe measured and against which address, and every tracked issue
  with its state, closed ones included. It refuses to start unless its home,
  cache, config and state directories are inside a temp home the lab created.
  `--seed` gives the gateway, DNS and path baselines ready values before the
  first tick, so a recorded episode replays against the same baselines. A
  seed that can't be applied stops the driver instead of leaving those rules
  learning.
- `tests/diagnose/health_lab.py` gives Diagnose a network it controls. A peer
  namespace owns 1.1.1.1, a temp `resolv.conf` names the lab gateway, and
  sysfs is remounted so interface rules read the lab's interfaces, not the
  host's. The lab keeps its own `resolv.conf` when the host's systemd-resolved
  rewrites its file mid-run. It drives the real engine through a slow, dead
  and lossy resolver, total gateway loss, ICMP delay at the gateway, delay
  beyond it, and a healthy link. It asserts what opens, what is listed under
  what, what closes and when, and that a scenario expecting nothing kept its
  rules measured throughout. `--quick` runs in the CI workflow the release
  guard waits on, on every push to main and on pull requests that touch
  Diagnose. The 20-minute quiet-loss negative runs weekly. A run that hangs is
  killed 60 s past its length, and a killed or timed-out run takes its
  namespaces and resolvers with it.
- Tests that hold Diagnose to the above. The pinned replay corpus now carries
  health-probe times, so it sees DNS and gateway decisions. It was re-recorded
  at the new 100 ms DNS ceiling, and the fixture's slow resolver is pinned: it
  opens at 06:48:20 on its baseline, with the upstream forwarder as the top
  cause. `iface.errors`, `iface.saturated` and `tcp.retrans_burst` each have
  tests that fire at today's thresholds and stay quiet just below them. One
  test lists every input Diagnose can leave unmeasured and fails if a
  detector reads one as evidence.
- The README says how to report a Diagnose misread, and asks for the output
  of `netwatch diagnose run --format json`.

### Fixed
- "100% loss" on a fresh start, and on any host where ICMP is blocked and
  the gateway answers no TCP port. The prober started every series at 100%
  and reported 100% when a probe could not be sent at all, so the dashboard
  tile, Lite's verdict line, the dense view and every export read a working
  network as dead until the first probe landed, or for good without
  privileges. Loss is now a three-state value: pending, unmeasured with the
  reason ("icmp is blocked here and the gateway answers no tcp port", "the
  resolver address is not usable by the probe"), or measured. Unmeasured
  probes no longer enter the rtt history, so Diagnose sees no observation
  rather than a dead gateway or a resolver failing 100% of queries. The
  incident report, AI Insights, the remote payload and the metrics endpoint
  carry "unmeasured" or `null` instead of `100`.
- Diagnose findings that read an input nobody measured as evidence:
  - `dns.slow_resolver` blamed the local UDP path on nothing. With no
    alternate resolver probed, "the alternate is also slow" passed, and one
    dropped frame a minute counted as interface drops, so a Wi-Fi laptop got
    "local: conntrack, udp buffers or nftables · strong". The alternate check
    now shows as not measured when there is no alternate, and the drops check
    needs the same 60/min floor as `iface.errors`. Until netwatch reads the
    kernel's UDP and conntrack drop counters, that cause can reach Likely at
    most, never Strong.
  - A socket whose RTT was never measured was treated as a 0 ms socket. It
    can no longer open `tcp.bufferbloat_remote` or give it RTT evidence. A
    retransmit burst on such a socket still opens, but its "rtt below the
    queueing line" check shows as not measured, so the cause stays at Likely.
  - An idle Wi-Fi link read as 0% retries. Under 1,000 frames a minute there
    is no retry share, and `retries_high` gives that as the reason it did not
    run instead of saying there is no retry counter. With no signal level
    either, `wifi.weak_signal` coverage says its inputs were not measured.
  - An interface the platform gave no info for read as "carrier up, wired".
    `link.down` and `wifi.weak_signal` now report not measured, and an open
    `link.down` no longer closes as fixed when the interface's info
    disappears.
  - macOS counts no interface drops (`netstat -ibn` has no drop column), and
    Diagnose read that as 0. There, `iface.errors` now judges errors alone
    and ranks a bad cable or duplex mismatch as the probable cause, not a
    small ring buffer. Its drop checks and `local_udp_path`'s
    `interface_drops` report `unsupported`, and recordings carry
    `"drops_per_min": null`.
  - `netwatch diagnose run` exited 0 ("the rules that could be evaluated
    were") on a host where ICMP is blocked and the gateway answers no TCP
    port, because a gateway probe that sent nothing still counted as
    evidence. It now exits 2 (incomplete) unless a gateway or resolver was
    actually measured or a target probe completed.
- On a systemd-resolved host `dns.slow_resolver` times the local stub, which
  answers root NS from its cache in 0 ms, and nothing said so. Coverage now
  reads "limited: measures the local stub at 127.0.0.53, not the upstream", a
  finding's scope says the same, and checks that would need the upstream
  show as not measured.
- Diagnose verdicts that were wrong for reasons no better model would fix:
  - `dns.failing` read an ICMP probe that has never run on the live path as
    "no reply", so every failing resolver ranked as *down*. A check that was
    not made now shows as not run for both causes, and the ranking says so.
  - `dns.slow_resolver`'s first-run ceiling was 20 ms, inside the normal
    range of ISP and mobile resolvers, so a first run on such a network opened
    a finding with no baseline behind it. The ceiling is now 100 ms; anything
    below that waits for the 3σ baseline test. The catalogue text matches.
  - The `dns.rtt_p50` baseline was learned from the latest single probe while
    the rule judged the rolling p50 of the probe history, two different
    statistics under one name. The baseline is now fed the p50 it is asked
    to judge, and only from a cycle that got a reply. The history still holds
    the replies from before an outage, so a silent resolver used to keep
    feeding its baseline the old timings.
  - `tcp.bufferbloat_remote` opened at Medium on any sending socket with rtt
    ≥ 100 ms even when no loaded-rtt test had placed the queue. It was already
    retitled "side unmeasured" in that case; it is now Info as well, since an
    unplaced queue is a reason to run the test, not a fault.
  - The link, saturation and socket detectors read `Thresholds::default()`
    instead of the engine's thresholds, so tuning the engine did not reach
    them. They take the engine's thresholds now.
  - `tcp.retrans_burst`'s catalogue trigger described a 3σ-over-baseline test
    the code does not implement; it now describes the absolute test it does
    (5 or more retransmits per minute on a socket under the queueing rtt).
  - `path.rtt_spike` never opened or closed while periodic traces ran. Each
    new trace cleared the last one's path for a tick, which restarted both
    the confirmation and the verify hold. The previous trace now stands until
    its result is 120 s old.

### Known gaps
- No recorded episode shows a finding opening and then closing. The pinned
  corpus's three findings all stay open to its end, so the replay test cannot
  catch a change in when a finding closes, and no rule this release touched
  has an open-to-close episode behind it. The health lab checks the closes of
  the DNS, gateway and path rules it drives. An open-to-close episode for
  every touched rule is a condition of 0.34.

## [0.32.5] - 2026-09-27

### Fixed
- A metrics test that failed on macOS. macOS answers `setsockopt` with
  `EINVAL` on a socket whose peer has already closed, and the slow-client
  test set its read timeout after the server had hung up.

0.32.4 was tagged but never published: the new release guard saw that test
fail on the tagged commit and stopped the release before it built anything.
0.32.5 is 0.32.4 with the test fixed; everything under 0.32.4 below ships in
this release.

## [0.32.4] - 2026-09-27

A security release. Text a peer chose could drive your terminal, traffic a
peer sent could grow netwatch's memory without limit or stop capture, and
other users on the machine could read what netwatch saved. One change needs
action before you upgrade: netwatch now refuses to start with an `http://`
remote URL. Point it at `https://`, or add `--insecure-remote` to the command
line or service unit.

### Fixed
- Text that someone else chose can no longer drive your terminal. An SNI,
  HTTP Host, DNS name, SSH banner, PTR record, whois or geo reply, process
  name or interface name reached the screen raw, so a ClientHello with SNI
  `ESC ]52;c;… BEL` wrote the viewer's clipboard, and a right-to-left override
  could make one hostname read as another. Control, bidi and zero-width
  characters now show as `·`, both where the text is collected and in every
  drawn frame.
- A packet that makes a parser panic no longer stops capture without a word.
  The capture thread died while the header still said it was capturing, and
  if it died holding the stream table, the connection list stopped updating
  and opening a stream crashed netwatch. Capture now stops with `Capture
  stopped: internal error: …` in the Packets header, and the rest of the app
  carries on. The panic report goes to the log file. Rust used to print it
  over the screen, along with any packet bytes it quoted.
- Traffic someone else sends can no longer make netwatch's memory grow
  without limit. Every spoofed source address queued a reverse-DNS lookup, a
  small compressed HTTP/3 body could inflate to gigabytes, captured streams
  could hold 2.5 GB between them, and a `--metrics` client that sent its
  request a byte at a time kept a thread for as long as it liked. Reverse DNS
  now resolves only the addresses in this host's own connections, from a
  bounded queue and cache. HTTP/3 bodies stop at 4 MiB and are marked
  truncated, and brotli is tried only when the response says
  `content-encoding: br`. Streams share a 256 MiB budget and the least
  recently active go first. The metrics endpoint reads at most 8 KiB within
  5 s per request, serves 16 clients at once, and warns at startup when it is
  reachable from the network. Remote, geo and whois requests now time out
  when a server stops answering.
- Less of what netwatch saves or sends can be read by someone else. Pcaps
  and incident bundles were written 0644, and without the sandbox the exports
  directory was 0755 too, so anyone on the machine could read the packet
  bytes, addresses and process names in them. The directory is now 0700 and
  those files 0600 with or without the sandbox, and an exports directory an
  earlier run left open is narrowed. An `http://` remote URL sent the API key
  and every snapshot in cleartext; netwatch now refuses one and exits unless
  `--insecure-remote` is given. `--help` now marks `--api-key` as
  discouraged, since any user on the host can read it in `ps`; set
  `NETWATCH_API_KEY` instead. Online geo lookups (`geoip_online`) stay
  cleartext, because ip-api.com has no HTTPS on its free tier, and `doctor`,
  Settings and the config reference now say so.
- A release no longer goes out from a commit whose CI failed. 0.32.2 and
  0.32.3 both reached every channel from red commits, because the release
  workflow started on the tag push and never asked CI. It now waits for CI on
  the tagged commit and builds nothing unless CI passed. It also refuses a tag
  that differs from Cargo.toml's version or has no section in this file.
  `scripts/release.sh X.Y.Z` makes the release commit and tag locally, with
  the version bumped in Cargo.toml, Cargo.lock, the RPM spec and this file.

## [0.32.3] - 2026-09-20

### Fixed
- The macOS build's lints: an explicit `drop` of the eBPF event source, which
  is a stub with no `Drop` on non-Linux, failed `clippy -D warnings` there.
- The RPM spec's version, which 0.32.2 shipped still reading 0.32.1. COPR
  builds from the spec rather than from Cargo.toml, so that release's COPR
  package would have carried the previous version's number.

Everything below shipped in 0.32.2, whose CI was red for the two reasons
above; 0.32.3 is that release with them fixed.

## [0.32.2] - 2026-09-20

### Added
- `netwatch diagnose run [--target NAME] [--budget 30s] [--format json]`: one
  bounded diagnosis with documented exit statuses — 0 no finding, 1 finding,
  2 incomplete, 3 error. Exit 2 exists so a run that gathered nothing cannot
  be read as a healthy host.
- The Diagnose detail pane draws the recent samples behind an issue's headline
  metric, with the samples above the rule's threshold coloured, so a spike that
  has passed reads differently from one still climbing.
- `netwatch diagnose coverage --doc` generates `docs/diagnostic-coverage.md`
  from the rule catalogue, and `netwatch diagnose corpus` regenerates the
  pinned replay corpus. Tests fail when either drifts from the code.
- A CI job runs the Diagnose fault lab in an isolated namespace on every push.
- The Egress tab shows how long since each process was last heard from, and
  `H` toggles the programs seen only in earlier sessions, which are hidden by
  default. Profiles persist as the drift baseline, so the tab used to open on
  every program ever observed on the machine.

### Changed
- eBPF process attribution runs under the sandbox instead of being refused by
  it. The worker enters with the filesystem policy applied, loads with the
  capabilities the load needs, drops them, and only then reads an event. The
  SDK's own reader thread inherits the filesystem policy but keeps its
  capabilities until the SDK offers an entry hook; that residual is recorded
  against the `ebpf-reader` component rather than left unsaid.
- The Diagnose detail pane fills the page. An incident is what the tab is for,
  and the pane used to stop at its last sentence.
- The dashboard timeline moved under interfaces in the right-hand column, so
  the connections table keeps the six rows the full-width strip was taking. A
  layout too narrow for that column keeps the strip.
- Diagnose no longer reports conclusions its evidence cannot support: a hop is
  only blamed for loss that was observed to propagate, receiver-side
  bufferbloat requires the loaded/idle comparison that places the queue, and a
  cause whose discriminating check never ran cannot read as `strong`.
- Confirmation and recovery are scoped per target: a target probed every ten
  seconds can no longer confirm or close an issue about one probed every five
  minutes.
- Closing an issue by hand is recorded as such rather than as a measured
  recovery credited to the last remediation step.
- Suppression follows demonstrated dependency: a gateway failure no longer
  demotes a target reached over a tunnel, and a resolver failure only explains
  targets that resolved through it.
- A target probe tries every resolved address rather than only the first, so
  one dead address in a DNS answer no longer reports a working service as down.
  The HTTP `Host` header now carries non-default ports and brackets IPv6
  literals.
- The throughput chart gives each direction its own scale when their peaks are
  more than 20× apart, with both axis labels shown; otherwise the shared scale
  is kept.
- A dashboard tile that alarms without a matching Diagnose finding says "no
  issue raised" rather than contradicting the "no issues" verdict beside it.
- Muted text in the nord, dracula, solarized and sky themes, and the severity
  red in sky, now meet WCAG contrast against their backgrounds; a test keeps
  them there.

### Fixed
- Dense-view saturation labelled its ceiling `0 Mb` for any link under a
  megabit, because the formatter divided integers by a million. It now reads
  in Gb, Mb, Kb or bits. Wi-Fi shows this most: the kernel reports no link
  speed, so the ceiling is the measured peak.
- An ARP probe that never ran is reported as unmeasured instead of as a failed
  ARP reply. Unprivileged runs printed "no arp reply from the gateway" on every
  gateway finding.
- Split-horizon DNS is no longer ruled out by its own signature: a private
  answer for a public name supports it rather than refuting it.
- An inconclusive re-run of a diagnostic test retracts the previous answer
  instead of leaving the superseded one ranking causes.

### Added (packaging)
- `cargo binstall netwatch-tui` fetches the release binary instead of
  compiling, so it needs no Rust toolchain build and no libpcap headers.
- A Fedora COPR repository: `sudo dnf copr enable matthart1983/netwatch`.
- An apt repository at <https://matthart1983.github.io/netwatch/apt> for Debian
  and Ubuntu (amd64 and arm64), signed and updated on each release, so the
  packages upgrade with `apt upgrade` instead of being downloaded by hand.

## [0.32.1] - 2026-09-20

### Added
- `.deb` and `.rpm` packages for x86_64 and aarch64 on every release, built
  from the same static binary as the tarball. They install the binary, the
  shell completions, the man page and the agent unit, depend on nothing, and
  print the `setcap` command rather than granting capabilities themselves.
- A multi-arch container image, `ghcr.io/matthart1983/netwatch`, built from the
  release binary on Alpine (~26 MB). It carries `ss`, `ip`, `ping` and `iw`,
  which netwatch shells out to; run it with `--net=host --pid=host
  --cap-add=NET_RAW`. Capture needs a rootful container.
- An RPM spec (`packaging/rpm/netwatch.spec`) for a Fedora COPR build from
  source against the system libpcap, and `docs/PACKAGING.md` describing every
  channel and the per-release steps.
- Releases ship a `SHA256SUMS` file and signed build provenance for every
  artifact (`gh attestation verify <file> -R matthart1983/netwatch`).
- Shell completions for bash, zsh and fish in `completions/`, and a man page at
  `docs/netwatch.1`. A test fails if an option is added to the parser without
  being added to both.

### Changed
- `brew install netwatch` now comes from homebrew-core, which Homebrew's
  autobump updates within hours of each release. The formula in
  `matthart1983/homebrew-tap` is deprecated and no longer updated by the
  release workflow; existing installs keep working.

### Fixed
- The crates.io publish step recognises cargo's current "already exists on
  crates.io index" wording, so re-running a release no longer fails there.
- Windows builds delay-load `wpcap.dll` in test executables as well as the
  app, so the test binary no longer needs Npcap present to start.

## [0.32.0] - 2026-09-19

### Changed
- **Egress alerting is blocked-only by default.** Alerts, and the Diagnose
  `egress.policy_violation` rule, now fire only for destinations you block
  explicitly in `egress-policy.toml`. Allowlist drift, undeclared processes under
  `strict = true` and new destinations stay visible in the Egress tab but no
  longer alert. Set `alert = "all"` at the top of the policy to restore the old
  behaviour; the Diagnose `egress.drift` rule is off unless you do.
- The status line under the tab bar reads `● no issues` (or `◌ no issues ·
  learning`) instead of the Diagnose coverage breakdown.
- The Diagnose tab shows one short panel when nothing is open, plus a "needs
  attention" panel for broken collectors and the session's history only when
  they have something in them. The engine strip, rule catalogue and report
  preview are gone from the working view; `o` still opens the full report.
- `report.md` renders issues, evidence, cause checks, the timeline and the
  environment as tables. It lists only the checks that could not run, and a
  report with nothing open is a single summary sentence.

### Added
- `[block]` (every process) and `[process.<name>.block]` tables in
  `egress-policy.toml`: `sni` (exact or `*.` wildcard), `asn`, `ip` (address or
  CIDR) and `ports`. A match is a `✗ blocked` verdict that outranks any allowlist
  match, sorts first in the Egress tab and exports as `"blocked"`. Promoting a
  baseline keeps hand-written block tables.
- Diagnose active experiments (IPv6 reachability, captive portal, path MTU),
  developer target probes (`[[diagnose_targets]]`: DNS, TCP, TLS and HTTP
  stages), namespace TCP accounting and egress rules. See `docs/DIAGNOSE.md`.
- Incident episodes are recorded and can be replayed, labelled and exported as a
  pseudonymised bundle (`netwatch diagnose episodes | replay | export`).
- After a manual fix, Diagnose suggests the next test and verifies recovery.
- Diagnose coverage (`9`, then `c`) is a scrolling table grouped by area, with
  coloured statuses and a detail panel for the selected check.

### Fixed
- Baselines no longer learn an ongoing incident away, and an issue needs
  consecutive samples before it opens.
- Scope counts are pluralised correctly ("1 destination", "1 flow").

## [0.31.4] - 2026-09-14

0.31.3 was tagged but never published: its release build failed. Everything
listed for 0.31.3 ships in 0.31.4.

### Fixed
- Linux process attribution works with worker confinement on. Since 0.31.0 the
  Landlock-confined connection worker could not read other processes'
  `/proc/<pid>/fd`, so `ss -p` and the procfs fallback attributed nothing and every
  socket showed as unattributed. A socket-ownership broker thread now starts before
  confinement and scans only kernel procfs tables; the confined worker applies its
  snapshot when it is under `MAX_MATCH_AGE` and the socket inode still matches the
  5-tuple. Identity checks compare start token always and executable/namespace only
  where the checking thread can read them, so PID reuse is still rejected. Sockets
  owned by other users remain unattributed without privilege.
- The armv5te release build runs inside its container again. An apostrophe in a
  comment ended the single-quoted `bash -c` script early, so the build steps ran
  on the host runner and the 0.31.3 release stopped before publishing.

## [0.31.3] - 2026-09-14 (not published)

### Added
- `netwatch-linux-armv5te` release binary for Debian armel on Marvell Kirkwood NAS
  boxes such as the Iomega ix2-dl. libpcap is statically linked; the binary needs
  Debian 12 (bookworm) or newer with `libatomic1`. Built in a bookworm container,
  whose 32-bit time_t `pcap_pkthdr` layout matches Rust's; the build fails if the
  layout changes. CI now runs `cargo check` for armv5te on every push. (#54)

### Fixed
- Captured packets whose `caplen` exceeds the snap length are skipped before their
  data is read. (#54)

## [0.31.2] - 2026-09-12

### Added
- Per-connection attribution evidence with observation time, process/flow identity,
  unknown reasons and separate event corroboration. Connections, Processes and
  Egress display flow and payload-byte coverage independently of backend readiness.
- Independent-process Linux TCP/UDP IPv4/IPv6 polling matrix and deterministic
  identity/freshness regressions. Broader capture/platform acceptance remains open.
- `netwatch doctor` and `doctor --json` report setup capabilities without starting
  collectors, contacting endpoints or changing recovery state. Optional
  `--check-capture` opens/configures/closes capture in a subprocess with a five-second
  deadline and reports its protection scope. CLI validation rejects missing values
  and conflicting options before startup; existing daemon and view aliases remain.
- A shared capability model supplies live startup/Settings summaries and doctor
  reports, distinguishing unchecked, unavailable, disabled, degraded and stale data.

### Fixed
- Linux attribution validates protocol, socket inode, process start and namespace;
  ambiguous and expired startup matches stay unknown. Destination-only eBPF and
  PKTAP hints cannot overwrite polling owners. Cache freshness is checked on read.
- New observed capture generations reset tuple state and rate baselines. Process
  totals and CPU sampling no longer rely on PID alone. Platforms without process
  start identity retain unverified polling names and omit unverified CPU values.
- Unix recovery stores explicitly release their lock on owner drop, preventing a
  concurrently inherited descriptor from delaying the next writer's acquisition.

## [0.31.1] - 2026-09-12

### Added
- Explicit Linux resolver authority commands (`resolver status`, temporary `set`,
  and `recover`) for administrator-confirmed unmanaged regular files. A shared
  root-owned lease/store, identity/digest checks and durable records protect
  cooperating transactions. Managed/symlink/platform adapters remain unavailable;
  TUI/daemon automatic edits stay disabled. Privileged VM acceptance is pending.
- Recovery store v2 in durable application state: versioned operation records,
  UUID backups with SHA-256 verification, Unix synced atomic journal replacement,
  and an OS-backed store lock. Live startup inspects both v2 and legacy evidence.
  The generic per-user store does not authorize resolver changes; the Linux
  authority command uses its own fixed shared store. Windows writes remain unavailable.

### Fixed
- TUI and daemon share recovery inspection, worker startup/readiness, sandbox
  application and initial polling. Legacy journal entries no longer trigger
  automatic startup/shutdown writes based on unverified paths or reused PIDs.
  Both modes preserve unresolved recovery and report why it needs manual review.
- Demo shutdown no longer saves simulated baselines to the host.
- A QUIC Initial packet whose declared `Length` was shorter than the
  packet-number field it implied crashed the capture thread on one crafted
  datagram (start-past-end slice). A CRYPTO frame with a large declared
  offset could abort the whole process via an unbounded `Vec::resize`. Both
  are now rejected as unparseable instead.
- `egress-profiles.json` (the learned process-to-destination baseline) was
  written at umask permissions; it now matches the egress policy file next
  to it at owner-only (`0600`).
- **The Linux release binary now ships static-only**
  ([#53](https://github.com/matthart1983/netwatch/issues/53)). Releases used
  to publish two Linux x86_64/aarch64 binaries — a dynamically-linked one
  needing the host's own libpcap, and a musl-static one bundling it — with
  nothing on the releases page or in the README saying which to pick. A
  minimal distro or container without libpcap preinstalled would download
  the dynamic one (the more obviously-named of the two) and fail with
  `libpcap.so.0.8: cannot open shared object file`, the same failure mode
  as the long-since-fixed #8. The static build already solved this; it just
  wasn't the only option. `netwatch-linux-x86_64` and
  `netwatch-linux-aarch64` are now the static builds themselves — the
  dynamic glibc targets are no longer built, and the `-static` suffix is
  gone because there is no longer a choice to disambiguate. A download
  script pinned to the old `-static` asset names needs the suffix dropped.

### Security
- Online GeoIP lookups (`http://ip-api.com`, used when no MaxMind database
  is configured) are now off by default behind a new `geoip_online` config
  key. Previously every public peer IP a connection or packet touched was
  sent to ip-api.com in cleartext with no opt-out; install a MaxMind
  `.mmdb`, or set `geoip_online = true`, to keep GeoIP lookups working.

## [0.31.0] - 2026-09-11

### Fixed
- RTT timeline tracks and spike events use recorded probe completion times.
  Missing or expired RTT readings show only the horizontal baseline, matching
  throughput. Subsecond refresh intervals no longer stretch the time scale.
- Diagnose no longer treats missing verification data as recovery or an empty
  issue list as proof of health. Stale observations are excluded; cached samples
  cannot complete a recovery hold or repeatedly train health baselines.
- Diagnostic reports retain closed findings and include runtime input coverage.
  Seven catalogued rules without Diagnose integration are now explicitly planned.
- Remediation failures after a target write now carry a recovery-required outcome
  with the operation and backup, instead of claiming the host is unchanged.
  Partial writes and unreadable recovery targets are not treated as successful
  recovery. UI details and Markdown/JSON reports preserve the outcome.
- Invalid, unsupported or unreadable journals are preserved and block subsequent
  writes, including shutdown persistence. Journal persistence failures are visible
  and block additional mutations. A second edit cannot overwrite an unresolved
  target's backup.

### Changed
- Linux worker entry points enforce a pinned filesystem ruleset before processing;
  strict entry failures block work and fail startup. Selected capability removals
  are verified, capture readiness is separate from start requests, and managed
  worker joins share a shutdown deadline. Privileged capture/restart validation
  remains pending.
- Exports now use the platform cache directory's `netwatch/exports` subtree.
  Shared temporary and whole-working-directory grants are removed; configured
  keylog/GeoIP inputs receive exact file grants. Replacement files require restart.
- SDK eBPF attribution is temporarily disabled under enabled sandbox policy;
  socket polling remains available. Settings reports worker policy entry results.
- Application preparation is separate from explicit worker startup. GeoIP,
  WHOIS, reverse-DNS and Insights constructors now require `start()` to process
  requests. Capture resource setup is separate from packet processing. Worker
  enforcement and remaining dependency/shutdown limitations are documented in
  the runtime lifecycle inventory. Library callers must also migrate
  `EventHandler::new` and `ConnTracker::new` to the explicit `start` APIs.
- Corrected sandbox documentation to describe calling-thread enforcement, existing
  dependency worker limitations, narrowed path grants and capability verification. Added a
  platform capability matrix and updated Insights setup, navigation and data handling.
- Live automatic resolver changes are temporarily unavailable pending durable
  recovery and supported resolver adapters. Diagnose provides manual steps;
  demo remediation remains simulated. Existing journals still receive conservative
  recovery attempts on TUI startup. Durable transactions, cross-process locking,
  and daemon startup reconciliation remain follow-up work.

## [0.30.4] - 2026-09-09

### Fixed
- **Windows: capture opened the wrong adapter, or none, on Hyper-V hosts**
  ([#51](https://github.com/matthart1983/netwatch/issues/51)). The friendly
  name ipconfig shows was matched as a *substring of Npcap's description*,
  which is the driver's name, not the adapter's. "Ethernet" therefore landed on
  the first "Hyper-V Virtual Ethernet Adapter" Npcap listed — the WSL switch,
  which sees nothing but mDNS — and "vEthernet (WSL)" matched nothing and was
  handed to Npcap verbatim, failing with "The system cannot find the file
  specified". Adapters are now matched by interface GUID from `Get-NetAdapter`,
  which is what Npcap's `\Device\NPF_{GUID}` name carries, with the adapter's
  IPv4 address as the fallback where PowerShell is unavailable. A name that
  matches no adapter says so instead of surfacing the raw open error. The
  lookup runs on the capture thread, so PowerShell start-up no longer sits in
  the key handler.
- **Windows: the default capture interface honours the default route.** The
  route-based pick from #43 only existed on Linux and macOS; Windows fell
  through to the first UP adapter with an IPv4, which on a Hyper-V host is
  often `vEthernet (Default Switch)`.

## [0.30.3] - 2026-09-08

### Added
- **All 25 Diagnose rules are active.** The four that shipped `Planned` now
  have their inputs:
  - `dns.truncation_retry` — the DNS probe decodes reply flags, so TC and
    SERVFAIL are counted rather than folded into "answered".
  - `dns.hijack_suspect` — each probe cycle also asks the configured resolver
    and a validating reference (1.1.1.1, DO bit set) for `dns.google`, a name
    with the same answer everywhere. A private address for a public name, or
    disagreement on most cycles, opens the issue.
  - `wifi.weak_signal` — signal level and transmit retries from
    `/proc/net/wireless` on Linux; other platforms report none, so the rule
    stays quiet there rather than guessing.
  - `nat.symmetric` — a STUN Binding Request to two servers from one socket,
    about once a minute; different public ports means an address-dependent
    mapping.

## [0.30.2] - 2026-09-08

### Added
- **Dense view: the number on a box's border is its key.** `1`–`4` zoom
  that box to the whole screen — the 60-second chart at forty rows, every
  interface, the full connection list — and again, or `Esc`, restores the
  grid. `Esc` now backs out one level rather than straight to the full view.
- Fade works under the `terminal` theme. It used to switch off there, on the
  grounds that a gradient needs blended colours; the palette already holds a
  bright variant of every hue, and two tokens are the two-step gradient btop
  draws on a 16-colour terminal. Nothing in between is synthesised.

### Changed
- The dashboard timeline scrolls one sample per tick, the same rule as the
  throughput chart above it, instead of resampling a fixed ten minutes onto
  the panel's columns — which sat still for four ticks and lurched, with the
  shape shimmering between lurches as samples crossed column edges on their
  own schedule. The header says the real window (`last 2m14s`); the ten-minute
  view stays on the Timeline tab.

### Removed
- The faint dot grid behind faded graphs. Three dotted horizontals across a
  plot read as extra copies of the line. `graph_fade` now means only the
  magnitude gradient.

## [0.30.1] - 2026-09-07

Dashboard fixes, mostly to graphs that were drawing something other than what
they claimed.

### Fixed
- **The mirrored throughput plot drew two zero lines.** rx and tx were rendered
  as independent plots in adjacent rects, each with its own baseline floor, so
  the shared zero line was a pair of solid full-width lines one row apart — on a
  quiet link, the whole graph. The split now lives in
  `graph::render_mirrored_with_max`, which owns the rule that the zero line is
  one row belonging to the rx half, and returns its height so the axis labels
  cannot drift from it. The fade grid is drawn once across the whole plot too;
  it used to appear behind rx and not behind tx.
- **The timeline's latency tracks were combed with gaps.** A sample was mapped
  to the single column its timestamp landed in, so 120 five-second probes
  across ~134 columns lit about seven in eight — the `dns rtt` and `gateway
  rtt` tracks read as dashed lines beside a solid `throughput` track over the
  same window. A sample now fills the columns its measurement interval covers.
- **Multi-interface throughput was summed at the wrong end of time.**
  Per-interface histories were aligned at index 0, the oldest sample, but they
  all end at *now* and grow backwards. A link that came up two minutes ago had
  its whole series shifted eight minutes into the past against one up all
  session: traffic drawn on a link before it existed, none on it now.
- The connections panel's `rtt 60s` column promised a sparkline and rendered
  the empty string in every cell. Removed; its ten columns go to the remote and
  app names. `verdict` narrows to its longest label now that the chip is a
  coloured word rather than a padded pill.
- The dashboard footer advertised `↵ drill` with nothing bound behind it.

### Added
- **The dashboard's connections panel groups by process.** One row per process
  with a rollup — rates summed, best RTT, retransmits summed, the group's
  *worst* verdict, and a distinct-host count — instead of one row per socket
  with the process name repeated down the column. `↑↓` moves a cursor (hidden
  until you press it), `space`/`Enter` folds the group under it, `z` folds
  everything. A process with a single socket stays a plain row rather than
  becoming a header with one child.
- **An `interfaces` panel replaces `health` on the dashboard**, beside
  connections at 141 columns and wider, and beside the throughput graph below
  that. Names which link is carrying the traffic that the throughput graph
  aggregates into one series — the question the dashboard could not answer.
  Health findings remain the Diagnose tab's subject, summarised by the latency
  tiles in the hero row.
- A DASHBOARD section in the help overlay, which had none.

### Changed
- Socket verdicts render as a coloured word instead of a filled pill.

## [0.30.0] - 2026-09-05

NetWatch gains a diagnostic engine: a Diagnose tab that names what is wrong,
ranks the explanations by the checks that separated them, offers a fix, and
closes the issue when its own success condition holds. The chrome is rebuilt to
one panel definition across every tab, and AI Insights becomes a commentary
block inside Diagnose rather than a tab of its own.

### Added
- **Diagnose (tab `9`) — issue → probable cause → remediation → verified
  close.** Deterministic; no model involved. Per-metric EWMA baselines with
  standard deviation, learned over a minimum of 30 minutes and scoped to a
  fingerprint of the network that taught them, so carrying a laptop from a
  1.2 ms office resolver to a hotel hotspot doesn't fire every rule at once. A
  25-rule catalogue with an explicit suppression graph, so a dead gateway is
  one finding with its consequences underneath rather than six. Causes are
  ranked by weighted check-pass fraction and shown as a word — `strong`,
  `likely`, `possible` — because the number underneath is not a calibrated
  probability and `92%` invites reading it as one; checks that couldn't run
  report as *not run* and count neither way.

  Remediations are key-bound and reversible, and journal their intent *before*
  they write, so a `SIGKILL` can't leave `/etc/resolv.conf` pointing where
  NetWatch put it — the next start reverts what a dead process left behind, and
  declines if something else has edited the file since. `report.md` and
  `report.json` come from the same `Vec<Issue>` the screen renders; a test
  fails if any line quotes a number no evidence field can justify.

  Four of the 25 rules are declared `Planned` and can never open an issue,
  because their inputs don't exist yet (a DNSSEC reference query, per-reply DNS
  flags, wireless statistics, a STUN probe), and two more detectors report
  their strongest check as *not run* for the same reason. The header states the
  split: a tool that lists 25 rules and evaluates 19 is misreporting its own
  coverage.
- **A verdict line under the tab bar on every tab**, from that same issue list:
  what is wrong, since when, what to press. When the baselines aren't learned
  yet it says so rather than claiming health it hasn't earned — the dashboard,
  Lite and Dense readouts now defer to the engine for the word "nominal".
- **`--demo`** replays a recorded incident through the real engine, rules and
  UI. Diagnose has nothing to say on a healthy machine and wants 30 minutes of
  baseline first, which makes it impossible to demonstrate honestly otherwise.
  Every frame is labelled, remediations touch nothing, and the issue still
  closes through the normal verify path.

### Changed
- **btop-style chrome across the whole tool.** Every box now comes from one
  `widgets::Panel` — rounded corners, title inline in the brand accent,
  metadata right-aligned in the same border row. There were 48 hand-built
  blocks across 15 files agreeing by convention rather than construction, two
  already drifted to a different border style on the same screen. Tab bar,
  table headers and panel titles move to the tool's lowercase voice; dropping
  the tab brackets returns twenty columns and stops the status chips clipping
  at 150 columns.
- **AI Insights is no longer a tab.** It renders inside Diagnose as labelled
  commentary on findings the engine has already established. `insights_enabled`
  and the other config keys are unchanged; tab `9` is Diagnose, and a config
  naming `insights` as its start tab resolves there.
- `screenshots/` is excluded from the published crate, as `docs/media/` already
  was.

### Fixed
- **`pid:0` owned megabytes of traffic** on Connections, Processes and Egress.
  PID 0 is the kernel swapper; this was what the label printed when attribution
  returned `None`, so "644 MB owned by pid:0" meant 644 MB unattributed — and
  the invented process sent an investigation hunting the sandbox for a bug that
  was in a format string. Unattributed traffic now says so; a known PID whose
  `comm` couldn't be read still reads `pid:<n>`.
- **`E` export silently did nothing under the default sandbox.** Exports went
  to `$HOME`, which the Landlock policy makes read-only, so every one failed
  with `Permission denied` — indistinguishable, with no confirmation on screen,
  from one that worked. They now land in the working directory the sandbox
  grants, and the path is shown.
- **The five KPI sparklines covered different spans at identical width.**
  Gateway, DNS and loss are sampled once per health probe; throughput once per
  refresh tick. All drew "the last N samples", so at five ticks per probe the
  latency tiles showed five minutes beside a throughput tile showing one, in a
  row meant to be read across. Every tile is resampled onto one window first.
- **Latency sparklines rendered flat, in both directions.** RTT was rounded to
  whole milliseconds, so a 0.5 ms resolver collapsed to 0 or 1 and any non-zero
  sample drew full height; and the ceiling was a raw `max()`, so one 200 ms
  excursion against a 2 ms baseline scaled everything else to the floor. RTT
  now plots in microseconds against a 95th-percentile ceiling with headroom
  above the median.
- **The Connections state column truncated `ESTABLISHED` to `ESTABLI…`**, which
  is not a state anyone can look up. States now have short names that fit whole
  — `estab`, `time-wait`, `close-wait` — and a mixed group drops the
  denominator rather than clipping the word.
- **The Timeline's "now" cursor overwrote the newest sample it pointed at**,
  painting a `│` one column in from the panel border so it read as doubled
  chrome. It tints the cells already there, which is what the "cyan = now"
  legend always claimed.
- The footer advertised `1-8:Tab` and `--help` said `1-7 Switch tabs` while the
  bar drew ten tabs.

## [0.29.2] - 2026-08-16

### Fixed
- **Windows: a default Npcap install failed with "wpcap.dll was not found"**
  ([#47](https://github.com/matthart1983/netwatch/issues/47)). Npcap 1.x puts
  its DLLs in `%SystemRoot%\System32\Npcap\` rather than `System32`, so they sit
  beside a WinPcap install instead of replacing it — and that subdirectory is
  not on the loader's search path. NetWatch imported `wpcap.dll` at load time,
  so the process died before `main()` against a Windows message box, and the
  only cure was reinstalling Npcap with *Install Npcap in WinPcap API-compatible
  Mode* ticked, which is off by default. The documented procedure — install
  Npcap, run NetWatch — therefore didn't work.

  `wpcap.dll` is now delay-loaded, and at startup NetWatch adds Npcap's own
  directory to the DLL search path and loads the library itself, the way
  Wireshark and nmap handle the same layout. A stock Npcap install works with no
  checkbox; a machine with no Npcap gets a message naming what to install and
  where to get it, instead of a modal from the loader. `--version` and `--help`
  now answer on a machine without Npcap too — they resolve before the check,
  and previously died with everything else.

## [0.29.1] - 2026-08-15

### Fixed
- **The Dense connection table reordered under the cursor.** Rows sorted on the
  instantaneous rate, and a single sample at the default tick is noise, so two
  flows of similar speed traded places constantly — measured at three swaps in
  five ticks with two active downloads. Because the selection is positional,
  every swap silently retargeted the detail block above to a different
  connection, so the panel changed what it was describing while you read it.
  The table now sorts on each flow's recent average instead. That is also the
  more honest answer to "which flow is busiest", and it matches the column the
  header claims to sort by. A genuinely faster flow still sorts above a slower
  one; only the noise is filtered.

## [0.29.0] - 2026-08-11

### Added
- **Dense view** (`--view dense`, or `V` to cycle, or Settings → View). A
  third answer to "how much terminal do you have": Lite spends 80×24 on one
  question, the tabbed TUI spends ten tabs on ten, and Dense spends a large
  terminal on showing everything at once — four boxes, no header bar, no menu
  bar, no status bar. Identity, sort state, page range and every keybind live
  inside the box borders, so every row carries data. It needs 130×44 as a
  floor and grows into whatever it is given: wider means more history in the
  plots and room for full hostnames, taller means more interfaces and more
  connections. Below the floor it falls back to the same 80×24 grid Lite
  targets, and it never scrolls sideways. The full TUI remains the default at
  every terminal size.
- **The mirrored dual graph.** Download grows up from a centre time axis,
  upload grows down from the same axis. Traffic symmetry becomes a shape you
  recognise without reading a number — a download burst is a cliff above the
  line, a backup job is a cliff below it. Both halves are braille at two
  samples per character cell, and every cell is coloured by its height in the
  plot rather than by which series it belongs to, so a spike's severity is
  pre-attentive. The plot carries one sample per sub-column and shifts by
  exactly one per tick, so it scrolls rather than re-bucketing in place, and
  its ceiling snaps to 1/2/5 × a power of ten — the scale moves when the
  traffic does, not every time the peak drifts a few percent.
- **A split colour vocabulary.** Throughput ramps cool→bright because high
  bandwidth is *busy*, not *bad* — a saturated link during a backup is
  working. Only bounded values where high genuinely is bad (link saturation,
  per-hop latency budget) get green→amber→red, and their meters colour by
  position along the bar, so the red zone is visible before you reach it. Red
  on a bandwidth graph would cry wolf every time you downloaded something.
  Palette-deferring themes collapse every ramp to a flat token by design,
  rather than synthesising 24-bit colour the theme exists to avoid.
- **Kernel TCP state per connection** — `cwnd`, `ssthresh`, `mss`, `rwnd` —
  in the Dense detail row, from `inet_diag` over netlink on Linux and the
  `net.inet.tcp.pcblist64` sysctl on macOS. Throughput tells you what
  happened; `cwnd` against `ssthresh` tells you whether you are in slow start
  or congestion avoidance, and a `cwnd` pinned small next to a healthy `rwnd`
  distinguishes "the network is congested" from "the peer isn't reading".
  The two kernels disagree about units — Linux counts segments, BSD counts
  bytes — so macOS values are normalised against the MSS and the column means
  one thing on both. They also spell "threshold not set" differently
  (`i32::MAX` against BSD's `0x3FFF_C000`); both render `∞`. Windows reads
  `--` until `GetPerTcpConnectionEStats` is wired up.
- **Link speed detection**, from `/sys/class/net/*/speed` on Linux and
  `ifi_baudrate` via `getifaddrs` on macOS, giving the saturation meter a real
  ceiling to measure against. The ceiling is never allowed below throughput
  actually measured on the link: a driver claiming the link is slower than
  traffic it has already carried is wrong, and macOS reports `ifi_baudrate`
  for Wi-Fi as the idle MCS — one machine advertised 304 Mb while sustaining
  456 Mb/s over it. The label names which ceiling is in play, because
  "of 1 Gb link" and "of 472 Mb seen" are different claims.
- `V` cycles full → lite → dense from any view; `--view <name>` selects one
  for a single run; **Settings → View** sets the default, live. `L` and
  `--lite` are unchanged.
- **A recorded demo** (`docs/media/demo-dense.gif`, now leading the README)
  with its tape and traffic generator checked in, so it can be re-recorded
  rather than only replaced. The generator uploads as well as downloads — a
  download-only workload leaves the mirrored graph's lower half flat, which
  would record the headline feature as half a graph.

### Fixed
- **`apply_edit` matched settings rows by bare integer** rather than by the
  `cursor::` constants that exist to name them, so inserting any row silently
  re-pointed every editor below it at the wrong setting. Latent until this
  release added one; now keyed by the constants, with a test that walks each
  named cursor to its own field.

## [0.28.2] - 2026-08-10

### Added
- **CIDR blocks in `allow_ip`.** The rule language could only name an exact
  address. `allow_ip` exists for destinations that carried no name — no
  ClientHello SNI, no resolved ASN — and those are disproportionately the ones
  behind cloud ranges that renumber, so declaring them meant enumerating
  addresses that change underneath the policy. `10.0.0.0/8` and
  `2001:db8::/32` now work alongside exact addresses. A malformed pattern
  matches nothing rather than everything: an allowlist that fails open on a
  typo silently admits what it could not parse.
- **A tour that includes the Egress tab** (`demo-tour.gif`, re-recorded) and a
  dedicated **`demo-egress.gif`** showing the whole observe → promote → warn
  loop against live traffic. Both now have tapes checked in, so they can be
  re-recorded rather than only replaced. The tour dropped from 9.2 MB to
  2.8 MB.

### Fixed
- **The Egress summary said "all precise" while a drift row was on screen.**
  The tally counted undeclared, unchecked and ASN-wide destinations but never
  drift, so a screen whose only finding was drift rendered a green
  "all precise" directly above a red `✗ drift` row — in both the header and
  the panel title. A reassuring summary contradicting the alarming detail is
  the one failure mode a policy linter cannot afford.
- **`S` did nothing on the Egress tab.** It reverses the sort on every other
  sortable tab; Egress had no entry in the sort state, so the key was silently
  inert. It now reverses, and the tab's natural order is documented as
  descending — every one of its modes is "most interesting first".
- **Exports resolved `$HOME` directly** instead of `dirs::home_dir()`, which
  the rest of the codebase uses. `HOME` is normally unset on Windows, where
  the old fallback quietly wrote incident bundles, PCAPs and egress exports
  into the working directory.
- Duplicate `space` entry in the Egress section of the help panel.

### Changed
- **`s` on the Egress tab opens the sort picker**, like the four other
  sortable tabs, instead of silently cycling through modes. One key meaning
  two different things was a trap for anyone with muscle memory from the rest
  of the app. The picker's columns are declared in sort-mode order with a test
  asserting the two cannot drift — a mismatch would sort by the wrong mode
  with no error and no panic.
- **The egress policy model moved to its own module** (`collectors/egress/
  policy.rs`). It has no dependency on the profiler and is the one part of
  netwatch that is a security control rather than an observation: a bug there
  does not produce a wrong number, it silently admits traffic that should have
  been reported. 520 lines that can be reviewed without the other 3,200.
  Re-exported, so no caller changed.
- Property tests for the SNI matcher — reflexivity, case, wildcard depth, and
  the neighbours a wildcard must never admit — plus mask monotonicity for the
  new CIDR matcher. Both were scoped in the egress plan and had not landed.

## [0.28.1] - 2026-07-29

### Added
- **Grouped trees on Connections and Egress.** `group: process` and
  `group: remote` were sort orders wearing the word "group" — rows clustered,
  but the key was restated on every one, so the widest column repeated the
  string above it and the process name was truncated to `Google Chrome…` for
  want of space. Both tabs now render one parent row per group carrying a
  rollup, with foldable children. 63 connections read as 13 processes.
- **Groups start folded**, so a tab opens on the overview rather than the
  detail. `z` folds or expands everything; `space` folds the group under the
  cursor, from a child row as well as its header. Configurable via
  `groups_start_collapsed` (default true) or the settings screen's
  "Groups Start Folded".
- **Byte accounting on Egress.** Destinations accumulate `bytes_out` /
  `bytes_in` plus a per-tick series for an inline sparkline, from rates the
  connection table already computed and discarded. An egress-forensics tab
  could not previously answer *how much data left this machine*.
- **A verdict vocabulary that distinguishes precision from breadth** —
  `✓ sni` / `✓ ip` (an endpoint), `~ asn` (an entire autonomous system),
  `? ech`, `✗ drift`, `— no rule`, `✗ undeclared`. Plus `s` sort (including
  **risk**), `/` filter, `d` detail pane and mouse support.
- **`strict = true` in `egress-policy.toml`.** Treats the policy as complete,
  so a process with no rule becomes a finding rather than a blind spot.
  Off by default. Without it the linter cannot see the one thing a compromise
  actually introduces — a binary nobody declared.
- **Remove a process from the policy** (`x` / `Del`, confirmed with `y`).
  Promotion could only ever grow an allowlist; withdrawing coverage meant
  editing the file by hand. Deletion preserves comments, unrelated rules, the
  `strict` flag and `0600` permissions, and refuses an unparseable file.

### Changed
- **Promotion no longer widens a rule to an autonomous system.** It wrote an
  `allow_asn` entry for any destination without an SNI, and a rule admits on
  *any* dimension — so one nameless hyperscaler flow at promote time admitted
  every host that AS operates, for that process, permanently, rendering
  `✓ ok`. Identity now comes from the SNI or the address. On a real
  25-process baseline this took rules with an ASN-wide entry from **12 of 25
  to 0**, and admitted (destination, port) pairs from 282 to 245.
  Hand-written `allow_asn` rules still match; nothing generates one.
- `Unassigned` — the geo database's *failure* label — is never promoted as an
  identity. Allowlisting it admitted every destination whose ASN lookup failed.
- The NDJSON export gains `undeclared` as a distinct verdict rather than
  folding it into `drift`; nothing was compared, so `drift` would overstate
  what the linter knows.

### Fixed
- **Egress `Seen` was a duration wearing a counter's clothes.** `observe` runs
  once per tick and incremented per tick a flow was present, so `31427` meant
  *open for 8.7 hours*, not 31k requests. Now rendered as a duration and
  labelled `Active`.
- Connections' UDP rows carry an empty state, so a group's dominant-state cell
  counted `""` as the winner and rendered a bare `11/13` — a fraction of
  nothing. Only named states compete.
- Removing the only rule from a policy file emptied it completely, taking the
  header that documents `strict` and promotion with it.
- `✗ undeclared` truncated to `✗ undeclare` in the Egress verdict column.
- Policy-edit status messages were invisible on the Egress tab: they render in
  the shared header slot, which the tab bar consumes at any ordinary width.

## [0.28.0] - 2026-07-28

### Added
- **Lite view (`--lite`, or `L` to toggle).** A single 80×24 screen for the
  one-machine case — throughput charts, gateway/DNS/internet reachability, and
  top talkers by process and host, with six keys. It shares the full TUI's
  collectors, so toggling between the two keeps all history. Also gives the
  small-terminal case a coherent rendering: the full TUI has no global minimum
  size and degrades silently below ~130×36.
- **Internet reachability probe.** `HealthStatus` gains `internet_rtt_ms` /
  `internet_loss_pct`, probing 1.1.1.1 with the same ICMP→TCP fallback the
  gateway probe uses. Distinguishes "the router is fine but the line is down"
  from "the router is down" — gateway and DNS alone can't tell those apart.

### Fixed
- **The `dots` graph style now renders a filled area instead of a sparse dot
  matrix.** `render_dots` lit only the left sub-column of each braille cell —
  the right-hand constant was declared but never used — so the "btop-style
  braille area plot" looked half-empty everywhere it was drawn. Affects every
  chart when `graph_style = "dots"`.
- Lite honours the app-wide `graph_style` / `graph_fade` settings. Its charts
  and sparklines previously hardcoded block glyphs and ignored both.

## [0.27.0] - 2026-07-26

Process identity becomes stable enough to key a policy on, and the egress linter
stops reporting drift it invented. Plus a theme for people who already have a
system-wide color scheme. (#44)

### Added
- **`terminal` theme — defers entirely to your terminal's palette.** For anyone
  running pywal, matugen, or a tuned terminal profile who wants NetWatch to follow
  along rather than impose its own colors. `dark` was already close (ANSI named
  colors, `bg: Reset`); this goes further where theme-matching actually breaks:
  `text_primary` is `Reset` (your exact configured foreground, not the white slot)
  and both selection backgrounds drop fixed RGB for `Indexed(8)`. Nothing in the
  theme pins an RGB value — a test enforces that. Accepts `system` and `ansi` as
  aliases. `dark` remains the default.
- **Security policy** (`SECURITY.md`): private reporting channel and threat-model
  scope.

### Fixed
- **Process identity now derives from the executable, not `comm`.** Two separate
  instabilities made names unusable as a policy key: the kernel truncates `comm`
  (16 bytes on macOS, 15 on Linux), so `Google Chrome Helper` and
  `Google Chrome Helper (GPU)` both arrived as `Google Chrome He`; and `lsof`
  reports the executable's filename, which for version-installed tools *is the
  version* — Claude Code appeared under six different names on one machine, with
  every upgrade minting another and orphaning any policy promoted for it. Identity
  now comes from the executable path (`proc_pidpath` / `/proc/<pid>/exe`), falling
  back to the nearest meaningful parent directory when the file itself is named
  like a bare version. Not `argv[0]` — any process can set that, which would let a
  program inherit another's rules by renaming itself. Measured on live
  connections: 19 distinct names → 15.
- **Blank destinations no longer warn as drift.** Processes appeared as `✗ drift`
  with no destination and no IP, and a violation message reading literally
  " not in allowlist". Four compounding defects: `parse_addr_parts(":443")`
  returned `Some("")` instead of `None`; `is_private_ip("")` is false so `observe()`
  let it through both guards; `upsert` overwrote a known `last_ip` with an empty
  one; and `violation()` built its subject as `sni.or(asn).unwrap_or(ip)`, yielding
  an empty string. Existing baselines repair without a migration.
- **The same program is no longer profiled twice under truncated and full names.**
  PKTAP carries a kernel-truncated `comm` while `lsof` reports the full name, so
  whichever attribution source won a tick decided the profile key — on one machine
  `Google Chrome He` and `Google Chrome Helper` held 16 and 12 destinations with
  only 7 in common, so promoting one ratified a baseline the other immediately
  drifted against. Names now fold onto one key, with hit counts and violation
  tallies carrying across the merge. VS Code's genuine `Code Helper` correctly
  stays separate from the truncated `Code Helper (Plu`.
- The per-process destination cap silently dropped entries at load, resurfacing
  later as drift for traffic that was still happening. It now warns once per load
  with the counts.

### Changed
- Install docs point at homebrew-core, Nix, AUR and Scoop.

## [0.26.1] - 2026-07-04

### Fixed
- **Packet capture now defaults to the NIC carrying the default route.** (#43)
  On multi-NIC machines (e.g. motherboards with two Ethernet ports) the capture
  tab picked the first UP interface with an IPv4 in enumeration order, which
  could be the idle port. The interface with the default route is now preferred,
  with the old heuristic as fallback.
- **`i` (cycle capture interface) now works while capturing** — it restarts the
  capture on the new interface, keeping the packet buffer and active BPF filter.
  Previously it silently did nothing until you stopped capture with `c`. The
  Packets footer now advertises the key (`i:Iface`).
- Loopback is no longer offered when cycling capture interfaces (still
  selectable via the `capture_interface` config key).

## [0.26.0] - 2026-07-04

The **egress policy linter** (Horizon 3): NetWatch learns what each process on your
machine normally talks to, lets you ratify that baseline into a policy, and warns when
traffic drifts from it — observe → promote → warn. It warns, it never blocks. SNI is read
from the cleartext ClientHello, so meaningful policy works without decryption or a keylog.

### Fixed
- **Promoted processes now all read `✓ ok` — a rule admits its own baseline.**
  A process with a mix of named and nameless (raw-IP) destinations got a
  *name-restricted* rule from the named ones, and its raw-IP destinations then
  drifted against that very rule — so after promote some rows stayed `✗ drift`
  instead of flipping to `✓ ok`. Rules now carry an `allow_ip` dimension: a flow
  is allowed if **any** declared dimension (SNI, ASN, or IP) matches, so a
  nameless destination is admitted by its IP. Promotion captures those IPs.
- **Egress promote is now additive — it accumulates the full allowlist.**
  Promotion replaced a process's rule with only what was observed in the
  current session, so re-promoting (or promote-all after some destinations had
  aged out of the live baseline) could *shrink* the list. Promotion now unions
  the observed entries with those already in the file — prior promotes and
  hand-added entries both survive; ratification only ever grows the allowlist.
- **Egress promote now reliably takes effect.** A freshly-promoted
  `egress-policy.toml` written under a loose umask could be group/world-writable,
  which the policy loader then refused — so the promote appeared to do nothing
  (verdicts stayed `—`). Policy writes are now owner-only (`0o600`) and tighten a
  loose pre-existing file, and a failed reload is reported instead of claimed as
  success. The promote confirmation also persists its full display duration.

### Changed
- **Egress tab shows the real destination IP** in its own column — nameless
  destinations no longer collapse to a `(ip)` placeholder, and the IP is carried
  in the NDJSON export. Active drift warnings now render in a panel **on the
  Egress tab itself**, newest first, instead of only in the Timeline alert feed.

### Added
- **Egress policy linter (Horizon 3 foundation)** — observe → promote → warn:
  - **Egress tab** (`0`): per-process destination profiles (SNI / ASN org / port),
    learned live from the cleartext TLS/QUIC ClientHello — no decryption required.
    Scrollable, with a policy verdict column (`✓ ok` / `✗ drift`) once a policy is loaded.
  - **`Shift+P` promote**: ratifies the observed baseline into
    `<config_dir>/netwatch/egress-policy.toml` (`process → allow_sni / allow_asn /
    allow_ports`, exact or `*.wildcard` SNI patterns). Review-before-trust — human
    ratification defeats baseline poisoning.
  - **`PolicyViolation` alerts**: flows outside a declared allowlist raise a
    Warning-severity alert naming the broken rule, with a per-flow cooldown. Only
    processes with a rule are checked; the linter warns, it never blocks.
  - **Persistent baseline**: learned profiles survive restarts
    (`<state_dir>/netwatch/egress-profiles.json`, saved once a minute and at quit;
    Landlock allow-listed). Destinations not seen for 30 days age out at load.
    `First`/`Last` columns show how long each destination has been known.
  - **Selective promotion**: `Enter` promotes just the selected process, with a
    diff on the status line (`+2 SNI, +1 ports`). Promotion now **merges** into
    `egress-policy.toml` via `toml_edit` — hand edits, comments, and rules for
    other processes survive; an unparseable policy file is refused, never
    clobbered.
  - **Headless linting**: `netwatch daemon` evaluates the same policy, and
    violations surface as `netwatch_policy_violations_total{process}` on the
    Prometheus `/metrics` endpoint (bounded cardinality — only declared
    processes can appear).
  - **ECH-aware verdicts**: flows with Encrypted ClientHello show `? ech`
    instead of `✗ drift` when the miss may be "name unreadable, by design",
    and the alert text says so.
  - **Wildcard suggestions**: when ≥3 subdomains of one apex accumulate,
    promotion writes a `# suggestion: *.apex.tld would cover N entries` comment
    above the rule — suggested, never silently collapsed.
  - **Config**: `egress_violation_cooldown_secs` (default 300) controls the
    per-flow re-warn interval.
  - **Hardening**: a group/world-writable `egress-policy.toml` is refused with
    a loud warning — the policy file is a trust anchor.
  - **Structured export** (`e` on the Egress tab): writes attributed egress
    records as versioned NDJSON (`netwatch.egress.v1`) — one metadata-only JSON
    object per line (process, SNI, ASN, IP, port, proto, ECH, first/last-seen,
    count, policy verdict), preceded by a `_meta` schema line. No payload ever.

## [0.25.9] - 2026-06-27

Deeper protocol decoding, broader threat-detection coverage, and a round of reliability and
documentation improvements.

### Added
- **HTTP request path and response status** in the Packets view and connection labels.
- **DNS response codes** (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, …) in DNS decode output, e.g.
  `example.com (type=1, NXDOMAIN)`.
- **Per-connection TCP handshake RTT** (SYN→SYN-ACK), measured per flow.
- **Persistent-connection C2 detection** — beaconing analysis now also covers long-lived
  single-connection heartbeats, in addition to new-connection patterns.
- **Fuzz coverage** across the L7 protocol parsers.

### Improved
- More reliable DNS analytics — query/response latency, NXDOMAIN counts, and per-domain metrics.
- Greater packet-capture resilience under worker-thread failure.
- Quieter beaconing and DNS-tunnel alerting, with de-duplication and cooldowns; C2 beaconing now
  raises a Critical alert, which triggers the Flight Recorder auto-freeze.
- Memory-bounded detection caches.
- Sandbox support for a custom `tls_keylog_path`.
- More accurate multi-label domain grouping (e.g. `*.co.uk`, `*.com.au`).

### Documentation
- Expanded and clarified the protocol-decoding, eBPF attribution, sandbox, and TLS decryption
  references — including TLS 1.2 decryption support.

## [0.25.8] - 2026-06-20

### Added
- **eBPF Phase 2: IPv6 + connected-UDP process attribution.** Kernel-side connect attribution, previously IPv4 TCP only (`tcp_v4_connect`), now also covers IPv6 TCP (`tcp_v6_connect`) and **connected UDP — including QUIC** (`ip{4,6}_datagram_connect` and their `__`-prefixed inner workers). This closes the loop on "decrypt the QUIC flow **and** name the process that owns it": QUIC/UDP flows where the client `connect()`s its socket (browsers, quiche) are now attributed via eBPF instead of falling back to `/proc` polling that misses short flows. The attribution cache is keyed on `(protocol, daddr, dport)` so a TCP and a UDP flow to the same destination (e.g. both to `:443`) never cross-attribute. Both the datagram-connect wrapper and its inner are attached best-effort because kernel builds disagree on which is on the connect path (the other is inlined or absent); a double-fire is idempotent. **Unconnected UDP** (`sendto`/`sendmsg` without a prior `connect()`) is not yet attributed. Linux-only; degrades to lsof/ss attribution where the kernel won't load the probes.

## [0.25.7] - 2026-06-11

### Added
- **Passive TLS 1.2 application-data decryption.** Extends the SSLKEYLOGFILE-driven decryptor (previously TLS 1.3 + QUIC) to TLS 1.2 AEAD flows. The 48-byte master secret from a `CLIENT_RANDOM` keylog line, plus the `server_random` read off the ServerHello, feed the TLS 1.2 PRF (RFC 5246 §5) to derive the key block; records are then decrypted for AES-128/256-GCM (RFC 5288 — 8-byte explicit nonce + 4-byte fixed IV) and ChaCha20-Poly1305 (RFC 7905). It reuses the shared keylog store, background watcher, `decrypted:` display filter, and stream/detail rendering, so 1.2 flows surface through the same UI as 1.3. A flow's version is inferred from which keylog secret is present (`CLIENT_RANDOM` ⇒ 1.2, `*_TRAFFIC_SECRET_0` ⇒ 1.3), and per-direction sequence resync recovers when the keylog secret is ingested after the first records flow. Legacy CBC mac-then-encrypt suites remain out of scope. A live verification harness ships as `examples/tls12_decrypt_live.rs` (with `scripts/verify-tls12-decrypt.sh`).

## [0.25.6] - 2026-06-08

### Added
- **Headless agent / fleet mode (`netwatch daemon`).** Runs the same collectors as the TUI with no rendering and streams to a backend — the fleet-agent entry point. Flushes its buffered telemetry on SIGTERM/Ctrl-C before exiting; reports collector liveness (a thread-panic flag) so a stalled agent surfaces as degraded instead of going silently quiet. Ships `systemd` and `launchd` service units under `packaging/`. The interactive TUI is unchanged. Enable streaming with `--remote`/`--api-key` (or `NETWATCH_REMOTE_URL`/`NETWATCH_API_KEY` so the key stays out of `ps`).
- **Durable remote ingest.** The remote publisher is now at-least-once instead of fire-and-forget: a bounded, drop-oldest queue (≈8h buffer) that only drops a batch after the backend ACKs it, with exponential backoff + jitter and batched drains, so a network blip no longer silently gaps telemetry. Envelopes are versioned (`schema_version`) and carry `agent_health` (collector status, dropped count, queue depth).
- **Prometheus `/metrics` + `/healthz` exporter (daemon).** `netwatch daemon --metrics` (default `127.0.0.1:9464`, the OpenTelemetry Prometheus port; loopback-only) exposes aggregate signals — per-interface throughput, gateway/DNS RTT + loss, connection/TCP-state counts, and `netwatch_up`/`netwatch_collectors_ok`/`build_info` — in Prometheus exposition format. Aggregate-only by design (per-flow forensics is kept out of metrics to avoid cardinality blow-ups). See `docs/observability-export.md`.
- **TLS 1.3 KeyUpdate / post-handshake re-keying (decryption Phase 2).** Long-lived TLS 1.3 sessions that issue a post-handshake KeyUpdate (RFC 8446 §4.6.3) now keep decrypting instead of going dark after the re-key. On an observed KeyUpdate, netwatch derives the next-generation traffic secret (`HKDF-Expand-Label(secret_N, "traffic upd", …)`), re-derives the AEAD key/IV, and resets the per-direction record sequence (§5.3). Recovery from a *missed* KeyUpdate packet (via keylog `*_TRAFFIC_SECRET_<N>` generations) is not yet implemented.

### Fixed
- **Logging no longer crashes the process when the log file can't be opened.** A root-owned `netwatch.log` left by a prior `sudo netwatch` run (or a read-only filesystem) used to panic at startup — fatal for the long-running daemon. File logging now degrades to disabled (with a one-line notice) instead.
- **Processes "TOP REMOTES" used a proportional byte split instead of real per-remote rates.**

## [0.25.5] - 2026-06-08

### Added
- **Cross-packet HTTP/3 stream reassembly (QUIC decryption Phase 3b).** HTTP/3 response bodies that span more than one QUIC 1-RTT packet now reassemble and decompress instead of truncating. A new `H3StreamReassembler` accumulates decrypted STREAM-frame bytes per HTTP/3 stream id, indexed by offset, across packets, and decodes the contiguous prefix from byte 0 (gzip/deflate/brotli) — so a body is recovered once its head and a contiguous run are present, even when packets arrive out of order. The reassembled body shows in the Protocol Detail and Payload Content panes and in the `y` clipboard yank. Per-stream (2 MiB) and per-flow (64 streams) caps bound memory; zstd and identity bodies remain out of scope.

### Changed
- **Decrypt layer surfaces only `application_data`** (TLS content-type 23): post-handshake NewSessionTicket (22) and alert (21) records no longer appear as "decrypted" plaintext, keeping the detail pane and stream view clean.

### Fixed
- **Stream view follows the selected packet.** Opening the stream view (`s`) now highlights the selected packet's bytes and scrolls to them, instead of always starting at the top of the stream.

## [0.25.4] - 2026-06-06

### Added
- **Follow decrypted stream.** The stream view (`s` on the Packets tab) now renders the **decrypted** application-data conversation for flows decrypted via `SSLKEYLOGFILE`, instead of the raw encrypted wire bytes. Each segment's recovered plaintext is mirrored from the packet onto its stream segment, so opening a decrypted flow shows the full plaintext HTTP request/response exchange in order — both directions, in Text and Hex modes. The encrypted handshake is omitted from the decrypted view so the request/response flow reads cleanly (its timing still shows in the header), and a "🔓 decrypted" indicator appears in the stream header. (Previously the stream view followed only the encrypted bytes, which rendered as gibberish for any TLS/QUIC flow.)

## [0.25.3] - 2026-06-03

### Fixed
- **Quit / tab-switch could hang on idle interfaces.** Capture now runs non-blocking, so quitting or switching tabs can't stall waiting on a silent link (fully resolves #41).

## [0.25.2] - 2026-06-03

### Fixed
- **Quit could hang on idle interfaces.** Enabled libpcap `immediate_mode` so a quit isn't blocked waiting for the next packet on a quiet interface (#41). Superseded by the non-blocking capture in 0.25.3.

## [0.25.1] - 2026-06-02

### Added
- **Process attribution for pre-existing connections.** A pre-sandbox `/proc` snapshot captures processes for connections that predate startup, plus native `/proc` attribution so processes show without `ss -p` (#38/#40).

### Fixed
- **eBPF attribution keying** on `(daddr, dport)` to match the netwatch-sdk `uaddr` fix.
- **Windows UTF-8 output** — embed a UTF-8 active-code-page manifest so text renders correctly in non-UTF-8 locales (#39).

## [0.25.0] - 2026-05-31

### Added
- **Passive QUIC 1-RTT application-data decryption via `SSLKEYLOGFILE`.** Extends the v0.24.0 TLS 1.3 decryption from TLS-over-TCP to QUIC's encrypted short-header (1-RTT) packets — the same opt-in, read-only `tls_keylog_path` mechanism. netwatch derives the 1-RTT keys from the keylog `*_TRAFFIC_SECRET_0` (RFC 9001 §5), removes header protection, reconstructs the truncated packet number (RFC 9000 §A.3), and AEAD-opens the payload. The cipher suite and per-direction connection-ID length aren't on the wire for short headers, so the first packet brute-forces them with AEAD authentication as the oracle, then caches the result per flow. Supports the three QUIC v1 suites (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305). Verified against the RFC 9001 §A.5 known-answer vectors and against live Chrome HTTP/3 traffic. QUIC v2 1-RTT, key updates (key-phase), and coalesced packets are out of scope for this phase.
- **HTTP/3 response-body decompression.** When a decrypted 1-RTT packet carries an offset-0 HTTP/3 DATA body, netwatch parses the HTTP/3 framing layer (RFC 9114), concatenates the DATA frames, and decompresses the body — gzip/deflate detected by magic bytes, brotli (`br`) by trial decompression (the `Content-Encoding` lives in the QPACK-compressed HEADERS frame, which is deliberately not decoded). The decoded body renders in the Payload Content pane. Scope is single-packet, offset-0 bodies; larger responses that span multiple packets need cross-packet stream reassembly (a later phase). zstd is out of scope.

### Changed
- **Decrypted QUIC packets are now labelled "QUIC 1-RTT decrypted"** (rather than "TLS decrypted") across the Protocol Detail pane, Payload Content title, and clipboard yank. The decrypted payload is shown once in the Payload Content pane instead of being duplicated in both panes.

## [0.24.0] - 2026-05-30

### Added
- **Passive TLS 1.3 application-data decryption via `SSLKEYLOGFILE`.** When a cooperating client process is launched with `SSLKEYLOGFILE` pointing at the path in the new `tls_keylog_path` config key, netwatch tails that NSS keylog, derives per-record AEAD keys, and decrypts TLS 1.3 Application Data on the Packets tab — the same trick Wireshark uses. Read-only and opt-in: only connections whose client cooperatively exported its secrets are decryptable (production / third-party / malware traffic is not). Supports `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and `TLS_CHACHA20_POLY1305_SHA256`. Verified against the RFC 8448 §3 known-answer vector (full key-schedule → AEAD-open → inner-plaintext pipeline) and against live traffic. TLS 1.2, QUIC application data, and 0-RTT are out of scope for this phase.
- **Decrypted-payload inspection.** Decrypted packets render bold-green in the list; the new `decrypted:true|false` filter selects them, and `contains "…"` now searches decrypted plaintext too. The Protocol Detail and Payload Content panes show the recovered plaintext (the latter titled "Payload Content (TLS decrypted)"), and `y` copies the full payload to the clipboard.
- **HTTP/1.x classifier** — extracts the method and `Host` header from requests and labels server responses (was a placeholder).
- **SSH classifier** — identifies the RFC 4253 version banner, e.g. `SSH-2.0-OpenSSH_9.0` (was a placeholder).

### Fixed
- **Keylog watcher race.** A flow's first application-data records routinely arrive before the keylog secret has been ingested; previously that permanently disabled decryption for the stream. A keylog miss is now retryable (only a missed ClientHello or an unsupported cipher disables a stream), `decrypt_record_resync` recovers the correct record sequence after late-arriving secrets, and the watcher poll was tightened from 500ms to 100ms.
- **Packet filter ignored by the detail pane, scroll, and click.** With a filter applied, scrolling (mouse/arrows), clicking, and the detail pane indexed the full capture instead of the filtered view, so a stale selection or a scroll past the filtered rows rendered details for packets not shown in the list (even when the filter matched nothing). The list, detail pane, scroll, and click now share one filtered view.

## [0.21.7] - 2026-05-26

### Fixed
- **Capture toggle (`c` on the Packets tab) no longer fails with `Capture failed: libpcap error: socket: Operation not permitted` on Linux under the default sandbox.** The Linux sandbox was dropping `CAP_NET_RAW` after startup on the assumption that "pcap is already open, we don't need raw sockets anymore." That assumption was wrong: multiple UI actions re-open a pcap handle mid-run — toggling capture from the Packets tab (`c`), cycling the capture interface (`i`), and arming the Flight Recorder (`Shift+R`) when capture is paused. Each one calls `socket(AF_PACKET, SOCK_RAW, …)` which needs `CAP_NET_RAW`. Split the drop list: `CAPS_TO_DROP_DEFAULT` keeps the BPF caps (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`) which aren't needed at runtime once the kprobe is attached; `CAPS_TO_DROP_STRICT` additionally drops `CAP_NET_RAW` for users who explicitly opted into "fail closed" with `--sandbox-strict` or `sandbox = "strict"`. Two new regression tests pin the policy.

## [0.21.6] - 2026-05-26

### Fixed
- **Saving settings under the Linux sandbox no longer fails with "Permission denied (os error 13)".** The Landlock allow-list put the config dir (`~/.config/netwatch/`) in the *read-only* bucket, but `NetwatchConfig::save()` writes `config.toml` here whenever a user changes a setting in the overlay (`S` → edit → `S` to save). On kernels new enough to enforce Landlock (≥5.13) the write was rejected and the user saw EACCES — worst of all, this blocked them from flipping the Sandbox setting itself to escape the restriction. Moved the config dir to the read-write list. Found on a Linux NUC trying to disable the sandbox via the Settings overlay.
- **Gateway probe no longer reports a fake 100% loss on systems with restrictive `ping_group_range`.** Even after v0.21.5 fixed the DNS probe, Gateway stayed on ICMP — which is unreachable on kernels with `net.ipv4.ping_group_range = 1 0` once the sandbox has dropped `CAP_NET_RAW` and Landlock has set `NO_NEW_PRIVS` (causing the kernel to ignore the file-cap on `/usr/bin/ping`). Added a TCP-connect fallback that runs *only* when ICMP returns 100% loss: tries port 80, 443, 53 in order (stopping at the first one to respond), counts `ConnectionRefused` as success because a RST proves the host is up. Steady-state cost is one port × 3 probes (cheap); only the genuinely-down-or-firewalled case pays the worst-case 9 connect attempts. ICMP-rich environments (default kernels, no sandbox) keep the old behavior — the TCP path doesn't run at all when ICMP succeeds even partially.

## [0.21.5] - 2026-05-26

### Fixed
- **DNS Health probe now sends a real DNS query instead of ICMP-pinging the server.** ICMP echo was a misleading health signal anyway (plenty of resolvers — cloud LBs, hardened routers, internal CoreDNS — drop ICMP while answering DNS just fine), but it also broke entirely on Linux hosts where `net.ipv4.ping_group_range = 1 0` and the sandbox has dropped `CAP_NET_RAW`. Even with `ping_group_range` permissive, Landlock sets `NO_NEW_PRIVS` which makes the kernel ignore the file capability on `/usr/bin/ping`, so the subprocess fallback dies too — leaving every DNS probe at 100% loss on affected systems. New `run_dns_query()` sends a 17-byte standard query for the root NS record over UDP/53 and times the response; unprivileged, no sandbox interaction, and a more honest "DNS health" signal because it tests what actually matters. Three new unit tests cover header layout + transaction-ID round-trip.

### Added
- **Sandbox enforcement mode is now a Settings entry.** New "Sandbox" row in the Settings overlay (`S`) cycles through `on` / `strict` / `off` with `←` / `→`. Persists to `~/.config/netwatch/config.toml` as the new `sandbox = "..."` key; the CLI flags `--no-sandbox` and `--sandbox-strict` still override per-invocation. Changes apply on next netwatch start — Landlock and dropped capabilities can't be undone at runtime, so the live process keeps whatever mode it launched with. The Settings row surfaces "Applies on next netwatch start." when selected so the restart requirement is visible inline. Existing configs without a `sandbox` field continue to load cleanly and pick up the default (`"on"`).

## [0.21.4] - 2026-05-26

### Fixed
- **Health widget no longer reports a fake 100% loss when the system advertises an IPv6 link-local DNS server.** `dns_servers.first()` picked whichever nameserver appeared first in `/etc/resolv.conf` — on macOS with IPv6 RA-discovered DNS, that's the link-local entry (e.g. `fe80::96ea:eaff:fe05:f074`) listed ahead of the routable IPv4 server. The native ICMP probe can't reach link-local targets because `IpAddr::parse` rejects the `%en0` zone identifier they require, so every probe failed and the Dashboard's DNS card showed "100% loss" even though the host's *other* DNS server was healthy. Added `NetworkConfig::primary_dns()` which skips `fe80::/10` and falls through to the next entry, so we now probe (and label) the routable IPv4 fallback. Globally-routable IPv6 nameservers (e.g. `2001:4860:4860::8888`) are still preferred over IPv4 when they come first — only link-local is skipped. ([#31](https://github.com/matthart1983/netwatch/issues/31))
- **scutil `--dns` parser no longer mangles IPv6 nameservers.** The previous parser split each `nameserver[N] : <addr>` line on every `:` and took index 1, which truncated any IPv6 address to its first hextet (`fe80::1` became `fe80`). Switched to `split_once(':')` so the address survives the parse. (Not what triggered #31 — macOS reads `/etc/resolv.conf` first and never reaches the scutil branch when that file is non-empty — but it was waiting to bite anyone whose resolv.conf was empty or unavailable.)

## [0.21.3] - 2026-05-24

### Fixed
- **`package.nix` version bumped to track Cargo.toml.** The Nix derivation was stuck at `version = "0.3.5"` even though the published crate is currently at v0.21.x — Nix users doing `nix build github:matthart1983/netwatch` got a derivation labeled v0.3.5 with the actual current source contents. Bumped to match Cargo.toml + added an inline comment reminding future maintainers to keep the two in sync per release. (Reminder surfaced while wiring up the syswatch sibling's `package.nix` in [syswatch#3](https://github.com/matthart1983/syswatch/issues/3).)

## [0.21.2] - 2026-05-23

### Fixed
- **Processes tab now includes UDP and non-ESTABLISHED TCP flows.** `ProcessBandwidthCollector::update` was filtering connections with `state != "ESTABLISHED"`, which silently excluded the bulk of normal traffic on macOS: every QUIC flow from a browser, every DNS resolver socket, mDNS responders, the whole UDP world (lsof and procfs report UDP with an empty state, not "ESTABLISHED"). The Processes tab was usable mostly for SSH and TCP-only services, missing everything modern web apps actually do. New filter is the inverse — only `LISTEN` and `CLOSED` sockets are skipped (they have no peer traffic by definition). Everything else, including UDP, `TIME_WAIT`, `CLOSE_WAIT`, `FIN_WAIT_*`, etc., now counts toward the process aggregate. Two new unit tests cover both directions of the regression (LISTEN/CLOSED still excluded, UDP/TIME_WAIT now included).

## [0.21.1] - 2026-05-23

### Fixed
- **TOP CONNECTIONS panel on the Dashboard now respects the fade setting.** v0.21.0 wired the fade through every chart and every table renderer except the dashboard's TOP CONNECTIONS rows — they're rendered through their own per-row path that bypassed the table-fade hook. Rows 1..N now fade top-bright / bottom-dim like every other table; row 0 (the visually-highlighted "rank 1" row that already carries `selection_bg`) stays at full intensity.
- **Processes tab no longer cuts the main list to 5 rows on typical terminals.** The layout reserved a fixed 11 rows for the drill-in panel below the table, which left the table with `Min(8)` — yielding only ~5 visible rows after borders + header on a 27-row terminal. The drill-in only shows 5 host rows + header + "others" + borders (≈ 8 rows needed), so the reservation was 3 rows wasted. Dropped to `Length(8)`; the main process table now gets 3 more rows on the same terminal.

## [0.21.0] - 2026-05-23

### Fixed
- **macOS health prober no longer reports a fake 100% loss.** The v0.18.0 native DGRAM ICMP path checked the reply type at offset 0 of the recvfrom buffer, which is correct on Linux (the kernel strips the IPv4 header for `SOCK_DGRAM IPPROTO_ICMP`) but wrong on macOS (the IPv4 header is delivered intact, so offset 0 is `0x45` — IP version/IHL nibble — not the ICMP type). Every reply was rejected, the prober reported 0 successful probes, and the Dashboard's Gateway / DNS RTT cards showed "100% loss" despite the network being fine. The reply check now sniffs `buf[0] >> 4 == 4` to detect a leading IPv4 header and skips past it via the IHL field. IPv6 leaves the header outside the recvfrom buffer on both kernels, so offset 0 stays correct there.
- Verified end-to-end on both platforms with `cargo run --example ping_smoke` against 1.1.1.1: macOS reports ~12 ms RTT / 0% loss (was 100% on v0.18.0–v0.20.0), Linux still ~12 ms RTT / 0% loss (no regression — the IHL skip only triggers when the first byte has the IPv4 version nibble, which doesn't appear on Linux's stripped-header path).

### Added
- **btop-style fade + faint grid as a Settings option.** New `Graph Fade (btop)` row in the Settings overlay (`S`); toggle with `←`/`→`/`Space`/`h`/`l`. The single switch governs three places at once when on:
  - **Charts** — every chart in the app (hero RX/TX panels, in-row connection / process sparklines, RTT history, timeline severity layers) renders columns with a right-bright / left-dim color gradient (newest data at full intensity, oldest at ~30%), with a faint `·` dot grid behind charts at least 16×4 cells (narrower in-row sparklines skip the grid to avoid visual noise).
  - **Tables** — Connections, Packets, Processes, and Stats tables fade row-by-row top-bright → bottom-dim (top row at full intensity, bottom row at ~55%) so visual hierarchy mirrors btop's process list. Selected row stays at full intensity regardless of position.
  - **Persistence** — setting saves to `~/.config/netwatch/config.toml` via the existing save flow.

  Default is off; the original solid-color look is unchanged for users who don't want the effect.

### Changed
- `graph::render` / `graph::render_with_max` now take a `GraphOpts` parameter (carries `fade: bool` and the theme `bg` color used as the fade anchor). `App::graph_opts()` builds it once and every call site passes it, so the toggle drives the whole UI from a single config switch.
- `render_bars` reimplemented to render manually instead of delegating to ratatui's `Sparkline` — necessary because `Sparkline` only supports a single color per chart and fade requires per-column color computation. Visual output is identical to the previous Sparkline-based path (same 8-glyph bar set, same right-aligned sample window) when fade is off.

### Implementation
- `fade_color(base, bg, alpha)` linearly interpolates RGB channels between base and background at the given alpha. Named/indexed colors fall back to sensible defaults (white → black) so non-RGB themes still get *some* gradient. Five unit tests cover endpoints, midpoint, alpha clamping, and the non-RGB fallback.
- Grid uses `·` (middle dot) at quartile-spaced rows and columns, colored 20% from `bg` toward a neutral gray so it sits well below the data on every theme.

## [0.20.0] - 2026-05-23

### Added — DPI protocol breadth

Nine new application-layer classifiers complete the long-tail of common
LAN / IoT / ops protocols that previously rendered as generic "TCP" /
"UDP" with port-number labels:

- **MQTT** (TCP/1883, /8883) — IoT pub/sub. Decodes the variable-length
  fixed header, recognizes CONNECT packets, extracts the MQTT 3.1 /
  3.1.1 / 5.0 client-id when present.
- **STUN** (RFC 5389, any UDP) — NAT-traversal / WebRTC. Magic-cookie
  (0x2112A442) check at offset 4 makes detection unambiguous; surfaces
  the message method + class (e.g. `BindingRequest`,
  `BindingSuccessResponse`, `AllocateErrorResponse`).
- **BitTorrent** (TCP, any port) — BEP 3 peer-wire handshake. Detects
  the 19-byte protocol-string magic + 8 reserved bytes; extracts the
  20-byte info-hash and renders as 40-char hex.
- **NetBIOS** — three flavours: name service (UDP/137), datagram
  service (UDP/138), session service (TCP/139). Surfaces the message
  type per flavour (e.g. `Session Request`, `Name Query`,
  `Datagram Direct Unique`).
- **SNMP** (UDP/161, /162) — ASN.1 BER decoder for the SEQUENCE +
  INTEGER (version) + OCTET STRING (community) prefix. Surfaces
  version `v1` / `v2c` / `v3` and the community string for v1/v2c —
  useful both for "what monitoring traffic is on this network" and as
  a security tell when default communities like `public` / `private`
  appear in plaintext.
- **SSDP** (UDP/1900) — UPnP service discovery. HTTP-like text parser
  recognizes `M-SEARCH`, `NOTIFY`, and 200 OK responses; extracts the
  search target (`ST:` / `NT:` header value).
- **FTP** (TCP/21, control channel) — recognizes 3-digit server reply
  codes (`220`, `230`, `530`, …) and a curated allowlist of client
  command verbs (USER, PASS, RETR, STOR, LIST, …) so HTTP/SMTP banners
  starting with "220 …" don't get misclassified.
- **LLMNR** (UDP/5355) — Link-Local Multicast Name Resolution.
  Wire-format-identical to DNS so the existing DNS parser is reused,
  rebadged as `Llmnr` when port 5355 is on the flow.
- **IGMP** (IP protocol 2) — multicast group management. Doesn't create
  a stream (no TCP/UDP), but the Packets-tab INFO column now decodes
  the message type (`Membership Query`, `v2 Membership Report`, `Leave
  Group`, etc.) and the group address.

### Changed
- `AppProtocol` enum gained 8 new variants (everything except IGMP,
  which lives at the IP layer). Variants serialize via existing
  `#[serde]` derives so Flight Recorder bundles remain
  forward-compatible.
- `classify_once` now takes `src_port` and `dst_port` so port-locked
  classifiers (LLMNR vs. DNS, SNMP, MQTT, NetBIOS, SSDP, FTP) can
  dispatch correctly without expanding the per-classifier signature.
- Connections-tab `APP` column, filter prefixes (`app:mqtt`,
  `app:snmp`, `app:ssdp`, …), Packets-tab `INFO` column + L7
  color-coding, all updated to render the new protocols.

### Notes

This substantially broadens DPI protocol breadth. After v0.20.0 netwatch
has 13 shipped classifiers (TLS / QUIC with Initial decrypt / DNS / HTTP /
SSH / MQTT / STUN / BitTorrent / NetBIOS / SNMP / SSDP / FTP / LLMNR) +
IGMP at the IP layer + 25 port labels — covering the operationally common
protocols, plus QUIC Initial-decryption depth that most terminal tools
don't attempt.

37 new unit tests across the 8 classifier files cover the success
case, the rejection of look-alike traffic (HTTP on FTP port, garbage
bytes on STUN port, etc.), and protocol-side variation (CONNECT vs
non-CONNECT MQTT, v1 vs v2c SNMP, M-SEARCH vs NOTIFY SSDP).

## [0.19.0] - 2026-05-23

### Added
- **TCP retransmit + out-of-order analytics per stream.** Every TCP segment now updates a per-direction high-water sequence number on its flow. Segments whose `seq + payload_len` lands behind that mark are classified by how far behind:
  - **Retransmit** when the gap exceeds `OOO_WINDOW_BYTES` (64 KB) — the sender is resending bytes the other side has effectively already received.
  - **Out-of-order** when the gap is smaller — network reorder, not retransmission.
  Pure ACKs (zero payload) are excluded so duplicate keep-alives don't inflate the count. 32-bit wraparound is handled with signed-diff arithmetic so long sessions (>2 GB per direction) still classify correctly.
- **Visible per row on the Connections tab.** When a flow has retransmits, the STATE cell renders `ESTAB… ↻N` in the error color; OOO-only flows render `ESTAB… ↹N` in warn color. Operators can scan a busy table and immediately see which flows are unhealthy without drilling into Stream View.
- **Per-direction breakdown in Stream View** (Enter on a connection → status bar). Shows `RETX:N (↑A ↓B)` and `OOO:N (↑A ↓B)` so the split between sender-side and receiver-side anomalies is visible.
- Six unit tests in `src/collectors/packets.rs` cover the classification: retransmit-far-behind, OOO-small-jump, pure-ACK-not-counted, forward-progress, per-direction tracking, and 32-bit wraparound.

### Changed
- `CapturedPacket` gained a `tcp_seq: Option<u32>` field; the transport-result tuple gained the seq element. `StreamTracker::track_packet` takes a `tcp_seq` parameter. The data flows from `parse_tcp` through `parse_transport` → `parse_ipv4_packet` / `parse_ipv6_packet` → `track_packet`.
- `Connection` struct gained `retransmits: u32` and `out_of_order: u32` fields, sourced from a new `StreamTracker::snapshot_anomalies()` snapshot during the connection collector's update tick. Both default to 0 via `#[serde(default)]` so on-disk Flight Recorder bundles and stored configs remain forward-compatible.

### Notes
This adds per-stream TCP retransmit / out-of-order analytics — health signals that previously meant dropping to a full packet analyzer. Combined with the v0.18.x sandbox arc, it strengthens netwatch's live-forensics edge; remaining areas to grow are DPI long-tail breadth (MQTT/BitTorrent/SNMP/…), smart staleness coloring, Windows/FreeBSD native process attribution, and distribution breadth.

## [0.18.1] - 2026-05-23

### Changed
- **Traceroute now uses a native UDP+TTL implementation on Linux** instead of shelling out to `/usr/bin/traceroute`. Same root cause as the ping rewrite in v0.18.0: Landlock sets `PR_SET_NO_NEW_PRIVS=1`, which makes the kernel ignore the setcap on the system `traceroute` binary, so the subprocess returned EPERM under sandbox and the Topology view's hop list stayed empty. The new path opens a plain UDP socket, enables `IP_RECVERR`, and reads ICMP Time Exceeded / Port Unreachable replies from the kernel's error queue via `recvmsg(MSG_ERRQUEUE)` — no capabilities required.
- Implementation note: `SO_RCVTIMEO` does not apply to error-queue reads, so the inner loop uses `poll(POLLERR)` with a 1 s deadline per probe to wait for the kernel to queue the ICMP error. Each probe targets a unique destination port (`33434 + ttl*3 + probe`) so the kernel can correlate the response back, matching the wire-level behaviour of the classic Van Jacobson traceroute.
- Subprocess `traceroute` / `tracert` paths are preserved for IPv6 targets (the native path is IPv4-only today; IPv6 follows similar logic with `Ipv6RecvErr` and `IPV6_UNICAST_HOPS` and is tracked for later), for macOS (which lacks `IP_RECVERR` / `MSG_ERRQUEUE` in its BSD-derived stack), and for Windows.

### Fixed
- **Topology view hops now populate under the sandbox.** Verified end-to-end on Linux against `1.1.1.1` (4 hops: orb-gateway → home-router → ISP next-hop → target, RTTs matching system `traceroute` exactly) and `192.168.0.54` (2 hops, target reached at hop 2). `examples/traceroute_under_sandbox.rs` reproduces the test.

### Notes
- Together with v0.18.0's native ICMP ping, the v0.17.x sandbox feature now has no known UX regressions versus v0.16.x. Both `health probes` and `topology` work with `Landlock ABI Vx, 4 caps dropped` active. The `--no-sandbox` workaround for either feature is no longer required.

## [0.18.0] - 2026-05-23

### Changed
- **Health probing now uses native DGRAM ICMP instead of `Command::new("ping")`.** The v0.17.x sandbox sets `PR_SET_NO_NEW_PRIVS=1` before applying Landlock (required by the kernel for unprivileged use), and `NO_NEW_PRIVS` causes the kernel to ignore the setcap on `/usr/bin/ping` on execve — so the subprocess fallback returned EPERM and both gateway and DNS RTTs sat at "0.0 ms / 100% loss" while the sandbox was active. The new path opens a `SOCK_DGRAM` `IPPROTO_ICMP` (and `IPPROTO_ICMPV6`) socket directly via `nix`, which gates on `net.ipv4.ping_group_range` (default `0 2147483647` on most distros — i.e. any user) instead of `CAP_NET_RAW`, so it works under sandbox without any capability requirement.
- The subprocess `ping` path is preserved as a fallback for systems where DGRAM ICMP isn't permitted (`ping_group_range` set to a restrictive range) and for Windows.
- Verified end-to-end on Linux under best-effort sandbox: `cargo run --example ping_under_sandbox -- 192.168.0.54` returns a clean RTT (3.25 ms in a representative LAN measurement) with Landlock ABI V7 active and `NO_NEW_PRIVS=1` set.

### Fixed
- **Gateway ping + DNS RTT no longer blank under the sandbox** (the regression flagged on v0.17.1). Net effect: with v0.17.1 you had to choose `--no-sandbox` to see health metrics; in v0.18.0 the default-on sandbox and health probing both work together.

### Notes
- The `Topology` tab's `traceroute` hops are still subprocess-based and will hit the same `NO_NEW_PRIVS` issue. That's a separate rewrite (UDP+TTL probes in-process) tracked for a later release. Workaround until then: traceroute renders correctly with `--no-sandbox`, and the rest of the Topology tab (gateway dot, ISP detection, color-coded edges) works under sandbox.

## [0.17.1] - 2026-05-23

### Fixed
- **Sandbox no longer breaks the Dashboard / Interfaces tabs on Linux.** The v0.17.0 Landlock allow-list omitted `/sys`, `/bin`, `/sbin`, `/usr` (the executable + library roots), and `/etc/{passwd,group,os-release,ld.so.*}` — so any reads from `/sys/class/net/*/{statistics,operstate,carrier,mtu,address,wireless}` returned EACCES, every subprocess (`ss`, `lsof`, `ip`, `traceroute`, `whois`) failed to execve under the policy, and `getaddrinfo` couldn't load NSS modules. The interface-info reader in `src/platform/linux.rs` swallows those errors via `unwrap_or_default()`, so the symptom was "everything blank" rather than a visible error in the log.
- The allow-list now covers `/proc`, `/sys`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, plus a narrow set of `/etc/*` files for NSS / TLS / time (deliberately narrow so a sudo'd netwatch still can't read `/etc/shadow` or `/etc/sudoers` through the sandbox), plus `/run/systemd/resolve` and `/run/dbus`. RW restriction (cache dir, CWD, `/tmp`, `/run/user/<uid>`) is unchanged.

If you hit the v0.17.0 regression, `netwatch --no-sandbox` was a working workaround; v0.17.1 makes that unnecessary.

## [0.17.0] - 2026-05-23

### Added
- **Security sandbox (Linux).** After pcap, PKTAP, and the eBPF kprobe finish setup, netwatch now restricts its own authority so a memory-safety bug in DPI parsing (the largest unsafe surface) cannot read SSH keys, exfiltrate arbitrary files, or pivot via new raw sockets. Two layers, applied in order:
  - **Capability drop** via the `caps` crate: `CAP_NET_RAW`, `CAP_BPF`, `CAP_PERFMON`, and the legacy `CAP_SYS_ADMIN` BPF fallback are removed from the Effective, Permitted, and Inheritable sets. The kprobe is already attached and the pcap fd is already open; the process never needs those capabilities again. Running without elevation (no `setcap`, no `sudo`) is a clean no-op.
  - **Landlock filesystem restriction** via the `landlock` crate, targeting ABI V4 with graceful BestEffort degrade to V3 / V2 / V1 on older kernels. The ruleset allows reads from `/proc`, the system resolver files (`/etc/resolv.conf`, `/etc/hosts`, `/etc/services`, `/etc/nsswitch.conf`, …), zoneinfo, CA bundles, NSS-module dirs, the user's `~/.config/netwatch/` and any configured GeoIP DB parent dirs; allows writes only to `~/.cache/netwatch/` (logs + Flight Recorder bundles), the startup CWD (PCAP exports), `/tmp`, and `/run/user/<uid>`. Everything else fails with `EACCES` at the kernel — independent of DAC.
- **Three enforcement modes**, selectable via CLI:
  - **default (best-effort)**: apply what the kernel supports; log a single warning if Landlock isn't enforced (e.g., kernel <5.13 or LSM not enabled). Don't refuse to start.
  - **`--no-sandbox`**: escape hatch for debugging; skips both cap drop and Landlock.
  - **`--sandbox-strict`**: refuse to start if any platform-supported restriction can't be applied. Intended for production deployments where the operator wants a hard guarantee.
- **Settings overlay sandbox row** — read-only info line showing the live enforcement state, e.g. `best-effort: Landlock ABI V4, 3 caps dropped`. Users can confirm the sandbox actually applied at runtime rather than trusting the README claim.
- **`examples/sandbox_smoke.rs`** — a runnable Linux smoke test that applies the sandbox in BestEffort mode and then exercises four real accesses: read `/proc/self/status` (allowed), read `/etc/shadow` (expected EACCES), open a raw socket (expected EPERM), print the enforcement report. Exits non-zero on any unexpected outcome. Used in dev to verify Landlock is actually enforcing.

### Notes

The sandbox is **Linux-only by design**, not Linux-first. macOS Seatbelt and Windows restricted-token are intentionally not on the roadmap. The threat the sandbox defends against — exploitable DPI parsing of hostile traffic — is a production-capture-host concern, not a dev-workstation one. Spending the budget on per-platform sandboxes for feature-matrix parity with neighbouring tools would dilute focus without buying users meaningful security. Landlock network blocking (TCP bind/connect denial on ABI V4) is also deferred: a blanket TCP-block would silently break the ip-api.com GeoIP fallback, `--remote` metric streaming, and inline WHOIS lookups. A future revision can add per-port allow-listing once those endpoints are reachable behind a stable list.

## [0.16.2] - 2026-05-20

### Fixed
- **USB-Ethernet adapters no longer mislabeled as Wi-Fi on the Interfaces tab** (#30). macOS hands out `en*` names to both the built-in Wi-Fi adapter and to USB / Thunderbolt Ethernet dongles, so the old name-prefix classifier flagged everything starting with `en` as `"wifi"` — the Dashboard at least hedged with `"ethernet/wifi"`, which made the two tabs visibly disagree. We now ask the OS what the adapter actually is and propagate that through a new `is_wireless` field on `InterfaceInfo`:
  - **macOS**: parses `networksetup -listallhardwareports` and matches BSD device → `Hardware Port: Wi-Fi` (or legacy `AirPort`).
  - **Linux**: presence of `/sys/class/net/<name>/wireless` (kernel-authoritative).
  - **Windows**: adapter-header type from `ipconfig /all` (`Wireless LAN adapter` vs `Ethernet adapter`).
  Wired adapters now render as `ethernet` everywhere; the `"ethernet/wifi"` hedge survives only as the fallback when detection is unavailable. The two duplicate `role_for()` helpers in `ui/interfaces.rs` and `ui/dashboard.rs` have been collapsed into one — the divergence between them was what produced the inconsistent labels in the first place.

## [0.16.1] - 2026-05-18

### Fixed
- **Shift+W now actually shows whois on the Connections tab** (#29). The keybinding was wired up and the help overlay advertised it, but the Connections UI never rendered the resolved cache entry — only the Packets tab did. The lookup fired silently into the background; nothing appeared in the UI. The detail strip below the connection table now shows `WHOIS  netname │ org │ range │ country` plus an optional description line, mirroring the existing Packets-tab format.

## [0.16.0] - 2026-05-17

### Added
- **Deep packet inspection (DPI) — see what each flow is actually doing, not just where it's going.** New `dpi` module classifies the application-layer protocol of every captured stream from its first non-trivial payload. Surfaces results across the entire UI:
  - **Connections tab** gets a new `APP` column showing `HTTPS api.anthropic.com` / `QUIC youtube.com` / `DNS example.com` / `SSH-2.0-OpenSSH_9.0` per row.
  - **Packets tab** `INFO` column shows the same DPI summary per packet (with subsequent packets on a flow inheriting the cached classification), and rows are color-coded by L7 protocol (cyan HTTPS/QUIC, green HTTP, brand DNS, yellow SSH) so the eye can group flows at a glance.
  - **Dashboard TOP CONNECTIONS** panel substitutes the DPI hostname for the raw remote IP — `172.217.x.x` becomes `youtube.com`, grouping collapses by service rather than per remote address.
  - **Packets tab detail pane** now decodes QUIC v1/v2 Initial packets: derives Initial keys via HKDF, strips header protection, AEAD-decrypts, and surfaces the inner frame structure (`CRYPTO offset=0 len=600`, `PADDING bytes=584`, etc.). This is the differentiator vs. peers — most network TUIs can't decrypt QUIC, so they can't show what's inside a QUIC Initial at all.
  - **Filter prefixes** in the Packets and Connections tabs: `app:tls`, `app:quic`, `app:dns`, `sni:reddit.com`, `host:api.example.com`. Same syntax across both tabs.
- **TLS classifier** — parses ClientHello via `tls-parser`, extracts SNI hostname + ALPN protocol. TLS 1.0–1.3.
- **QUIC classifier** — implements full RFC 9001 (QUIC v1) and RFC 9369 (QUIC v2) Initial-packet decryption: HKDF-Expand-Label key derivation, AES-128-ECB-derived header-protection mask, AES-128-GCM AEAD with `nonce = iv XOR pn`, CRYPTO-frame walk. Reuses the TLS classifier on the reassembled ClientHello to extract SNI.
- **Cross-packet QUIC reassembly** — Chrome's modern ClientHellos commonly span multiple Initial packets; the SNI extension can land in fragment 2+. We buffer CRYPTO frames per-stream and retry SNI extraction across packets, capped at 16 KB of accumulated buffer.
- **DNS classifier** — hand-rolled wire-format parser for the first question's qname + qtype. Handles plain DNS-over-UDP, mDNS (5353), LLMNR (5355). Refuses compression pointers in the question section to keep parsing linear-time.
- **HTTP classifier** — `httparse`-backed request-line + Host-header extraction.
- **SSH classifier** — server/client banner-line capture (`SSH-2.0-OpenSSH_9.0`).
- **`extract_udp_app_payload`** public helper on the packets collector — the UI uses it to feed a captured packet's bytes back through the QUIC decrypt pipeline for the detail-pane frame breakdown.

### Changed
- **Connections tab refresh cadence** moved from 2 s to 1 s. The `busy` flag still coalesces under load, so the effective cadence becomes `max(tick, lsof_duration)`. New flows now appear within a second of opening on the wire.
- **Local-only join fallback for wildcard-remote UDP connections.** `lsof` on macOS commonly reports Chrome's QUIC UDP sockets with remote `*:*` even when the kernel has a specific peer. The strict 5-tuple stream join used to drop those — now we fall back to matching by local endpoint, attaching the DPI tag from whichever Stream owns the same local port. For QUIC this is unambiguous (one flow per ephemeral local port) and is the path that lets the APP column light up at all for browser traffic.
- **307 tests pass** (up from 296), 33.8% line coverage / 44.4% function coverage. New DPI classifiers shipped with their own unit tests (dns 94%, tls 82%, quic 63% incl. the RFC 9001 Appendix A.2 end-to-end test vector that exercises every layer of the decryption stack).

### Fixed
- **macOS no longer falsely shows "eBPF active"** (this is the v0.15.12 hotfix already released earlier today; preserved here for completeness). The dashboard footer now reads live attribution state via `attribution_status()` and shows `pktap active` on macOS instead of the placeholder.
- **Demo GIF re-recorded** with the agg/asciinema pipeline so the README capture reflects the v0.15.x UI layout cleanly.

## [0.15.12] - 2026-05-17

### Fixed
- **Dashboard footer now reports the real attribution path** — The `eBPF active` / `eBPF off` indicator was reading a boot-time placeholder field that was always set to `Active` whenever the `ebpf` feature compiled in. Since the feature is `default = ["ebpf"]` and the field was never updated from the placeholder, every macOS build falsely advertised "eBPF active" even though eBPF is Linux-only. The footer now reads live state via `App::attribution_status()`, which already knows per-OS what's actually doing kernel attribution. macOS shows `pktap active` (the actual mechanism), Linux shows `eBPF active` only when the BPF object loaded successfully, and unprivileged Linux fallbacks show `eBPF off` or `lsof attr` correctly.

## [0.15.11] - 2026-05-17

### Added
- **Two new themes: `sky` and `paper`** — both paint panel backgrounds rather than letting the terminal show through. `sky` is a calm cool-blue dark theme; `paper` is a light theme with AAA-contrast data colors tuned against off-white. Cycle themes from settings or pass `--theme paper`.
- **Graceful recovery from poisoned mutexes** — A panic inside a critical section used to leave shared state in a `PoisonError` state and ripple downstream panics across the whole UI thread. We now `unwrap_or_else` on poisoned guards by clearing the inner state and continuing, so a single panic in a collector doesn't take the TUI with it.
- **Structured file-only logging** — Diagnostic logging now writes to a configurable file rather than stderr (which fights the TUI for the terminal). Levels and target file controllable via env vars. Off by default so the binary still has zero non-UI output.

### Changed
- **Refactored hot-path state into snapshot pattern** — `AppCaches` and `AppUiState` extracted out of the monolithic `App` struct, with hot reads on the UI thread going through cheap snapshots instead of holding the collector lock. Eliminates the occasional input-lag stutter under bursty traffic.

### Fixed
- **Help dialog now respects the active theme** — Previously rendered with hard-coded colors that clashed on `paper` and `sky`. Now derives all colors from the theme palette like every other panel.
- **`paper` popup backgrounds inherit the painted bg** — Settings, help, and confirmation popups were transparent on `paper`, exposing whatever sat behind them. They now paint their own background to match the theme.
- **`paper` data colors meet AAA contrast against off-white** — Several greens and blues failed contrast checks; darkened to compliant variants.
- **Packets tab block titles match the rest of the UI** — They were dim regular weight; now brand-color bold like every other tab's titles. Consistency fix.
- **Default fg set alongside bg** so unstyled spans inherit the theme's text color rather than the terminal's default (which broke `paper` and looked wrong on `sky`).
- **`minimal` theme** (previously `light`) renamed to reflect its constraint — it defers to the terminal's palette for body text, which is the right call for terminals with custom palettes but isn't truly "light." Subsequently deleted entirely after testing showed it duplicated `dark` on the only terminal where it rendered correctly.
- **`process_bandwidth` test de-flaked** for CI — byte-accumulation test was timing-sensitive and intermittently failed under loaded runners.

## [0.15.10] - 2026-05-13

### Added
- **Per-process bandwidth uses real per-connection rates** — Previously the Stats "TOP PROCESSES by RX" panel and the Processes tab split total interface bytes proportionally to each process's *connection count*. With most processes holding a single connection this gave every process an identical fictional slice. The collector now aggregates each connection's measured `rx_rate`/`tx_rate` per `(process, pid)` and accumulates cumulative bytes by integrating rate × elapsed across ticks, with stale entries pruned after 5 minutes. The panel only shows real data; processes with no measured traffic report 0 instead of an equal fake share.
- **`setcap` Linux install path documented** — README now explains the `sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip'` recipe so users can run netwatch without sudo and still get packet capture + eBPF process attribution. Capability table in the README clarifies what each cap unlocks.
- **mimalloc as the global allocator** — Replaces glibc's `ptmalloc` on Linux (and the system allocator everywhere else). Long-running TUI daemons that spawn short per-tick threads pay a noticeable RSS tax to ptmalloc's per-thread arena retention; mimalloc returns memory to the OS more aggressively and meaningfully reduces the steady-state baseline. Functionally transparent.
- **Memory-cap diagnostic overlay** — Press `M` to surface every bounded in-memory collection alongside its current fill ratio, so long-running sessions can verify the caps actually hold under load. Diagnostic tool, documented in the help dialog only.

### Fixed
- **UI no longer flickers between traffic bursts** — Dashboard "ACTIVE INTERFACE" `N live N idle` badge, the Interfaces tab's filter and per-row dot, and the Stats top-processes panel all judged "is this active?" by comparing the current-tick rate to 0. Rates are genuinely 0 most ticks even on busy interfaces, so badges, dots, and counts flapped every refresh. New shared `widgets::interface_recently_active` helper checks the last few history samples instead. Top-processes accumulates bytes across ticks (above) so the panel stays populated through idle moments instead of flashing then emptying.
- **Stats "TOP PROCESSES by RX" no longer shows 0-byte entries** — Panel was reading `process_bandwidth.ranked()` directly, which is sorted by combined RX+TX rate. A TX-heavy process with no RX traffic could land in the top 5 and render as `<name> — 0 KB`. Re-sorted locally by `rx_bytes` and zero-RX entries filtered out before taking the top 5.
- **Connections tab: clicking a row now selects that row (#28)** — Mouse hit-test had two bugs: the content-top arithmetic missed the 2-row chip strip and 10-row detail strip, and the new selection was computed as `connection_scroll + visible_row` (relative to the previously-selected row) instead of `window_top + visible_row` (relative to the visible window). Result: clicking the top visible row at scroll>0 didn't change the selection, and clicking deeper rows landed on rows further down than intended, often scrolling the view as the new selection re-centered. Renderer and handler now share `table_inner_area` and `compute_window_top` helpers from `ui::connections`. Reported by @sliddjur.
- **Clearer error when `traceroute` isn't installed** — Topology's auto-traceroute returned a bare "No such file or directory" on Linux distros that don't include `traceroute` (e.g. Ubuntu default). Now surfaces a distro-aware install hint instead.

## [0.15.9] - 2026-05-12

### Changed
- **`cargo install netwatch-tui` now ships eBPF too** — bumped the `netwatch-sdk` dep to 0.1.2, which carries a pre-built `netwatch_sdk_ebpf.o` (2424-byte eBPF ELF) directly in the published crate. The SDK's `build.rs` embeds it via `include_bytes!` automatically, so any Linux build picks it up without needing nightly Rust + bpf-linker + LLVM 18 on the consumer side. Closes the remaining gap from v0.15.8 where only `brew install` and direct tarball downloads got eBPF.
- **Release workflow simplified** — dropped the now-redundant "Build netwatch-sdk eBPF object" + `[patch.crates-io]` step. The Linux release tarballs still get the same BPF object, but via the published SDK instead of an in-workflow clone-and-build.

## [0.15.8] - 2026-05-10

### Fixed
- **Linux release tarballs now ship with the eBPF BPF object embedded** — the v0.15.6 attempt failed because netwatch-sdk's `crates/ebpf-programs/rust-toolchain.toml` listed `bpfel-unknown-none` as a target, making rustup try to download `rust-std` for a tier-3 target that has no precompiled artifact. SDK fix landed at netwatch-sdk@48f8960; netwatch's release workflow re-enables the BPF build step (clone SDK, install bpf-linker, run `scripts/build-ebpf.sh`, then `[patch.crates-io]`-override the SDK so cargo build picks up the local copy with the BPF object embedded). Linux users downloading the tarball or installing via Homebrew now get kernel-attributed PIDs out of the box; `cargo install netwatch-tui` users still fall back to lsof until the SDK starts shipping the pre-built `.o` on crates.io directly.

## [0.15.7] - 2026-05-10

### Fixed
- **v0.15.6 release was broken** — the new "Build netwatch-sdk eBPF object" step in the release workflow tried to install the SDK's pinned nightly (`nightly-2026-01-15`) but rustup couldn't fetch `rust-std` for `bpfel-unknown-none` on that date (intermittent nightly-channel coverage gap). The first Linux build job failed and `fail-fast` cancelled everything else, so no v0.15.6 binaries shipped. v0.15.7 reverts the workflow's BPF build step; Linux release tarballs ship with the `ebpf` feature compiled in but the BPF object missing, so `EventSource::new` returns `BpfObjectMissing` at runtime and netwatch falls back to lsof/ss attribution. macOS PKTAP is unaffected. The actual BPF-shipping fix is now blocked on bumping the SDK's pinned nightly (and ideally the SDK starts shipping the pre-built `.o` on crates.io directly).

## [0.15.6] - 2026-05-10

### Added
- **Kernel-level Linux process attribution via netwatch-sdk eBPF** — On Linux, netwatch now loads a `tcp_v4_connect` kprobe (via [`netwatch-sdk`](https://crates.io/crates/netwatch-sdk) Phase 1) that captures `(pid, comm, src/dst, dst_port)` for every outbound TCP connect at kernel time. The Connections collector overlays those attributions onto rows from `ss`/`lsof` polling — same shape as the macOS PKTAP integration — which catches sub-2-second flows that polling misses and reports the actual *thread* `comm` rather than the parent binary's name. The Connections header now shows `attribution: ebpf` (green) when the kprobe is loaded or `attribution: lsof — ebpf unavailable: …` (warn) with the specific reason when it fell back; the per-row bullet glyph swaps to `◉` for kernel-attributed rows. Requires `CAP_BPF` + `CAP_PERFMON` (or root) and kernel ≥ 5.10. The Linux release tarballs ship with the BPF object pre-embedded (the release workflow runs the SDK's `scripts/build-ebpf.sh` and builds netwatch against a `[patch.crates-io]` override that picks up the artifact). For `cargo install netwatch-tui` users on Linux, eBPF currently falls back to `BpfObjectMissing` until the SDK starts shipping the BPF object on crates.io directly — a separate piece of work.

### Changed
- The `ebpf` feature is now on by default. Builds gracefully fall back to lsof/ss attribution when the platform can't load eBPF — non-Linux hosts (returns `UnsupportedPlatform`), missing capabilities, kernel < 5.10, or the BPF object isn't embedded. macOS continues to use PKTAP for its kernel-attribution path; both sources flip `Connection.attribution` so the renderer can flag them uniformly.

## [0.15.5] - 2026-05-10

### Added
- **Reliable QUIC SNI extraction (RFC 9001 + RFC 9369)** — The Packets tab now decrypts QUIC v1 and v2 Initial packets per the spec and surfaces the embedded TLS ClientHello's `server_name` extension on the row. Previously netwatch had a heuristic that scanned the Initial payload for a cleartext ClientHello pattern, which doesn't work because real Initials are AEAD-protected with keys derived from the Destination Connection ID; that heuristic always returned `—` on real-world traffic. The new implementation does the full HKDF-Expand-Label key derivation, AES-128 header protection removal (via `ring::aead::quic`), AES-128-GCM payload decryption, and CRYPTO frame reassembly. Verified against RFC 9001 Appendix A.1 (key derivation byte-match) and Appendix A.2 (full sample packet → `example.com` SNI). Lives in the new `src/collectors/quic.rs` module; `ring 0.17` promoted from transitive to direct dep.

## [0.15.4] - 2026-05-10

### Fixed
- **Second memory-leak source for non-sudo Linux runs** — `TrafficCollector::interfaces()` was deep-cloning the full per-interface state (including each interface's two 600-sample history `VecDeque`s) on every call, ~96 KB per call on a 10-interface host. The Dashboard alone hit it 4 times per render and `App::tick()` another 6, totalling ~10 calls/sec ≈ 1 MB/sec of allocation churn. On Linux, glibc's per-thread arena retention turns that churn into climbing RSS even though no logical leak exists in the data structures. The accessor now returns `Arc<Vec<InterfaceTraffic>>` and `update()` swaps in a fresh `Arc` each tick — reads are a single atomic refcount bump regardless of interface count or history depth. `har5ha` reported continued RSS climb on v0.15.3 (~115 MB after 90 min on Dashboard-only); this addresses the source the v0.15.1 packet-pipeline fix couldn't reach because pcap is dormant without root. Reported in #27.

## [0.15.3] - 2026-05-09

### Added
- **Kernel-level process attribution on macOS via PKTAP** — netwatch now opens xnu's `pktap` pseudo-device alongside the regular packet capture (when running with sudo) and harvests `(pid, comm, direction)` straight from the kernel for every captured frame. The Connections, Dashboard, Topology, Timeline, and Insights tabs all consume this attribution, so short-lived flows that close inside one lsof poll window — `curl` to a CDN, a DNS query, an mDNS announcement — now show the real owning process instead of `—`. Threaded processes whose `comm` differs from the parent get the actual thread name rather than the parent binary's. Falls back to the existing lsof/ss/netstat polling path when PKTAP can't be opened (no root, non-Apple libpcap, kernel feature missing); attribution source is tracked per-row via a new `AttributionSource` enum (`Lsof` default, `Pktap` after kernel overlay).
- **`pktap_probe` example** — `sudo cargo run --example pktap_probe` prints attributed events as they arrive, useful for confirming PKTAP works on a given macOS build before turning on the full TUI.

### Fixed
- **PKTAP attribution on macOS 15+** — Apple renamed the libpcap symbol used to enable per-packet metadata: macOS 14 and earlier exported `pcap_set_want_pktap_pktmetadata`, macOS 15 dropped that and exports the shorter `pcap_set_want_pktap` instead. The dlsym lookup now probes both names so the same build picks up attribution across older and newer macOS without a recompile. Surfaced when the probe failed with `pcap_set_want_pktap_pktmetadata not found` on macOS 15.4.1.

## [0.15.2] - 2026-05-07

### Fixed
- **Refresh-rate setting now hot-reloads** — Changing `Refresh Rate (ms)` in the Settings popup used to require a restart because `EventHandler` captured `tick_rate` once at construction. The polling thread now re-reads an `Arc<AtomicU64>` each iteration and a saved change takes effect on the next poll cycle.
- **Filter-aware connection selection (#26)** — Under an active connection filter, `PgDn`-to-bottom left `connection_scroll` clamped against the *unfiltered* list while the table rendered the filtered list, so subsequent `UpArrow` looked stuck and mouse clicks on visible rows did nothing. All five clamp/select sites (PgDn, mouse click, `W`/`T`/`Enter` action handlers) now route through `connections::filtered_sorted_conns(app)` so the rendered view drives selection bounds.

### Changed
- **Dots graph style narrower per-sample** — One filled sub-column per sample window instead of both, with the area-fill below each sample's peak preserved. Gives the classic btop "comb" look with visible gaps between samples.

## [0.15.1] - 2026-05-05

### Fixed
- **Memory leak under sustained packet capture** — `StreamTracker` retained every unique flow for the lifetime of the process, and the per-IP `rtt_history` map plus the `rtt_sampled_streams` set grew without bound alongside it. On a busy host this drove RSS into the 1 GB+ range after roughly an hour. Stream storage is now an LRU map capped at 1024 flows (with a 256-entry watermark), `rtt_history` keys are bounded to 256 remote IPs (FIFO eviction), and the sampled-streams set self-prunes against the live tracker on every visit. The per-tick deep-clone of all streams in the RTT sampler is also gone, replaced with an in-place visitor. Reported in #27.
- **`g` toggle on the Connections tab now actually shows GeoIP** — `app.show_geo` was wired to the keybinding but only the Packets tab read it. Connections now renders a `GEO` column (country code plus city when available) between REMOTE and STATE while the toggle is on. Reported in #27.

## [0.15.0] - 2026-05-04

### Added
- **Selectable graph styles** — A new `Graph Style` setting (Settings → ←/→) cycles between `bars` (the existing solid-color stacked-block sparkline) and `dots` (a btop-style braille pixel-fill that gives 4× vertical resolution per cell). Persists to `~/.config/netwatch/config.toml` alongside the theme. Applies to every chart in the app — dashboard throughput, interface detail chart, top-connections row sparklines, RTT history, processes RX, stats throughput, and the timeline activity strip.

### Changed
- **All sparklines route through a single `graph::render` helper** — Per-call-site `Sparkline::default().data().style()` is replaced with `crate::graph::render(...)`. The timeline's three-color severity overlay shares a y-axis via `graph::render_with_max(...)` so layers stay aligned regardless of style. `dots` skips zero samples so flat-zero spans render nothing instead of a baseline floor — keeps stacked overlays clean.

## [0.14.1] - 2026-04-29

Re-spin of v0.14.0 to correct version metadata. The v0.14.0 commit on
the tag was missing the Cargo.toml/Cargo.lock bump and CHANGELOG entry
(staging mistake), so the binaries shipped under v0.14.0 reported
themselves as `0.14.0-rc.3` internally and `cargo publish` rejected the
duplicate. v0.14.1 ships the same feature set with consistent version
metadata across all release channels.

No code changes vs. the intended v0.14.0 — the whole "what's new"
section below applied to that release and applies here.

## [0.14.0] - 2026-04-29

### Added
- **Topology view, redesigned** — Local addresses (this host + LAN peers) anchor the left side of the graph, public Internet peers on the right, with ROUTER → ISP as the spine in the middle. Each spine box has a colored health dot pinned to its trunk so router/ISP status is visible at a glance. PR #24.
- **Auto-traceroute on launch** — A one-shot traceroute to `1.1.1.1` is kicked at startup so the ISP gateway hop populates the topology view without requiring the user to press T. Manual `T` against the selected remote still works.
- **Real RTT and CPU on Processes tab** — Per-process kernel RTT (min across the process's TCP connections) and CPU% are now wired through to the Processes tab, with rolling history sparklines.
- **Timeline detectors** — Timeline flags RTT spikes and interface flap events as discrete activity entries.

### Changed
- **Whole-app design pass** — Dashboard, Connections, Interfaces, Packets, Stats, Topology, Processes, and Insights tabs reworked around the v0.14 design pack. Visual hierarchy, typography, and color usage are now consistent across tabs.
- **Throughput sparkline fills wide terminals** — Sparkline history was capped at 60 samples (60s @ 1Hz) but the chart could render ~94 cells on a 1200-px terminal, leaving ~36% empty space on the left. History is now capped at 600 samples (10 min). The throughput chart title reflects what's actually drawn (`last 60s` on narrow terminals, `last Nm` on wider ones).
- **Throughput KPI trend window stays short** — Even with the history extension, the KPI tile's trend arrow continues to compare only the most recent ~minute, so the arrow stays responsive instead of smoothing across the full 10 min.

### Notes
First non-RC tag in the 0.14 line. Stable `cargo install netwatch-tui` and `brew upgrade` will both pick this up; `0.14.0-rc.1`/`-rc.2`/`-rc.3` remain on crates.io for anyone pinning to a specific RC.

## [0.13.0] - 2026-04-23

### Added
- **Per-tab sort picker** — Press `s` on Dashboard, Connections, Interfaces, or Processes to open a sort picker overlay. Navigate with `↑↓` or `j/k`, `Enter` to apply, `S` to toggle ascending/descending, `/` to filter columns by name, `Esc` or `s` to close. Each tab remembers its own sort state. Dashboard and Interfaces sort once at render so the sparkline and the table stay index-aligned. #20, #21
- **Comprehensive sort test coverage** — ~38 new tests covering per-tab sort integration, `cmp_ip_addr` (IPv4/IPv6/brackets/wildcards/port tiebreakers), `cmp_f64` (NaN-safe via `total_cmp`), case-insensitive comparators, picker cursor/filter edge cases, and meta-tests that fail CI if a new column is added without a matching comparator arm. #22
- **Vim-style navigation keys** — `j`/`k` alias `↓`/`↑` for list/stream/help/settings scrolling; `h`/`l` alias `←`/`→` for settings theme and default-tab selectors. Arrow keys continue to work unchanged. Stream view's existing `h` (toggle hex/text mode) is preserved. Fixes #18.

## [0.12.5] - 2026-04-21

### Changed
- **Case-insensitive process-name sort in Connections** — The Connections tab's Process column now sorts case-insensitively, so `Finder`, `facetime`, and `kernel_task` interleave in dictionary order instead of splitting into two alphabetical runs. Case-only differences use byte-wise order as a deterministic tiebreaker. Fixes #16.

### Removed
- **Misleading `s:Sort` hint on Processes tab** — The hint was never wired up (the Processes tab is always sorted by total bandwidth descending via the bandwidth ranker) and is gone from the footer.

## [0.12.4] - 2026-04-21

### Changed
- **Default Tab setting is now a cycler** — The "Default Tab" row in the Settings popup (`,`) now cycles through valid tabs with `←` / `→`, mirroring the Theme row. Previously it was a free-text field that required knowing (or guessing) the tab names, and the error hint listing valid values could get truncated at narrow terminal widths. Fixes #17.

## [0.12.3] - 2026-04-19

### Changed
- **Ocean theme — readable group-box borders** — In addition to muted text, group-box borders and separators now use the lighter `#B5B6B7` neutral so panel outlines stay legible on the `#224FBC` background.

### Reverted
- **Dashboard single-interface collapse** — The v0.12.2 behaviour that hid the Interfaces table on single-interface systems is reverted. In practice almost every machine has `lo0` and other virtual interfaces alongside the physical one, which are useful for diagnostics, so hiding the table was rarely correct.

## [0.12.2] - 2026-04-18

### Changed
- **Ocean theme — readable muted text** — `text_muted` in the Ocean theme is now a lighter neutral (#B5B6B7) so secondary labels (group headers, units, etc.) are legible against the `#224FBC` background. The previous value (Apple's bright-black slot, #818383) failed WCAG AA contrast.
- **Dashboard hides Interfaces panel when only one interface exists** — On single-interface systems, the Interfaces table collapses and Top Connections expands to fill the reclaimed space, showing more rows.

## [0.12.1] - 2026-04-18

### Added
- **Ocean theme** — New color theme tuned for Terminal.app's "Ocean" profile (bg #224FBC). Uses Apple's default Terminal ANSI palette values for legibility on the deep blue background. Set `theme = "ocean"` in `~/.config/netwatch/config.toml` or switch via Settings (`,`).

### Changed
- **Integer byte/rate formatting** — Byte totals and transfer rates now display as integers (e.g. `42 MB/s` instead of `42.3 MB/s`). Decimals rarely contained significant signal and added visual noise.
- **Zero values render as `-`** — Empty rates and zero totals show a dash instead of `0 B` / `0 B/s`, reducing noise in tables where many rows are idle.
- **Right-aligned numeric columns** — Rate and byte columns in Dashboard, Interfaces, Processes, and Stats tabs are now right-aligned to fixed widths, so unit suffixes stay put across rows instead of jumping as values change.

## [0.12.0] - 2026-04-18

### Added
- **Per-connection Down/Up column** — The Connections tab now shows live RX/TX rates per flow, sourced from the ambient packet capture. Sort by throughput with `s` to find the busy connection, then `Enter` to drill into its packets.
- **Ambient packet capture at launch** — NetWatch now starts capture automatically on startup (using the configured interface and BPF filter, if any). Connection rates are populated as packets arrive. If capture fails for lack of privileges, the app continues running with the Down/Up column blank.

### Changed
- **BPF filter is now config-only** — The `b` keybinding for live-editing the BPF capture filter on the Packets tab has been removed. Set a BPF filter in Settings (`,`) → BPF Filter if you need one; it applies at launch. The display filter (`/`) is unaffected.
- **Disk metrics exclude macOS internal mounts** — Remote disk metrics now skip `/Volumes/`, `/System/Volumes/`, and `/private/` mounts so APFS firmlinks no longer appear as duplicate rows.

## [0.11.3] - 2026-04-17

### Fixed
- **Processes tab empty on Linux** — Linux `ss` outputs `ESTAB` instead of `ESTABLISHED`, causing the processes and top connections tabs to show zero entries. The parser now normalizes the state at parse time.
- **Windows UI responsiveness** — Moved interface stat collection to a background thread so key bindings no longer block for 5–30 seconds on Windows.
- **Atomic ordering** — Relaxed traffic collector busy-flag from `SeqCst` to `Acquire`/`Release`.

## [0.10.0] - 2026-04-11

### Added
- **AI Insights tab** — Restored as an opt-in feature (off by default). Enable in Settings (`,`) → AI Insights: on. Analyzes live packet data and network state every 15 seconds and surfaces security concerns, performance issues, and anomalies as bullet-point summaries.
- **Configurable AI endpoint** — Supports local Ollama (`local`, default) and any remote endpoint (Ollama Cloud or custom proxy) via the AI Endpoint setting. Point it at a cloud URL to skip local model setup entirely.
- **AI settings in the Settings overlay** — Three new settings: AI Insights (on/off), AI Model (default: `llama3.2`), AI Endpoint (`local` or a full base URL). Changes apply live without restart.

### Changed
- **Tab count** — Tab [9] Insights appears in the header only when AI Insights is enabled. The zero-config experience for users who don't enable it is unchanged.

## [0.9.0] - 2026-04-03

### Added
- **Flight Recorder** — Rolling 5-minute incident capture that records packets, connections, health snapshots, DNS analytics, bandwidth context, and network-intel alerts.
- **Incident bundle export** — `Shift+E` exports a bundle containing `summary.md`, `packets.pcap`, `connections.json`, `health.json`, `bandwidth.json`, `dns.json`, `alerts.json`, and `manifest.json`.
- **Manual and automatic freeze** — `Shift+F` freezes the current incident window, and critical network-intel alerts now auto-freeze an armed recorder so transient failures are preserved.

### Changed
- **Global recorder status in header** — NetWatch now shows `REC 5m` while armed and `FROZEN` after a capture window is locked.

## [0.8.1] - 2026-03-30

### Removed
- **AI Insights tab** — Removed the Ollama-dependent Insights tab. NetWatch is a sharp network tool, not an AI wrapper. The tab required external setup (Ollama + model download) that broke the zero-config promise for 95% of users.

### Changed
- **Tab count reduced from 9 to 8** — Cleaner navigation: Dashboard (1), Connections (2), Interfaces (3), Packets (4), Stats (5), Topology (6), Timeline (7), Processes (8).
- **README rewritten** — Shorter, sharper, sells the product. Install instructions above the fold. Detailed keybindings collapsed. Platform badge is honest (macOS + Linux only).
- **Hardened error handling** — Fixed `unwrap()` calls in production code paths to prevent panics on unexpected input.

## [0.8.0] - 2026-03-14

### Added
- **Processes tab** — Per-process bandwidth ranking with RX/TX rates, connection counts, and totals
- **JSON/CSV export** — Export connection data from the Connections tab
- **CI/CD pipeline** — GitHub Actions with cross-compilation for Linux (x86_64/aarch64), macOS (x86_64/aarch64), and Windows
- **Homebrew formula** — `brew install matthart1983/tap/netwatch`
- **Clippy + fmt enforcement** in CI

## [0.7.0] - 2026-02-28

### Added
- **AI Network Insights** — Ollama integration with auto-analysis every 15s
- **Connection Timeline** — Gantt-style connection lifetime visualization
- **Network Topology** — ASCII network map with health indicators
- **Traceroute** — Built-in hop-by-hop traceroute from Topology or Connections
- **Network Intelligence** — Port scan detection, beaconing detection, DNS tunnel detection
- **TCP handshake timing** — SYN→SYN-ACK→ACK latency measurement
- **Handshake histogram** — Latency distribution in Stats tab
- **Display filters** — Wireshark-style filter syntax with combinators
- **BPF capture filters** — Applied at capture time for efficient filtering
- **Stream reassembly** — TCP/UDP conversation view with text and hex modes
- **Expert info & coloring** — Automatic severity classification
- **Packet bookmarks** — Mark and jump between packets of interest
- **PCAP export** — Save captures to standard .pcap files
- **Protocol statistics** — Protocol hierarchy table
- **5 color themes** — Dark, Light, Solarized, Dracula, Nord with instant switching
- **Settings menu** — Live configuration editing with TOML persistence
- **Mouse support** — Clickable tabs, scroll wheel, row selection
- **GeoIP** — Online + offline MaxMind .mmdb support
- **Whois/RDAP** — On-demand IP lookup
- **Latency sparklines** — Per-connection RTT trend visualization

## [0.1.0] - 2025-11-05

### Added
- Initial release
- Dashboard with live interface stats and bandwidth sparklines
- Connections table with process attribution
- Interface detail view
- Network health probes (gateway + DNS)
- Packet capture with protocol decoding (DNS, TLS, HTTP, ICMP, ARP, DHCP, NTP)
- Cross-platform support (macOS, Linux)
