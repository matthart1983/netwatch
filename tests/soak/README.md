# Flood soak

The flood soak runs netwatch's real App against a packet flood for an hour.
It checks that memory stays under the documented ceiling, that the capture
caps hold, and that frames stay inside their time budget. It also measures
decode rates, drops, CPU time and frame times, which docs/PERFORMANCE.md
publishes. It needs no root. Everything runs in an unprivileged user,
network and mount namespace.

| File | What it is |
| --- | --- |
| `examples/flood_soak.rs` | The driver. A daemon session of the App with capture on the lab interface, ticked as `refresh_rate_ms` asks and drawn at 10 frames a second into a 200x50 terminal that writes to `io::sink`. It prints one JSON line a second. |
| `tests/soak/flood.py` | The generator. Writes frames to an AF_PACKET socket from the far side of the veth, or runs a real TCP bulk transfer. Standard library only. |
| `tests/soak/flood_soak.py` | The harness. Builds the namespaces, runs the driver and the generator through the schedule, runs the real `netwatch daemon`, and gates the result. |

## Running it

```sh
cargo build --release --example flood_soak --bin netwatch
python3 tests/soak/flood_soak.py --smoke             # about 5 minutes
python3 tests/soak/flood_soak.py                     # about 75 minutes
python3 tests/soak/flood_soak.py --self-test         # the gates, against canned lines
python3 tests/soak/flood_soak.py --summarise flood-soak.jsonl   # gate a saved run again
```

The harness re-execs itself under
`unshare --user --map-root-user --net --mount`. Ubuntu 24.04 refuses that
until `kernel.apparmor_restrict_unprivileged_userns` is 0. Fedora allows it
as installed. It needs `ip`, `nsenter`, `unshare` and `mount`.

`--scenarios` runs a subset. `--minutes` sets the length of both cycles
together, and `--paced-seconds` and `--daemon-seconds` the other two steps;
a `--daemon-seconds` of 0 skips the daemon. `--geoip-db` and
`--geoip-asn-db` load offline GeoIP databases into the driver and the
daemon, and a release candidate's soak runs with Country and ASN loaded.
`--calibration` takes an earlier `flood-soak.json` and fails any scenario
that decodes less than 25% of the packets a second it did there.
`--tcpreplay FILE` sends the replay scenario with tcpreplay instead of the
generator's own sender.

The driver also runs on its own, decoding only, with no namespace:

```sh
cargo run --release --example flood_soak -- --replay tests/fixtures/pcap --seconds 5
```

That loops the pcap fixtures through the capture thread's decode path, with
new addresses on every pass, and prints frames decoded a second. It builds
no App and runs on any platform.

## The lab

```text
this namespace   nw0 203.0.113.1/30   netwatch captures here; the bulk sink listens on port 5001
peer namespace   fl0 203.0.113.2/30   flood.py sends from here
```

The harness remounts sysfs so `/sys/class/net` lists this namespace's
links. The driver refuses to start unless HOME and every XDG directory
point inside the temp home the harness made, so a run never touches a real
configuration. The lab has no default route. The health probes and
resolver lookups the App makes fail inside the namespace, and nothing
leaves the host.

## Schedule

One driver process runs steps 1 and 2, so a leak shows as growth from the
first cycle to the second.

| Step | Full run | `--smoke` |
| --- | --- | --- |
| 1. Each scenario at full rate, two cycles | 5 min each, 60 min | 20 s each, 4 min |
| 2. Small UDP paced at 50,000 and 100,000 packets a second | 2.5 min each | 10 s each |
| 3. `netwatch daemon` under `mix` and `bulk` at once | 10 min | 30 s |

| Scenario | Traffic |
| --- | --- |
| `udp-churn` | 60 B UDP frames, a new 5-tuple on every frame |
| `syn-churn` | 54 B TCP SYNs, a new 5-tuple on every frame |
| `dns` | DNS queries and answers over 10,000 flows, each asking for its own name |
| `mtu-tcp` | 1514 B TCP segments over 1,000 flows, each flow in sequence, so streams fill to their byte cap |
| `replay` | The pcap fixtures with every address changed on each pass, as tcpreplay `--unique-ip` does |
| `bulk` | A real TCP connection written with `sendall`. Segmentation offload then puts frames of up to 64 KB on the veth |
| `mix` | `udp-churn`, `syn-churn`, `dns`, `mtu-tcp` and `replay`, 256 frames of each in turn |

The frame scenarios address a MAC nobody owns, so the receiving stack drops
them without answering. A real flood would also cost the kernel's network
stack. Here only capture and netwatch pay for it.

## Gates

| Gate | Passes when |
| --- | --- |
| `run` | Every step finished, and the driver exited 0 |
| `generator` | Every planned phase ran and its generator reported |
| `hwm` | The driver's VmHWM is at most 512 MiB, or `--ceiling-mib` |
| `plateau` | Cycle 2's highest VmRSS is at most cycle 1's plus 16 MiB |
| `held_bytes` | Stream bytes held are within the stream budget on every line |
| `ring_bytes` | The packet ring holds at most 32 MiB on every line |
| `streams` | At most 1,280 streams on every line |
| `threads` | Fewer than 100 threads, in the driver and the daemon |
| `capture` | Capturing, with no capture error, on every line |
| `panic` | No thread panicked, counting a parser panic that capture caught |
| `sampled` | The driver printed a line for at least 95% of the planned seconds |
| `super_frames` | A frame larger than 16 KiB reached the ring during a bulk phase. Without one, the runner's veth did no segmentation offload and the ring never held large frames |
| `frame_p99` | Every view drew, and each view's 99th-percentile frame took at most 33 ms over the run |
| `daemon_hwm` | The daemon's VmHWM is at most the ceiling |
| `daemon_capture` | The daemon held an AF_PACKET socket |
| `daemon_exit` | The daemon was still running at the end and exited 0 on SIGTERM |
| `pps_floor` | With `--calibration` only. Each scenario's median decoded rate is at least 25% of the calibration's |

Every phase reports decode rate, drops and CPU, but only `pps_floor` gates
on them. A shared runner's speed varies too much from run to run for a
tighter floor. The flight recorder stays disarmed throughout, which is the
configuration the 512 MiB ceiling is stated for.

## Output

`--out`, `flood-soak.json` by default, holds the summary. Per phase it gives
the offered rate, the median received, decoded and dropped packets a
second, drop %, CPU, peak VmRSS and VmHWM, and frame p50, p99 and max by
view. It also gives the medians by scenario across both cycles, the
daemon's figures, and every gate with its reading. The `.jsonl` beside it
keeps the raw records, one per line, each with a `kind`:

| `kind` | What it records |
| --- | --- |
| `run` | The plan, the ceiling, the commit and the host |
| `driver` | One line the driver printed |
| `phase` | A phase's first and last driver second and the generator's report |
| `daemon` | One second of the daemon's /proc figures |
| `daemon_end` | Whether the daemon held a packet socket, and how it exited |
| `end` | Anything that went wrong in the steps |

A driver line has these fields:

| Field | What it holds |
| --- | --- |
| `received`, `dropped`, `decoded` | libpcap's u64 totals since capture started, as of its last poll |
| `ring_len`, `ring_bytes` | What the packet ring holds |
| `max_frame` | The largest frame among the packets that arrived that second and were still in the ring |
| `streams`, `held_bytes`, `stream_budget`, `dropped_flows` | The stream tracker's flows and bytes against its budget |
| `scan_states`, `beacon_states`, `alerts` | The sizes of the detectors' tables |
| `connections` | Rows in the connection table |
| `rss_kib`, `hwm_kib`, `threads` | From /proc/self/status |
| `utime_s`, `stime_s` | CPU seconds from /proc/self/stat |
| `tick_ms` | The longest App tick that second |
| `frame_ms` | Every frame time that second, by view |
| `capturing`, `capture_error`, `panicked` | Whether capture is running, its error, and whether any thread panicked |

Frame times are listed rather than summarised per line. Ten frames a second
over six views is one or two per view, and percentiles taken that way
cannot be combined over a phase.

## Limits

- The generator is a Python AF_PACKET sender, not tcpreplay. It sent more
  than a million small frames a second here, several times what netwatch
  decodes, so it never limits a phase. `--tcpreplay` uses tcpreplay
  instead.
- Drop % is libpcap's dropped count over its received count. On Linux the
  kernel counts a dropped packet in both.
- The detectors read only the packets still in the ring at each tick, so
  under a flood their port-scan and DNS counts are a sample of the traffic.
- `max_frame` sees only packets still in the ring when the line is written,
  which under `bulk` is the last thousand or so of each second. Most data
  frames are super-frames when offload works, so the gate fails only when
  none arrive.
- Root inside a user namespace is not root on the host. The driver and the
  daemon run with the capabilities the namespace grants and the sandbox
  they apply themselves. A run as real root would drop a different set of
  capabilities. Memory and frame times do not depend on that.
- `netwatch daemon` exports no capture counters yet, so its phase reports
  memory, threads and CPU only.
