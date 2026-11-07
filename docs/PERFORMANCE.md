# Performance

These numbers come from the 0.40 release candidate. `tests/soak/flood_soak.py` and `scripts/scale-bench.sh` produce them, and the release checklist in [PACKAGING.md](PACKAGING.md) asks for a fresh run on each release candidate.

| | Reference machine | GitHub runner |
| --- | --- | --- |
| Commit | `82967cf` | `82967cf` |
| CPU | AMD Ryzen AI 9 HX 370 w/ Radeon 890M, 24 threads | AMD EPYC 9V74 80-Core Processor, 4 vCPUs |
| Memory | 62 GiB | 15 GiB |
| Kernel | 7.1.13-200.fc44.x86_64 | 7.0.0-1017-azure |
| Run | local | [flood-soak.yml](https://github.com/matthart1983/netwatch/actions/runs/41262777336) |

A shared runner's speed varies from run to run, so read its figures as a floor, not a benchmark.

## Memory ceiling

netwatch stays under **512 MiB of resident memory** in a soak with default budgets and the flight recorder disarmed, with or without the Country and ASN GeoIP databases. The soak fails if either the driver or the daemon passes it.

| Peak (VmHWM), MiB | Reference machine | GitHub runner |
| --- | ---: | ---: |
| Six views drawing, flood running | 378.2 | 389.4 |
| `netwatch daemon`, flood running | 396.6 | 400.9 |

The ceiling doesn't cover an armed flight recorder or a City database (127 MiB). The largest parts are the stream tracker, whose budget is an eighth of the host's memory up to 256 MiB, and the packet ring, at 32 MiB. Both soaks held to those budgets on every sample.

Cycle 2 peaked 15.3 MiB above cycle 1 on the reference machine and 14.3 MiB above it on the runner. That is inside the 16 MiB the soak allows, but only just, and these runs can't tell a slow leak from run-to-run variation. Five-minute smokes have gone the other way (cycle 2 peaked 11 MiB lower on a runner). A longer soak would settle it.

## Flood soak

Each run floods a veth pair in a private network namespace for an hour: two cycles of six scenarios, then paced rates, then ten minutes of the real daemon. A Python AF_PACKET generator sends the traffic, so the soak needs no extra packages. It offers up to about 1.5 million packets a second on the reference machine and about 350,000 on the runner. The harness can use tcpreplay for the replay scenario if asked.

**Drop is what the kernel discarded before netwatch read it**, and a flood is meant to cause it: capture and decoding run on one thread, so CPU sits at about one core. The soak checks that netwatch keeps running within its budgets and keeps drawing, not that it keeps up with a flood. Figures are medians over both cycles, leaving out each phase's first two seconds.

### Reference machine

| Scenario | Offered pps | Decoded pps | Drop | CPU | Peak RSS, MiB | Slowest view, frame p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| udp-churn | 1,409,444 | 282,026 | 80.4% | 103% | 139.7 | 6.5 (packets_filtered) |
| syn-churn | 1,274,851 | 255,712 | 80.7% | 103% | 144.1 | 13.0 (stats) |
| dns | 1,522,794 | 263,158 | 82.9% | 103% | 143.0 | 7.3 (packets_filtered) |
| mtu-tcp | 1,070,548 | 103,416 | 90.5% | 103% | 378.2 | 13.2 (packets_filtered) |
| replay | 513,828 | 213,533 | 57.1% | 105% | 134.5 | 5.0 (stats) |
| bulk | 12.9 GB/s | 123,632 | 71.6% | 103% | 199.4 | 6.6 (timeline) |

### GitHub runner

| Scenario | Offered pps | Decoded pps | Drop | CPU | Peak RSS, MiB | Slowest view, frame p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| udp-churn | 341,508 | 158,115 | 54.0% | 103% | 119.9 | 7.0 (stats) |
| syn-churn | 341,514 | 153,530 | 54.6% | 103% | 128.3 | 8.9 (stats) |
| dns | 352,363 | 147,346 | 58.4% | 103% | 129.5 | 8.9 (stats) |
| mtu-tcp | 276,834 | 62,305 | 77.5% | 103% | 388.6 | 16.6 (packets_filtered) |
| replay | 194,164 | 130,195 | 30.4% | 103% | 118.2 | 8.0 (stats) |
| bulk | 3.5 GB/s | 59,647 | 43.5% | 102% | 181.7 | 6.0 (packets) |

### Rates netwatch keeps up with

Sent at a fixed rate, on the same path as the flood.

| Host | Offered pps | Decoded pps | Drop | CPU | Slowest view, frame p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Reference machine | 50,000 | 50,044 | 0.0% | 30% | 3.7 |
| Reference machine | 100,000 | 100,645 | 0.0% | 40% | 4.3 |
| GitHub runner | 50,000 | 50,048 | 0.0% | 37% | 4.3 |
| GitHub runner | 100,000 | 100,352 | 0.0% | 71% | 4.6 |

These are the only rates measured. The highest drop-free rate is somewhere above 100,000 packets a second and hasn't been measured.

### Frame times under the flood

Over the whole run, in ms, against a budget of 33 ms p99.

| View | Reference machine, p50 / p99 | GitHub runner, p50 / p99 |
| --- | ---: | ---: |
| dashboard | 0.9 / 1.5 | 1.2 / 4.3 |
| connections | 0.7 / 1.1 | 0.9 / 1.0 |
| packets | 1.1 / 2.1 | 1.6 / 4.7 |
| packets_filtered | 2.0 / 9.9 | 3.3 / 16.1 |
| stats | 2.5 / 5.4 | 3.9 / 7.4 |
| timeline | 1.4 / 2.7 | 2.2 / 3.1 |

### Daemon

| Host | Load | CPU | Peak (VmHWM), MiB |
| --- | --- | ---: | ---: |
| Reference machine | mix+bulk | 103% | 119.1 |
| Reference machine | mtu-tcp+bulk | 103% | 396.6 |
| GitHub runner | mix+bulk | 101% | 125.7 |
| GitHub runner | mtu-tcp+bulk | 102% | 400.9 |

## 10,000 connections

`NW_PERF_SLACK=1 scripts/scale-bench.sh` on the reference machine, commit `82967cf`, from a release build. Budgets apply at 10,000 rows. The 50,000 row column has no budget. Most frame cases take 49-88 ms p99 there, so a table that size draws at under 30 frames a second.

| Case, ms p50 / p99 | 2,000 rows | 10,000 rows | 50,000 rows | Budget at 10,000 rows |
|---|---:|---:|---:|---|
| frame/connections/process | 1.30 / 1.52 | 5.98 / 8.60 | 47.28 / 58.93 | p99 ≤ 33.0 ms, ok |
| frame/connections/remote | 1.79 / 2.18 | 9.80 / 18.03 | 66.80 / 88.16 | p99 ≤ 33.0 ms, ok |
| frame/connections/none | 1.58 / 2.80 | 8.77 / 12.51 | 43.83 / 63.29 | p99 ≤ 33.0 ms, ok |
| frame/connections/filter | 1.00 / 2.13 | 5.82 / 7.68 | 24.52 / 35.88 | p99 ≤ 33.0 ms, ok |
| frame/connections/geo | 1.56 / 2.93 | 7.32 / 10.49 | 50.04 / 65.90 | p99 ≤ 33.0 ms, ok |
| frame/connections/capped | 1.60 / 2.86 | 9.15 / 12.20 | 53.07 / 64.76 | p99 ≤ 33.0 ms, ok |
| diagnose/join | 0.17 / 0.65 | 1.07 / 2.00 | 12.56 / 21.65 | p50 ≤ 2.0 ms, ok |
| diagnose/sockets | 0.91 / 1.62 | 8.10 / 10.34 | 89.47 / 95.03 | - |
| poll/update | 21.05 / 23.28 | 63.52 / 71.88 | 332.44 / 378.72 | p50 ≤ 150.0 ms, ok |
| key/scroll/process | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.00 | p99 ≤ 5.0 ms, ok |
| key/scroll/none | 0.00 / 0.00 | 0.01 / 0.01 | 0.02 / 0.02 | p99 ≤ 5.0 ms, ok |
| tick/steady | 1.15 / 2.28 | 11.03 / 14.46 | 89.56 / 102.51 | p50 ≤ 15.0 ms, ok |
| tick/churn | 2.02 / 2.54 | 14.11 / 18.07 | 123.65 / 147.22 | p50 ≤ 15.0 ms, ok |
| tick/capture | 2.44 / 2.84 | 19.59 / 27.81 | 135.01 / 200.40 | - |
| frame/dashboard | 1.08 / 1.33 | 4.77 / 6.85 | 34.49 / 48.96 | p99 ≤ 33.0 ms, ok |
| frame/topology | 0.64 / 0.69 | 2.71 / 4.94 | 20.08 / 30.56 | p99 ≤ 33.0 ms, ok |
| frame/timeline | 0.85 / 0.99 | 3.38 / 4.87 | 18.81 / 25.30 | p99 ≤ 33.0 ms, ok |
| frame/dashboard/verdicts | 1.51 / 1.82 | 7.89 / 11.89 | 57.36 / 78.19 | p99 ≤ 33.0 ms, ok |
| frame/dense | 1.14 / 1.38 | 5.41 / 7.91 | 48.04 / 59.93 | p99 ≤ 33.0 ms, ok |

**One known miss.** `tick/capture` has no budget because it doesn't meet the 15 ms that `tick/steady` and `tick/churn` do. With a capture running, a tick at 10,000 rows takes about 19.6 ms at p50. About 8 ms of that is copying each row's annotation history, and reducing it means reworking the PCAPNG evidence code.

## Running them

```sh
scripts/scale-bench.sh                       # quiet machine; raises the open-file limit
python3 -I tests/soak/flood_soak.py          # about 75 minutes, no root needed
gh workflow run flood-soak.yml --ref <branch>
```

[tests/soak/README.md](../tests/soak/README.md) describes every scenario and gate.
