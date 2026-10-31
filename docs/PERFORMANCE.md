# Performance

These numbers come from the 0.39 release candidate. `tests/soak/flood_soak.py` and `scripts/scale-bench.sh` produce them, and the release checklist in [PACKAGING.md](PACKAGING.md) asks for a fresh run on each release candidate.

| | Reference machine | GitHub runner |
| --- | --- | --- |
| Commit | `8cb6110` (same code as `3775387`) | `3775387` |
| CPU | AMD Ryzen AI 9 HX 370 w/ Radeon 890M, 24 threads | AMD EPYC 9V74 80-Core Processor, 4 vCPUs |
| Memory | 62 GiB | 15 GiB |
| Kernel | 7.1.13-200.fc44.x86_64 | 7.0.0-1017-azure |
| Run | local | [flood-soak.yml](https://github.com/matthart1983/netwatch/actions/runs/41155844699) |

Commit `8cb6110` and `3775387` differ only in CI workflows and docs. A shared runner's speed varies from run to run, so read its figures as a floor, not a benchmark.

## Memory ceiling

netwatch stays under **512 MiB of resident memory** in a soak with default budgets and the flight recorder disarmed, with or without the Country and ASN GeoIP databases. The soak fails if either the driver or the daemon passes it.

| Peak (VmHWM), MiB | Reference machine | GitHub runner |
| --- | ---: | ---: |
| Six views drawing, flood running | 393.6 | 387.4 |
| `netwatch daemon`, flood running | 410.4 | 398.9 |

The ceiling doesn't cover an armed flight recorder or a City database (127 MiB). The largest parts are the stream tracker, whose budget is an eighth of the host's memory up to 256 MiB, and the packet ring, at 32 MiB. Both soaks held to those budgets on every sample.

Cycle 2 peaked 15.5 MiB above cycle 1 on the reference machine and 15.9 MiB above it on the runner. That is inside the 16 MiB the soak allows, but only just, and these runs can't tell a slow leak from run-to-run variation. Five-minute smokes have gone the other way (cycle 2 peaked 11 MiB lower on a runner). A longer soak would settle it.

## Flood soak

Each run floods a veth pair in a private network namespace for an hour: two cycles of six scenarios, then paced rates, then ten minutes of the real daemon. A Python AF_PACKET generator sends the traffic, so the soak needs no extra packages. It offers up to about 1.4 million packets a second on the reference machine and about 350,000 on the runner. The harness can use tcpreplay for the replay scenario if asked.

**Drop is what the kernel discarded before netwatch read it**, and a flood is meant to cause it: capture and decoding run on one thread, so CPU sits at about one core. The soak checks that netwatch keeps running within its budgets and keeps drawing, not that it keeps up with a flood. Figures are medians over both cycles, leaving out each phase's first two seconds.

### Reference machine

| Scenario | Offered pps | Decoded pps | Drop | CPU | Peak RSS, MiB | Slowest view, frame p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| udp-churn | 1,411,012 | 279,720 | 80.6% | 103% | 145.2 | 8.0 (packets_filtered) |
| syn-churn | 1,323,820 | 269,836 | 79.5% | 103% | 147.1 | 5.3 (stats) |
| dns | 1,339,432 | 228,357 | 82.6% | 103% | 146.2 | 8.2 (stats) |
| mtu-tcp | 942,684 | 95,132 | 89.8% | 103% | 393.6 | 18.8 (packets_filtered) |
| replay | 509,246 | 223,020 | 55.0% | 103% | 161.6 | 5.1 (stats) |
| bulk | 12.9 GB/s | 126,756 | 69.7% | 101% | 196.8 | 2.8 (timeline) |

### GitHub runner

| Scenario | Offered pps | Decoded pps | Drop | CPU | Peak RSS, MiB | Slowest view, frame p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| udp-churn | 351,220 | 165,762 | 52.9% | 103% | 139.2 | 6.4 (stats) |
| syn-churn | 348,198 | 165,920 | 52.4% | 103% | 142.6 | 8.2 (stats) |
| dns | 356,496 | 154,952 | 56.5% | 103% | 145.8 | 9.0 (stats) |
| mtu-tcp | 285,874 | 62,947 | 78.0% | 103% | 387.4 | 17.2 (packets_filtered) |
| replay | 200,264 | 132,100 | 31.4% | 103% | 129.4 | 8.4 (stats) |
| bulk | 3.6 GB/s | 56,154 | 48.3% | 102% | 175.7 | 5.4 (packets) |

### Rates netwatch keeps up with

Sent at a fixed rate, on the same path as the flood.

| Host | Offered pps | Decoded pps | Drop | CPU | Slowest view, frame p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Reference machine | 50,000 | 50,048 | 0.0% | 25% | 4.1 |
| Reference machine | 100,000 | 100,480 | 0.0% | 40% | 4.2 |
| GitHub runner | 50,000 | 50,036 | 0.0% | 36% | 4.3 |
| GitHub runner | 100,000 | 100,493 | 0.0% | 69% | 5.4 |

These are the only rates measured. The highest drop-free rate is somewhere above 100,000 packets a second and hasn't been measured.

### Frame times under the flood

Over the whole run, in ms, against a budget of 33 ms p99.

| View | Reference machine, p50 / p99 | GitHub runner, p50 / p99 |
| --- | ---: | ---: |
| dashboard | 0.9 / 1.4 | 1.1 / 4.2 |
| connections | 0.7 / 1.1 | 0.9 / 1.0 |
| packets | 1.1 / 1.9 | 1.6 / 5.1 |
| packets_filtered | 1.9 / 14.0 | 3.0 / 15.9 |
| stats | 2.5 / 6.1 | 3.6 / 7.3 |
| timeline | 1.6 / 2.5 | 2.1 / 3.1 |

### Daemon

| Host | Load | CPU | Peak (VmHWM), MiB |
| --- | --- | ---: | ---: |
| Reference machine | mix+bulk | 102% | 125.6 |
| Reference machine | mtu-tcp+bulk | 103% | 410.4 |
| GitHub runner | mix+bulk | 101% | 122.1 |
| GitHub runner | mtu-tcp+bulk | 101% | 398.9 |

## 10,000 connections

`NW_PERF_SLACK=1 scripts/scale-bench.sh` on the reference machine, commit `8cb6110`, from a release build. Budgets apply at 10,000 rows. The 50,000 row column has no budget. Most frame cases take 40-64 ms p99 there, so a table that size draws at under 30 frames a second.

| Case, ms p50 / p99 | 2,000 rows | 10,000 rows | 50,000 rows | Budget at 10,000 rows |
|---|---:|---:|---:|---|
| frame/connections/process | 1.35 / 2.56 | 5.89 / 9.32 | 40.72 / 47.21 | p99 ≤ 33.0 ms, ok |
| frame/connections/remote | 1.98 / 2.73 | 10.24 / 15.23 | 59.13 / 63.81 | p99 ≤ 33.0 ms, ok |
| frame/connections/none | 1.62 / 1.92 | 8.70 / 10.06 | 46.57 / 52.50 | p99 ≤ 33.0 ms, ok |
| frame/connections/filter | 1.03 / 1.90 | 5.51 / 6.24 | 23.29 / 29.80 | p99 ≤ 33.0 ms, ok |
| frame/connections/geo | 1.38 / 2.81 | 6.62 / 7.95 | 42.47 / 49.13 | p99 ≤ 33.0 ms, ok |
| frame/connections/capped | 1.54 / 3.03 | 7.60 / 16.75 | 47.70 / 50.69 | p99 ≤ 33.0 ms, ok |
| diagnose/join | 0.17 / 0.17 | 1.01 / 1.56 | 9.98 / 11.15 | p50 ≤ 2.0 ms, ok |
| diagnose/sockets | 0.88 / 0.92 | 5.52 / 6.61 | 73.05 / 74.02 | - |
| poll/update | 24.77 / 28.14 | 62.37 / 74.82 | 297.49 / 310.79 | p50 ≤ 150.0 ms, ok |
| key/scroll/process | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.00 | p99 ≤ 5.0 ms, ok |
| key/scroll/none | 0.00 / 0.00 | 0.00 / 0.00 | 0.02 / 0.02 | p99 ≤ 5.0 ms, ok |
| tick/steady | 1.02 / 1.28 | 8.69 / 10.70 | 82.86 / 90.10 | p50 ≤ 15.0 ms, ok |
| tick/churn | 1.65 / 3.83 | 12.77 / 18.15 | 113.43 / 122.09 | p50 ≤ 15.0 ms, ok |
| tick/capture | 2.13 / 2.94 | 17.58 / 21.47 | 126.72 / 136.12 | - |
| frame/dashboard | 0.95 / 1.24 | 4.25 / 5.32 | 32.57 / 41.87 | p99 ≤ 33.0 ms, ok |
| frame/topology | 0.56 / 0.72 | 2.52 / 3.00 | 17.76 / 26.57 | p99 ≤ 33.0 ms, ok |
| frame/timeline | 0.74 / 0.94 | 3.18 / 5.06 | 14.95 / 26.98 | p99 ≤ 33.0 ms, ok |
| frame/dashboard/verdicts | 1.30 / 1.55 | 8.20 / 10.13 | 50.96 / 56.14 | p99 ≤ 33.0 ms, ok |
| frame/dense | 0.89 / 1.06 | 4.76 / 8.69 | 45.90 / 50.62 | p99 ≤ 33.0 ms, ok |

**One known miss.** `tick/capture` has no budget because it doesn't meet the 15 ms that `tick/steady` and `tick/churn` do. With a capture running, a tick at 10,000 rows takes about 17.6 ms at p50. About 8 ms of that is copying each row's annotation history, and reducing it means reworking the PCAPNG evidence code.

## Running them

```sh
scripts/scale-bench.sh                       # quiet machine; raises the open-file limit
python3 -I tests/soak/flood_soak.py          # about 75 minutes, no root needed
gh workflow run flood-soak.yml --ref <branch>
```

[tests/soak/README.md](../tests/soak/README.md) describes every scenario and gate.
