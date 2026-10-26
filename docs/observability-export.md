# Observability export (Prometheus / `/metrics`)

The `netwatch daemon` can expose its aggregate signals as a Prometheus
`/metrics` endpoint plus a `/healthz` liveness probe, so you can scrape netwatch
straight into Prometheus, Grafana, VictoriaMetrics, or any OpenTelemetry
Collector with a Prometheus receiver — no glue.

> Scope: the exporter runs on the **daemon/agent** today. (TUI export is on the
> roadmap.) It is **aggregate-only by design** — per-flow forensics
> (SNI/JA4/process) is high-cardinality and is intentionally kept out of metrics
> to avoid the cardinality-driven cost blow-ups that plague host-priced
> observability vendors. Per-flow signals belong in the flow-event/OTLP stream.

## Enabling

```sh
# Default endpoint: 127.0.0.1:9464 (the OpenTelemetry Prometheus exporter port)
netwatch daemon --metrics

# Custom bind address
netwatch daemon --metrics-addr 0.0.0.0:9464
# or
NETWATCH_METRICS_ADDR=0.0.0.0:9464 netwatch daemon
```

The endpoint binds to loopback by default — bind to `0.0.0.0` only behind a
trusted network boundary.

- `GET /metrics`  → Prometheus text exposition (format 0.0.4)
- `GET /healthz`  → `200 ok` while the process is alive (k8s liveness / systemd)

## Exposed metrics

| Metric | Type | Notes |
|---|---|---|
| `netwatch_up` | gauge | Always 1 while serving |
| `netwatch_collectors_ok` | gauge | 0 if a collector thread has panicked (alert on this) |
| `netwatch_build_info{version}` | gauge | Agent version label |
| `netwatch_interface_receive_bytes_total{interface}` | counter | Per-interface RX bytes |
| `netwatch_interface_transmit_bytes_total{interface}` | counter | Per-interface TX bytes |
| `netwatch_interface_receive_packets_total{interface}` | counter | RX packets |
| `netwatch_interface_transmit_packets_total{interface}` | counter | TX packets |
| `netwatch_interface_receive_errors_total{interface}` | counter | RX errors |
| `netwatch_interface_transmit_errors_total{interface}` | counter | TX errors |
| `netwatch_interface_receive_drops_total{interface}` | counter | RX drops |
| `netwatch_interface_transmit_drops_total{interface}` | counter | TX drops |
| `netwatch_interface_receive_bytes_per_second{interface}` | gauge | Current RX throughput |
| `netwatch_interface_transmit_bytes_per_second{interface}` | gauge | Current TX throughput |
| `netwatch_gateway_rtt_seconds` | gauge | RTT to default gateway |
| `netwatch_gateway_loss_ratio` | gauge | Gateway packet loss (0–1) |
| `netwatch_dns_rtt_seconds` | gauge | RTT to primary DNS |
| `netwatch_dns_loss_ratio` | gauge | DNS packet loss (0–1) |
| `netwatch_connections` | gauge | Tracked connections |
| `netwatch_tcp_connections{state}` | gauge | TCP connections by state (`time_wait`, `close_wait`) |
| `netwatch_capture_packets_received_total` | counter | Packets libpcap received |
| `netwatch_capture_packets_dropped_total` | counter | Packets libpcap dropped because its kernel buffer was full, plus drops by the interface or driver |
| `netwatch_capture_packets_decoded_total` | counter | Captured packets netwatch decoded into its packet list |
| `netwatch_policy_violations_total{process}` | counter | Egress-policy violations per process (post-cooldown; only processes declared in `egress-policy.toml` can appear, so cardinality stays bounded) |

Names and units follow Prometheus base-unit conventions (`_bytes`, `_seconds`,
`_ratio`, `_total`). The 1.0 compatibility promise covers the names, types and
labels in this table. A 1.x release can add metrics but does not rename or
remove these.

The three capture counters count from when the capture opened, and netwatch
reads them from libpcap once a second. They have no sample while no capture is
running, for example when the daemon lacks permission to capture, so alert on
`absent(netwatch_capture_packets_received_total)` as well as on a rising
`rate(netwatch_capture_packets_dropped_total[5m])`. libpcap's own counters are
32-bit and wrap after about four billion packets; these are 64-bit and keep
counting. On Linux loopback (`lo`) libpcap counts each packet twice, once
sent and once received, but hands netwatch one copy, so there the received
count is twice the decoded count.

## Prometheus scrape config

```yaml
scrape_configs:
  - job_name: netwatch
    static_configs:
      - targets: ["127.0.0.1:9464"]
```

## Roadmap

- **OTLP push** (gRPC/HTTP) to an OpenTelemetry Collector, with network
  attributes aligned to OpenTelemetry semantic conventions.
- **Flow-event stream** (NDJSON / OTLP logs) for per-flow forensics, kept
  separate from metrics to preserve low cardinality.
