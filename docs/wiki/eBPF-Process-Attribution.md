# Process attribution and eBPF

Linux can verify procfs socket ownership; eBPF SDK connect events provide corroborative hints rather than independently verified full-tuple ownership. A compiled feature, installed capability or loaded probe alone does not establish attribution coverage.

macOS `lsof`/PKTAP, Windows socket-table observations and FreeBSD observations have different limits; non-Linux process identities are unverified. PKTAP hints cannot overwrite verified ownership. Polling can miss short-lived connections and stale observations must not become current owners.

The [attribution evidence model](@repo@/docs/attribution.md) defines identity, freshness, coverage denominators and controlled results. See [[Permissions]] and [[Platform Support]] for availability. Do not interpret unknown ownership as benign traffic.

<!-- include: docs/attribution.md -->
