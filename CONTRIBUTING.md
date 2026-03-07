# Contributing to NetWatch

## Error Handling Conventions

### Mutex locks

`Mutex::lock().unwrap()` and `RwLock::write().unwrap()` are acceptable throughout the codebase. We do not use `catch_unwind` or poison recovery — a poisoned lock indicates unrecoverable state and panicking is the correct response.

### System calls and external commands

Functions that shell out (`Command::new(...)`) or perform I/O must handle errors gracefully:
- Return `Vec::new()` or a default value on failure (e.g., `parse_lsof()`, `parse_linux_connections()`)
- Store error messages in shared state for UI display (e.g., `PacketCollector.error`)
- Never `unwrap()` on `Command::new(...).output()` — always match or use `?`

### User-controlled input

Never `unwrap()` on data derived from user input (filter expressions, addresses). Use `Option`/`Result` and return `None` or a default on parse failure. The display filter parser (`parse_filter`) returns `Option<FilterExpr>` — invalid filters are silently ignored, not panics.

### Network data

Packet parsing must validate buffer lengths before indexing. All parsers check minimum sizes (e.g., `data.len() < 14` for Ethernet) and return `None` for malformed packets. Never index into packet data without a bounds check.

### Thread spawning

Background threads that run external commands (connections, health probes) use an `AtomicBool` busy guard to prevent unbounded thread accumulation. Always check the guard before spawning.

## Code Style

- Follow existing patterns in neighbouring code
- Use `#[cfg(target_os = "...")]` for platform-specific code, not runtime checks
- eBPF code is gated behind `#[cfg(all(target_os = "linux", feature = "ebpf"))]`
- Named constants for magic numbers (see `CAPTURE_SNAPLEN`, `CAPTURE_TIMEOUT_MS`, etc.)
- Prefer `Arc<Mutex<T>>` for shared mutable state between threads
- Prefer `Arc<AtomicBool>` for simple flags

## Security

- Never use shell expansion or `sh -c` — always `Command::new("binary").args([...])`
- Never log or display secrets, API keys, or credentials
- Packet capture data may contain sensitive payloads — the pcap export feature writes raw data, which is expected behaviour for a network diagnostic tool
- eBPF programs require `CAP_BPF` / root — fail gracefully with a status bar warning, never escalate privileges programmatically
