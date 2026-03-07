# NetWatch — Cleanup & Hardening Spec

Generated from comprehensive code review and security audit.

---

## Priority 1: Critical — Resource Exhaustion

### 1.1 Unbounded Thread Spawning in ConnectionCollector

**File:** `src/collectors/connections.rs`  
**Issue:** `update()` spawns a new `std::thread` on every call (every ~2s). If `lsof`/`ss` blocks longer than the tick interval (system load, I/O stall), threads accumulate with no upper bound, eventually hitting the OS thread limit and crashing.

**Fix:**  
Replace fire-and-forget `thread::spawn` with a guard pattern:

```rust
pub struct ConnectionCollector {
    pub connections: Arc<Mutex<Vec<Connection>>>,
    busy: Arc<AtomicBool>,
}

impl ConnectionCollector {
    pub fn update(&self) {
        if self.busy.load(Ordering::SeqCst) {
            return; // previous update still running
        }
        self.busy.store(true, Ordering::SeqCst);
        let connections = Arc::clone(&self.connections);
        let busy = Arc::clone(&self.busy);
        thread::spawn(move || {
            let result = /* parse_lsof() or parse_linux_connections() */;
            *connections.lock().unwrap() = result;
            busy.store(false, Ordering::SeqCst);
        });
    }
}
```

**Scope:** `src/collectors/connections.rs`  
**Tests:** Unit test confirming a second `update()` call is a no-op while the first is in-flight.

---

### 1.2 Unbounded Thread Spawning in HealthProber

**File:** `src/collectors/health.rs`  
**Issue:** Identical to 1.1 — `probe()` spawns a thread every ~5s. `ping -c 3` can hang for 3+ seconds per target (gateway + DNS = 6s), exceeding the 5s interval.

**Fix:**  
Same `AtomicBool` guard pattern as 1.1.

**Scope:** `src/collectors/health.rs`  
**Tests:** Unit test confirming guard prevents concurrent probes.

---

## Priority 2: High — Input Validation & Memory Safety

### 2.1 Filter Parser Stack Overflow

**File:** `src/collectors/packets.rs`  
**Issue:** The display filter parser (`parse_not`, `parse_and`, `parse_or`) recurses without a depth limit. A filter like `not not not not ... tcp` (100+ levels) will overflow the stack and crash.

**Fix:**  
Add a `depth: usize` parameter to recursive parse functions. Return `None` when depth exceeds `MAX_FILTER_DEPTH` (32).

```rust
const MAX_FILTER_DEPTH: usize = 32;

fn parse_or(tokens: &[&str], pos: usize, depth: usize) -> Option<(FilterExpr, usize)> {
    if depth > MAX_FILTER_DEPTH {
        return None;
    }
    // ... existing logic, passing depth + 1 to recursive calls
}
```

**Scope:** `src/collectors/packets.rs` — `parse_or`, `parse_and`, `parse_not`, `parse_filter_expr`  
**Tests:** Test that a filter with 100 nested `not` operators returns `None` instead of crashing.

---

### 2.2 Unsafe Pointer Cast in eBPF ConnTracker

**File:** `src/ebpf/conn_tracker.rs`  
**Issue:** `*(buffers[i].as_ptr() as *const ConnEvent)` — no check that the buffer is at least `size_of::<ConnEvent>()` bytes. If the kernel sends a truncated event, this reads uninitialised memory (undefined behaviour).

**Fix:**  
```rust
let buf = &buffers[i];
if buf.len() < std::mem::size_of::<ConnEvent>() {
    continue; // skip truncated events
}
let evt = unsafe { &*(buf.as_ptr() as *const ConnEvent) };
```

**Scope:** `src/ebpf/conn_tracker.rs`  
**Tests:** N/A (Linux-only code path, tested via integration test on Linux).

---

## Priority 3: Medium — Robustness & Performance

### 3.1 Packet Capture Lock Contention

**File:** `src/collectors/packets.rs`  
**Issue:** The capture thread acquires a write lock on the packet `Vec` for every single captured packet. If the UI thread holds the read lock during rendering, the capture thread blocks and the OS may drop packets at the interface level.

**Fix:**  
Batch packet insertion. Accumulate packets in a thread-local `Vec` and flush to the shared state every 100 packets or 100ms, whichever comes first.

```rust
let mut batch: Vec<CapturedPacket> = Vec::with_capacity(100);
let mut last_flush = Instant::now();

// In capture loop:
batch.push(packet);
if batch.len() >= 100 || last_flush.elapsed() > Duration::from_millis(100) {
    let mut packets = shared_packets.write().unwrap();
    packets.extend(batch.drain(..));
    last_flush = Instant::now();
}
```

**Scope:** `src/collectors/packets.rs`  
**Tests:** Benchmark before/after to verify reduced lock acquisitions.

---

### 3.2 Wire Up eBPF Pipeline

**File:** `src/app.rs`, `src/ebpf/conn_tracker.rs`  
**Issue:** `ConnTracker` is never instantiated. `RttMonitor` is created but never receives data. The eBPF feature compiles but does nothing at runtime even on Linux with `--features ebpf`.

**Fix:**  
In `App::new()` (behind `#[cfg(all(target_os = "linux", feature = "ebpf"))]`):
1. Attempt to create `ConnTracker`
2. On success, start its async reader task
3. In `App::tick()`, drain events from `ConnTracker` and feed into `ConnectionCollector` / `RttMonitor`
4. On failure, set `ebpf_status = EbpfStatus::Unavailable(reason)` and fall back to polling

**Scope:** `src/app.rs`, `src/ebpf/conn_tracker.rs`  
**Tests:** Integration test on Linux VM.

---

### 3.3 Fragile lsof Output Parsing

**File:** `src/collectors/connections.rs`  
**Issue:** `parse_lsof()` splits on whitespace and indexes by column position. Process names containing spaces, or `lsof` output format changes between macOS versions, will produce corrupted or missing data.

**Fix (short-term):**  
Use `lsof -F` (machine-readable output format) which produces tagged fields:
```
p1234       ← PID
c<name>     ← command name
f4          ← fd
tIPv4       ← type
n<addr>     ← name
TST=ESTABLISHED ← TCP state
```

**Fix (long-term):**  
On macOS, use `libproc::listpidinfo` via the `libproc` crate for direct process-to-socket mapping without shelling out.

**Scope:** `src/collectors/connections.rs`  
**Tests:** Add test cases with sample `lsof -F` output containing edge cases (spaces in process names, IPv6 addresses).

---

### 3.4 Hardcoded Capture Constants

**File:** `src/collectors/packets.rs`  
**Issue:** Magic numbers `100` (timeout ms) and `65535` (snaplen) are hardcoded inline with no documentation or configurability.

**Fix:**  
Extract to named constants:
```rust
const CAPTURE_TIMEOUT_MS: i32 = 100;
const CAPTURE_SNAPLEN: i32 = 65535;
const MAX_CAPTURED_PACKETS: usize = 50_000;
```

**Scope:** `src/collectors/packets.rs`  
**Tests:** N/A (constant extraction only).

---

## Priority 4: Low — Code Hygiene

### 4.1 Remove `#![allow(dead_code)]` Blanket Suppression

**File:** `src/ebpf/rtt_monitor.rs`  
**Issue:** The blanket `#![allow(dead_code)]` hides legitimate dead code warnings. When eBPF is wired up (3.2), this should be removed and any remaining dead code cleaned up.

**Fix:**  
After completing 3.2, remove the `#![allow(dead_code)]` and address each warning individually — either by wiring up the code or deleting truly unused items.

**Scope:** `src/ebpf/rtt_monitor.rs`, `src/ebpf/mod.rs`, `src/app.rs`

---

### 4.2 Consistent Error Handling Strategy

**Files:** Multiple  
**Issue:** Mix of `unwrap()`, `unwrap_or_default()`, and silent ignoring of errors. Most `unwrap()` calls on `Mutex::lock()` are fine (only panic if a thread panicked while holding the lock), but the pattern should be documented as a project convention.

**Fix:**  
Add a comment in `src/app.rs` or a `CONTRIBUTING.md` documenting:
- `Mutex::lock().unwrap()` is acceptable — we use `catch_unwind` nowhere, so a poisoned mutex means unrecoverable state
- System calls (`Command::new`, file I/O) must return `Result` or use `unwrap_or_default`
- Never `unwrap()` on user-controlled input (filters, addresses)

**Scope:** Documentation only.

---

## Implementation Order

| Phase | Items | Effort |
|-------|-------|--------|
| **Phase 1** | 1.1, 1.2 (thread guards) | ~1 hour |
| **Phase 2** | 2.1 (parser depth limit), 2.2 (unsafe bounds check) | ~1 hour |
| **Phase 3** | 3.1 (batch locking), 3.4 (constants) | ~1 hour |
| **Phase 4** | 3.2 (wire eBPF pipeline), 3.3 (lsof -F) | ~3 hours |
| **Phase 5** | 4.1, 4.2 (hygiene) | ~30 min |

Total estimated effort: **~6.5 hours**
