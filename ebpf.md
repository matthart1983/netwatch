# eBPF — a deep overview

## The model

eBPF is a tiny RISC-like virtual ISA with 11 64-bit registers and its own bytecode, originally derived from BSD's classic BPF filter but extended for general-purpose use. The kernel verifies, JIT-compiles, and runs user-supplied programs in response to kernel events. The programs are sandboxed — bounded loops, no arbitrary memory access, no unbounded execution — and the safety comes entirely from the **verifier**, not the runtime.

The mental model: you write a small function (in C or Rust), compile it to BPF bytecode, hand it to the kernel via the `bpf()` syscall, the kernel statically proves it can't crash or hang, then attaches it to some event source (a syscall, a network interface, a kernel function entry, a tracepoint). When that event fires, your code runs in kernel context — with access to event data and a set of helper functions.

The interesting consequence: you can extend kernel behavior **without writing kernel modules**. No reboot, no signed binary, no risk of taking down the box. This is why it ate the kernel-extension space.

## Program types — where you can hook

A BPF program's "type" is the contract: what data it sees, what it can return, what helpers it can call. The biggies:

| Type | Hook | What you can do |
|------|------|-----------------|
| `kprobe` / `kretprobe` | Function entry/exit, anywhere in kernel | Inspect args + registers. **Fragile**: kernel internal API, breaks across versions |
| `fentry` / `fexit` | Function entry/exit via BPF trampoline (5.5+) | Same as kprobe but ~3x faster, type-safe via BTF |
| `tracepoint` | Stable instrumentation points (`syscalls/sys_enter_connect`, sched events, etc.) | The "official" tracing surface. ABI is stable |
| `XDP` | Network driver receive path, before skb allocation | Drop, redirect, modify packets at line rate. Used by Cilium, Cloudflare |
| `tc` (traffic control) | After skb allocation, ingress/egress | More feature-rich than XDP but slower |
| `sk_msg`, `sockops` | Socket operations | TCP-aware proxying without userspace hops |
| `cgroup_*` | Cgroup attach points | Per-container policy: bind, connect, sendmsg, sysctl |
| `LSM` | Linux Security Module hooks (5.7+) | Replace AppArmor/SELinux with BPF policies |
| `uprobe` | Userspace function entry | Trace any user binary, including statically linked Go/Rust |
| `perf_event` | perf counter overflow, hardware events | Profilers — `perf record` style sampling |

Netwatch's path is `kprobe` on `tcp_v4_connect` — fragile in principle (kernel internal function), but stable in practice because that symbol is decades old. A modern rewrite would use `fentry/tcp_v4_connect` for the perf win and BTF-typed args.

## Maps — the data plane

BPF programs can't talk to userspace directly, can't allocate heap memory, can't keep stack state across invocations. Maps fill that gap: persistent key-value structures the kernel manages, accessible from both BPF (via helpers) and userspace (via the `bpf()` syscall).

Map types you actually use:
- **`BPF_MAP_TYPE_HASH`** — general K/V, per-cpu variants for high-write paths
- **`BPF_MAP_TYPE_ARRAY`** — index-keyed, fixed size, very fast
- **`BPF_MAP_TYPE_PERCPU_*`** — one instance per CPU, no locking, aggregated at read time
- **`BPF_MAP_TYPE_RINGBUF`** (5.8+) — MPSC ring buffer to userspace, this is what netwatch uses. Supersedes the older `BPF_MAP_TYPE_PERF_EVENT_ARRAY` (perf buffer) which had per-cpu buffers and ordering surprises
- **`BPF_MAP_TYPE_LRU_HASH`** — bounded with LRU eviction, useful for caches
- **`BPF_MAP_TYPE_PROG_ARRAY`** — tail calls (jump to another BPF program; how XDP/tc programs compose)

The ring buffer is the workhorse for "kernel observes thing, tell userspace." It's lockless on the producer side, supports variable-length records, and gives userspace a poll-able fd. The old perf buffer is still common in the wild but has worse semantics — events can arrive out of order across CPUs.

## The verifier — what makes all of this possible

This is the part most people underestimate. The verifier does **path-sensitive abstract interpretation** over your bytecode before allowing it to run:

- Every memory access is bounds-checked. `*ptr` requires the verifier to prove `ptr` is non-null and points into a known region (stack, map value, packet data with bounds, etc.)
- Every loop must be provably bounded. The historical limit was no loops at all (you unrolled); modern kernels (5.3+) support bounded loops up to ~1M total verified instructions, and `bpf_loop()` (5.17+) lets you do up to 8M iterations against a callback
- Helpers have signatures the verifier knows. Passing the wrong pointer type fails verification, not at runtime
- The verifier tracks **register state** (ptr+offset, scalar with known range, scalar with unknown range) and refuses any operation that could produce an out-of-bounds value

This is why eBPF can be safe-by-construction without runtime checks. It's also why writing eBPF *feels* weird: you're constantly working around the verifier. Common things that fail:
- A pointer you derived from packet data that you forgot to re-bounds-check after an arithmetic op
- Recursion (forbidden)
- A loop the verifier can't prove terminates
- Reading > 8 bytes from a `bpf_probe_read_kernel` call without splitting it
- Stack frame > 512 bytes
- Total program > 1M verified instructions (used to be 4K)

The verifier error messages are infamously cryptic. Reading them is a skill that takes weeks.

## CO-RE and BTF — the portability story

The original problem: a kprobe reads kernel struct fields by offset. The offset of `sock->__sk_common.skc_daddr` differs between kernel versions because the struct layout changes. So a BPF program compiled against 5.4 won't work on 6.1. People worked around this with BCC (compile at runtime on the target host, ship LLVM) — wasteful and fragile.

**BTF** (BPF Type Format) is a compact debug-info-like format the kernel emits at build time describing every type. **CO-RE** (Compile Once, Run Everywhere) uses BTF to **relocate** struct field accesses at load time: the BPF program is compiled once with relocation directives (`BPF_CORE_READ(sk, __sk_common.skc_daddr)`), and the kernel loader rewrites the offsets to match the running kernel.

The win is: one prebuilt BPF object that works on any kernel ≥5.5 with BTF (which is essentially all distros from 2021 onward).

Caveats:
- The target kernel must have BTF (`/sys/kernel/btf/vmlinux` exists)
- Some embedded distros still ship without it; you fall back to BTFHub external BTF blobs
- CO-RE doesn't help with renamed or removed fields, only moved ones. You still have feature-check via `bpf_core_field_exists()`

## Toolchain choices

For Rust specifically:
- **libbpf-rs** — thin bindings over upstream `libbpf` (the canonical loader). Mature, conservative, used by big projects (e.g., bpftop, parca). C BPF code is compiled by clang separately.
- **aya** — pure-Rust loader + Rust-as-BPF-source. The whole stack is Rust. Younger but very active. CO-RE support has been catching up.
- **redbpf** — older, less maintained, mostly deprecated in favor of aya
- **bcc-rs** — bindings to the C BCC project; ships an LLVM at runtime, so you compile on the target. Avoid for production tools.

Aya is the netwatch-sdk choice. The active question is whether aya's CO-RE coverage is mature enough or whether you'd want libbpf-rs+C as a fallback for edge cases.

For prototyping and ad-hoc tools: **bpftrace** is the AWK of eBPF. One-liners for "what's calling this function," "what's the histogram of this latency." Not for production but indispensable for understanding what's happening.

## Permissions model

Pre-5.8: loading BPF required `CAP_SYS_ADMIN`. Big footgun — anything that wanted to load a BPF program was effectively root.

5.8+ split it:
- **CAP_BPF** — load BPF programs and maps
- **CAP_PERFMON** — attach to perf events (tracepoints, kprobes, fentry)
- **CAP_NET_ADMIN** — attach XDP/tc programs

Netwatch's `setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip'` is the modern minimal set. On a 5.8+ kernel this means the netwatch binary can load kprobes without being root.

On older kernels (< 5.8), there's no way around root for BPF.

## Loading and lifecycle

1. `bpf(BPF_PROG_LOAD)` — submit bytecode + license + map descriptors. Kernel runs the verifier, JITs the code, returns a program fd.
2. `bpf(BPF_LINK_CREATE)` (or older `perf_event_open` + `ioctl`) — attach the program to an event source. Returns a link fd.
3. As long as anyone holds the program fd or the link fd, the program stays loaded. Dropping all references unloads it.
4. Pinning: you can pin a program/map/link to `/sys/fs/bpf/...` so it survives the loader process. This is how systemd and Cilium hot-restart without dropping packets.

The fd-based lifecycle means most loaders just hold the fd in a userspace daemon. Netwatch holds it in the SDK's `EventSource` struct — when it drops, kernel cleans up.

## Performance characteristics

- **JIT overhead**: nil. JITed BPF is x86-64 native code with bounds-check inserts where verifier required them. A kprobe firing 100K times/second is normal.
- **kprobe vs fentry**: kprobe uses INT3 patching + a generic dispatcher. fentry uses a per-function trampoline with direct branch — ~3x faster, but requires 5.5+ and the function must be ftraceable.
- **Map access**: hash map lookup is ~20-50ns. Per-cpu maps avoid the contention, costing ~5ns.
- **Ring buffer vs perf buffer**: ring buffer is faster (lockless producer) and has stronger ordering. Always prefer it if you can require 5.8+.
- **Where eBPF wins big**: replacing iptables (10-100x for big rulesets), userspace packet filtering (XDP processes packets before skb allocation, saving the dominant cost), profilers that needed `perf` + offline symbolization.

## Patterns you'll hit

- **Tail calls** — BPF programs are stack-bounded (512 bytes) and instruction-bounded (1M). Big logic gets split: program A finishes, calls into program B via a PROG_ARRAY map. Used heavily in Cilium and XDP routing.
- **Per-cpu aggregation** — count something hot? Use PERCPU_HASH, sum in userspace at read time. Avoids cache line bouncing.
- **Reading user memory** — `bpf_probe_read_user()` for userspace pointers; `bpf_probe_read_user_str()` for strings. Both fallible (page faults handled by returning -EFAULT).
- **Strings are pain** — fixed-length char arrays mostly. Comparing to a constant requires a manual loop or `__builtin_memcmp`.
- **The "phantom" pointer** — verifier requires you re-check bounds after arithmetic. `p = p + offset; *p` fails verification even if `*p` was just checked, because the verifier widens the range and can't prove it's still valid.

## Where it's going

- **BPF as kernel-API extension**: kfuncs (kernel functions explicitly exported to BPF, more stable than kprobes), BPF iterators (walk kernel data structures from userspace via BPF), struct_ops (replace function pointer tables in TCP congestion control, BPF schedulers)
- **sched_ext** (6.12+): write Linux schedulers in BPF. Production-real.
- **BPF LSM** displacing AppArmor/SELinux for new policy work
- **Windows**: Microsoft is shipping `ebpf-for-windows`, with the same bytecode and verifier semantics. Same toolchain (libbpf compatibility) targets both kernels. Still rough but real.
- **The verifier is the long-term bottleneck**. Programs keep getting bigger; the verifier keeps getting smarter; the gap is roughly: anything that needs unbounded compute belongs in userspace, not BPF.

---

For netwatch specifically, the relevant frontier is: aya's CO-RE story (the [SDK migration plan](https://github.com/matthart1983/netwatch-sdk)), and whether to expand beyond IPv4 TCP connect to UDP/IPv6 and to sockops for L7 attribution. The kprobe model is the most fragile shape; fentry+CO-RE is the modern equivalent. Worth doing.
