# Doctor and capability reporting

Run a read-only setup report before starting the interactive UI or daemon:

```sh
netwatch doctor
netwatch doctor --json
```

From a source checkout, use `cargo run -- doctor --json`. The first `--` ends
Cargo's options and passes the remaining arguments to Netwatch.

Static doctor reads configuration and local setup facts. It does not start
collectors, open capture, send probes, contact configured endpoints, inspect or
recover journals, create state directories, or save configuration. On Windows it
checks standard Npcap DLL locations and asks the Service Control Manager whether
the `npcap` driver service is running, without loading Npcap. A dynamically
linked build still requires its loader dependencies to start the executable.

On Windows the `capture_library` entry's reason says which of these it found:

| Reason | State | Meaning |
| --- | --- | --- |
| `npcap_missing` | `unavailable` | No `wpcap.dll` in `System32\Npcap` or `System32`. `next_check` gives the download link. |
| `npcap_driver_stopped` | `unavailable` | Npcap's files are there but its driver service is not running. `next_check` gives `sc.exe start npcap`. |
| `npcap_driver_missing` | `unavailable` | A `wpcap.dll` with no `npcap` driver service, as WinPcap or a partial uninstall leaves. |
| `npcap_present_unloaded` | `not_checked` | Installed, and the driver is running or its state could not be read. Npcap is not loaded. `--check-capture` tests a real open. |

Before 0.38, every Windows host with a `wpcap.dll` reported `not_checked`
with `npcap_present_unloaded`, including the two `unavailable` cases above.

Missing or malformed configuration is reported explicitly; malformed content and
configured endpoint credentials are not echoed. A configuration file that cannot
be read or parsed makes `config` `unavailable`, with reason `config_unreadable` or
`config_invalid`. Its detail names the file and, for a parse error, the line and
column; starting `netwatch` prints the full parse error, which quotes the line.
Live sessions refuse to start on such a file, and doctor still completes and exits
successfully. Configuration defaults are used where needed to describe the
remaining checks, except that `--check-capture` does not open capture: `capture`
is `not_checked` with reason `config_not_loaded`, because the defaults could check
a weaker sandbox mode than the one configured. An enabled feature is not evidence
that its backend works.

## Optional capture check

```sh
netwatch doctor --check-capture
netwatch doctor --json --check-capture --interface eth0
```

The optional check selects the configured interface, or uses live interface
selection when none is configured. `--interface` overrides that selection. It
opens and configures capture using the configured BPF filter, then closes it
without reading packets. This can require capture permissions and temporarily
enable promiscuous capture, following the normal capture path.

The parent gives the isolated check process five seconds to finish, then kills
and reaps it on timeout. The check takes the capture thread's policy and reports
it for that process only, in a `capture-check` protection. Its `network_policy` is
what the check saw: after the capture layer it tries a TCP bind, and a connect to a
loopback listener it binds itself, and a deny the layer reports but the kernel does
not give becomes a warning. It does not prove enforcement in live workers,
successful packet delivery, process attribution or network health. No active probes
or cloud calls are made. Platform interface discovery may invoke local system
helpers.

## Landlock

On Linux, static doctor checks what this kernel gives a parser thread. It starts a
disposable thread, applies the parser policy there, even with the sandbox disabled,
tries a TCP bind and a connect to its own loopback listener, and lets the thread
end. It starts no worker, touches nothing else in the process and sends nothing off
the machine. The result is the top-level `landlock` object, null off Linux:

```json
"landlock": {
  "kernel_abi": 9,
  "availability": "available",
  "errata": [1, 2, 3],
  "parser_check": {
    "enforced_abi": 9,
    "restrictions": ["filesystem", "tcp_bind", "tcp_connect",
      "abstract_unix_socket", "signal", "pathname_unix_socket"],
    "tcp_bind": "denied",
    "tcp_connect": "denied"
  }
}
```

`availability` is `available`, `not_enabled` (built into the kernel, left out of its
`lsm=` list), `not_built`, or `unknown` if the check could not ask. `not_built` also
covers something such as a container's seccomp profile blocking Landlock's syscalls:
the crate netwatch uses reads any errno but `EOPNOTSUPP` as a kernel without it. `errata` lists
the fixes the kernel reports, by the numbers in the kernel's Landlock documentation.
`tcp_bind` and `tcp_connect` are `denied`, `allowed` or `error`, for any other
outcome. In a session's log `parser_check` comes from a parser worker's entry report
and no connection is tried, so it says what the layer enforced.

`protections` is empty and `tasks_holding_net_raw` is null in that report, because
static doctor runs no session. [Where each value can be read](#where-each-value-can-be-read)
says where those are.

The `landlock` capability sums that up:

| State | Reason | Meaning |
| --- | --- | --- |
| `ready` | `parser_network_denied` | The kernel denied a parser thread TCP bind and connect. |
| `degraded` | `kernel_abi_below_4` | The kernel cannot deny TCP (Linux older than 6.7). Parser threads keep the network, and `--sandbox-strict` refuses to start. |
| `unavailable` | `landlock_not_enabled` | Built in but not enabled at boot (`EOPNOTSUPP`). |
| `unavailable` | `landlock_not_built` | The kernel has no Landlock (`ENOSYS`), or something such as a container's seccomp profile blocks it. Netwatch cannot tell which. |
| `unavailable` | `self_test_failed` | The kernel can deny TCP and the check did not see it do so. |
| `disabled` | `sandbox_disabled` | The configuration turns the sandbox off. The object above still says what the kernel offers. |
| `unavailable` | `platform_unsupported` | Not Linux. |

Each entry in `protections` describes one thread. Static doctor has none, and
`--check-capture` has one, `capture-check`. A session's log has one for main and for
each worker:

| Field | Meaning |
| --- | --- |
| `landlock_abi` | The Landlock ABI of what this thread enforces, 0 if nothing: the newest feature in force. The filesystem layer alone is 3 at most, TCP needs 4, the abstract socket and signal scopes 6, pathname Unix sockets 9. Before 0.39 this was the kernel's ABI, which on Linux 7.1 read 9 on threads that enforce 3. |
| `landlock_kernel_abi` | The ABI the kernel reports. |
| `network_policy` | `denied` when this thread's TCP bind and connect are, `allowed` when it entered and they are not, as for main and the network workers, and `not_entered` when it has no report. That last one is a capture that failed to open, a worker just started, or `ebpf-reader`, the note for the eBPF SDK's reader thread, which inherits `denied` from the `ebpf` worker. `denied` does not mean no network: see the [threat model](THREAT-MODEL.md), items 4 and 6. |
| `landlock_restrictions` | Any of `filesystem`, `filesystem_write` (capture's layer has no write grant), `tcp_bind`, `tcp_connect`, `abstract_unix_socket`, `signal`, `pathname_unix_socket`, and `socket_create` for the seccomp filter on capture, keylog and the metrics threads. |
| `capture_authority` | CAP_NET_RAW on this thread: `dropped`, `retained_for_reopen`, `not_held` or `not_applicable`. |
| `socket_filter` | The no-socket filter: `installed`, `unknown_arch` (this build has no syscall table for it), `failed` or `not_applicable`. |

The top-level `tasks_holding_net_raw` is process-wide, because capabilities are per
thread and only a session has threads to audit. It lists `{tid, comm}` for each
thread that held CAP_NET_RAW when startup audited the process. It is null in every
`doctor` report, `--check-capture` included, and off Linux. A session's log has the
real list, which is empty in a daemon session with the sandbox on.

`network_restricted` stays false. It describes the whole process, and main and the
network workers keep the network.

As root, the `sandbox` capability's detail and Settings say `running as root:
containment limited`. Root still owns most files whatever the sandbox does, and
[SECURITY.md](../SECURITY.md) scopes sandbox escapes to non-root runs.

## Where each value can be read

No command prints a running session's snapshot as JSON. `doctor` is a separate
process and cannot see into one, so a session reports on itself in Settings and in
its log:

| Value | `doctor --json` | `doctor --json --check-capture` | Settings in a session | Session log | `scripts/capture-authority-audit.sh` |
| --- | --- | --- | --- | --- | --- |
| `landlock` object | The disposable thread's check | The same check | No | From a parser worker's entry report | No |
| `landlock` capability | Yes | Yes | No | No | No |
| `protections` | `[]` | One entry, `capture-check` | Totals only: `TCP denied on N/M parser workers`, `N/M worker entries verified`, and a row for up to three workers with a warning | `main`, and every worker that has started | No |
| `tasks_holding_net_raw` | `null` | `null` | No | The list startup's audit found | Reads every task's four sets from `/proc/<pid>/task` itself, and holds the log's list to being empty |
| CAP_NET_RAW on main | No | No | `CAP_NET_RAW kept on main` or `dropped once capture opened` | `capture_authority` on `main` | The same `/proc` read |
| `socket_filter` | No | On `capture-check` | Only if skipped: `no-socket filter skipped` | On each worker | No |

A daemon or TUI session writes the log line once, when its first health cycle has
started its workers, five ticks in:

```sh
grep 'session protections' ~/.cache/netwatch/netwatch.log.* | tail -1 | sed 's/.*report=//' | jq .
```

It holds `landlock`, `protections` and `tasks_holding_net_raw`. It is `info` on the
target `netwatch::sandbox`, which the default log filter keeps, so a `RUST_LOG` that
leaves that target out drops it. A session that ends before those five ticks writes
none. A worker that starts later, such as a Diagnose probe or an export, is not in it.
The audit script needs a user namespace and runs a daemon of its own, so it checks
this build rather than a session you already have.

## Output contract

[`schemas/doctor.v1.schema.json`](../schemas/doctor.v1.schema.json) describes the JSON, and
[JSON schemas](REFERENCE.md#json-schemas) has the rules it follows. JSON uses a `metadata` block
naming that schema, `schema_version: 1`, a `scope` (`static` or `capture_check`), `platform`,
selected `interface` (null when there is none), `capabilities`, `protections` and `network_restricted`, which is deprecated.
The additive `attribution_coverage` field is null in doctor reports; only runtime
snapshots contain observed coverage. See [attribution evidence](attribution.md).
The additive `landlock` and `tasks_holding_net_raw` fields are described under
[Landlock](#landlock).
Each capability has an `id`, `state`, machine-readable `reason`, explanatory
`detail` and optional `next_check`. On Linux, `connections` names where a live
session reads the connection table. It is `ready` (`ss_found`) when `ss` is on
`PATH`, and `degraded` (`proc_net_fallback`) when it is not and the kernel's
`/proc/net` tables are read instead. When `/proc/net/tcp` cannot be read either,
it is `unavailable` (`no_connection_table`) and the table will be empty. Static
doctor does not run `ss`, so one that is present but fails shows only in a live
session. There Settings shows a `connections: degraded` row with the reason, and
the log records the fallback and why. `geoip_db` reads the databases a session
would open. It is `ready` (`db_loaded`) when they open, `degraded` (`db_stale`)
when one was built over 60 days ago, `unavailable` (`db_unreadable`) when the
Country or City file does not open, and `degraded` (`db_unreadable`) when only the
ASN file does not. A file does not open when it is not a regular file, is over
its size limit (2 GiB for a path in the config, 256 MiB for a file `netwatch geoip
update` saved), is not a MaxMind database, or has a build date out of range. With no Country or City database it is `disabled`
(`not_configured`), and `next_check` suggests `netwatch geoip update`. When
lookups answer with DB-IP's data, judged by each file's own `database_type`, the
`detail` starts with `IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0`. A
live session reports what it opened at startup. States are `ready`, `not_checked`,
`unavailable`, `disabled`, `degraded` and `stale`. Consumers should tolerate new
capabilities and reason codes. A report is a point-in-time observation.

A completed diagnostic report exits successfully even when capabilities are
unavailable. Inspect states in JSON to enforce your own requirements. Invalid CLI
arguments or a fatal command error exit unsuccessfully. Plain text is wrapped for
an 80-column terminal and does not depend on color.

Live startup and Settings use the same model with actual capture, attribution,
probe completion, TCP freshness and component protection observations. A separate
doctor process cannot inspect that live process; its report describes setup or
its own isolated capture check. Neither a ready capture backend nor completed
probes imply a healthy network. Network containment is per thread and partial:
parser and capture threads are denied TCP bind and connect, and main and the network
workers are not.

## Verification scope

Linux automated coverage includes CLI validation, serialization, narrow-terminal
text, subprocess timeout cleanup, unavailable interfaces, malformed config,
configured endpoint traps and unchanged recovery/configuration files. These tests
do not establish privileged capture success or macOS/Windows runtime parity.
On Windows, CI runs the release binary's `--version`, `doctor` and
`doctor --json` on a runner without Npcap and checks that it reports
`npcap_missing` with the download link.
