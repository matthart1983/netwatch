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
and reaps it on timeout. The check reports sandbox enforcement for that process
only. It does not prove enforcement in live workers, successful packet delivery,
process attribution or network health. No active probes or cloud calls are made.
Platform interface discovery may invoke local system helpers.

## Output contract

JSON uses `schema_version: 1`, a `scope` (`static` or `capture_check`), `platform`,
selected `interface`, `capabilities`, `protections` and `network_restricted`.
The additive `attribution_coverage` field is null in doctor reports; only runtime
snapshots contain observed coverage. See [attribution evidence](attribution.md).
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
ASN file does not. With no Country or City database it is `disabled`
(`not_configured`), and `next_check` suggests `netwatch geoip update`. A live
session reports what it opened at startup. States are `ready`, `not_checked`,
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
probes imply a healthy network. Network containment is not provided.

## Verification scope

Linux automated coverage includes CLI validation, serialization, narrow-terminal
text, subprocess timeout cleanup, unavailable interfaces, malformed config,
configured endpoint traps and unchanged recovery/configuration files. These tests
do not establish privileged capture success or macOS/Windows runtime parity.
On Windows, CI runs the release binary's `--version`, `doctor` and
`doctor --json` on a runner without Npcap and checks that it reports
`npcap_missing` with the download link.
