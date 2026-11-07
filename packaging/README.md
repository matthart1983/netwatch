# Packaging — netwatch fleet agent

Service definitions for running `netwatch daemon` (the headless agent) as a
long-running service that streams to a netwatch cloud / NetWatch Core backend.

The daemon runs the same collectors as the TUI with no rendering, buffers
snapshots in a durable bounded queue, and flushes that queue on SIGTERM before
exiting.

## Configuration

Both units pass the backend endpoint and API key via environment variables
(`NETWATCH_REMOTE_URL`, `NETWATCH_API_KEY`) rather than CLI flags, so the key
never appears in `ps`. The equivalent manual invocation is:

```sh
NETWATCH_API_KEY=<key> netwatch daemon --remote https://cloud.example.com
```

`--api-key <key>` is deprecated. It stays accepted through 1.x, with a warning, and
goes in 2.0, and it puts the key where any user on the host can read it with `ps`.

The URL must be `https://`. netwatch refuses an `http://` URL, which would
send the API key in cleartext, unless `--insecure-remote` is also given; for
a unit, that means adding the flag to `ExecStart` or `ProgramArguments`.

## Linux (systemd)

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin netwatch
sudo install -m0755 target/release/netwatch /usr/bin/netwatch
sudo install -d -m0750 -o netwatch -g netwatch /etc/netwatch
printf 'NETWATCH_REMOTE_URL=%s\nNETWATCH_API_KEY=%s\n' \
  "https://cloud.example.com" "<key>" | sudo tee /etc/netwatch/agent.env >/dev/null
sudo chmod 0640 /etc/netwatch/agent.env && sudo chown root:netwatch /etc/netwatch/agent.env
sudo cp packaging/systemd/netwatch.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now netwatch
journalctl -u netwatch -f
```

The unit runs unprivileged with only `CAP_NET_RAW`, `CAP_BPF`, and
`CAP_PERFMON` (eBPF process attribution needs the latter two). netwatch applies
its own Landlock sandbox on top after startup, and drops `CAP_NET_RAW` from its
threads once capture has opened. The open capture descriptor can still capture
and inject on any interface in the network namespace. The unit grants these
capabilities to its service user, so the binary carries none and can stay 0755:
it needs no `setcap` and no group restriction.

## Connection log (experimental)

The unit runs `netwatch daemon` without the flow log. To turn it on, add a
drop-in with `sudo systemctl edit netwatch`:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/netwatch daemon --flow-log file --flow-log-dir /var/log/netwatch
```

The unit's `LogsDirectory=netwatch` makes `/var/log/netwatch`, owned by the
service user with mode 0700, which the flow log's sandbox write grant requires.
Files are daily (`flows.YYYY-MM-DD.ndjson`, UTC days) and kept for 14 days;
`--flow-log both` also sends each line to the journal. See REFERENCE, Flow log.

As the unit stands, the log names a process only where the service user can
read its sockets, or where eBPF saw the `connect()`. To name other users'
processes too, add these lines to the same drop-in:

```ini
AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
```

The proc-broker thread uses them to read every process's `/proc/<pid>/fd`.
Every other thread drops CAP_SYS_PTRACE; the sandboxed ones keep
CAP_DAC_READ_SEARCH, but Landlock still limits which paths they open.
CAP_SYS_PTRACE is what lets a process inspect, and attach to, any other, so
this is a larger grant than capture needs.

## macOS (launchd)

```sh
sudo install -m0755 target/release/netwatch /usr/local/bin/netwatch
sudo cp packaging/launchd/com.netwatch.agent.plist /Library/LaunchDaemons/
# edit NETWATCH_REMOTE_URL / NETWATCH_API_KEY in the plist, then:
sudo launchctl bootstrap system /Library/LaunchDaemons/com.netwatch.agent.plist
```

To keep the connection log as well, add `--flow-log`, `file`, `--flow-log-dir`
and `/var/log/netwatch` to `ProgramArguments`, and create that directory first
with `sudo install -d -m0700 /var/log/netwatch`.

`scripts/build-dmg.sh` builds an Apple Silicon `.dmg` with the binary and an
installer script. The installer copies netwatch to `/usr/local/bin` and asks
before it starts a daemon, which runs with the connection log on. Neither the
binary nor the `.dmg` is signed or notarized.

macOS uses BPF capture and `lsof` observations; Linux eBPF does not run on macOS.
PKTAP metadata does not establish verified socket ownership. macOS process
identity remains unverified even with elevated capture access; see
[attribution evidence](../docs/attribution.md).
