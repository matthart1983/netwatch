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

## Debian / Ubuntu package with the connection log (this fork)

```sh
scripts/build-deb.sh                     # → target/netwatch_<version>+flowlog1_amd64.deb
sudo apt install ./target/netwatch_*+flowlog1_amd64.deb
sudo tail -f /var/log/netwatch/flows.$(date -u +%F).ndjson
```

The script builds a static musl binary with libpcap 1.10.5 linked in, as the
upstream release does, so the package depends on nothing at install time. To
build it, the dependencies come from apt:

```sh
sudo apt install musl-tools flex bison make curl file binutils dpkg-dev linux-libc-dev
```

and Rust from rustup (`rustup target add x86_64-unknown-linux-musl`), since
apt's Rust is older than the crate's `rust-version`. The build itself runs
without root. Installing creates the `netwatch` system user and enables and
starts `netwatch.service`, which runs
`netwatch daemon --flow-log file --flow-log-dir /var/log/netwatch`. The unit
gives the service its capabilities; the binary carries none. Besides capture
and eBPF, it grants CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH, which only the
proc-broker thread keeps, to read other processes' sockets: without them every
process but netwatch itself is logged with a null `process`. Removing the
package stops the service; purging also deletes `/var/cache/netwatch` and
`/var/lib/netwatch`, and leaves the log in `/var/log/netwatch`.

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

## macOS (launchd)

```sh
sudo install -m0755 target/release/netwatch /usr/local/bin/netwatch
sudo mkdir -p /var/log/netwatch && sudo chmod 0700 /var/log/netwatch
sudo cp packaging/launchd/com.netwatch.agent.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.netwatch.agent.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.netwatch.agent.plist
```

The plist runs `netwatch daemon` with the flow log on, written to `/var/log/netwatch`.
The `.dmg` from `scripts/build-dmg.sh` does the same steps from an installer.

Full eBPF/PKTAP attribution on macOS requires root; without it the daemon falls
back to lsof/ss-based attribution.
