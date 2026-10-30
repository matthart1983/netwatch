# Security Policy

NetWatch is a network diagnostics tool that typically runs with elevated
privileges and parses hostile input (live packet captures) by design. Security
reports are taken seriously and handled as the highest-priority work.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

- Preferred: [**GitHub private vulnerability reporting**](https://github.com/matthart1983/netwatch/security/advisories/new)
  ("Report a vulnerability" under the Security tab).
- Alternatively: email **matthew.t.hartley@gmail.com** with `[netwatch security]`
  in the subject.

You'll get an acknowledgement within **72 hours** and a triage verdict within
**7 days**. Fixes for confirmed vulnerabilities ship as a patch release as soon
as they're ready — NetWatch is independently maintained, so severe reports jump
every queue. Please give us a reasonable window to ship a fix before public
disclosure; we're happy to coordinate timing and will credit you in the
advisory and release notes (or keep you anonymous, your call).

## Supported versions

NetWatch is pre-1.0. Security fixes target the **latest release** only —
please reproduce on the current version before reporting.

| Version | Supported |
|---|---|
| latest release | ✅ |
| anything older | ❌ upgrade first |

## Scope — what we care about most

NetWatch's threat model assumes packets on the wire are attacker-controlled,
and that the tool often runs as root. In rough priority order:

1. **Privilege escalation** — anything that lets an unprivileged local user
   leverage NetWatch's elevated capture/eBPF privileges.
2. **Sandbox escape** — on Linux, NetWatch applies a post-startup Landlock
   sandbox; bypasses in non-root runs (including `--sandbox-strict`) are in scope.
   Root runs work, but containment is limited and the sandbox is defence in
   depth only. This does not exclude hostile-input or privilege-escalation bugs
   merely because they are reproduced in a root run.
3. **Hostile-input handling** — crashes, hangs, or memory unsafety in the
   packet, DPI, TLS/QUIC, DNS, or HTTP parsers when fed malicious traffic.
   (Parser *panics* on hostile input are security bugs here, not ordinary
   crashes — they're a remote DoS against a monitoring tool.)
4. **Sensitive-data mishandling** — TLS session keys from a keylog file,
   captured payloads, or incident-bundle/flight-recorder exports ending up
   somewhere unexpected (world-readable files, logs, remote streaming).
5. **Daemon/remote mode** — API-key handling and anything reachable from the
   network when running `netwatch daemon` with `--remote` or `--metrics-addr`.

Out of scope: vulnerabilities in dependencies with no NetWatch-specific
exploit path (report upstream, though a heads-up is welcome), issues requiring
an already-root attacker, and self-inflicted configurations (e.g. exposing the
metrics endpoint to the internet deliberately).

## Hardening notes for operators

- Worker entry points now apply Linux filesystem policy before processing;
  capture prepares its device before policy entry. Strict startup rejects required
  entry failures. Writable grants use dedicated application paths, and configured
  inputs receive exact file grants. Network policy is per thread: parser and capture
  threads are denied TCP bind and connect from Linux 6.7, capture, keylog and the
  metrics threads also get EPERM from socket(2), and main and the network workers keep
  the network. `netwatch doctor --json` shows what this kernel gives a parser thread,
  and a session's log what each of its threads got. Privileged
  capture/restart acceptance and some shutdown guarantees remain pending. See the
  [exact scope](docs/REFERENCE.md#landlock-sandbox-linux).
- Treat TLS keylog files and exported incident bundles as secrets — they can
  contain decrypted traffic.
- `netwatch daemon` metrics bind to `127.0.0.1` by default; keep it that way
  unless you have a reason not to.

See the [threat model](docs/THREAT-MODEL.md) for per-thread privileges, outbound
traffic, unsupported boundaries and planned hardening.
