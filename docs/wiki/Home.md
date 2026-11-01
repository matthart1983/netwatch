# NetWatch documentation

NetWatch is a terminal network diagnostics tool. Start with [[Getting Started]], then use [[Doctor]] when a capability is missing.

- **Find a problem:** [[Diagnose and Coverage]], [[Network Intelligence]], [[Traceroute]].
- **Inspect traffic:** [[Tab System]], [[Keyboard Controls]], [[Display Filters]], [[TLS Decryption]].
- **Understand ownership:** [[eBPF Process Attribution]], [[Egress]].
- **Control access and disclosure:** [[Permissions]], [[Sandbox]], [[Configuration and Privacy]].
- **Operate and develop:** [[Daemon and Metrics]], [[Platform Support]], [[Build System]], [[Testing]].

The [documentation index](@repo@/docs/index.md) links to the detailed contracts. Current development changes are labeled unreleased; this wiki's baseline is the released version in the header.

## Choose a workflow

| What you want to answer | Start here | What you should expect |
| --- | --- | --- |
| Why is an application slow? | [[Diagnose and Coverage]] | Target-stage timings, findings, available evidence and a bounded CLI run. |
| Which process talks to this host? | [[eBPF Process Attribution]], then [[Egress]] | Ownership confidence, destination history and policy drift. |
| What did the connection send? | [[Packet Capture Engine]], [[TLS Decryption]] | Retained capture, stream inspection, supported decryption and exports. |
| Can I run without root? | [[Permissions]], [[Doctor]] | Actual checks and restricted platform setup instructions. |
| What leaves or stays on my machine? | [[Configuration and Privacy]] | Outbound triggers, defaults and persistent state. |
| How does the implementation work? | [[Architecture]], [[Module Reference]] | Runtime flow, worker lifecycle and source map. |

The topic pages contain the procedures and reference tables directly. Shared sections
are generated from the same repository documents used by contributors; source links
are there for traceability, not as a substitute for the guide.

## A first investigation

Run `netwatch doctor`, start `netwatch`, and select the interface that carries the
traffic you want to inspect. In the full view, open Connections (`2`) to locate
the peer, then use `Enter` to inspect matching packets. Open Diagnose (`9`) to
check whether measured evidence supports a connectivity finding. If a view is
empty, inspect permissions and coverage before interpreting that as no activity.

For a reproducible report, record the version, interface and time window. Review
addresses, names and payloads before sharing any capture or diagnostic export.
