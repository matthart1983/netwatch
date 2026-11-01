# NetWatch documentation

Repository documents describe this checkout; development-only behavior is labeled
unreleased. The [public wiki](https://github.com/matthart1983/netwatch/wiki) identifies
its release baseline and documentation source commit on each page.

## Start and troubleshoot

- [Install and first run](../README.md)
- [Doctor: setup and optional capture checks](doctor.md)
- [Permissions](REFERENCE.md#permissions)
- [Troubleshooting](wiki/Troubleshooting.md)
- [Platform capabilities and validation limits](CAPABILITIES.md)

## Use NetWatch

- [Commands, views, keys and filters](REFERENCE.md)
- [Diagnose and coverage](DIAGNOSE.md), [rule contracts](diagnostic-coverage.md)
- [Egress workflow](REFERENCE.md#egress-policy-linter)
- [TLS and QUIC decryption](REFERENCE.md#tls-13--12-decryption)
- [Attribution: ownership, freshness and coverage](attribution.md)
- [Configuration and outbound traffic](REFERENCE.md#what-netwatch-sends-off-this-machine)
- [Optional AI commentary and disclosure](INSIGHTS.md)
- [Daemon service setup](../packaging/README.md), [Prometheus metrics](observability-export.md)

## Understand and maintain

- [Architecture](ARCHITECTURE.md), [runtime lifecycle](runtime-lifecycle.md)
- [Security boundary](THREAT-MODEL.md), [reporting vulnerabilities](../SECURITY.md)
- [Measured performance and retention limits](PERFORMANCE.md)
- [Recovery storage](recovery-store.md), [resolver authority](resolver-adapter.md)
- [Contributing and test tiers](../CONTRIBUTING.md)
- [Packaging and release checks](PACKAGING.md)
- [Documentation and wiki maintenance](wiki-maintenance.md)

## Design and historical material

Dated reviews, design documents, research plans and implementation plans record
intent or evidence at their stated revision. They are not current user instructions.
Use the references above for shipped behavior. Architecture/eBPF HTML tours are
historical teaching illustrations with links to the current contracts. Release
notes describe their release, not necessarily the current implementation.
