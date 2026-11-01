# AI Insights

Insights is off by default and appears inside Diagnose (`9`). Processes is tab `8`. Deterministic findings and remediation guidance do not require a model.

Enable AI Insights in Settings and configure an Ollama-compatible endpoint and an available model. A nonempty retained packet snapshot is needed. See the [complete setup](@repo@/docs/INSIGHTS.md).

Requests include addresses, DNS names, decoded packet summaries and network measurements. A remote endpoint receives those data; plain HTTP off-host is warned about but still sent. A localhost endpoint does not prove local-only inference because its server may forward requests.

Commentary can be wrong or disagree with findings and is not validated against Diagnose issue objects. See [disclosure and limitations](@repo@/docs/INSIGHTS.md#data-sent-to-the-endpoint).
