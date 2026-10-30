# AI Insights

Insights is optional AI commentary inside **Diagnose (tab `9`)**, below the
findings. Tab `8` is Processes. Insights is off by default; deterministic
rule detection, cause ranking and remediation do not require a model.

The commentary comes from a network snapshot, not from a validated explanation
of Diagnose's issue objects. It can be incorrect or disagree with a finding.
Enabling it does not enable automatic model-directed remediation.

## Setup

1. Configure an Ollama-compatible server with a model it can serve.
2. Press `,` to open Settings and enable **AI Insights**. Set the model and
   endpoint there, or edit Netwatch's config:

   ```toml
   insights_enabled = true
   insights_model = "llama3.2" # Netwatch's default; must be available on your server
   insights_endpoint = "local"
   ```

3. Open Diagnose with `9` in the full view. The commentary block shows whether
   it is waiting, analysing, available, unable to reach the endpoint, or reporting
   a model error. Capture must have supplied a nonempty packet snapshot.

Configuration lives in the platform config directory under `netwatch/config.toml`
(`~/.config/netwatch/config.toml` on a typical Linux installation). Settings changes
recreate the Insights collector with the current model and endpoint.

`local` (or an empty endpoint) resolves to `http://localhost:11434`. To use another
server, set its base URL, for example `http://gpu-box.lan:11434`. Netwatch appends
`/api/chat` and sends an Ollama chat request. It does not configure provider API
keys or authentication headers. Choose a model supported by your server; Netwatch
does not maintain a model catalogue or benchmark model quality.

## Timing and retained data

The collector uses a 15-second rate-limit interval and a 30-second request timeout.
Response time and worker scheduling affect when commentary appears. The collector
skips snapshots with zero retained packets; it does not require a new packet since
the previous analysis. Pausing capture can therefore leave old traffic available
for another analysis. Commentary is not proof that current traffic was measured.

## Data sent to the endpoint

The prompt includes:

- Retained packet count and protocol counts.
- Top destination addresses with packet counts.
- Recent DNS query names and observed address-to-hostname mappings.
- Expert warnings/errors, including source/destination addresses and decoded
  packet summary text.
- Established and other connection counts.
- Gateway/DNS RTT and loss, plus bandwidth rates.

Packet-derived summaries use at most the last 500 retained packets, with further
limits on individual lists. Raw packet byte buffers are not attached, but decoded
summary text, names and addresses can still be sensitive. There is no redaction
profile for this prompt.

The configured endpoint receives the snapshot. A remote URL sends it off-host;
plain HTTP provides no transport encryption. Netwatch marks an `http://` endpoint
that is not on this host as `cleartext, off-host`: a line on the Diagnose page,
with or without an open issue, a label on the AI Endpoint row in Settings, and in
`netwatch doctor`, `insights` as degraded with reason `cleartext_off_host`. It warns
and still sends; there is no key to refuse. Loopback addresses, `localhost` and
`https://` carry no mark. A localhost URL only identifies the
first recipient: an Ollama-compatible server may forward inference to a cloud
provider. Netwatch neither verifies local-only execution nor enforces a network
boundary around the model server. Check that server's configuration and data
handling before enabling commentary for sensitive traffic.

## Troubleshooting

- **Waiting for the first analysis:** confirm capture has retained packets and
  allow time for a request and model response. Merely enabling Insights does not
  supply capture permissions.
- **No model answering:** check the endpoint in Settings and confirm the server
  is running and reachable. For the default endpoint, its model listing can be
  inspected with `curl http://localhost:11434/api/tags`.
- **Model error:** read the message in the commentary block. Confirm that the
  configured model exists on the selected server; check server-side forwarding
  or authentication if applicable.
- **Slow or old commentary:** check request timeouts and server capacity, and
  remember that retained packets can outlive active capture. Previous commentary
  can remain visible alongside a new request or error status.

Netwatch speaks the Ollama `/api/chat` protocol. A service using a different API
requires a compatible intermediary; direct integrations with other provider APIs
are not implemented.

## Disabling

Turn AI Insights off in Settings or set `insights_enabled = false` before startup.
The app then stops feeding snapshots to the collector. Disabling does not recall
requests already sent; a worker may finish an in-flight request or queued work
before exiting. It does not stop Netwatch's other network activity, such as health
probes or lookups. `third_party_probes = false` stops the automatic probes to public
servers; see the [configuration reference](REFERENCE.md#security).

Implementation references: [snapshot and worker](../src/collectors/insights.rs),
[commentary UI](../src/ui/diagnose.rs), [configuration](../src/config.rs).
