# AI Insights

NetWatch's **Insights** tab (tab `8`) feeds a rolling snapshot of your network
activity — protocol mix, top talkers, DNS queries, connection state counts,
gateway/DNS health, and expert warnings/errors — to a local LLM every 15
seconds and renders the model's analysis in the TUI.

Insights is **opt-in** and **off by default**. When enabled, NetWatch talks to
an [Ollama](https://ollama.com) server — either the local daemon on your own
machine, a remote Ollama host on your network, or Ollama's hosted **cloud
models** (see [Using cloud models](#using-cloud-models)). The local Ollama
daemon is always the HTTP target; for cloud models it simply proxies your
request through to Ollama's infrastructure, so netwatch itself never needs
to handle API keys directly.

---

## Quick start

1. Install Ollama: <https://ollama.com/download>
2. Pull a model:
   ```sh
   ollama pull llama3.2
   ```
3. Make sure the Ollama daemon is running (`ollama serve`, or the macOS/Windows
   tray app — `ollama run llama3.2` once will also start it).
4. Launch NetWatch, press `,` to open the settings menu, and toggle
   **AI Insights** on. Or edit the config file directly (see below).
5. Press `8` to switch to the Insights tab. The first analysis appears within
   ~15 seconds once packets are being captured.

---

## Configuration

NetWatch reads its config from `~/.config/netwatch/config.toml`. The three
Insights-related fields are:

```toml
# Enable the Insights tab. Off by default.
insights_enabled = true

# Model name as Ollama knows it. Must be pulled via `ollama pull <model>`.
insights_model = "llama3.2"

# "local" is shorthand for http://localhost:11434.
# Point this at a remote Ollama host by giving a full base URL.
insights_endpoint = "local"
```

You can also edit these live from the settings menu (`,` from any tab — use
`↑/↓` to move between rows, `Enter` to edit, `Esc` to commit). Changes take
effect immediately — the insights worker is restarted with the new model and
endpoint.

### Choosing a model

Any Ollama-compatible model works. Smaller models give faster responses and
use less RAM; larger models give better analysis. Reasonable local picks:

| Model          | Size   | Notes                                         |
|----------------|--------|-----------------------------------------------|
| `llama3.2`     | ~2 GB  | Default. Good balance of speed and quality.   |
| `llama3.2:1b`  | ~1 GB  | Fastest; runs comfortably on modest hardware. |
| `llama3.1:8b`  | ~5 GB  | Better reasoning; needs ~8 GB free RAM.       |
| `mistral`      | ~4 GB  | Solid alternative to llama3.                  |
| `qwen2.5:7b`   | ~5 GB  | Strong at structured analysis.                |

Pull whichever you want and set `insights_model` to the exact tag Ollama uses
(`ollama list` shows installed models).

If you'd rather not run a model locally, use a **cloud model** instead —
any tag ending in `:cloud` is served by Ollama's hosted infrastructure and
needs no local GPU or RAM. See the next section.

### Using cloud models

Ollama's hosted cloud lets you run larger models than your machine could
handle locally. The local Ollama daemon still answers on `localhost:11434`;
it just forwards your chat request to Ollama's servers and streams the
response back. From NetWatch's perspective, nothing changes — you point
`insights_model` at a `:cloud` tag and leave `insights_endpoint = "local"`.

Setup:

1. Sign in to your Ollama account from the CLI:
   ```sh
   ollama signin
   ```
   This opens a browser to authenticate and stores the credentials in
   `~/.ollama/`. NetWatch never sees them — the daemon handles auth.
2. List available cloud models:
   ```sh
   ollama ls
   ```
   Cloud models appear with the `:cloud` suffix (e.g. `minimax-2.5:cloud`,
   `gpt-oss:cloud`, `qwen3-coder:cloud`, `deepseek-v3.1:cloud`). Check
   <https://ollama.com/cloud> for the current catalog and any account
   requirements.
3. Set the model in NetWatch's config:
   ```toml
   insights_enabled = true
   insights_model = "minimax-2.5:cloud"
   insights_endpoint = "local"
   ```
   Or edit it live from the settings menu (`,`).

Cloud models generally return faster than running a large model locally on
CPU-only hardware, and you avoid the 10–30 second warm-up while a local
model loads into RAM. The tradeoff is that snapshot data leaves your machine
— see [Privacy](#privacy) below.

### Pointing at a remote Ollama host

If Ollama is running on another machine (a home server, a GPU box, etc.),
give `insights_endpoint` a full base URL:

```toml
insights_endpoint = "http://gpu-box.lan:11434"
```

NetWatch appends `/api/chat` to whatever base URL you provide. The request
times out after 30 seconds. Remote Ollama servers must be reachable over HTTP
with no auth — Ollama doesn't ship with auth out of the box, so put it behind
a VPN or a reverse proxy on an internal network only.

---

## Privacy

The snapshot NetWatch sends to the model contains:

- aggregated protocol counts
- top destination IPs with packet counts
- recent DNS queries and their resolved hostnames
- expert-layer error/warning summaries
- gateway and DNS RTT/loss stats
- current bandwidth rates

It does **not** include raw packet payloads.

**Where that data goes depends on which model you pick:**

- **Local models** (e.g. `llama3.2`, `mistral`) — every byte stays on the
  machine running Ollama. Nothing leaves your network.
- **Remote self-hosted Ollama** (a VPS, home server, etc.) — data travels
  over whatever network path you set up. Prefer a VPN or internal network.
- **Cloud models** (`*:cloud` tags) — the local Ollama daemon forwards
  each snapshot to Ollama's hosted infrastructure for inference. Review
  Ollama's privacy policy at <https://ollama.com/privacy> before using
  cloud models for traffic you consider sensitive.

If privacy is the priority, stick to a local model.

---

## Troubleshooting

### Status shows `OllamaUnavailable`

NetWatch got a connection-refused error when calling the endpoint. Fixes:

- Confirm Ollama is running: `curl http://localhost:11434/api/tags` should
  return JSON.
- On macOS, start it via the menu-bar app or `ollama serve`.
- On Linux, `systemctl --user start ollama` (if installed as a user service)
  or just `ollama serve` in a terminal.
- If using a remote endpoint, check firewall rules and that Ollama is bound
  to `0.0.0.0:11434` rather than loopback (`OLLAMA_HOST=0.0.0.0 ollama serve`).

### Status shows `Error: model 'X' not found`

Ollama hasn't pulled that model yet. Run `ollama pull <model>` and make sure
`insights_model` in the config matches the tag exactly (`ollama list` to see
installed tags — note that `llama3.2` and `llama3.2:latest` are the same thing,
but `llama3.1` and `llama3.2` are not).

### Cloud model returns an auth error

If you set a `:cloud` model but see an error mentioning auth, unauthorized,
or a 401/403 response, the local Ollama daemon isn't signed in. Run
`ollama signin` and try again. You can sanity-check the daemon directly with:

```sh
curl http://localhost:11434/api/chat \
  -d '{"model":"minimax-2.5:cloud","messages":[{"role":"user","content":"ping"}],"stream":false}'
```

If that curl succeeds but NetWatch still errors, the model name in your
config probably doesn't match the tag exactly.

### Insights are slow or stale

- The first response after enabling can take 10–30 seconds while the model
  loads into memory.
- Analysis is rate-limited to once every 15 seconds, and only runs when at
  least one packet has been captured in that window.
- If the model takes longer than 30 seconds to respond, NetWatch times out
  the request and shows an error. Switch to a smaller model (e.g. `llama3.2:1b`)
  or give Ollama more resources.

### Nothing appears on the Insights tab at all

- Check that `insights_enabled = true` in the config (or that the toggle in
  the settings menu is on).
- Make sure packet capture is actually running — the Packets tab should show
  traffic. Insights only runs when there are packets to analyze.
- Watch the tab header for the status badge (`Idle`, `Analyzing`, `Available`,
  `Error`, `OllamaUnavailable`).

---

## Non-Ollama cloud providers (not supported)

NetWatch speaks the Ollama `/api/chat` protocol only. Direct integrations
with OpenAI, Anthropic, Gemini, etc. are not supported — but because Ollama
itself offers a wide range of hosted `:cloud` models (see
[Using cloud models](#using-cloud-models)), you can usually get a
comparable experience without needing a direct provider integration. If
you specifically need a non-Ollama provider, please open an issue.

---

## Disabling

Either flip the toggle off in the settings menu, or set
`insights_enabled = false` in the config file. When disabled, no snapshots
are collected and no requests are made to Ollama.
