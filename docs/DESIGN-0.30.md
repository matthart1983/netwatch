# netwatch 0.30 — screen design

> Design/review record: this document can include proposals and revision-specific results.
> For current user behavior, use the [documentation index](index.md).

Derived from the nine renders in `NetWatch btop redesign` (`renders/01-dashboard`
… `09-egress`, 2026-09-04). Those renders are the authority for anything this
document leaves ambiguous.

The renders cover tabs 1–8 and 0. There is no Diagnose render; §9 derives that
tab from the global rules plus `netwatch-diagnose-v2.html`.

This describes *chrome and layout only*. What the numbers mean, which rules
fire and what the report contains live in `spec/netwatch-diagnose-spec.md`.

---

## 1. The frame

Every screen is the same five bands, top to bottom. Only the middle one
changes between tabs.

```
┌──────────────────────────────────────────────────────────────────────┐
│ tab bar            ◉ netwatch  1 dashboard … 0 egress   [chips]      │  1 row
│ status strip       ▌ degraded  dns 169.254.1.1 is 3.2σ …   ↵ diagnose│  1 row, conditional
│ control strip      show [concern 3] all 9 …            / filter  s sort│ 1 row, conditional
│                                                                      │
│ panels             the tab's own layout                              │  rest
│                                                                      │
│ footer             : command  ↵ drill  esc back  …      [toast]      │  1 row
└──────────────────────────────────────────────────────────────────────┘
```

No band is ever drawn empty to hold its place. A tab with nothing to say in
the status strip does not reserve the row — it gives it to the panels.

### 1.1 Tab bar

```
◉ netwatch  1 dashboard  2 connections  3 interfaces  4 packets  5 stats
            6 topology  7 timeline  8 processes  9 diagnose  0 egress
                                          ● rec 02:41   frozen   eth0
```

- Brand `◉ netwatch` in accent, **lowercase**. The product is lowercase
  everywhere on screen; `NetWatch` appears in prose and nowhere in the UI.
- Ten tabs, `1`–`9` then `0`, names lowercase. The digit takes the key-hint
  colour so the bar doubles as its own keymap; the name takes muted.
- The current tab is a filled segment: panel-raised background, accent text,
  bold. Selected and unselected occupy identical width — the click hit-test
  and the renderer walk one geometry function.
- Right-hand chips, in this order, each omitted when inactive:
  `● rec MM:SS` (error-tinted ground), `frozen` (warn ground, inverse text),
  `⏸ paused`, `⚠ N` (error ground), then the capture interface in muted text.
- **Truncation priority** when the bar does not fit: drop the interface name,
  then `frozen`, then the recorder timer's label (keeping `●`), then tab names
  from the right, keeping every digit. A clipped tab name is a bug; the v0.29
  bar clipped to `06:5`, `EGRE`, `FROZE` at 150 columns.

### 1.2 Status strip

Present whenever any issue is open, or the tab has a standing condition to
report. One row, three parts:

```
▌ degraded  dns 169.254.1.1 is 3.2σ slow since 06:48:10 · path changed at hop 3 06:44   ↵ diagnose  f freeze  e export
```

- A left accent bar `▌` in the severity colour — the only place a bare colour
  block carries meaning.
- The severity word (`degraded`, `path changed`, `2 drifts`) bold in the
  severity colour, then the sentence in primary text, clauses joined by ` · `.
- Right-aligned contextual keys for *this* condition, styled as §1.4.
- When nothing is wrong it collapses to one dim line, not a green banner.
  Green means healthy, and "healthy" is not news worth a coloured bar.
- The strip reads from the same `Vec<Issue>` as the Diagnose tab. It is not
  allowed a second source.

### 1.3 Control strip

Segmented controls for what the tab is showing. One row:

```
show [concern 3] all 9  established 5  listen 2  time-wait 2    group [none] host process    / filter  s sort  g group  v verdicts
```

- A dim group label (`show`, `group`, `range`, `unit`, `window`, `kinds`,
  `match`, `capture`, `sort`), then its options.
- The active option is a filled chip: panel-raised ground, primary text.
  Inactive options are muted text on no ground.
- Counts ride inside the option (`all 9`, `established 5`), muted.
- Right-aligned: the keys that change these controls.

### 1.4 Key hints

One rendering everywhere — footer, status strip, control strip, panel actions:

> **key** in accent, one space, **label** in muted. Two spaces between pairs.

`↵ drill`, not `↵:Drill`. No colons, no capitalised labels, no `Enter`. The
glyph is what the user presses: `↵` `esc` `↑↓` `←→` `[ ]` `space` `/` `:`.

A key appears **once** per footer. `e export` and `E export` in the same strip
is the bug the v0.29 review found on Processes; `↑↓ issue` beside
`↑↓ scroll` is the same bug wearing two labels.

A key is advertised only while it does something. `↵ apply fix` disappears once
the fix has been applied; `space fold` is absent under `group: none`; `:
command` stays out of the footer until the palette exists. A hint for a dead
key is the same defect as v0.29's Timeline filters that never fired.

Confirmations share one vocabulary wherever they appear — the footer toast and
any transient line under the panels: `✓` and the status colour for success,
`✕` and the error colour for failure. Two confirmations for one class of event
is one too many to learn.

### 1.5 Footer

```
: command  ↵ drill  esc back  d diagnose  r rec  f freeze  e export  ? help      ✓ exported ~/netwatch_incident_20260903-065122/ · 8 files · 6.4 MB
```

- `: command` is always first. Universal keys (`? help`, `q quit`) last.
  Tab-specific keys sit between, most-used first.
- The right end carries the transient toast: a `✓` and the outcome, including
  **the path** for anything written to disk. An export that reports nothing is
  an export the user cannot find. Errors use `✕` and the error colour.

---

## 2. Panels

```
╭ 1 connections ───────────────── 9 shown · attribution procfs ok · geo off (no db) ╮
│ …                                                                                 │
╰───────────────────────────────────────────────────────────────────────────────────╯
```

- Rounded corners, one-cell border, dim border colour throughout.
- **Badge**: a panel that summarises another tab carries **that tab's key** in
  an inverse chip at the start of the title — so the dashboard's connections
  box wears `2`, its health box `9`, its timeline box `7`. The number is a
  promise about what pressing it does, and it is read from the tab bar's own
  labels so a renumbered tab renumbers every badge pointing at it.
  A panel with nowhere to go carries no badge. Per-screen ordinals are not
  allowed: `1`, `2`, `3` in reading order looks like a shortcut and is not one
  — pressing `3` on the third box jumped to Topology.
- Title in accent, bold, lowercase.
- Right-aligned metadata in the same border row, muted: counts, windows,
  units, provenance. Context, never a heading.
- The focused panel takes the accent on its border. That is the only
  difference; no second border style, no double lines.
- A panel whose metadata does not fit drops the metadata. It never wraps into
  the border or pushes the corner.

### 2.1 Sizing

Panels size to content, within a declared min/max. Whatever is left goes to
graphs and detail panes — never to padding a list.

Concretely, from the renders: the Interfaces list is 2 rows because there are
two interfaces; the Processes list is 8 rows because there are 8 processes.
Neither reserves a screen. A list panel more than ~30% empty is a layout bug,
and v0.29 shipped several at 90%.

Rows that add nothing individually fold into one:

```
  2 listeners   0.0.0.0:80  [::]:80   –   listen   …   folded   z expand
  ▸ nginx · sshd · systemd-resolved                    no egress    folded
```

### 2.2 Column failure

When a column has no data for most rows, collapse the column and say why in
the panel metadata — `attribution procfs ok`, `geo off (no db)`. A wall of
`—` is the tool failing quietly.

`unattributed` is the label for a connection with no owning process. Never
`pid:0`: PID 0 is the kernel swapper, and printing it for a *missing* pid
invents a process that owns nothing.

---

## 3. Colour

Three vocabularies. Nothing borrows across them.

| Role | Use | Never |
|---|---|---|
| **status** green / amber / red | health only — a value against its threshold | a row dot, a series, an accent |
| **series** rx cyan / tx violet | direction of data | status |
| **ui** accent cyan, key-hint blue, muted slate | chrome, keys, labels | status |

Rules that follow from it:

- Nothing is green unless it is healthy. `0%` loss is green; `0 B` transferred
  is muted.
- The active tab is a raised ground with accent text, not amber.
- Hotkeys are the key-hint colour, which is not the warning colour.
- Red means *abnormal against a baseline*. `out of order 438` in red with no
  baseline, as v0.29 drew it, means nothing.

### 3.1 Verdict chips

Socket and policy verdicts render as filled pills, dark text on a saturated
ground, lowercase:

`bufferbloat` warn · `slow resolver` error · `receiver-limited` info ·
`app-limited` good · `ok` good · `new · not in policy` violet ·
`folded` / `idle` muted

The chip colour is the *severity of the verdict*, which is why `app-limited`
is green and `bufferbloat` is amber. It is not a category colour.

### 3.2 Selection

The selected row is drawn as **per-column chips**: each cell gets the raised
ground with the gutter between columns left at the panel ground, so the row
reads as a set of values rather than one highlighter stripe.

```
  ncat 473 │ 10.88.0.3:9000 │ – │ estab │ – │ 2.0 MB/s │ 184ms │ 12 │ bufferbloat
  ^^^^^^^^   ^^^^^^^^^^^^^^   ^   ^^^^^   ^   ^^^^^^^^   ^^^^^   ^^   ^^^^^^^^^^^
  each cell on the raised ground; gutters stay on the panel ground
```

On palette-deferring themes the raised ground is `Indexed(8)`, the only slot
conventionally rendered as a neutral mid-grey in both light and dark terminal
themes.

### 3.3 Ramps

Bounded values that genuinely worsen as they climb — link saturation, latency
budget — use green → amber → red, sampled by **position along the meter**, so
the far end shows the alarm colour before the value reaches it.

Magnitude — throughput, byte totals — uses cool → bright. A saturated link
during a backup is working, not failing.

### 3.4 Fade

The fade runs **up** the plot, not along it. A cell's colour comes from how
high it sits, sampled from the magnitude ramp at its own vertical midpoint —
dim at the baseline, the series colour in the middle, lightened at the peak.
That is what makes a filled area read as depth rather than as a block, and it
is the property that lets a steady series still show its shape.

Fading along the time axis instead — old columns dim, new columns bright —
dims the history rather than describing it, and leaves a flat wall in exactly
the way the v0.29 review objected to. There is one ramp implementation, in
`graph.rs`; every renderer samples it.

On palette-deferring themes the magnitude ramps collapse to a flat token,
because their midpoints exist only as synthesised blends. The severity ramp
does **not** collapse: it steps between the theme's own three status tokens.
Flattening it deletes the vocabulary and paints every nominal hop amber.

---

## 4. Graphs

- Braille (2×4) cells. Two independently-addressed sub-columns per cell, so a
  120-column graph carries 240 samples.
- **Mirrored** around a zero line: rx above in cyan, tx below in violet, one
  shared time axis.
- Y-axis labels always (`10M`, `5M`, `0`, `3M`) and an x-axis with at least
  three stops (`-104s`, `-60s`, `-30s`, `now`).
- Scale toggle: linear / log, key `t` or `l`, current state named in the panel
  metadata (`t scale log`).
- Peak and mean in the panel metadata, not overlaid on the plot.
- A steady flow must not render as a solid wall. If autoscaling to peak
  produces one, the scale is wrong, not the data.

**Sparklines** in table cells are ~10 cells of bars coloured by the status
ramp — the per-row 60-second history (`rtt 60s`, `rx 60s`, `activity`). A
one-row sparkline has no vertical axis to spend, so it takes the middle of the
ramp: the series colour itself, at full strength.

**Meters** are `■`-filled, `·`-empty, coloured by position.

**Distributions** are horizontal histograms with a labelled log axis
(`0.1  1  10  100  300ms`) and the percentiles written beneath as text.

**Timeline tracks** stack one metric per row against a single time axis, with
event markers under it (`▲ 06:44 path change`) and a cursor.

---

## 5. Numbers

- Every metric with a baseline shows base, σ and direction:
  `base 1.2 · σ 0.4 · 3.2σ` / `base 0.1 · σ 0.02 · nominal`.
- Deviations are sentences with timestamps — `dns 3.2σ above baseline since
  06:48:10 (3m12s). alt resolver 1.1.1.1 fine.` — not a bare sparkline.
- Counters say where they came from when two sources disagree:
  `counters from /proc, capture from libpcap`.
- A count from a ring buffer is labelled as the ring, never as the session.
  v0.29's `RETRANS 0 of 5.0k` was the ring size wearing a session label.
- Frame counts on offloaded links count **inner segments**. GRO/TSO frames
  reported whole produced `71.8% other` on a pure TCP/IPv4 link.
- Ages are computed from the event's own timestamp, not stamped at render.

---

## 6. Navigation

- `1`–`9`, `0` switch tabs, from anywhere, always.
- `:` opens the command palette.
- `↵` drills into the selected row; `esc` goes back one level.
- A **breadcrumb** above the panels shows the drill path, with the current
  level bold and `esc back` dim at the end:

  `health › dns 169.254.1.1 › connections › packets      esc back`

- Panel badges are the focus targets where a tab defines them.
- `↑↓` selects within the focused panel. It appears once in the footer.

---

## 7. Per-tab layout

Each entry lists the panels in badge order.

**1 dashboard** — hero row of five stat cards (gateway rtt, dns rtt, internet
rtt, loss, retrans), each titled in its own border, with value, unit, inline
sparkline and a baseline line. Then `1 throughput` (mirrored graph) beside `2 health` (per-target rows
with sparklines, then the findings as prose). Then `3 connections` (top rows,
sorted by concern, verdict column). Then `4 timeline` (stacked tracks).

**2 connections** — `1 connections` table: process, remote, app, state, rx/s,
tx/s, rtt, retr, age, verdict, rtt 60s. Detail row beneath: `2` the socket's
tcp_info (cwnd, ssthresh, rwnd, mss, rtt/var, retrans, out of order, pacing),
`3 why <verdict>` with the rtt-vs-tx graph and the reading in prose, then an
unnumbered actions list.

**3 interfaces** — `1 interfaces` table sized to the interface count
(iface, ip, role, link, rx/s, tx/s, saturation meter, err, drop, 60s). Then
`2 <iface>` detail (mac, gateway, dns, queues, offload, qdisc, driver;
session counters; the standing finding) beside `3 throughput`.

**4 packets** — breadcrumb. `1 packets` list with an expert-warning gutter
column. Then `2 #<n>` layered decode with hex, beside `3 stream #<n>` with the
stream summary, the resolver stats and the latency plot.

**5 stats** — hero row of six counters. Then `1 protocol` (l7 nested under l4,
bar per row), `2 top processes`, and `top remotes` — bars **proportional to
value**; v0.29 drew 600 B at five-sixths of the track. Then session throughput
beside `3 rtt distribution`.

**6 topology** — status strip. `1 local` (self, gateway, dns, peers) beside
`2 paths` (one row per target, hops as chained boxes, the changed hop
highlighted, silent hops dashed). Then `3 hops` table: #, host, asn, loss,
last, p50, p95, jitter, distribution, 60s — with the superseded hop shown as
`3'` beneath its replacement. A `reading` line states the conclusion in prose.

One hop, one RTT. v0.29 showed the ISP gateway at 87.9 ms in the node and
31.0 ms in the table on the same screen.

A hop that does not answer ICMP while later hops are clean is `silent hop, not
loss` — never 100% loss.

Wildcard listeners (`0.0.0.0`, `::`) are not LAN peers.

**7 timeline** — `1 tracks` (stacked metric rows, event markers, cursor).
Then `2 events` (time, kind, event, evidence) beside `3 at cursor` — every
track's value at the cursor, then the correlation in prose.

**8 processes** — `1 processes` table (process, pid, conns, rx/s, tx/s,
totals, rtt p50, retr, verdict, rx 60s). Then `2 <proc>` detail (cmdline,
cgroup, threads, fds, policy, sockets), `destinations`, `3 tx and rtt`.

**0 egress** — status strip with the drift decisions. `1 process →
destination` tree, foldable, with match granularity (ip / asn / sni), bytes
each way, first/last seen, activity sparkline and policy state. Then
`2 <flow>` detail (what was seen, sni, asn, baseline, what would match) with
the allow/deny actions, beside `3 policy diff` — the actual toml that `w`
would write, as a diff.

---

## 8. Dense and Lite

Not re-mocked. They inherit §3 colour, §3.1 verdicts and §5 numbers. Dense
keeps its own layout: it is the densest screen in the tool and the direction
the rest of this document is walking toward.

---

## 9. 9 diagnose

No render exists. Derived from §1–§6 and `netwatch-diagnose-v2.html`.

- Status strip carries the worst open issue and `↵ apply`.
- Engine strip beneath it: what has inputs, how far the baselines are, how
  much of the ruleset is live. A user seeing no issues must be able to tell
  "healthy" from "not looking yet". In demo mode this strip carries the
  non-suppressible `DEMO` chip.
- `1 issues` — the open issues, severity-ordered, each three lines: severity
  and title, subject and headline evidence, `since`. Selection per §3.2.
- `chronology` — every tracked issue in the window, oldest first, including
  the consequences the issue list files under their root cause and anything
  the engine has closed. The issue list answers "what is wrong"; this answers
  "in what order", which is the argument the cause ranking rests on. The close
  of a remediated issue lands here, so the log does not stop one beat before
  the payoff.
- `2 <issue title>` — the detail pane, badge and severity-tinted border, four
  headings in the order the report uses: **issue** (evidence, samples, window,
  scope), **probable cause** (ranked, each with its passed checks written out),
  **recommended remediation** (numbered apply steps with their keys, then
  instruct steps, then escalate), **verify** (the condition that closes it).
  Consequences of this issue are listed last under `explained by this issue`.
- The rule catalogue is reference, not a finding. It belongs behind `?`, or in
  the space the issue list genuinely does not need — never larger than the
  issue list, and never with every line ellipsised.
- Footer: `↑↓ issue  ↵ apply  a ack  m mute  o report  e export  y copy`.

---

## 10. What this replaces

Anything in `screenshots/` predates this document. Where a screen still
matches those captures — a 90%-empty list panel, `1-8:Tab`, `e:Export`
alongside `E:Export`, an amber active tab, a solid-wall throughput graph — the
screen is wrong, not this document.

---

## 11. Built as of this document

**The frame.** Tab bar (§1.1), status strip with its severity rail (§1.2), the
control strip as a shared widget (§1.3), one key-hint rendering with
deduplication (§1.4), and the footer with its toast and path (§1.5). Keys are
advertised only while they do something.

**Panels.** Chrome, badges, content sizing, and metadata that drops rather than
overlapping (§2). Verdict chips coloured by severity (§3.1). The severity ramp
survives on palette-deferring themes (§3.3).

**1 dashboard.** Five hero tiles, each carrying `base · σ · nominal | N.Nσ` and
its own `since`; `internet rtt` and `retrans` added, `throughput` dropped as a
duplicate of the panel below it. Mirrored shared-scale throughput with y and x
axes and a linear/log toggle on `t`. Health with three probe targets and the
engine's findings in prose. Connections with `app` and `verdict` columns,
ordered by concern. A timeline of three metrics on one axis with event markers.

**4 packets.** Capture strip carrying ring size, shown, drops and pkt/s — drops
because a packet list without one cannot be trusted. Expert summary in the
panel metadata; `n`/`N` walk the findings and `x` narrows to them, with the
capture-clearing action moved to `X`. DNS query→reply latency in the decode,
compared against the resolver's own baseline. A stream summary panel beside the
decode, carrying the resolver's query/reply counts and percentiles.

**Not built.** The `:` command palette and the drill-through breadcrumb (§1.5,
§6). Per-column selection chips (§3.2). The mirrored/labelled graph contract on
tabs other than Dashboard (§4). The per-tab layouts in §7 for tabs 2, 3, 5, 6,
7, 8 and 0. Expert analysis for retransmission ordinals, SACK ranges, DNS
truncation and RTO (§7, `4 packets`) — the column and its navigation exist, the
classifier does not yet produce those four findings.
