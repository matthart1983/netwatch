#!/usr/bin/env bash
# Prepare an isolated HOME for the NetWatch Dense demo recording, and print it.
#
# Same reasoning as `demo-lite-env.sh` — netwatch reads its config from
# `dirs::config_dir()`, which derives from $HOME, so recording against the
# operator's real config makes the GIF depend on whatever theme they happen to
# have set. This one differs in two deliberate ways:
#
#   - `theme = "dark"`, NOT `"terminal"`. The Lite demo pins the terminal
#     palette so its colours come from the user's own theme; that is correct
#     there and fatal here. Dense encodes magnitude as a colour ramp, and a
#     palette-deferring theme collapses every ramp to a single flat token by
#     design (see `Ramps::from_theme`) — it would record the one feature the
#     view exists to show as a solid block of one colour. `dark` is RGB
#     throughout, so the gradient survives.
#
#   - `refresh_rate_ms = 250`. History gains one sample per refresh tick and
#     the plot carries one sample per braille sub-column, so at the 500 ms
#     default a 130-column terminal needs two full minutes before the graph
#     reaches the left edge. At 250 ms it fills in one, and the plot visibly
#     scrolls rather than creeping — which is what the recording needs to show.
#     Every rate on screen is still measured per tick, so nothing is distorted.
#
# Usage (from a tape):  export HOME=$(./scripts/demo-dense-env.sh)
set -euo pipefail

# `mktemp -t NAME` is BSD syntax; GNU coreutils rejects a template with no
# X's ("too few X's in template") and exits 1, which under `export
# HOME=$(...)` silently sets HOME to the empty string — netwatch then finds no
# config and records in whatever the defaults are. Spell the template out so
# both mktemps take it.
DEMO_HOME="$(mktemp -d "${TMPDIR:-/tmp}/netwatch-dense-home.XXXXXX")"
CFG_DIR="$DEMO_HOME/Library/Application Support/netwatch"

# Linux puts it under ~/.config; create both so the tape is portable.
mkdir -p "$CFG_DIR" "$DEMO_HOME/.config/netwatch"

cat > "$CFG_DIR/config.toml" <<'TOML'
theme = "dark"
refresh_rate_ms = 250
view = "full"
graph_style = "bars"
graph_fade = false
TOML

cp "$CFG_DIR/config.toml" "$DEMO_HOME/.config/netwatch/config.toml"

echo "$DEMO_HOME"
