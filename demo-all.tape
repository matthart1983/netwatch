Output demo-all.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 750
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms
Set Framerate 12
Set Padding 10

# Strategy: Hide vhs during each tab switch (vhs's Type seems to drop
# keystrokes when the recorder is actively capturing in a long run, but
# survives during Hide). Show again to record ~5s of live motion per tab.
# Requires:  NETWATCH_DEMO_PASSWORD='...' vhs demo-all.tape

Hide
Type `echo "$NETWATCH_DEMO_PASSWORD" | sudo -S ./target/release/netwatch`
Enter
Sleep 30s
Show

# ── 1. Dashboard ──────────────────────────────────────────
Sleep 5s

Hide
Type "2"
Sleep 1s
Show

# ── 2. Connections ────────────────────────────────────────
Sleep 5s

Hide
Type "3"
Sleep 1s
Show

# ── 3. Interfaces ─────────────────────────────────────────
Sleep 5s

Hide
Type "4"
Sleep 1s
Show

# ── 4. Packets ────────────────────────────────────────────
Sleep 5s

Hide
Type "5"
Sleep 1s
Show

# ── 5. Stats ──────────────────────────────────────────────
Sleep 5s

Hide
Type "6"
Sleep 1s
Show

# ── 6. Topology ───────────────────────────────────────────
Sleep 5s

Hide
Type "7"
Sleep 1s
Show

# ── 7. Timeline ───────────────────────────────────────────
Sleep 5s

Hide
Type "8"
Sleep 1s
Show

# ── 8. Processes ──────────────────────────────────────────
Sleep 5s

Hide
Type "9"
Sleep 1s
Show

# ── 9. Insights (lingers longest — the new tab) ──────────
Sleep 7s

Hide
Type "q"
Sleep 500ms
