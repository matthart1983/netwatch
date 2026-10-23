# fish completion for netwatch
#
# Kept in step with src/cli.rs by `completions_and_man_cover_every_option`
# in that file: adding an option there fails the test until it is listed
# here too.
#
# Install: copy to ~/.config/fish/completions/netwatch.fish (the .deb and
# .rpm packages install it system-wide).

# No file completion; netwatch takes subcommands and flags, not paths,
# except where a subcommand below says otherwise.
complete -c netwatch -f

# ── subcommands ───────────────────────────────────────────────────────
complete -c netwatch -n __fish_use_subcommand -a daemon -d 'Headless agent, no TUI'
complete -c netwatch -n __fish_use_subcommand -a doctor -d 'Read-only setup report'
complete -c netwatch -n __fish_use_subcommand -a diagnose -d 'Diagnose runs, coverage, episodes and exports'
complete -c netwatch -n __fish_use_subcommand -a uptime -d 'Outage history from the uptime log'
complete -c netwatch -n __fish_use_subcommand -a resolver -d 'Inspect or change the DNS resolver'

complete -c netwatch -n '__fish_seen_subcommand_from diagnose' -a 'run coverage episodes replay features export corpus'
complete -c netwatch -n '__fish_seen_subcommand_from resolver' -a 'status set recover'
complete -c netwatch -n '__fish_seen_subcommand_from uptime' -l since -x -d 'Period, e.g. 7d, 24h, 90m'
complete -c netwatch -n '__fish_seen_subcommand_from uptime' -l json -d 'JSON output'
complete -c netwatch -n '__fish_seen_subcommand_from uptime' -l csv -d 'CSV output'

# ── options ───────────────────────────────────────────────────────────
complete -c netwatch -l remote -r -d 'Remote https:// URL (requires API key)'
complete -c netwatch -l api-key -r -d 'Discouraged: use NETWATCH_API_KEY'
complete -c netwatch -l insecure-remote -d 'Allow an http:// remote URL'
complete -c netwatch -l view -x -a 'full lite dense' -d 'full, lite, or dense'
complete -c netwatch -l lite -d 'Start in Lite view'
complete -c netwatch -l demo -d 'Replay the Diagnose demo'
complete -c netwatch -l no-sandbox -d 'Disable sandbox'
complete -c netwatch -l sandbox-strict -d 'Require sandbox enforcement'
complete -c netwatch -l metrics -d 'Daemon metrics on 127.0.0.1:9464'
complete -c netwatch -l metrics-addr -r -d 'Daemon metrics address'
complete -c netwatch -l daemon -d 'Headless mode (alias: --headless)'
complete -c netwatch -l headless -d 'Alias for --daemon'
complete -c netwatch -l generate-config -d 'Write default config and exit'
complete -c netwatch -s h -l help -d 'Show help'
complete -c netwatch -s V -l version -d 'Show version'

# ── subcommand options ────────────────────────────────────────────────
complete -c netwatch -n '__fish_seen_subcommand_from doctor' -l json -d 'JSON capability report'
complete -c netwatch -n '__fish_seen_subcommand_from doctor' -l check-capture -d 'Try a real capture'
complete -c netwatch -n '__fish_seen_subcommand_from doctor' -l interface -x -a '(ls /sys/class/net 2>/dev/null)' -d 'Interface to check'
complete -c netwatch -n '__fish_seen_subcommand_from diagnose' -l json -d 'JSON output'
complete -c netwatch -n '__fish_seen_subcommand_from diagnose' -l seconds -x -d 'Sampling window, 1..120'
complete -c netwatch -n '__fish_seen_subcommand_from diagnose' -l test -x -d 'Run one check'
complete -c netwatch -n '__fish_seen_subcommand_from diagnose' -l out -r -F -d 'Write to file'
complete -c netwatch -n '__fish_seen_subcommand_from diagnose' -l schema -r -F -d 'Write the feature schema'
complete -c netwatch -n '__fish_seen_subcommand_from diagnose' -l since -x -d 'Days of history'
complete -c netwatch -n '__fish_seen_subcommand_from diagnose' -l dry-run -d 'Preview without writing'
complete -c netwatch -n '__fish_seen_subcommand_from diagnose' -l target -x -d 'Configured target to diagnose'
complete -c netwatch -n '__fish_seen_subcommand_from diagnose' -l budget -x -d 'Run time, 5s..10m'
complete -c netwatch -n '__fish_seen_subcommand_from diagnose' -l format -x -a 'text json' -d 'Output format'
complete -c netwatch -n '__fish_seen_subcommand_from diagnose' -l only -x -d 'One corpus entry'
complete -c netwatch -n '__fish_seen_subcommand_from diagnose' -l include-beta -d 'Count beta rules in the exit status'
complete -c netwatch -n '__fish_seen_subcommand_from resolver' -l unmanaged -d 'Confirm the resolver file is unmanaged'
complete -c netwatch -n '__fish_seen_subcommand_from resolver' -l seconds -x -d 'Revert after N seconds, 1..3600'
