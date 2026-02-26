# NetWatch Demo — AI Network Insights
# Showcases tabs 6-8: Topology, Timeline, and AI Insights
# Run: sudo -v && vhs demo-insights.tape

Output demo-insights.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 60ms

# Launch NetWatch with sudo for full features
Type "sudo ./target/release/netwatch"
Enter

# Dashboard loads — let data populate
Sleep 5s

# Start packet capture from Dashboard (switch to Packets, start capture, come back)
Type "4"
Sleep 1s
Type "c"
Sleep 3s

# Switch to Topology tab — show network neighbourhood
Type "6"
Sleep 4s

# Scroll through remote hosts
Down
Sleep 1s
Down
Sleep 1s
Down
Sleep 2s

# Switch to Timeline tab — show connection lifetimes
Type "7"
Sleep 3s

# Cycle time window
Type "t"
Sleep 2s
Type "t"
Sleep 2s

# Scroll through connections
Down
Sleep 500ms
Down
Sleep 500ms
Down
Sleep 2s

# Switch to Insights tab — show AI analysis
Type "8"
Sleep 3s

# Trigger on-demand AI analysis
Type "a"
Sleep 18s

# Scroll through insights
Down
Sleep 1s
Down
Sleep 1s
Down
Sleep 3s

# Show help overlay to see all 8 tabs
Type "?"
Sleep 4s

# Scroll help to see new tab sections
Down
Down
Down
Down
Down
Down
Down
Down
Down
Down
Sleep 3s

# Close help
Type "?"
Sleep 1s

# Back to Dashboard for final view
Type "1"
Sleep 3s

# Quit
Type "q"
Sleep 1s
