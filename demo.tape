Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 10

# Launch — instant visibility
Type "./target/release/netwatch"
Enter
Sleep 4s

# Dashboard: interfaces, bandwidth, health, connections — all at once
Sleep 3s

# Connections — see which process owns each socket
Type "2"
Sleep 3s

# Interfaces — per-interface detail
Type "3"
Sleep 3s

# Topology — network map
Type "6"
Sleep 3s

# Processes — per-process bandwidth
Type "8"
Sleep 3s

# Back to Dashboard
Type "1"
Sleep 2s

Type "q"
Sleep 500ms
