# NetWatch — "forensics hero" demo: watch TLS 1.3 get decrypted live.
# This is the asset that should be the README hero image (replaces the
# dashboard-tour demo.gif). Record with:  ./scripts/record-forensics-demo.sh
#
# Requires NETWATCH_DEMO_PASSWORD in the environment (sudo password for the
# capture), a release build at ./target/release/netwatch, and `vhs` + `curl`.
# Keys/timings below assume the v0.24 Packets tab — nudge the Sleeps if your
# machine is slower or a step hasn't settled before the next keypress.

Output demo-forensics.gif

Require curl

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set Framerate 18
Set Padding 10

# Stage the scene (hidden): a COOPERATING client (curl) exports its TLS session
# secrets to the default keylog path NetWatch watches (/tmp/sslkeylog.txt) and
# loops HTTPS requests so there's a live TLS 1.3 stream to decrypt. Same
# SSLKEYLOGFILE mechanism Wireshark uses — we only decrypt traffic we control.
Hide
Type "bash -lc 'rm -f /tmp/sslkeylog.txt; (while true; do SSLKEYLOGFILE=/tmp/sslkeylog.txt curl -s https://example.com >/dev/null 2>&1; sleep 0.6; done &) ; echo $NETWATCH_DEMO_PASSWORD | sudo -S ./target/release/netwatch'"
Enter
Sleep 6s
Show

# Packets tab → start capture.
Type "4"
Sleep 1500ms
Type "c"
Sleep 4s

# Filter to ONLY the records NetWatch has decrypted — proof it's not just
# port-labelling, it's reading plaintext out of TLS 1.3.
Type "/"
Sleep 800ms
Type "decrypted:true"
Enter
Sleep 3s

# Open the stream view and toggle to text: the plaintext HTTP exchange inside
# the encrypted session, decoded live in the terminal.
Type "s"
Sleep 2s
Type "h"
Sleep 5s

Hide
Type "q"
Sleep 500ms
