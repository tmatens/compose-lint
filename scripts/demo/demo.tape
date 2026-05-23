# README hero demo for compose-lint.
#
# Source recording script for the README GIF. Deterministic: VHS replays this
# headlessly, so the cast re-renders identically against any version.
# To regenerate, see scripts/demo/README.md.

Output demo.gif

Require compose-lint

Set Shell bash
Set FontSize 20
Set Width 1180
Set Height 760
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 45ms

# Quiet, predictable prompt — no hostname/cwd noise in the frame.
Hide
Type "export PS1='$ '"
Enter
Type "clear"
Enter
Show

Sleep 800ms

# 1. Lint a small, ordinary-looking compose file. Six findings stream past,
#    landing on the two HIGH ones: a plaintext password (CL-0020) and a
#    port bound to every interface (CL-0005, with line carets), then the
#    FAIL verdict.
Type "compose-lint docker-compose.yml"
Sleep 600ms
Enter
Sleep 5s

# 2. Drill into the exposed-port finding with the offline rule docs —
#    no browser, no network.
Type "compose-lint --explain CL-0005"
Sleep 600ms
Enter
Sleep 5s
