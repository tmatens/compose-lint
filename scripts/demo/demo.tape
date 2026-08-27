# README hero demo for compose-lint.
#
# Source recording script for the README GIF. To regenerate, see
# scripts/demo/README.md.

Output demo.gif

Require compose-lint

# A normal-width terminal at a large, legible font. `tput rmam` (below) turns
# off line wrapping so compose-lint's long finding and reference lines clip at
# the right edge instead of wrapping raggedly — the structured left side
# (severity, rule id, message, underline, fix/ref) stays clean. Height gives
# 32 rows at this font, exactly what the lint step needs on 0.25.0 (command +
# 30 output lines + prompt — the no-config Note line took the spare row), so
# the banner stays on screen. The fixture has two services, so the cast also
# shows the per-service grouping the report uses.
Set Shell bash
Set FontSize 22
Set Width 1500
Set Height 1000
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 45ms
Set Framerate 12

# Quiet prompt + disable line wrapping. The steady block cursor stays visible in
# every frame; retime.py detects it and synthesizes the blink. Hidden from the
# recording.
Hide
Type "export PS1='$ '"
Enter
Type "tput rmam"
Enter
Type "clear"
Enter
Show

Sleep 1s

# 1. Lint a small, mostly-hardened compose file. Three findings, one per tier,
#    grouped by service and severity-sorted within each — under `watchtower`, a
#    mounted Docker socket (CL-0001, CRITICAL, with a box-drawing underline)
#    above a tag-only image pin (CL-0019, MEDIUM); under `db`, a plaintext
#    credential (CL-0020, HIGH) — then the FAIL verdict. Pause on the typed
#    command, then on the output.
Type "compose-lint docker-compose.yml"
Sleep 1900ms
Enter
Sleep 8s

# 2. Drill into the socket finding with the offline rule docs, read through a
#    pager so the doc arrives top-down: page one is the title, the severity
#    derivation, and the references; a page-down shows the doc continuing.
#    The explicit `| less -S` is a bridge: 0.25.0 predates ADR-034, which
#    makes a bare `--explain` page itself on a TTY. When this cast is
#    re-rendered on >= 0.26.0, drop the pipe — the choreography stays the
#    same, and the toolchain image's PAGER/LESSCHARSET env (see Dockerfile)
#    keeps the rendering identical.
Type "compose-lint --explain CL-0001 | less -S"
Sleep 1900ms
Enter
Sleep 5500ms
Space
Sleep 5500ms
