# Stack demo for compose-lint.
#
# Source recording script for docs/assets/demo-stack.gif. To regenerate, see
# scripts/demo/README.md.
#
# The story: a service that is hardened as written in compose.yaml, and two
# files beside it that Compose reads without being asked. compose.override.yml
# turns on `privileged`, and .env moves the published port from the default
# 127.0.0.1 to all interfaces. compose-lint is run with no arguments, the way
# `docker compose up` is, and grades the merged result: the CRITICAL comes
# from the override and the port from .env.
#
# The fixture's .env is committed as stack/env, because .env is gitignored
# repo-wide; the hidden setup copies the stack to /tmp/stack and names it
# .env there, as fix.tape copies its fixture before --apply.

Output stack.gif

Require compose-lint

# Same terminal as the other two casts so the GIFs sit at the same size. 32
# rows at this font and height. The first screen needs 25 (three commands, 17
# lines of compose.yaml, 3 of the override, 1 of .env, the prompt); the lint
# screen needs 30 (command + 28 output lines + prompt), leaving two spare.
Set Shell bash
Set FontSize 22
Set Width 1500
Set Height 1000
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 45ms
Set Framerate 12

Hide
Type "export PS1='$ '"
Enter
Type "tput rmam"
Enter
Type "rm -rf /tmp/stack && mkdir -p /tmp/stack && cp stack/compose.yaml stack/compose.override.yml /tmp/stack/ && cp stack/env /tmp/stack/.env && cd /tmp/stack"
Enter
Type "clear"
Enter
Show

Sleep 1s
Type "cat compose.yaml"
Sleep 1200ms
Enter
Sleep 4s
Type "cat compose.override.yml"
Sleep 1200ms
Enter
Sleep 2500ms
Type "cat .env"
Sleep 1200ms
Enter
Sleep 3500ms

Hide
Type "clear"
Enter
Show

Sleep 500ms
Type "compose-lint"
Sleep 1500ms
Enter
Sleep 9s
