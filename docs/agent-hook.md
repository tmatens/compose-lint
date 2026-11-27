# Lint at edit time with a coding agent hook

A coding agent that edits a Compose file can run compose-lint right after each edit and read the findings before it moves on. The CI gate still decides what merges. The hook moves the feedback earlier, to the point where the agent already has the file open.

This page shows the setup for Claude Code, which is the only agent it has been tested with (version 2.1.332). Any agent that can run a command after a file edit and read its output should work the same way, but I haven't tried others.

## What you need

- `compose-lint` on the `PATH` of the machine where the agent runs. `pip install compose-lint` is enough.
- `jq`, which the script uses to read the edited path.
- Your `.compose-lint.yml`, if you have one. compose-lint reads it from beside the Compose file, the same as in CI, so recorded exceptions apply here too.

## The hook script

Save this as `.claude/hooks/compose-lint.sh` and make it executable.

```bash
#!/usr/bin/env bash
# Lints a Compose file after a coding agent edits it, and hands any findings
# back to the agent. Reads the hook's JSON from stdin. Needs jq.
set -u

path=$(jq -r '.tool_input.file_path // empty')
case "$(basename "$path")" in
  compose.yml | compose.yaml | docker-compose.yml | docker-compose.yaml) ;;
  *) exit 0 ;;
esac
[ -f "$path" ] || exit 0
command -v compose-lint >/dev/null || exit 0

out=$(compose-lint check --fail-on medium --skip-suppressed -- "$path" 2>&1)
case $? in
  0) exit 0 ;;
  1) echo "compose-lint found problems in $path. Fix them in this change, or record an exception with a reason in .compose-lint.yml." >&2 ;;
  *) echo "compose-lint could not lint all of $path. This is not a finding, so do not edit the file to clear it. Report it." >&2 ;;
esac
echo "$out" >&2
exit 2
```

## Register it

Add the hook to `.claude/settings.json` in the repository.

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/compose-lint.sh",
            "timeout": 60
          }
        ]
      }
    ]
  }
}
```

Claude Code runs the command after each `Edit` or `Write` and passes the edited path as JSON on stdin. When the script exits 2, Claude Code gives the script's stderr to the agent. The [Claude Code hooks reference](https://code.claude.com/docs/en/hooks) has the full contract.

## What the flags are for

- **`--fail-on medium`.** The CI default is `high`. A lower threshold fits here because the agent is already in the file and a medium finding is usually a few lines to fix. Raise or lower it to suit, and keep CI as the gate.
- **`--skip-suppressed`.** Findings you have already recorded an exception for are left out, so the agent is not told about them again on every edit.
- **Fix guidance is left on.** The agent gets each rule's fix text along with the finding. Add `-q` if you want one line per finding.
- **`--`** keeps a file name that starts with a dash from being read as an option.

## Exit 1 and exit 2 are different

The script gives the agent a different instruction for each, because the right response is different.

Exit 1 means findings at or above the threshold. Those are fixed in the Compose file or recorded in `.compose-lint.yml` with a reason.

Exit 2 means compose-lint could not run or could not see the whole stack, for example an `extends:` that points at a file that is not there. That is a [coverage gap](compatibility.md#coverage-gaps-are-not-findings) and not a finding, so there is nothing in the service to fix. If part of the stack can't be read on the machine where the agent runs and you accept that, add `--allow-partial-coverage` to the hook. The gap is then reported as a warning. Leave the flag out of CI.

## What to expect

- **The whole file is linted.** In my test the agent added one service to a file that had one, and was handed nine findings. Some were on the service that was already there, which the agent had not touched. Say in your project instructions whether the agent should fix findings it did not cause or leave them and report.
- **The hook cannot undo an edit.** It runs after the file is written. If the agent ignores the findings, the file stays as it is until CI lints it.
- **Only the four default file names are matched.** Add your own names to the `case` line if your Compose files are called something else.
- **A missing `compose-lint` is silent.** The script exits 0 when the command is not on the `PATH`, so a teammate without it installed is not blocked. CI still lints.

## Tell the agent what counts as a fix

The message the script prints names the two acceptable outcomes: fix the finding, or record an exception with a reason. It helps to say the same thing in your project instructions, along with what does not count. Deleting the service does not, and neither does turning a rule off for the whole file when the finding is about one service.

[Automation and agent use](cli.md#automation-and-agent-use) in the CLI reference covers the rest of what an agent tends to get wrong, and [Configuration](configuration.md) covers how exceptions are written.
