# CLI reference

Three subcommands. `check` is the default — a bare `compose-lint` works, and
auto-detects the Compose file. The authoritative help is `compose-lint --help`
(and `fix --help` / `init --help`); this page is its web copy.

```
compose-lint [check] [OPTIONS] [FILE ...]   Lint files (default; bare invocation works)
compose-lint fix [OPTIONS] [FILE ...]       Auto-remediate auto-fixable findings
compose-lint init [OPTIONS] FILE            Generate a starter .compose-lint.yml

check options:
  --format {text,json,sarif}   Output format (default: text)
  --fail-on {low,medium,high,critical}
                               Minimum severity to trigger exit 1 (default: high)
  -v, --verbose                Repeat the fix block and reference on every finding (text mode)
  -q, --quiet                  One line per finding — no fix, reference, or excerpt (text mode)
  --skip-suppressed            Hide suppressed findings from output
  --allow-partial-coverage     Grade a file whose `include:` / cross-file `extends:`
                               could not be resolved, instead of failing (exit 2)
  --no-merge-overrides         Lint each file alone instead of merging the
                               `compose.override.yml` Compose merges beside it
  --no-env                     Ignore a `.env` sitting beside the Compose file,
                               which Compose reads for COMPOSE_FILE and for
                               `${VAR}` values
  --config PATH                Path to config file (default: .compose-lint.yml)
  --strict-config              Treat config diagnostics (unknown rule id or key) as errors, not warnings
  --explain CL-XXXX            Print the full documentation for a single rule
                               (through a pager on an interactive terminal)
  --no-pager                   Print --explain output directly, bypassing the pager
  --version                    Show version and exit

fix options:
  --apply                      Write fixes in place (default: print a dry-run diff)
  --only CL-XXXX               Restrict fixes to the named rule(s); repeatable
  --no-merge-overrides         Fix each file alone instead of merging the
                               `compose.override.yml` Compose merges beside it
  --no-env                     Ignore a `.env` sitting beside the Compose file
  --config PATH                Path to config file (suppressions are honored)
  --strict-config              Treat config diagnostics (unknown rule id or key) as errors, not warnings

init options:
  -o, --output PATH            Where to write the config (default: .compose-lint.yml)
  --force                      Overwrite an existing config file
```

## Color

Color is on when stdout is a terminal. Set `NO_COLOR` to disable it (even on a
terminal) or `FORCE_COLOR` to force it through a pipe — e.g. into `less -R` or a
CI log that renders ANSI.

## Pager

`--explain` pages its rule doc through `less -RFX` when stdout is a terminal
([ADR-034](adr/034-explain-pages-on-a-tty.md)) — `-F` means a doc that fits
one screen prints and exits with no pager interaction. `PAGER` selects a
different pager; `--no-pager`, a non-empty `NO_PAGER`, or `TERM=dumb`
disables paging; a pager binary that isn't installed falls back to a plain
dump. Piped or redirected output never pages and is byte-identical to the
pre-pager behavior, so scripts and CI need no changes. The findings report
itself never pages.

## End of options

`--` marks the end of options: everything after it is a file path, never a
flag. That matters to any integration that assembles a command line from
repository content. The pre-commit hook ships `args: [--]` because pre-commit
builds the command as `entry + args + filenames` — without the separator, a
repository directory named `--config=cfgdir` holding a `compose.yml` arrives
as `--config=cfgdir/compose.yml` and installs an attacker-authored policy for
the run. compose-lint cannot insert the separator itself: flags after a
positional (`compose-lint init docker-compose.yml -o ci.yml`) are documented
and must keep working, so placing `--` is the caller's job. If you set
`args:` in your pre-commit config, keep `--` last.
