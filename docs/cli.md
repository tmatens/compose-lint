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
one screen prints and exits with no pager interaction. The default pager
labels its controls in the status line (`CL-XXXX · Space next · b back ·
q quit`) instead of less's bare `:`; a custom `PAGER` keeps its own prompt. `PAGER` selects a
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

## Automation and agent use

Everything below is also true of a shell script; it is written out because a
coding agent driving compose-lint tends to pattern-match on "linter" and get
these five wrong. Nothing here enumerates rules — `--explain CL-XXXX` is the
single source for what a rule means and how to fix it, it reads the rule docs
shipped inside the wheel, and it needs no network.

**Exit 2 is not "the lint failed".** Exit 1 means findings at or above the
threshold — that is the failure to act on. Exit 2 means compose-lint could not
run, *or* could not see the whole stack: an unresolved `include:` or cross-file
`extends:` means part of the stack was never graded, so the run cannot honestly
report a verdict. Treating exit 2 as a findings failure invents remediation work
that does not exist. Either resolve the coverage gap or downgrade it
deliberately with `--allow-partial-coverage`, which demotes it to a stderr
warning. `fix` reports gaps and never fails on them; it is not the gate.

**`fix` is a dry run by default, and its refusals are the safety property.**
A bare `compose-lint fix` prints a diff and writes nothing; `--apply` writes
in place through an atomic swap, guarded by a re-parse and a verify-apply pass.
It deliberately refuses regions it cannot rewrite safely — anchors, merge keys,
`${VAR}` interpolation — and reports findings whose remediation is
context-dependent (CL-0006 capability lists, CL-0001 socket mounts) as needing
manual review rather than guessing at a value only the operator can choose.
That is the contract, not an unfinished fixer: see [the fix design
contract](fix.md). When `fix` declines a finding, hand-editing the same change
into place discards the guard that made the decline correct.

Two consequences for an agent reporting on a `fix` run. An edit that alters
runtime behavior carries a `⚠ behavior-changing` line naming what breaks —
surface it, because the label *is* the mitigation; nothing else withholds the
risky fix. And the diff goes to stdout while status goes to stderr, so
`compose-lint fix file.yml > changes.diff` captures exactly the patch and
nothing else.

**Suppression has one shape.** Findings are suppressed in `.compose-lint.yml`
with a `reason`, which flows through to `suppression_reason` in JSON,
`justification` in SARIF, and after `SUPPRESSED` in text — the suppressed
finding is still reported, so a suppression stays visible rather than
disappearing. There are no inline suppression comments, and no comment syntax
to guess at. `compose-lint init` generates a baseline config from a file's
current findings, as per-service `exclude_services` entries with placeholder
reasons to replace. Deleting the offending service to clear a finding is not a
fix; neither is a global `enabled: false` where the finding is about one
service.

**Severity is derived, not chosen.** Each rule's severity is what the two-axis
matrix in [severity.md](severity.md) produces for its cell, under a stated
attacker baseline and Docker posture. Report the severity the tool emits and
quote `--explain` for the reasoning; re-ranking a finding because it feels more
or less urgent in context is exactly the failure mode the model exists to
prevent. If it genuinely reads wrong, that is an issue worth filing, not a
number worth adjusting in a report.

**Parse `--format json`, never the text output.** JSON is a versioned envelope
([ADR-015](adr/015-machine-readable-output-contract.md)): a top-level
`version`, a `tool` block, `findings`, and `errors` carrying the files that
failed to parse. New
top-level fields are additive and do not bump `version`, so a consumer can read
what it knows and ignore the rest. Text output is for humans and is not a
contract — its banner, summaries and verdict go to stdout only in text mode, so
JSON and SARIF redirects stay clean. Piped output is never paged or colored,
so no flag is needed to make a run scriptable.

Two smaller things worth knowing when assembling a command line
programmatically: pass `--` before the file paths (see [End of
options](#end-of-options)) whenever any part of the command comes from
repository content, and pin a version if the run gates CI, because new and
tightened rules ship in MINOR releases.
