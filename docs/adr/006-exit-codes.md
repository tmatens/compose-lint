# ADR-006: Exit Code Behavior

**Status:** Accepted

**Context:** CI pipelines need clear pass/fail signals.

**Decision:** Exit 0 if no findings meet the threshold. Exit 1 if any finding at or above the threshold. Exit 2 for usage/file errors. Default threshold is HIGH. Configurable via `--fail-on`.

**Rationale:**
- Matches Hadolint's `--failure-threshold` and KICS's severity-mapped exit codes.
- Default behavior is strict (fail on high/critical) but teams can relax with `--fail-on critical` or tighten with `--fail-on low`.
- Exit 2 for file/config errors distinguishes "your compose file has issues" from "compose-lint itself couldn't run."
- A rule that raises is isolated rather than aborting the run (the failure is reported to stderr and the sweep continues), and maps to exit 2 for the same reason: it means compose-lint itself couldn't complete the analysis, not that the file failed the lint. This keeps a crash from being silently truncated mid-sweep or mistaken for a clean exit-1 findings result. The same holds for `fix` and `init`, whose writes are decided by that sweep: a crash there writes nothing for that file and exits 2, as a parse error does.
- Exit 0 means "no findings at or above the threshold", not "Docker Compose would run
  this project". compose-lint is not a schema validator, and two ordinary shapes make
  the difference visible: `env_file: [missing.env]` and an unset `${VAR:?required}`
  each make `docker compose config` exit 1 and refuse the project outright, while
  compose-lint exits 0 (both verified against Docker Compose 5.4.0). The verdict is not
  wrong — a project that cannot deploy has no deployment to grade — but "clean" is a
  generous word for it, and a pipeline that treats exit 0 as "safe to ship" is reading
  a claim this tool does not make. Validation is `docker compose config`'s job and
  running both is the intended arrangement.

**Amendment (pre-1.0): what exit 2 covers now.** The decision above names
"usage/file errors". Exit 2 has since grown to every case where compose-lint
could not complete an honest verdict: a coverage gap
([ADR-036](036-resolve-references-that-stay-inside-the-project.md)), a crashed
rule (above), a config error, and a size refusal. `fix` and `init` never exit 1
([ADR-014](014-fix-remediation.md), [ADR-011](011-config-bootstrap-ux.md)). The current
table for all three subcommands is [CLI reference: Exit codes](../cli.md#exit-codes).
