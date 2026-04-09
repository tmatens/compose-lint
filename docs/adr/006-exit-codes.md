# ADR-006: Exit Code Behavior

**Status:** Accepted

**Context:** CI pipelines need clear pass/fail signals.

**Decision:** Exit 0 if no findings meet the threshold. Exit 1 if any finding at or above the threshold. Exit 2 for usage/file errors. Default threshold is HIGH. Configurable via `--fail-on`.

**Rationale:**
- Matches Hadolint's `--failure-threshold` and KICS's severity-mapped exit codes.
- Default behavior is strict (fail on high/critical) but teams can relax with `--fail-on critical` or tighten with `--fail-on low`.
- Exit 2 for file/config errors distinguishes "your compose file has issues" from "compose-lint itself couldn't run."
