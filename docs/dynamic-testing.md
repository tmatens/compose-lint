# Dynamic testing plan

Existing coverage: ClusterFuzzLite PR fuzzing (`cflite-pr.yml`) and daily batch fuzzing (`cflite-batch.yml`) exercise `LineLoader → _validate_compose → _collect_lines → engine.run_rules` under address+undefined sanitizers with a seed corpus from `tests/compose_files/`. CodeQL (weekly) and Docker Scout (daily) cover static analysis and published-image CVEs. Publish-time wheel content check lives in `publish.yml`.

This plan addresses the gaps those workflows don't cover.

---

## Gap 1 — ReDoS sweep over rule regexes

**Problem.** Rules that match image tags, env vars, ports, or capability strings can introduce catastrophic backtracking. Atheris won't reliably find these (the pathological inputs are narrow), and CodeQL's Python ReDoS query has known false-negative rates on dynamically-constructed patterns.

**Approach.**
- Script `scripts/check_redos.py` that imports every rule class, collects compiled patterns (and any `re.compile` / `re.search` string literals found via AST walk), and runs each through [`redos`](https://pypi.org/project/redos/) or shells out to [`recheck`](https://makenowjust-labs.github.io/recheck/) (Node, hash-pinned).
- Fail on any "vulnerable" or "unknown-complexity" verdict; require an allowlist entry with justification to waive.
- Wire into a new `.github/workflows/redos.yml` on weekly cron + `workflow_dispatch`. Not a PR gate initially — run it until it's quiet, then promote.

**Acceptance.** Clean run on current rule set; a deliberately-planted `(a+)+$` in a test rule is flagged.

**Effort.** ~0.5 day. Dev-dep added to `requirements-dev.lock` via the existing `uv pip compile` flow.

---

## Gap 2 — SARIF/JSON output fuzzing

**Problem.** `fuzz/fuzz_compose.py` stops at `engine.run_rules`. Findings whose `message`/`path`/`snippet` derive from attacker-controlled compose content never flow through `formatters/sarif.py` or `formatters/json.py`. A crafted service name that breaks a SARIF consumer (GitHub code scanning, VS Code SARIF Viewer) would not be caught today.

**Approach.**
- Extend the existing harness: after `engine.run_rules`, run each formatter over the findings list and validate output.
- For SARIF: parse with `jsonschema` against the SARIF 2.1.0 schema (vendor the schema under `fuzz/schemas/` to keep the harness offline-capable for OSS-Fuzz-style builds).
- For JSON: `json.loads` round-trip plus a minimal schema check.
- For text: assert no control characters that would corrupt a terminal (bell, cursor-move escapes) unless we explicitly emit them.
- Any schema-validation failure or uncaught exception is a crash.

**Acceptance.** Harness builds green under CFLite; a deliberately-malformed finding (e.g. `message=""` where SARIF requires non-empty) causes a crash in a local run.

**Effort.** ~1 day. No new workflow — reuses `cflite-pr.yml` / `cflite-batch.yml`.

---

## Gap 3 — Shift wheel-contents check left

**Problem.** `publish.yml` greps the built wheel for `AGENTS.md|CLAUDE.md|.env|/tests/|.git/`, but only at tag-push time. A PR that adds a forbidden path (e.g. a new memory directory, an IDE settings file) only fails at release, after merge.

**Approach.**
- Add `tests/test_wheel_contents.py` (marked `@pytest.mark.slow` or gated behind an env flag so it doesn't run in every matrix leg). Builds the wheel and sdist via `python -m build`, inspects with `zipfile` / `tarfile`, asserts the same forbidden-path list as `publish.yml`.
- Factor the forbidden-path list into a single source (e.g. `tests/_wheel_deny.py`) that both the test and `publish.yml` read, to prevent drift.
- Run on one Python version in CI, not the full matrix.

**Acceptance.** Deliberately adding a tracked `CLAUDE.md` copy under `src/compose_lint/` fails the test locally.

**Effort.** ~0.5 day. No new workflow.

---

## Non-goals

- **Replacing CFLite.** The PR+batch fuzzing setup is the right shape; these additions complement it.
- **OSS-Fuzz submission.** Possible later but orthogonal to the gaps above.
- **Property-based rule testing** (Hypothesis over rule inputs). Higher value than ReDoS/SARIF fuzzing in some ways but a larger scope — tracked separately if pursued.

## Rollout order

1. Gap 3 (cheapest, highest per-hour value — stops accidental wheel pollution pre-merge).
2. Gap 2 (extends existing harness; no new workflow).
3. Gap 1 (new workflow, dev-dep churn; do last).
