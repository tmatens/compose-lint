# Mutation testing

`mutmut` measures whether the test suite would catch small semantic
changes to rule predicates — operator flips, boundary changes, swapped
constants. Surviving mutants point at lines whose behavior isn't pinned
down by any test.

This is a measurement step, not a CI gate. Run it on demand when
authoring or modifying a rule, and use the results to identify gaps.

## Scope

Configured in `pyproject.toml` under `[tool.mutmut]`:

- **Mutated**: `src/compose_lint/rules/` and `src/compose_lint/_image.py`.
- **Excluded**: parser (better tested with property-based tools),
  formatters (output shape covered by snapshot tests), engine, CLI, and
  config loading. Revisit as those areas stabilise.

## Running

```bash
uv run --extra dev mutmut run
uv run --extra dev mutmut results
uv run --extra dev mutmut show <mutant-name>
```

The first run takes ~15s on a recent laptop. Re-runs are incremental.
`mutants/` is a working directory mutmut creates beside the repo root —
it is gitignored.

## Baseline

At the time mutation testing was first introduced (compose-lint 0.6.0):

- First run: **79 mutants, 53 killed (67%)**
- After dead-branch removal and a loader test:
  **65 mutants, 54 killed (83%)**, 11 surviving

The 14-mutant drop and 6 extra kills came from:

- Deleting a dead defensive branch in `CL-0005 _is_wildcard_ip`
  (8 mutants no longer generated)
- Adding `tests/test_rule_loader.py` to exercise `_load_rules`
  discovery (6 mutants killed)

The 11 remaining survivors fall into two buckets:

- **Equivalent mutants** (6): `split(":", 1)` ≡ `split(":")`,
  `split(":", 1)` ≡ `rsplit(":", 1)` for the valid Docker user/image
  syntaxes our tests use. Semantically identical for our input space —
  no test on legal input will distinguish them.
- **Trailing-slash dead branches** in `CL-0013 _is_sensitive` (5):
  minor cleanup opportunity in the path-normalisation logic.

## When to run

- Authoring a new rule: aim for kill rate ≥ 90% on the new rule's
  module before merge.
- Modifying a rule predicate (boundary tightened, operator changed):
  re-run mutmut and check the changed module's mutants are still killed
  or appropriately retired.
- Quarterly health check on `src/compose_lint/rules/` to catch drift.

If mutmut surfaces a survivor that maps to a real predicate gap, add
the assertion to the rule's `tests/test_CL00XX.py` rather than
suppressing the mutant. If it's an equivalent or cosmetic mutant
(string-mutation marker, log-message text), document it in a
follow-up issue rather than reshaping the source to satisfy mutmut.
