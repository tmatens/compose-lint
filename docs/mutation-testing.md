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
- After triage of the 11 survivors (issue #178):
  **53 mutants, 51 killed (96%)**, 2 surviving

The drops and extra kills came from:

- Deleting a dead defensive branch in `CL-0005 _is_wildcard_ip`
  (8 mutants no longer generated)
- Adding `tests/test_rule_loader.py` to exercise `_load_rules`
  discovery (6 mutants killed)
- Replacing `s.split(sep, 1)[0]` with `s.partition(sep)[0]` in
  `_image.split_image_ref` and `CL-0018 _is_root_user` — same
  behavior, idiom mutmut does not generate the same equivalent
  mutants for (6 mutants no longer generated)
- Removing the dead post-rstrip branch in `CL-0013 _is_sensitive`
  and routing the literal-root case through the existing rstrip
  path; trailing-slash fixture added to lock down normalisation
  (5 mutants killed or no longer generated)

The 2 remaining survivors are genuinely equivalent for our input space:

- `compose_lint.rules._image.x_split_image_ref__mutmut_5`:
  `partition("@") → rpartition("@")`. Equivalent because OCI image
  refs contain at most one `@` (digest separator); both partitions
  yield the same first element.
- `compose_lint.rules.CL0013_sensitive_mount.x__is_sensitive__mutmut_4`:
  `rstrip("/") → rstrip("XX/XX")`. `rstrip` takes a set of chars; the
  set `{X, /}` strips the same trailing `/` from every path we test
  against, since no sensitive Docker host path ends in a literal `X`.

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
