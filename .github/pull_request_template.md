<!--
Thanks for contributing! Fill in the sections below. Delete any that don't
apply. See CONTRIBUTING.md for the full workflow, commit conventions, and
signing requirements.
-->

## Summary

<!-- What does this PR change? One or two sentences. -->

## Why

<!-- Why is this change needed? Link to the issue, bug report, OWASP/CIS
     reference, or incident that motivated it. -->

Closes #

## Type of change

- [ ] New rule (`CL-XXXX`)
- [ ] Bug fix
- [ ] Refactor (no behavior change)
- [ ] Documentation
- [ ] Build / CI / release tooling
- [ ] Other:

## Checklist

- [ ] Commits are signed (GitHub shows **Verified**)
- [ ] One logical change per commit; no unrelated changes bundled in
- [ ] `ruff check`, `ruff format --check`, `mypy src/`, and `pytest` all pass locally
- [ ] New/changed behavior has tests (positive **and** negative cases for rules)
- [ ] Docs updated where behavior changed (`README.md`, `docs/rules/CL-XXXX.md`, `CHANGELOG.md`)
- [ ] No AI attribution anywhere (commits, comments, docs)

## New rule only

<!-- Delete this section if this PR is not a new rule. -->

- [ ] Grounded in an authoritative source (OWASP, CIS, or Docker docs) with a
      direct link in `references`
- [ ] Severity matches the [scoring matrix](../docs/severity.md)
- [ ] Fix guidance is specific and copy-pasteable (before / after YAML)
- [ ] `docs/rules/CL-XXXX.md` added

## Breaking changes

<!-- Does this change the CLI, config format, rule IDs, or exit code contract?
     If yes, describe the migration path. If no, write "None". -->

None
