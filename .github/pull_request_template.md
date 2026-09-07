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

## Origin

<!-- Tick everything that applies. This helps a reviewer decide where to spend
     attention; it does not affect whether the PR is accepted. -->

- [ ] Personal contribution
- [ ] Contributed on behalf of an employer or client
- [ ] Produced primarily by an automated agent

## Evidence

<!-- The questions no check can answer for you. A line each is plenty, and
     "n/a" is a fine answer where it doesn't apply — a blank one is not.
     A question you find you can't answer is the finding. -->

**Which tests cover this change, and what do they assert?**

<!-- Name them, e.g. `tests/test_CL0031.py::test_flags_privileged`. CI
     already requires 90% of the lines you touched to be covered, so "a test
     executes this line" is proven before a reviewer arrives. This asks the
     part coverage cannot see: whether the assertion would actually fail if
     the behavior regressed. For a rule, that means a case that triggers and
     a case that must not. -->

**What does this change make wrong elsewhere?**

<!-- README, docs/, examples, a rule page, a message quoted in a test. "It
     doesn't" is a fine answer, but say it deliberately rather than by
     leaving this empty. -->

## Checklist

<!-- Short on purpose. CI checks sign-off, the four local gates, AI
     attribution, the rule surfaces and the severity matrix, and a reviewer
     reads those off the checks tab — repeating them here only asks you to
     agree with a check that has already run. What's left is what CI cannot
     see for itself. -->

- [ ] Commits are **signed** — GitHub shows a `Verified` badge on the commits
      tab (proves *who committed*; not the same as signing off, which the
      `dco` check enforces separately — see CONTRIBUTING.md)
- [ ] One logical change per commit; no unrelated changes bundled in
- [ ] `tests/corpus_snapshot.json.gz` is **not** in this PR (a maintainer regenerates it)

## New rule only

<!-- Delete this section if this PR is not a new rule. -->

**Which source grounds this rule, and where does it demonstrate the need in a
container context?**

<!-- Link it and quote the line. OWASP, CIS or Docker docs. Generic
     host/Linux hardening that a container's defaults already neutralize is
     not enough — see CL-0022 and CL-0023, which were removed for exactly
     that. If the container-context evidence is thin, the rule's premise
     needs a runtime check in `scripts/validate_rule_premises.py` instead. -->

**Paste the before / after YAML a user would apply.**

<!-- Copy-pasteable, not a description of what to do. If you can't write the
     "after" without knowing something the finding doesn't tell the user,
     the fix guidance isn't specific enough yet. -->

## Breaking changes

<!-- Does this change the CLI, config format, rule IDs, or exit code contract?
     If yes, describe the migration path. If no, write "None". -->

None
