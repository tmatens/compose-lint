# The fix design contract

`compose-lint fix` auto-remediates the findings whose edit is mechanically
unambiguous — one correct value, in one place, with no collateral change to
the rest of the file. The guarantee is about the *edit*, not the *outcome*:
an auto-fix can still change how the stack behaves, which is why every such
edit is labelled `⚠ behavior-changing` with the specific breakage named. This
page is the full contract behind the README's summary.

- **Dry-run by default; `--apply` writes in place** via an atomic swap that
  preserves the file's permission bits — an interrupted write never corrupts the
  Compose file.
- **Only mechanically unambiguous fixes are applied.** Findings whose
  remediation is context-dependent (e.g. CL-0006 capability lists, CL-0001
  socket mounts) are reported as needing manual review, never auto-edited — the
  tool refuses rather than guess at a value only you can choose.
- **Behavior-changing edits are labelled, not withheld.** Every edit that alters
  runtime behavior emits a `⚠ behavior-changing` line naming what breaks, on the
  dry-run *and* on `--apply`, so the warning reaches you on whichever path you
  took. The label is the mitigation; there is no severity gate that quietly
  drops risky fixes.
- **Suppressed findings are never touched** — `.compose-lint.yml` disables and
  per-service excludes are honored.
- **Refuses rather than risk a wrong rewrite.** Files using YAML anchors, merge keys, or `${VAR}`
  interpolation in the affected region are skipped rather than risk a wrong
  rewrite, and every apply is re-parsed and re-linted before it is written —
  anything that wouldn't round-trip clean is refused with the diff surfaced for
  diagnosis.
- **Diff is data, status is human.** The diff goes to stdout; progress and
  warnings go to stderr, so `compose-lint fix file.yml > changes.diff` captures
  exactly the patch.

## SARIF suggested changes

Structured fixes also ride in SARIF output: `compose-lint check --format sarif`
populates `fixes[].artifactChanges`, which GitHub Code Scanning renders as an
inline suggested change on the pull request.
