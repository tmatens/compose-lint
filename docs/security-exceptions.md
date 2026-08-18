# Accepted security findings

GitHub keys a Code Scanning dismissal to the alert's *location fingerprint*,
so an accepted finding "resurfaces" as a fresh, undismissed alert whenever
edits above it move the line — Scorecard alert #81, dismissed *won't fix* in
May 2026, came back as alert #101 in August after unrelated `publish.yml`
edits shifted its line (#594). Dismissals are therefore not a durable
record; this file is.

**How the release preflight uses it:** the code-scanning sweep (Step 0 of
the release process) matches each open alert against the rows below on
**rule + file + message** — never on alert number or line. A matched alert
is previously accepted: re-dismiss it in the UI citing this file, and
proceed. An alert with no row here is a real finding — fix it forward, or
add a row via a reviewed PR recording why it cannot be fixed and what
compensates.

| Rule | File | Message | Why it cannot be fixed | Compensating control | History |
| ---- | ---- | ------- | ---------------------- | -------------------- | ------- |
| Scorecard `PinnedDependenciesID` | `.github/workflows/publish.yml` | `pipCommand not pinned by hash` | The `testpypi-smoke` retry loop installs the wheel that was built and uploaded to TestPyPI moments earlier in the same workflow run; that wheel's hash does not exist when the workflow source is written. | Post-install integrity is verified via Sigstore in `verify-release-signatures`. | Accepted 2026-05-21 (alert #81); resurfaced by line movement and re-accepted 2026-08-17 (alert #101). |
