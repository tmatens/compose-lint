# CI reference

Contributor-facing reference for every workflow in `.github/workflows/`. If
you're cutting a release instead, see [`RELEASING.md`](RELEASING.md); for the
per-channel publish contract see [`DISTRIBUTION.md`](DISTRIBUTION.md).

## At a glance

| Workflow                  | Trigger                                    | Purpose                                                |
| ------------------------- | ------------------------------------------ | ------------------------------------------------------ |
| `ci.yml`                  | Push to `main`, every PR                   | Primary PR gate — lint, types, tests, security, guards |
| `cflite-pr.yml`           | PR touching parser/engine/rules/fuzz       | Per-PR fuzzing focused on the diff                     |
| `cflite-batch.yml`        | Nightly (04:17 UTC) + manual               | Deeper fuzzing across both sanitizers                  |
| `codeql.yml`              | Every PR + weekly (Mon 04:27 UTC)          | Static analysis, results in Code Scanning              |
| `scorecard.yml`           | Branch-protection change + weekly          | OpenSSF Scorecard, results in Code Scanning            |
| `scout-scan.yml`          | Daily (06:00 UTC) + manual                 | Docker Scout CVE scan against the published image      |
| `vuln-report.yml`         | Daily (06:30 UTC) + manual                 | Rolling issue listing every vulnerability with a fix   |
| `publish.yml`             | `v*` tag push + manual (Docker republish on a tag) | Release pipeline — see `RELEASING.md`          |
| `release-prep.yml`        | Manual (`workflow_dispatch`, maintainer)   | Opens the "Prepare X.Y.Z release" PR                   |
| `marketplace-smoke.yml`   | Push to `main` touching the file + manual + weekly cron | Verifies the published action, pre-commit hook, and the `uvx`/`pipx run` one-shot forms end-to-end |
| `forgejo-smoke.yml`       | PRs + pushes to `main` touching the harness + manual + weekly cron | Runs the Forgejo guide's snippet on a live containerized Forgejo |
| `forgejo-smoke-bump.yml`  | Daily (05:17 UTC) + manual                 | Opens the PR that moves the harness to the newest Forgejo + runner, docs claim included |
| `digest-age-gate.yml`     | Daily (06:23 UTC) + manual (dry run by default) | Merges Renovate's gcr.io/ghcr.io digest PRs once unchanged for 72h, the age gate Renovate cannot apply to them |
| `os-smoke.yml`            | Called by `ci.yml` on PRs touching code + push to `main` + manual + weekly cron | pytest (3.11 and 3.13) + pre-commit hook on macOS and Windows — **gates via `ci-ok`** |
| `sarif-ingestion.yml`     | Push to `main` touching SARIF inputs + manual + weekly cron | Uploads a probe SARIF to Code Scanning and asserts GitHub ingested it — then deletes its own alerts |


### Why SARIF ingestion is not a PR check

`ci.yml`'s action smoke passes `upload-sarif: "false"` on purpose, so
nothing on the PR path ingests a compose-lint SARIF into Code Scanning.
SARIF rejections are schema- and semantics-level — a duplicate `ruleId`,
an out-of-range region, a `level` GitHub does not accept — and none of
them are visible to a shape assertion written against the same mental
model that produced the file. They surface in the *consumer's* job.

`sarif-ingestion.yml` closes that (#610) off the PR path deliberately:
fork PRs can never hold `security-events: write`, and a PR-time job would
push deliberately-insecure fixture findings into this repo's alert set on
every run. Post-merge and weekly also matches what it can actually catch
— GitHub tightening SARIF acceptance has no PR to attach to.

The probe deletes its own analysis afterwards, so the fixtures' findings
do not linger in Code Scanning. The parts that *can* be checked on the PR
are: `tests/test_sarif_ingestion_probe.py` asserts the probe's lint still
exits 0 (so only an upload failure can fail that job) and that the
document still carries several artifact locations, more than one `level`,
a suppression, and no duplicate `ruleId`.

---

## PR-time checks — `ci.yml`

Runs on every PR to `main`. All jobs must pass before merge. Concurrency
cancels in-progress runs when you push new commits to the same PR. A push to
`main` is never cancelled: the ruleset does not require a PR to be up to date
before merging, so `main`'s own run is what proves the merged result.

| Job                       | Purpose                                                                                   |
| ------------------------- | ----------------------------------------------------------------------------------------- |
| `lint`                    | `ruff check` + `ruff format --check` on `src/` and `tests/`                               |
| `type-check`              | `mypy src/ tests/`; strict on `src/`, relaxed on `tests/`                                  |
| `test`                    | `pytest` across the Python matrix — 3.11, 3.12, 3.13, 3.14                          |
| `coverage`                | `pytest --cov` with `--cov-fail-under=80` — fails below 80% statement coverage repo-wide; on a PR, `diff-cover` also fails below 90% coverage of the lines that PR adds or changes (see note) |
| `security`                | `bandit -r src/ -ll` (blocking) + `pip-audit` for dep CVEs (informational on PRs — see note) |
| `dependency-review`       | Blocks PRs adding deps with known high-severity CVEs or disallowed licenses               |
| `actionlint`              | Lints every workflow under `.github/workflows/`: actionlint (embeds shellcheck for `run:` blocks) and zizmor (template injection, cache poisoning, kept tokens, unpinned uses; exceptions in `.github/zizmor.yml`) |
| `hadolint`                | Lints the Dockerfile with hadolint (when the Dockerfile or `ci.yml`, which carries the hadolint pin, changes) |
| `dist-check`              | `python -m build` + `twine check --strict` + the wheel/sdist content guards from `publish.yml`, on PRs touching code or the locks — a packaging regression fails here, not after the tag |
| `dockerfile-digests`      | Fails if any `FROM @sha256:` in the Dockerfile is a per-arch manifest instead of an index |
| `docker-smoke`            | Builds `linux/amd64` **and `linux/arm64`** from the Dockerfile on native runners and runs each against fixtures (only when build inputs change) |
| `action-smoke`            | Runs `./action.yml` against clean and insecure fixtures; asserts exit codes               |
| `docker-smoke` / `precommit-smoke` | Also compare the reported findings against `tests/smoke/insecure.golden.json` — exit codes alone hid five of the fixture's six rules |
| `fix-smoke`               | `fix --apply` round trip on LF and CRLF copies of the insecure fixture — result parses, `docker compose config` accepts it, endings stay uniform, no new finding, idempotent |
| `rule-premises`           | Runs `scripts/validate_rule_premises.py` in a live container to prove each rule's premise  |
| `version-consistency`     | Fails if `pyproject.toml` and `src/compose_lint/__init__.py` disagree on the version      |
| `changelog-gate`          | If a PR bumps the `version`, `CHANGELOG.md` must have a matching `## [X.Y.Z]` section     |
| `dco`                     | Every commit must carry a `Signed-off-by` trailer (Developer Certificate of Origin)       |
| `no-ai-attribution`       | Fails if a commit adds AI authorship attribution (`Co-Authored-By` AI, "Generated by", …) |
| `commit-subjects`         | Every commit subject is under 72 characters and carries no Conventional Commits prefix (`feat:`, `fix:`, …) |

`version-consistency` and `changelog-gate` were added in 0.3.8 to catch
the historically painful release-bump mistakes at review time rather
than tag-push time.

### Patch-coverage gate (`diff-cover`)

The `coverage` job runs two gates over one measurement pass.

The **repo-wide floor** (`--cov-fail-under=80`) is what the OpenSSF Best
Practices Silver `test_statement_coverage80` criterion measures: statement
coverage across the whole package. It is the trunk's number and is not
traded away for anything below.

The **patch gate** grades only the lines the PR adds or changes.
`diff-cover` diffs against the PR's base commit and reads the same
`coverage.xml` the floor produced, so nothing is measured twice. It exists
because a floor structurally cannot see a change that adds untested code —
a handful of new uncovered lines does not move a whole-repo percentage, so
the floor stays green and the only thing standing between untested code and
`main` is a checkbox the author ticks about their own work. The threshold is
90%, deliberately above the floor: new code that has tests lands near 100%,
and the gap is room for a genuinely untestable line, which takes a
`# pragma: no cover` and a comment saying why.

It runs on `pull_request` only. A push to `main` has no base to diff
against, and the floor is the gate that speaks for the aggregate.

A PR that touches only docs, tests or metadata has no measurable line in
its diff. `diff-cover` reports that and passes — correctly. The problem is
that it reports exactly the same thing, and passes just as quietly, when
`coverage.xml` has stopped lining up with the repo: it matches a report path
against a diff path as text, so a gate that has silently stopped measuring
anything looks identical to a gate with nothing to measure. That is the
failure this whole check exists to stop, one level up, so
`.github/scripts/patch-coverage.py` wraps it with two checks:

- **Every file the report names must exist here, and it must name some.**
  Runs on every invocation, not only the quiet ones. This is the case that
  matters: a report written against `compose_lint/cli.py` when the diff says
  `src/compose_lint/cli.py` matches nothing at all, and no comparison
  against the diff would notice, because the mismatch makes both sides
  empty.
- **When nothing was measured, no line the diff adds may be one the report
  calls a statement.** This catches line numbers that have drifted from the
  diff. It is deliberately not claimed as exhaustive — code appended past
  the report's last statement leaves nothing to intersect — so it backs up
  the path check rather than standing in for it.

`tests/test_patch_coverage.py` covers both, since a wrong parser there would
make the guard itself the silent check it exists to prevent.

### Dependency-CVE gate (`pip-audit`)

`pip-audit` queries a live advisory database, so a CVE newly disclosed
against an *unchanged*, already-pinned dependency turns the check red with
no code change — and because the lock is shared with `main`, that would
block every open PR at once. To avoid blocking unrelated work on a
time-of-disclosure accident, the gate is split three ways:

- **On PRs** the `pip-audit` step is `continue-on-error` — it still runs
  and is visible in the job log, but does not fail `ci-ok`. (`bandit` in
  the same job stays blocking.)
- **Continuous detection** comes from Renovate's OSV alerts
  (`osvVulnerabilityAlerts`), which open a security PR the day an advisory
  lands instead of waiting for the weekly schedule.
- **At release time** the same `pip-audit` invocation is a hard gate in
  `publish.yml`'s `build` job, where the build/publish toolchain actually
  runs and touches release integrity. The `--ignore-vuln` set is kept
  identical in both places.

### Dependency lockfiles

CI installs dev dependencies from hash-pinned lockfiles:

- `requirements.lock` — runtime only (PyYAML).
- `requirements-dev.lock` — dev + lint + security + publish extras.
- `requirements-build.lock` — container builds only.

Any `pip install` in CI passes `--require-hashes`. The one exception is
`python -m pip install --upgrade pip` in the `security` job, which bootstraps
pip itself before the hash-pinned install runs. Regeneration instructions
live in [`CLAUDE.md`](../CLAUDE.md) under "Regenerating lockfiles".

---

## Fuzzing — `cflite-pr.yml` and `cflite-batch.yml`

`fuzz/fuzz_compose.py` is an Atheris harness that feeds arbitrary bytes
through `LineLoader → _validate_compose → _collect_lines → engine.run_rules`.
Any uncaught exception outside the expected-error set is a crash.

### PR fuzzing (`cflite-pr.yml`)

Path-filtered to PRs touching `src/**`, `fuzz/**`, `.clusterfuzzlite/**`,
or the workflow itself — i.e., any source change (CLI and formatters
included, since they sit under `src/`). Docs-only, tests-only, and
config-only PRs skip. `fuzz-seconds: 120`, `mode: code-change`.

Failures surface as a red X on the PR plus a SARIF entry in the Security
tab. Reproducer bytes are in the run's artifacts — download, feed to the
harness locally to reproduce, fix, re-run.

### Batch fuzzing (`cflite-batch.yml`)

Nightly matrix across `address` and `undefined` sanitizers, `fuzz-seconds: 600`.
No `storage-repo` is configured, so each run starts from a cold corpus —
the depth cap is "what 10 minutes reaches from the seed corpus". See
[`dynamic-testing.md`](dynamic-testing.md) for the rationale and the
gap that storage-repo would close.

### When a scheduled fuzz run fails

1. The run opens (or comments on) an issue titled `Scheduled run failed:
   ClusterFuzzLite batch fuzzing (<sanitizer>)`, via the shared
   `report-scheduled-failure` composite. GitHub also emails the workflow
   author.
2. SARIF crashes are uploaded to **Security → Code Scanning**.
3. The crash reproducer is in the run's artifacts (90-day retention).

The issue is the tracker; the fix is manual: download the reproducer,
reproduce locally with `python fuzz/fuzz_compose.py <file>`, land a fix
via PR, land the new corpus entry in `fuzz/corpus/` if applicable, and
close the issue with the PR.

The `RecursionError` fix in 0.3.5 came from this path.

---

## Static analysis — `codeql.yml`

Runs on every PR and weekly (Mondays, 04:27 UTC). Alerts land in
**Security → Code Scanning**. PR alerts show inline as review comments.

Weekly runs catch advisories added to the CodeQL query set that apply
to unchanged code — a new rule can flag something your last PR didn't.

---

## Supply chain — `scorecard.yml`

OpenSSF Scorecard runs on every branch-protection-rule change and
weekly (Mondays, 05:13 UTC). Results go to **Security → Code Scanning**
under the `scorecard` category.

The Signed-Releases check specifically inspects the last five GitHub
Releases for accompanying signature files (`.sigstore`, `.sig`, `.asc`,
`.intoto.jsonl`). `publish.yml`'s `create-release` job attaches Sigstore
bundles to satisfy that check.

---

## Image scanning — `scout-scan.yml`

Runs daily (06:00 UTC) against the published Docker Hub image. Catches
new CVEs filed against the runtime image's base layers after the release
shipped. Results go to **Security → Code Scanning** under the
`docker-scout` category.

Scheduled CVE scans need no action unless a high-severity alert appears —
at that point the fix is usually a Renovate PR bumping the base image
digest, which ships in the next patch release.

---

## Fixable-vulnerability report — `vuln-report.yml`

Runs daily (06:30 UTC), just after the Scout sweep. It answers one
question: **is there anything with an available fix right now?**

The blocking gates elsewhere are severity-scoped on purpose — the
dependency review fails at `high`, the Scout gate at `critical` — so a
fixable low or medium never blocks unrelated work. That leaves a
visibility gap, because a fixable MEDIUM in the published image is real
and actionable but silent. This workflow closes the gap by reporting on
**fixability rather than severity**, without changing what blocks.

Output is a single **rolling issue** labelled `fixable-vulns`:

- The body is rewritten in place on every run — one issue, never a
  stream of per-CVE issues.
- It **closes itself** when nothing fixable is left. An open issue
  therefore means "there is something to fix right now"; there is no
  triage backlog to groom.
- Advisories with **no** available fix are listed in a collapsed section
  and deliberately do not open or close the issue.

Two properties are worth preserving if you edit it:

**It applies no `--ignore-vuln` suppressions.** An advisory filtered out
of the `ci.yml` / `publish.yml` gates still appears here. This is the
anti-rot property: a suppression whose written justification has gone
stale is otherwise invisible to pip-audit (filtered by ID) *and* to
Renovate (the existing pin is already satisfiable) at the same time. That
is not hypothetical — the `tuf` ignore claimed "no fix is installable
under current constraints" for months after `sigstore` relaxed the pin
that made it true.

**A scanner failure fails the job.** `scripts/vuln_report.py` errors out
if either report is missing or has an unexpected shape rather than
rendering an empty body, because a reporting job that silently reports
clean is worse than no reporting job at all.

---

## Release pipeline — `publish.yml`

Tag-triggered, plus a manual Docker-only republish (below). Full detail in
[`RELEASING.md`](RELEASING.md) and the per-channel contract in
[`DISTRIBUTION.md`](DISTRIBUTION.md). Summary:

`verify-tag` → `build` → `testpypi` → `testpypi-smoke` + `docker-smoke`
+ `docker-scout` → **`release-gate` (manual approval)** → `publish` +
`docker-publish` in parallel → `create-release` →
`bump-marketplace-smoke-pin`.

`docker-smoke` calls [`release-docker-smoke.yml`](../.github/workflows/release-docker-smoke.yml),
the shared pre-publish battery — build the image, then assert the version
matches the tag, the clean fixture exits 0, the insecure fixture exits 1,
and SARIF output parses, each under the fully-hardened flag set README
documents. It was extracted when a second, manual publish workflow kept
its own copy and that copy drifted (#633); the republish path is now
`publish.yml`'s own `workflow_dispatch`, so it runs the same job.

`docker-scout` is separate from the smoke because it needs
`security-events: write` to upload its SARIF, which the shared smoke
workflow should not have to grant. It gates `release-gate` alongside the
smoke, so a critical CVE still blocks the release.

`verify-tag` is the first gate: it asserts the tag is annotated (not
lightweight), that the tag commit is reachable from `origin/main`, and
that the tag's SSH signature verifies against `.github/allowed_signers`
via `git verify-tag` — the cryptographic root of the release provenance
chain. Every downstream job inherits the check via `needs:`.

`release-gate` is the single human-in-the-loop gate: one approval on the
`release` environment covers every channel. The per-channel environments
(`pypi`, `dockerhub`) carry no reviewer of their own. What they enforce is
a deployment branch policy — only `v*` tags may enter them — so a job
reaches a publishing credential only from a tag, and only after
`verify-tag` has checked that tag's signature against
`.github/allowed_signers`. The Docker Hub push token is an environment
secret of `dockerhub` (not a repo secret), so this holds for the per-arch
build jobs too — see docs/RELEASING.md "Docker Hub credential scoping". The gate is the signed tag plus one approval;
with a single maintainer, a second approval on the same run would be the
same person clicking twice.

`build` generates an SPDX SBOM (`sbom.spdx.json`) covering the wheel
and sdist via `anchore/sbom-action`. `create-release` attaches it to
the GitHub Release alongside the distributions and Sigstore bundles.
`docker-publish` does the equivalent for the image — generates an SBOM
and `cosign attest`s it to the manifest digest.

The `bump-marketplace-smoke-pin` job opens a post-release PR updating
`marketplace-smoke.yml` to the SHA the tag pointed at. `GITHUB_TOKEN`
can't push commits that modify `.github/workflows/*`, so this job
uses a repo-scoped PAT stored in the `MARKETPLACE_SMOKE_PAT` secret.
The job preflights that secret and fails early if it's unset. The PR is
also *authored* with that PAT (not `GITHUB_TOKEN`): a `GITHUB_TOKEN`-
authored PR does not trigger `pull_request`/`push` workflows (GitHub's
recursion guard), so it would land with zero checks and sit blocked
until someone closed and reopened it. Authoring it as the PAT user makes
the required checks run automatically.

The job then arms **auto-merge** on that PR, so it lands on its own once
`ci-ok` is green. The arm is the shared `.github/actions/arm-auto-merge`
composite, one definition for every bot-authored PR this repository opens
(this job, `release-prep.yml`, `forgejo-smoke.yml`; three hand-copies had
drifted, [#1057]). Given a PR and a PAT it reports one `result`: `armed`;
`already-armed` (a re-run); `merged-direct`, when every required check had
already finished — GitHub refuses to arm a PR in that "clean" state, so
`gh pr merge --auto` merges it on the spot instead (and the explicit direct
merge behind it covers gh handing the refusal through); that merge is
permitted only in the clean state, so neither path lands ahead of `ci-ok`;
`skipped-no-token`; or `failed`. It never fails the calling job;
each caller turns the result into its own step-summary wording. The merge
here gates nothing irreversible: the PR opens only
after `publish`, `docker-publish` and `create-release` have all succeeded,
so PyPI, Docker Hub and the GitHub Release are already permanent by the
time it exists — the `release` environment approval upstream is the
control, and it happened before any of that. The pinned SHA is
`git rev-parse "${TAG}^{commit}"` computed in the job, so it is right by
construction rather than by inspection. Auto-merge needs **Allow
auto-merge** enabled on the repository; without it the step warns, the PR
waits for a manual merge, and the release is otherwise unaffected — it is
deliberately not a job failure, since the release has already shipped and
a red X would misreport that.

What this removes is a step that could be *forgotten*, which is the
failure this job exists to prevent: v0.14.1 shipped with the README
snippet still pinned to v0.14.0. What it does not remove is the check on
the result — a post-release smoke failure now opens an issue (see
`marketplace-smoke.yml` below), which is what made automerging safe to
turn on.

Merging that PR is what triggers `marketplace-smoke.yml` — deliberately,
so the smoke runs against the release just cut. It also means the smoke
runs minutes after the publish, inside the window where PyPI's JSON API
already shows the release but the `/simple/` index pip resolves against
does not. That race failed the 0.20.0 run ([#612]), so two things now
absorb it: `marketplace-smoke.yml`'s `pypi-propagated` job gates every
PyPI-consuming job on the version being visible on `/simple/`, and
`action.yml`'s install retries with backoff for ~100s. A propagation delay therefore costs wall-clock, not a
red run, and if it does exhaust the retries the message says so instead
of `Process completed with exit code 1`.

[#612]: https://github.com/tmatens/compose-lint/issues/612
[#1057]: https://github.com/tmatens/compose-lint/issues/1057

### Provisioning `MARKETPLACE_SMOKE_PAT`

Create a **fine-grained personal access token**:

- Scope: this repository only
- Permissions:
  - **Contents:** Read and write
  - **Workflows:** Read and write
  - **Pull requests:** Read and write
- Expiration: whatever your rotation policy allows; Renovate won't
  prompt you, so a calendar reminder helps

Store as the `MARKETPLACE_SMOKE_PAT` repo secret. Classic PATs with
the `repo` + `workflow` scopes also work, but fine-grained is easier
to revoke and audit.

---

## Maintainer-triggered workflows

### `release-prep.yml`

**Actions → Release prep → Run workflow**, enter the version number
(e.g. `0.3.8`). Opens the "Prepare X.Y.Z release" PR: bumps both version
strings, renames the CHANGELOG `[Unreleased]` section, inserts a fresh
empty one, and links to the manual tag-signing step in the PR body.

The job then arms **auto-merge** on that PR, so it lands on its own once
`ci-ok` is green — the same shared `arm-auto-merge` action as the
marketplace-pin job above. Every
line of the diff is derived from the one dispatch input and re-derived by
CI (`version-consistency`, `changelog-gate`, the doc-pin check and
`lockfiles` all run on the PR), and the CHANGELOG prose was reviewed under
`[Unreleased]` before the dispatch; release-prep only renames the heading.
The merge gates nothing irreversible: the signed tag is still pushed by
hand afterwards, and the `release` environment approval during `publish.yml`
is the control. Auto-merge needs **Allow auto-merge** enabled on the
repository; without it the action warns and the PR waits for a manual merge,
which is deliberately not a job failure. The arm is PAT-only: on the
`GITHUB_TOKEN` fallback the token input is empty and the arm is skipped with
a warning, because a merge armed
by the default token lands on behalf of github-actions[bot] and the
recursion guard then suppresses main's push workflows — no post-merge CI
pass, no docs deploy — for a release commit.

Like the marketplace-pin job, this PR is authored with the
`MARKETPLACE_SMOKE_PAT` secret so its checks run automatically. Unlike
that job it falls back to `GITHUB_TOKEN` when the secret is absent
(release-prep touches no `.github/workflows/*` file, so the token still
works) — but the fallback PR lands check-less and needs a manual
close+reopen, so keep the secret configured. `forgejo-smoke-bump.yml`
uses the secret the same way, with the same fallback.

The signed annotated tag is **not** created here. Tag creation stays
manual because (a) `GITHUB_TOKEN`-created tags don't trigger downstream
workflows and (b) the SSH-signed tag is the root of the Sigstore
provenance chain. See `RELEASING.md`.

### `publish.yml` — Docker republish (`workflow_dispatch`)

Republishes the Docker image of an existing release, and nothing else.
Dispatch it **on the release tag** (`gh workflow run publish.yml --ref
vX.Y.Z`, or **Use workflow from** → the tag). `verify-tag` refuses a run
on any other ref, including a branch that happens to share the tag's name.

It runs `verify-tag`, both `docker-smoke` legs, `docker-scout`, the
`release-gate` approval, `docker-build` and `docker-publish`. The PyPI
jobs, `dockerhub-description`, `create-release` and the post-release
follow-ups are push-only. Image aliases (`X.Y`, `X`, `latest`) move only
when the tag is the highest release they cover, so republishing an older
version never drags them backwards (`scripts/release_image_tags.py`).

It exists inside `publish.yml` rather than as a separate workflow because
the workflow file is part of the image's signing identity: a republish
signs as `publish.yml@refs/tags/vX.Y.Z`, the identity every release is
verified against. 0.3.4 was republished by the separate workflow this
replaced and carries that workflow's identity instead. Unlike that
workflow, this path goes through the `release-gate` approval.

A dispatch runs the workflow file as it was at the tag, so it works only
for tags cut after the trigger was added (every release after 0.34.0), and it cannot fix a
defect in that tag's own workflow: that takes a patch release.
`tests/test_publish_dispatch.py` evaluates every job condition for push and
dispatch runs, since this path otherwise runs only when it is needed.

Document why you used it in the GitHub Release notes — every invocation
should leave a paper trail.

### `marketplace-smoke.yml`

Verifies the published integration surfaces the way an external user
consumes them: the GitHub Action as `tmatens/compose-lint@<sha>` from
the Marketplace, and the pre-commit hook as
`repo: https://github.com/tmatens/compose-lint` pinned at a release tag
(the `precommit-published-smoke` job, added for issue #570). Unlike
`ci.yml`'s `action-smoke` and `precommit-smoke` jobs (which use the
tree under test via `$/` and `try-repo`), these catch regressions at the
publish boundary: a missing or broken tag, a packaging regression, a
broken published `action.yml`, a PyPI outage during install.

Auto-runs on push to `main` that touches `marketplace-smoke.yml` — i.e.,
when `bump-marketplace-smoke-pin`'s PR lands (it bumps both the action
SHA pins and the pre-commit `CL_RELEASE_TAG` rev) — so the
freshly-pinned release is verified without a manual step. Also
triggerable from the Actions tab for ad-hoc re-verification, and runs
weekly on a schedule so a regression that develops *between* releases
(a yanked dependency, a resolver change, a registry-side issue) is
noticed before a user's workflow breaks.

Both unattended triggers — the weekly cron and the post-release push —
open an issue on failure via `report-failure`. The push leg is the one
that matters most and was added last: by the time it runs, the release
has already shipped to PyPI, Docker Hub and GitHub Releases, so there is
no gate left to fail closed and nothing else would say so. It was
covered only by whoever merged the pin PR happening to watch the run,
which stopped being a person when that PR started automerging. A manual
`workflow_dispatch` opens no issue: someone set it off and is watching.

### `forgejo-smoke.yml`

Proves README's Forgejo Actions snippet — and its "Verified on Forgejo X,
runner Y" claim — empirically (issue #573). GitHub-hosted CI cannot *be*
a Forgejo runner, but it can host one: `scripts/forgejo_smoke.py` boots a
throwaway Forgejo + act_runner stack
(`scripts/forgejo_smoke/compose-forgejo-smoke.yml`), extracts the snippet
from `README.md` **verbatim** at runtime (documented and tested cannot
drift — they are one string), pushes a repo whose workflow is that
snippet with the shared clean fixture as its compose file, dispatches it,
and requires success. It then asserts the README's verified-on versions
against the live instance and runner, so bumping the harness images
without moving the claim (or vice versa) fails the run.

Runs weekly, on PRs and pushes to `main` touching the harness — which is
how each Forgejo release re-proves the snippet: the bump PR below carries
this run as its check — and manually. Deliberately not on docs-only PRs:
the release-prep PR bumps the snippet's `compose-lint==X.Y.Z` pin before
that version exists on PyPI, which would fail spuriously; the weekly run
covers the new pin after release instead.

### `forgejo-smoke-bump.yml`

Opens the PR that moves the harness to the newest Forgejo and runner
releases. It has to be two files or nothing: the image pins in
`scripts/forgejo_smoke/compose-forgejo-smoke.yml` **and** the "Verified on
Forgejo X, runner Y" line in `docs/forgejo.md`, because `forgejo-smoke.yml`
asserts the two agree — which is also why Renovate could never do this
bump even where it can see the file (it cannot move the docs line). And
it cannot see the file: the hosted Renovate fails to look up either
registry (`Failed to look up docker package codeberg.org/forgejo/forgejo:
no-result`, likewise `data.forgejo.org/forgejo/runner`, plus `Error
obtaining docker token`) while a local `renovate --platform=local
--dry-run=lookup` resolves both, so the failure is the hosted runner's
egress. `renovate.json` disables the docker-compose manager on that file
so two writers never race on one pin.

Daily rather than weekly because Codeberg deletes a superseded Forgejo
patch tag — digest included — within days of the next patch ([#746]);
the old pin is on the clock from the moment a release ships.

`scripts/forgejo_smoke_bump.py` is three-valued like `eol_watch.py`: 0
nothing to do, 1 files rewritten (the job commits them, one branch per
target version pair, and never reopens a pair a human has already closed),
2 no trustworthy answer — a registry unreachable, an anchor gone from
either file, or a tag resolving to a per-architecture manifest instead of
a manifest list — which fails the run and is reported as an issue. Policy:
the newest stable `X.Y.Z` of each image, never a `-rootless` variant or a
floating `16`/`16.0` tag. A major that breaks the guide's snippet surfaces
as a red `Forgejo smoke test` check on the bump PR, which is the review.

Because that check is the review, a human clicking merge after reading it
green adds nothing, so `forgejo-smoke.yml` arms **auto-merge** on the PR
when the smoke passes: a green bump lands on its own once `ci-ok` is green.
It uses `--auto`, not a direct merge, so GitHub still waits for the required
`ci-ok` check — the smoke itself is deliberately *not* required, to keep a
job with external dependencies (codeberg.org, data.forgejo.org) off every
PR's required path. When `ci-ok` finishes first, GitHub refuses to arm an
already-mergeable PR ("clean status"); the shared `arm-auto-merge` action
then merges directly, which is only permitted because the required checks
have already passed. Arming runs in its own job (`arm-bump-automerge`,
holding only the `contents: read` that fetching a `$/` action takes, and no
checkout) so the PAT never shares a runner with the PR head's code, and it
is PAT-only: without `MARKETPLACE_SMOKE_PAT` the action skips with a warning
rather than falling back to `GITHUB_TOKEN`, whose
merge would push `main` without triggering the post-merge smoke. A red run
never arms auto-merge and stays open for a human. The PR carries the
`manual-merge` label (applied best-effort after creation) so it shows in the
same "what needs me" query as the non-automerge Renovate PRs until it either
auto-merges away or a human handles the red.

The PR is authored with `MARKETPLACE_SMOKE_PAT` (see below) so its checks
run; without the secret it falls back to `GITHUB_TOKEN` and lands
check-less, like `release-prep.yml`.

[#746]: https://github.com/tmatens/compose-lint/issues/746

### `digest-age-gate.yml`

Merges Renovate's digest refreshes from **gcr.io and ghcr.io** (distroless,
the oss-fuzz builder, vhs) once they have aged the same three days the
Docker Hub digests wait under Renovate's `minimumReleaseAge` ([#1059]).
Those PRs open with `age-gated` (their own label, set in `renovate.json`,
so `manual-merge` keeps meaning "a human has to act") because Renovate
cannot age them: its
docker datasource takes a release timestamp from Docker Hub's
`tag_last_pushed` and from nowhere else — the OCI distribution API exposes
no publish time ([renovatebot/renovate#39064]), and distroless's
reproducible builds zero the image timestamps anyway. The review on them
was already mechanical (`dockerfile-digests` and both `docker-smoke` legs
are required via `ci-ok`); the human click added only the age check, and
this is the age check.

The clock is the **head commit's timestamp**: "first time we saw this
digest" is never earlier than its publish time, so 72h from first-seen is
at least 72h from publish — conservative by construction. PR `created_at`
would not do, because Renovate force-pushes the branch when the digest
moves again; the head commit resets with every push, so a fresh digest
waits its own 72h and a plain rebase waits again too (over-conservative,
never leaky). The 72h constant is `MIN_AGE_HOURS` at the top of the
workflow and must move with `renovate.json`'s `minimumReleaseAge`.

Selection is conjunctive and the step summary shows every candidate with
its decision: author `renovate[bot]`, head `renovate/*`, label
`age-gated`, title `Update <image> Docker digest to <sha>` (Docker Hub
digests automerge via Renovate and carry no label, so this is exactly the
gcr/ghcr set), no draft, no fork, every commit authored by Renovate (a
hand-touched branch needs a human, Renovate's own automerge rule),
`ci-ok` green on the head, merge state `CLEAN`, head commit ≥ 72h old. A
red, conflicting, draft or hand-touched PR is left alone and gets
`manual-merge` added (removed again once it is clean), so the "what needs
me" query stays truthful; a PR whose `ci-ok` is still running is simply
waited for. To hold one back deliberately, convert it to a draft. A dry
run touches no labels.

The merge is the shared `arm-auto-merge` action with `expected-head` set
to the SHA the selection looked at (`gh pr merge --match-head-commit`), so
a push that lands in between fails the merge rather than shipping content
nobody aged. By the time the gate runs `ci-ok` finished long ago and the PR
is "clean", so the merge is immediate and the action reports
**`merged-direct`**. Should a PR have stopped being clean in between and the
action arm instead, the gate disarms it again: GitHub keeps auto-merge
armed across a collaborator's pushes, so an armed PR would merge whatever
digest Renovate pushed next, unaged. It merges with
`MARKETPLACE_SMOKE_PAT` so the push to `main` triggers main's push
workflows as a human merge would; without the secret the merge job skips
with a warning and the PRs wait. Each merge leaves a comment on the PR
saying why it was eligible. A manual dispatch is a **dry run by default**
(the summary table, no merge); untick the box to merge from a dispatch.

Built to be deleted: if upstream Renovate gains a registry-agnostic
release timestamp, scope these images back into the digest automerge rule
in `renovate.json` and remove this workflow and this section.

[#1059]: https://github.com/tmatens/compose-lint/issues/1059
[renovatebot/renovate#39064]: https://github.com/renovatebot/renovate/issues/39064

### `os-smoke.yml`

The developer-machine legs (issue #572): pytest and the pre-commit smoke
on macOS and Windows at Python 3.13 — the platforms where the CLI and the
hook predominantly run.

**Part of the merge gate since #608.** `ci.yml` calls this workflow
(`workflow_call`) as its `os-smoke` job whenever the `code` or `workflows`
path filter matches, and `ci-ok` needs that job — so a macOS or Windows
regression blocks the PR that introduces it. Branch protection needed no
change, because it points only at `ci-ok`. Roughly 2 minutes of wall clock
for all four legs, in parallel with the rest of the suite.

Note that lockfile PRs do **not** skip these legs: the `code` filter
matches `requirements*.lock`. That is intended — the locks are compiled
`--universal`, so a dependency bump is exactly the change that can break
on one OS alone — but it does mean Renovate PRs wait on macOS/Windows.

The `workflow_dispatch`, weekly `schedule` and `push: main` triggers all
remain. The cron is not redundant with the gate: drift that arrives with
no PR at all — a yanked dependency, a resolver change, a runner-image
update — is structurally invisible to a merge gate.

The soak behind the promotion was narrow: the legs' only failures were the
rollout commits that introduced them (#584–#587, which is what they were
for), and every run from `d757ee3` onward was green — but that was 9 runs
inside a single day. If a leg turns out to flake in the merge path, the
fix is to quarantine that leg here, not to widen `ci-ok`'s pass
condition.

---

## Dependency updates — Renovate

Renovate opens every dependency bump as a PR (`.github/renovate.json`; the
schedule is Monday before 04:00 UTC, base images and security fixes open at
once). Whether a PR merges itself or waits for a person follows one rule:

**A bump merges itself when the PR's own CI exercises the new version, so a
green run is the review.** It waits for a person when the first real run
would come after the tag, or when it changes a contract rather than
refreshing one. It is disabled when the pin records a fact rather than a
dependency choice, or when another workflow owns it.

Automerge still has two gates on top of a green `ci-ok`: the release must
be three days old (`minimumReleaseAge`; `renovate/stability-days` stays
pending until then), and Renovate merges it itself rather than arming
GitHub auto-merge, so the age check cannot be skipped. A red PR never
merges. Security PRs open immediately, ungrouped and unaged, and then
follow the same rules as any other update.

| Update | Outcome | Why |
| --- | --- | --- |
| Patch, pin, digest, lock maintenance (Python, actions) | Automerge | Smallest change; the full suite runs on the PR |
| Minors of Python dev tooling, including `build` and `twine` | Automerge | Every optional-dependency group is installed and run by a PR gate; `dist-check` builds and `twine check`s the dists |
| `pyyaml` minors | Automerge | `pyproject.toml` allows `>=6.0.2,<7`, so only the locks move, never the wheel's range |
| Minors of actions on the CI path | Automerge | The bumped action runs in the PR's own workflows |
| Minors of release-path actions that also run on the CI path (`checkout`, `setup-python`, `upload-artifact`, `login-action`, `build-push-action`, `setup-buildx-action`, `scout-action`, `codeql-action`) | Automerge | Same as above: the PR runs them before any tag does |
| Compose, actionlint, hadolint pins in `ci.yml` (patch and minor) | Automerge | Each bump runs the tool it bumps: the differential suites, actionlint over every workflow, hadolint over the Dockerfile. A red Compose bump is the one that needs triage |
| Docker Hub base-image digests | Automerge | Docker Hub supplies the release timestamp the three-day gate needs; `dockerfile-digests` and `docker-smoke` run on the PR |
| gcr.io / ghcr.io digests (distroless, oss-fuzz builder, vhs) | `age-gated`, merged by `digest-age-gate.yml` | Same review as Docker Hub, but those registries give Renovate no timestamp; the gate waits 72h from first sight instead (see [`digest-age-gate.yml`](#digest-age-gateyml)) |
| Majors of anything | `manual-merge` | A changed contract: a green run only proves the old tests still pass |
| Ubuntu runner image | `manual-merge` | Arrives as a major and moves every job at once |
| Minors of the six release-only actions (`attest-build-provenance`, `download-artifact`, `sbom-action`, `gh-action-pypi-publish`, `cosign-installer`, `gh-action-sigstore-python`) | `manual-merge` | They run only after the tag, so their first real run is after the irreversible step. They also hold the `github-actions-release` group |
| `sigstore` minors | `manual-merge` | The verifier must move in lockstep with `gh-action-sigstore-python`, which is manual |
| The demo `compose-lint` pin (`scripts/demo/`) | Disabled | It records which release the committed GIF was rendered on; it moves only when the demo is regenerated ([`RELEASING.md`](RELEASING.md)) |
| Forgejo smoke stack pins | Disabled | Owned by [`forgejo-smoke-bump.yml`](#forgejo-smoke-bumpyml), which also moves the docs claim Renovate cannot |

**Labels.** `manual-merge` means a person has to act, in every case. A
grouped PR carries it exactly when at least one update in it is not
eligible, which is exactly when Renovate will not merge it. `age-gated`
means waiting out 72h; the gate adds `manual-merge` to one only if it goes
red, conflicts, or is hand-touched. An automerge-eligible PR whose CI is
red carries no label, so it does not appear in a `manual-merge` query:
look for open Renovate PRs with a failing check as well.

Each rule's full reasoning, with the Renovate behaviour it depends on, is
in its `description` in `.github/renovate.json`. Change the rule there and
this table together.

---

## Where findings land

| Signal                              | Location                                               |
| ----------------------------------- | ------------------------------------------------------ |
| PR-gating job failure               | Red X on the PR, inline log                            |
| Fuzzing crash (PR or batch)         | Security → Code Scanning + run artifacts               |
| CodeQL alert                        | Security → Code Scanning, PR review comments           |
| Scorecard finding                   | Security → Code Scanning (`scorecard` category)        |
| Docker Scout CVE                    | Security → Code Scanning (`docker-scout` category)     |
| Vulnerability with an available fix | Rolling issue labelled `fixable-vulns`                 |
| Scheduled workflow failure          | Issue `Scheduled run failed: <workflow>` — one per workflow, repeat failures comment on it (`.github/actions/report-scheduled-failure`); plus the author email and red X |
| Post-release smoke failure          | Issue `Post-release run failed: Marketplace smoke test` — same action, separate thread from the weekly one so a break in a shipped release is not triaged as a flake |
| Renovate PR                         | A PR per update. Automerges once green and three days old when the PR itself exercises the change; otherwise labelled `manual-merge` (a person has to act) or `age-gated` (gcr/ghcr digests, merged by `digest-age-gate.yml` after 72h). See [Dependency updates](#dependency-updates-renovate) |

The Security tab is the single pane of glass for everything except
PR-gating failures (which stay on the PR) and Renovate bumps (which
open their own PRs).

The two security surfaces are complementary rather than redundant: the
Security tab is the **passive** record — deduplicated, auto-resolving,
and complete across severities — while the `fixable-vulns` issue is the
**active** channel that actually notifies, filtered to what is
actionable today. Note that the Security tab covers image and code
findings only; Python dependency advisories reach it through no path at
all, since `pip-audit` emits no SARIF. For those, the rolling issue is
the *only* standing surface.
