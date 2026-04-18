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
| `publish.yml`             | `v*` tag push                              | Release pipeline — see `RELEASING.md`                  |
| `release-prep.yml`        | Manual (`workflow_dispatch`, maintainer)   | Opens the "Prepare X.Y.Z release" PR                   |
| `publish-channel.yml`     | Manual (`workflow_dispatch`, maintainer)   | Emergency single-channel publish                       |
| `marketplace-smoke.yml`   | Manual (`workflow_dispatch`, maintainer)   | Verifies the published Marketplace action end-to-end   |

---

## PR-time checks — `ci.yml`

Runs on every PR to `main`. All jobs must pass before merge. Concurrency
cancels in-progress runs when you push new commits to the same PR.

| Job                       | Purpose                                                                                   |
| ------------------------- | ----------------------------------------------------------------------------------------- |
| `lint`                    | `ruff check` + `ruff format --check` on `src/` and `tests/`                               |
| `type-check`              | `mypy src/` in strict mode                                                                |
| `test`                    | `pytest` across the Python matrix — 3.10, 3.11, 3.12, 3.13, 3.14                          |
| `security`                | `bandit -r src/ -ll` + `pip-audit` for CVEs in hash-pinned dev deps                       |
| `dockerfile-digests`      | Fails if any `FROM @sha256:` in the Dockerfile is a per-arch manifest instead of an index |
| `docker-smoke`            | Builds `linux/amd64` from the Dockerfile and runs it against fixtures (path-filtered)     |
| `action-smoke`            | Runs `./action.yml` against clean and insecure fixtures; asserts exit codes               |
| `version-consistency`     | Fails if `pyproject.toml` and `src/compose_lint/__init__.py` disagree on the version      |
| `changelog-gate`          | If a PR bumps the `version`, `CHANGELOG.md` must have a matching `## [X.Y.Z]` section     |

The last two were added in 0.3.8 to catch the historically painful
release-bump mistakes at review time rather than tag-push time.

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

Runs on PRs that change files the harness actually exercises — parser,
engine, config, models, rules, fuzz/, or the harness workflow itself.
Docs-only, CLI-only, and formatter-only PRs skip fuzzing because they
can't affect the paths under test. `fuzz-seconds: 120`, `mode: code-change`.

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

1. GitHub Actions emails the workflow author by default.
2. SARIF crashes are uploaded to **Security → Code Scanning**.
3. The crash reproducer is in the run's artifacts (90-day retention).

No auto-issue filing. Triage happens manually: download the reproducer,
reproduce locally with `python fuzz/fuzz_compose.py <file>`, land a fix
via PR, land the new corpus entry in `fuzz/corpus/` if applicable.

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

## Release pipeline — `publish.yml`

Tag-triggered. Full detail in [`RELEASING.md`](RELEASING.md) and the
per-channel contract in [`DISTRIBUTION.md`](DISTRIBUTION.md). Summary:

`build` → `testpypi` → `testpypi-smoke` + `docker-smoke` → **`release-gate`
(manual approval)** → `publish` + `docker-publish` in parallel →
`create-release` → `bump-marketplace-smoke-pin`.

`release-gate` is the single human-in-the-loop gate: one approval on the
`release` environment covers every channel. Per-channel environments
(`pypi`, `dockerhub`) add a second required approval before each production
publish.

The `bump-marketplace-smoke-pin` job opens a post-release PR updating
`marketplace-smoke.yml` to the SHA the tag pointed at. Today that job is
blocked from pushing directly because `GITHUB_TOKEN` lacks `workflows`
scope — the PR is opened by hand until a PAT with `workflow` scope is
wired in.

---

## Maintainer-triggered workflows

### `release-prep.yml`

**Actions → Release prep → Run workflow**, enter the version number
(e.g. `0.3.8`). Opens the "Prepare X.Y.Z release" PR: bumps both version
strings, renames the CHANGELOG `[Unreleased]` section, inserts a fresh
empty one, and links to the manual tag-signing step in the PR body.

The signed annotated tag is **not** created here. Tag creation stays
manual because (a) `GITHUB_TOKEN`-created tags don't trigger downstream
workflows and (b) the SSH-signed tag is the root of the Sigstore
provenance chain. See `RELEASING.md`.

### `publish-channel.yml`

Emergency escape hatch when one channel's smoke is broken and another
must ship. Enter the tag and the channel (`pypi` or `dockerhub`). Bypasses
the shared `release-gate` but still requires the per-channel environment
approval.

Document why you used it in the GitHub Release notes — every invocation
should leave a paper trail.

### `marketplace-smoke.yml`

Verifies the published GitHub Action as it appears on the Marketplace —
consumes `tmatens/compose-lint@<tag>` the same way an external user
would. Unlike `ci.yml`'s `action-smoke` job (which uses the local
`action.yml` at `./`), this catches regressions at the Marketplace
boundary: a missing tag, a broken published `action.yml`, a PyPI outage
during install.

Run it after every release bump PR merges.

---

## Where findings land

| Signal                              | Location                                               |
| ----------------------------------- | ------------------------------------------------------ |
| PR-gating job failure               | Red X on the PR, inline log                            |
| Fuzzing crash (PR or batch)         | Security → Code Scanning + run artifacts               |
| CodeQL alert                        | Security → Code Scanning, PR review comments           |
| Scorecard finding                   | Security → Code Scanning (`scorecard` category)        |
| Docker Scout CVE                    | Security → Code Scanning (`docker-scout` category)     |
| Scheduled workflow failure          | Email to workflow author + red X on Actions tab        |
| Renovate PR                         | Opens a PR tagged accordingly                          |

The Security tab is the single pane of glass for everything except
PR-gating failures (which stay on the PR) and Renovate bumps (which
open their own PRs).
