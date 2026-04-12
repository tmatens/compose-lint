# compose-lint

## Project Overview

compose-lint is a security-focused linter for Docker Compose files, distributed as a
Python package on PyPI. It targets the same niche as Hadolint (Dockerfiles) but for
Compose files: zero-config, opinionated, fast, grounded in OWASP/CIS standards.

This is not a Dockerfile linter, not a runtime security scanner, and not a replacement
for full-platform tools like KICS or Checkov. It does one thing well: static analysis
of Compose files for dangerous misconfigurations.

## Architecture

- **Language**: Python >=3.10
- **Build system**: Hatchling (PEP 517)
- **Package name**: `compose-lint` (PyPI), `compose_lint` (import)
- **Entry point**: `compose_lint.cli:main`
- **Single runtime dependency**: PyYAML >=6.0
- **License**: MIT

### Key design patterns

- YAML parsing uses a custom `LineLoader(yaml.SafeLoader)` that captures line numbers.
  The parser exposes `load_compose(path) -> (data, lines)`. Rules receive plain dicts,
  not library-specific types.
- The parser must handle Compose v2 and v3 schema differences, YAML anchors, merge keys
  (`<<:`), and extension fields (`x-`). Environment variable interpolation (`${VAR}`)
  should be left as-is (not resolved by the linter).
- The parser validates that the input is a valid Compose file, not just valid YAML:
  - Top-level `services:` key must exist
  - `services:` must be a mapping, not a list or scalar
  - Each service entry must be a mapping
  - Invalid input produces clear error messages (e.g., "Not a valid Compose file:
    missing 'services' key")
  - The parser does NOT perform full Compose schema validation — that is Docker's job.
    Unknown keys are ignored, not rejected. The linter validates security posture, not
    schema conformance.
- Each rule is a class inheriting `BaseRule`, registered via decorator. Rules declare
  their own ID (CL-XXXX), severity, OWASP/CIS references, and a `check()` method that
  yields findings.
- Rule IDs use the `CL-` prefix, zero-padded to 4 digits, never reused.
- Findings are dataclasses (see `models.py`), not dicts.
- Formatters receive a list of `Finding` objects and produce output. Each formatter is
  a module in `formatters/` exposing a `format(findings) -> str` function.

### Severity levels

Ordered by rank (see `docs/severity.md` for the full scoring matrix):

- **CRITICAL**: Direct path to host compromise. No chaining required.
- **HIGH**: Exposed attack surface or requires chaining for cross-container/host impact.
- **MEDIUM**: Requires chaining for single-container impact, or hardening gap with cross-container scope.
- **LOW**: Hardening gap contained within a single container.

### Exit code contract

- Exit 0: No findings at or above the failure threshold
- Exit 1: One or more findings at or above the failure threshold
- Exit 2: Usage error (invalid arguments, file not found, invalid Compose file)
- Default threshold: HIGH (medium/low findings alone produce exit 0)
- Configurable via `--fail-on` flag (`--fail-on low`, `--fail-on critical`)

### CLI interface

```
compose-lint [OPTIONS] [FILE ...]

Options:
  --format {text,json,sarif}  Output format (default: text)
  --fail-on SEVERITY          Minimum severity to trigger exit 1 (default: high)
  --skip-suppressed           Hide suppressed findings from output
  --config PATH               Path to .compose-lint.yml config file
  --version               Show version and exit
```

### Config file

`.compose-lint.yml` supports per-rule overrides:

```yaml
rules:
  CL-0001:
    enabled: false          # Disable a rule entirely
  CL-0003:
    enabled: false
    reason: "SEC-1234 — Approved by J. Smith"  # Optional exception tracking
  CL-0005:
    severity: high          # Override default severity
```

Disabled rules still run and produce suppressed findings in the output. The optional
`reason` field records why a rule was disabled (e.g., exception ticket). It flows
through as `suppression_reason` (JSON), `justification` (SARIF), or is shown after
the `SUPPRESSED` label (text).

The engine loads config, merges it with defaults, and passes it to the rule runner.
Inline suppression comments (e.g., `# compose-lint: disable=CL-0001`) are not
supported -- do not implement unless explicitly planned.

### Source layout

```
src/compose_lint/       # Package root
  cli.py                # argparse CLI
  parser.py             # YAML loading + line number tracking
  engine.py             # Rule runner + result collection
  models.py             # Finding, Severity, RuleMetadata dataclasses
  formatters/           # text, json, sarif output
  rules/                # One file per rule: CL0001_*.py, CL0002_*.py, etc.
tests/
  compose_files/        # YAML fixtures (secure, insecure, mixed)
  test_CL0001.py        # One test file per rule
  test_parser.py, test_cli.py, test_engine.py
docs/
  adr/                  # Architecture Decision Records -- consult before proposing
                        # architectural changes
  rules/                # Per-rule documentation (CL-0001.md, etc.)
```

## Rule Design Philosophy

### Grounding in authoritative sources

Every rule must be grounded in at least one of:

- **OWASP Docker Security Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- **CIS Docker Benchmark**: https://www.cisecurity.org/benchmark/docker
- **Docker official documentation**: https://docs.docker.com/

No opinion-only rules. If a finding cannot be traced to an authoritative source, it
does not belong in this tool. When a user questions a rule, the reference should end
the debate.

### Every finding must be actionable

A finding is only valuable if the user knows exactly what to do about it. Each rule must
provide:

1. **Clear description**: What was detected and why it matters (the risk, not just the
   violation)
2. **Concise fix guidance**: Specific, copy-pasteable remediation -- not vague advice
   like "consider securing this." Show the before and after.
3. **Authoritative references**: Direct links to the OWASP/CIS/Docker docs section that
   supports the finding. Users should be able to click through and read the full context.

Severity must reflect real-world criticality: how exploitable is this, what is the blast
radius, and how commonly does this lead to actual incidents? Do not inflate severity to
make findings seem more important. Do not create findings that waste the user's time
with noise they cannot act on.

### Severity assignment criteria

Severity is determined by a two-axis matrix (see `docs/severity.md`):

- **Exploitability**: Direct > Exposed > Requires chaining > Hardening gap
- **Impact scope**: Host > Cross-container > Single container

The matrix intersection determines the severity. Supply chain rules (e.g., CL-0004) are
scored by judgment since they don't fit the runtime exploitation model.

## Development

### Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Quality checks

```bash
ruff check src/ tests/          # Linting
ruff format --check src/ tests/ # Formatting
mypy src/                       # Type checking (strict mode)
pytest                          # Tests
```

All four must pass. CI runs these on every PR.

### Adding a new rule

1. Create `src/compose_lint/rules/CL{NNNN}_{snake_name}.py`
2. Inherit from `BaseRule`, use the `@register_rule` decorator
3. Set `id`, `name`, `severity`, `description`, `references` (must cite OWASP or CIS)
4. Implement `check(service_name, service_config, global_config)` yielding `Finding` objects
5. Add test file `tests/test_CL{NNNN}.py` with both positive (triggers) and negative (clean) cases
6. Add fixture YAML files in `tests/compose_files/`
7. Add rule documentation in `docs/rules/CL-{NNNN}.md`
8. Ensure fix guidance is specific and actionable -- show the exact YAML change needed
9. Include direct links to the supporting OWASP/CIS/Docker docs section

### Contributor workflow

[CONTRIBUTING.md](CONTRIBUTING.md) is the source of truth for the commit,
signing, and PR rules. Everything below is a condensed mirror for agents
working in this repo — if it ever drifts from CONTRIBUTING.md,
CONTRIBUTING.md wins.

**Commit conventions**

- One logical change per commit. Rules, features, refactors, and docs each get
  their own commit. Don't bundle unrelated changes.
- Imperative subject under 72 characters ("Add CL-0011 rule for X", not
  "Added CL-0011" or "CL-0011").
- Explain the *why* in the body, not just the *what*. The diff shows what
  changed; the message explains the reason.
- No Conventional Commits prefixes (`feat:`, `fix:`, etc.) — descriptive
  imperative subjects are preferred.
- Follow the **No AI authorship attribution** rule in "Things to avoid"
  below. No `Co-Authored-By` trailers for AI tools, no "Generated by"
  notices in code, no "built with AI" badges on docs.

**Commit signing**

All commits to `main` must be signed so GitHub shows the "Verified" badge.
Follow the SSH signing setup in [CONTRIBUTING.md](CONTRIBUTING.md#commit-signing)
— it uses the SSH key you already push with. Verify locally with
`git log --show-signature` (each commit should print `Good "git" signature`)
or `git log --format='%h %G? %s'` (every commit should show `G`, never `N`).
If a commit lands as `N` (no signature), stop and fix the git config before
proceeding.

**Pull requests**

All changes to `main` go through a PR — including solo-maintainer changes.
Direct pushes to `main` are not permitted.

1. Branch from `main` with a descriptive name (`docs/contributor-workflow`,
   `rules/CL-0011-user-namespaces`, `fix/parser-merge-keys`).
2. Make small focused commits (above).
3. Run all four local checks (`ruff check`, `ruff format --check`, `mypy`,
   `pytest`) before pushing.
4. Open the PR and fill out `.github/pull_request_template.md`.
5. Wait for CI to go green.
6. Squash-merge. `main` stays linear with one commit per logical change; the
   full PR history is preserved on the PR page.

Keep PRs small. Don't mix refactors with behavior changes — land the refactor
first, then the behavior change, in separate PRs. The only exception is an
initial repo-setup PR that bootstraps interconnected files (templates, config,
docs) that only make sense together.

**Releases**

See [docs/RELEASING.md](docs/RELEASING.md). Do not cut a release without
working the checklist; in particular, the version string lives in *both*
`pyproject.toml` and `src/compose_lint/__init__.py`, and missing one is the
exact mistake the checklist exists to prevent.

## Code Standards

- **Type annotations**: All public functions must have type annotations. `mypy --strict` is enforced.
- **No unnecessary dependencies**: PyYAML is the only runtime dependency. Dev dependencies (ruff, mypy, pytest) go in optional `[dev]` extras.
- **Latest stable versions**: When any dependency, library, package, base image, or tool must be used, always use the latest stable version unless there is a specific, documented reason not to (e.g., known incompatibility, alpha/beta status). If the latest stable version cannot be used, state why.
- **Rules receive plain Python types**: Never leak parser-specific types (ruamel, etc.) into rule code. Rules work on `dict`, `list`, `str`, `int`, `bool`.
- **Test coverage**: Every rule needs positive and negative test cases. Target 100% rule coverage.
- **Python 3.10+ compatibility**: Do not use syntax or stdlib features added after 3.10 (e.g., no `type` aliases from 3.12, no `ExceptionGroup` from 3.11 without checking availability).

## CI/CD

- **CI**: GitHub Actions -- ruff + mypy + pytest on every PR (`ci.yml`)
- **Publishing**: GitHub Actions trusted publisher to PyPI on release tag (`publish.yml`)
- **Pre-commit**: `.pre-commit-hooks.yaml` for pre-commit framework integration

### Publishing security

- **Trusted Publishers only**: All real PyPI releases must go through GitHub Actions OIDC
  trusted publishing. No manual `twine upload` to real PyPI. This eliminates stored API
  tokens entirely — GitHub Actions authenticates directly with PyPI via OIDC, tied to
  a specific repo + workflow + branch.
- **Sigstore attestations**: The `publish.yml` workflow must enable build attestations
  via the `pypa/gh-action-pypi-publish` action's `attestations: true` flag. This gives
  users cryptographic proof the package was built from this repo.
- **2FA required**: PyPI and TestPyPI accounts must have 2FA enabled.
- **Project-scoped tokens only**: If API tokens are ever used (e.g., TestPyPI name
  reservation), they must be scoped to the `compose-lint` project, never account-wide.
  Delete tokens after one-off use.

### Dependency pinning

Anything that resolves over the network at build, test, or release
time must be pinned to an immutable ref. Mutable refs (tags,
version ranges, `latest`) trust the upstream author to never
repoint them and make every CI run a roll of the dice. Pin at
rest; let Renovate or Dependabot bump the pin.

The rule has five sub-cases with different conventions. They're
all the same principle — pin what you can — but the mechanics
differ.

#### 1. GitHub Actions workflows

**Every** `uses:` reference in `.github/workflows/*.yml` must be
pinned to a full commit SHA, with the tag in a trailing comment so a
human can still read the version. No first-party carve-out:
`actions/checkout`, `actions/setup-python`, `github/codeql-action`,
and every other `actions/*` / `github/*` action pins to a SHA, same
as third-party actions. Self-references like `tmatens/compose-lint`
pin to a SHA too.

```yaml
- uses: owner/repo@0123456789abcdef0123456789abcdef01234567 # v1.2.3
```

- **Get the SHA from the ref:** `git rev-parse vX.Y.Z^{commit}` for
  tags you control, or resolve via the API for third-party actions:
  ```bash
  gh api repos/OWNER/REPO/git/ref/tags/vX.Y.Z -q .object.sha
  # if that returns a tag object (annotated tag), deref it:
  gh api repos/OWNER/REPO/git/tags/<that-sha> -q .object.sha
  ```
- **Keep the SHA and the `# vX.Y.Z` comment in sync.** Drift
  between the two is worse than no comment — the human reads the
  comment, the runner reads the SHA, and they should never
  disagree. Dependabot/Renovate PRs update both atomically.
- **The one legitimate exception** is `uses: ./` (a local composite
  action in this repo). That's a path, not a ref, and there is
  nothing to pin.
- **If a SHA pin is genuinely impossible for some other reason,
  leave an inline comment explaining why** — don't silently ship a
  tag pin. CodeQL's
  `workflow/third-party-action-not-pinned-to-commit-sha` rule
  enforces this for third-party actions, and Scorecard's
  `Pinned-Dependencies` check enforces it for first-party actions
  too.

The motivating rationale is supply-chain integrity: a tag pin
trusts the upstream author to never repoint the tag. The earlier
first-party exemption here relied on CodeQL's whitelist, but
Scorecard does not whitelist first-party actions, and uniformity
("pin everything you consume from a registry") is simpler than
maintaining a policy seam. Commit b59847c ("Pin third-party GitHub
Actions to commit SHAs") was the original precedent.

#### 2. Runtime dependencies (`pyproject.toml` `[project] dependencies`)

compose-lint is a **library** published to PyPI, not an application.
Library runtime deps use SemVer-compatible *ranges*, not exact
pins. Exact-pinning `PyYAML==6.0.3` would create a resolver
conflict for anyone who installs compose-lint alongside a different
PyYAML patch, which is exactly the pain library consumers feel
when careless upstream maintainers over-pin.

The rule for compose-lint:

- **Lower bound is the minimum version we've actually tested
  against.** Not a guess, not a copy from the package's README.
- **No upper bound unless we've observed a break.** A speculative
  upper cap (`<7`) locks consumers out of versions that may be
  fine; only add one after a concrete incompatibility.
- **Never use `*`, unpinned, or `latest`.** Those aren't ranges;
  they're abdication.

This is the one place the "pin everything" rule bends, and only
because the cost of over-pinning in a library is paid by every
downstream user.

#### 3. Development dependencies (`pyproject.toml` `[project.optional-dependencies.dev]`)

Dev deps (ruff, mypy, pytest, and anything else under `[dev]`) are
not consumer-visible, so the library-vs-app tension from (2) does
not apply. These should be pinned tightly enough that CI is
reproducible across days, ideally via a lockfile
(`uv.lock` or a `pip-compile`-generated `requirements-dev.txt`)
committed to the repo.

Short of a full lockfile, exact-pin each dev dep in
`pyproject.toml` (`ruff==X.Y.Z`, not `ruff>=X.Y`). The churn this
creates is absorbed by Renovate/Dependabot.

#### 4. CI tool installs (`pip install` inside workflows)

Any `pip install <pkg>` in a workflow `run:` block must pin the
package to an exact version:

```yaml
- run: pip install ruff==0.14.4     # good
- run: pip install ruff             # bad — resolves to whatever's newest
```

An unpinned `pip install ruff` reaches out to PyPI on every CI run
and can silently change behavior overnight when ruff cuts a new
release. The only safe default is an exact pin, bumped by
Renovate/Dependabot in a reviewable PR.

If the tool is already listed in `[project.optional-dependencies.dev]`
and the job runs `pip install -e ".[dev]"`, that's also fine — the
pin lives in `pyproject.toml` per (3). What's *not* fine is a
separate ad-hoc `pip install <pkg>` line inside the workflow with
no version.

#### 5. Docker base images

Not applicable to this repo today (compose-lint is a Python
package, no Dockerfile, no runtime images). If that ever changes,
base images get **digest-pinned**:

```dockerfile
FROM python:3.13-slim@sha256:<64-char-digest>
```

Tag-only references like `python:3.13-slim` are mutable — Docker
Hub repoints them on every patch rebuild — which defeats the
purpose. Digest pins + Renovate is the standard pattern.

### Package contents safety

Before any release, verify that the sdist and wheel contain only intended files:

```bash
tar tzf dist/*.tar.gz
unzip -l dist/*.whl
```

The following must **never** appear in published packages:

- `.env` or any secrets/credentials
- `.git/` directory
- `AGENTS.md` / `CLAUDE.md` or any agent/AI assistant configuration
- Memory files, session files, or IDE configuration
- Test fixtures (these belong in the sdist for `pytest` but not in the wheel)

Use `[tool.hatch.build.targets.wheel]` and `[tool.hatch.build.targets.sdist]` exclude
patterns in `pyproject.toml` if hatchling's default `.gitignore`-based exclusion is
insufficient.

## Things to avoid

- **No AI authorship attribution.** Contributions are attributed to their
  human author. Do not add `Co-Authored-By` trailers crediting AI tools,
  "Generated by"-style notices in code or comments, or "built with AI" badges
  on documentation. The human contributor is accountable for what they
  submit regardless of how it was produced; AI tools can't sign a CLA,
  respond to a security advisory, or be held liable for a regression. This
  rule is about *credit and accountability*, not about the word "AI"
  appearing — legitimate mentions in security rules, ADRs, or test fixtures
  are unaffected.
- Do not add runtime dependencies beyond PyYAML without discussion
- Do not use ruamel.yaml (see ADR-003 for rationale)
- Do not reuse or retire rule IDs -- CL-XXXX IDs are permanent
- Do not add rules without authoritative grounding (OWASP, CIS, Docker docs)
- Do not create findings that are not actionable -- if you can't tell the user exactly
  what to change, the finding is not ready
- Do not inflate severity -- match real-world exploitability and blast radius
- Do not add inline suppression syntax unless explicitly planned
- Do not reference private or internal-only tooling in any file -- if in
  doubt whether something belongs in a public repo, leave it out
- Do not ship anything that depends on a mutable ref. Workflows pin
  third-party `uses:` to a full commit SHA; dev deps and CI tool
  installs pin to exact versions; library runtime deps use SemVer
  ranges (never `latest` or unpinned); Docker base images pin by
  digest. See "Dependency pinning" under CI/CD for the full
  breakdown and the rationale for each sub-case.
