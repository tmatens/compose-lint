# compose-lint

Security-focused linter for Docker Compose files. Python >=3.11, PyYAML only runtime dep, MIT license.

## Architecture

- **Parser**: `LineLoader(yaml.SafeLoader)` captures line numbers. `load_compose(path) -> (data, lines)`. Handles v2/v3, anchors, merge keys (`<<:`), extension fields (`x-`). Normalizes `${VAR:-default}` document-wide to the value Compose ships with no `.env`, so rules classify what is deployed; a reference with no default (`${VAR}`) is left as written. Validates `services:` exists and is a mapping. Does NOT do full Compose schema validation.
- **Rules**: Classes inheriting `BaseRule`, registered via `@register_rule`. IDs are `CL-XXXX`, zero-padded. They are permanent and never reused. The pre-1.0 reclamation window (a rule that should not have shipped could be removed and its id left fallow) closed with ADR-028, which records a keep/remove disposition for every rule; CL-0012, CL-0015 and CL-0023 are fallow forever (`tests/test_rule_surfaces.py`). A rule now leaves only through the deprecation lifecycle in `docs/compatibility.md`. Rules receive plain Python types (`dict`, `list`, `str`, `int`, `bool`), never parser-specific types.
- **Findings**: Dataclasses in `models.py`, not dicts.
- **Formatters**: Modules in `formatters/` exposing `format(findings) -> str`.
- **Engine**: `engine.py` runs rules, collects results, applies config overrides.

## Severity

CRITICAL > HIGH > MEDIUM > LOW. A rule's severity is **derived**, not chosen: it is what the two-axis matrix in `docs/severity.md` produces for the rule's cell, under a stated attacker baseline and the grounded Docker posture (ADR-020). Shipping a different number is legal only as a declared override from the closed reason list, with a link — `tests/test_severity_matrix.py` fails otherwise. Evaluating cells until one yields the number you expected is the documented failure mode the model exists to prevent, so if the result disagrees with instinct, fix an axis definition or file an override rather than trying a different cell.

## Exit codes

- 0: No findings at/above threshold
- 1: Findings at/above threshold
- 2: Usage error (bad args, file not found, invalid Compose) **or a coverage gap** — unresolved `include:` / cross-file `extends:`, where part of the stack was never linted. `--allow-partial-coverage` downgrades the gap to a stderr warning. `fix` reports gaps but never fails on them; it is not the gate.
- Default threshold: HIGH. Configurable via `--fail-on`.

## CLI output

Stdout carries data (findings in `check`; future artifacts in operations like `fix` or `completion`). Stderr carries human status and errors. Today's text-mode banner, per-file summary, aggregate summary, and verdict are the exception — gated on `output_format == "text"` in `cli.py` so JSON/SARIF redirects stay clean. When a second stdout-emitting mode lands, decide in that feature's ADR whether to extend the gate or move human-status lines to stderr permanently. `--explain` pages through `$PAGER` on a TTY only (ADR-034); piped output is byte-identical to a pagerless run.

## Config file (`.compose-lint.yml`)

Disables still produce suppressed findings. `reason` flows to `suppression_reason` (JSON), `justification` (SARIF), or after `SUPPRESSED` (text). No inline suppression comments.

## Quality checks

`ruff check src/ tests/`, `ruff format --check src/ tests/`, `mypy src/` (strict), `pytest`. All four must pass, scoped exactly as written — CI lints only `src/` and `tests/`, and a bare `ruff check` also sweeps `scripts/`, which has known, accepted violations. CI test matrix: Python 3.11–3.14 on ubuntu-24.04.

Running a branch's tests from a `git worktree` needs `PYTHONPATH` pointed at that worktree's `src/`. The dev install is editable and resolves `compose_lint` to the **main checkout's** `src/`, so a bare `pytest` in a worktree grades the branch's tests against `main`'s source and fails in exactly the way a genuinely broken change would. Confirm with `python -c 'import compose_lint; print(compose_lint.__file__)'` before believing a red run.

## Adding a rule

See CONTRIBUTING.md for the full checklist. Every rule must cite OWASP, CIS, or Docker docs **that demonstrate the need in a container context** — generic host/Linux hardening a container's defaults already neutralize is not enough (see CL-0022/CL-0023). If a container-context source is thin, the rule's premise must be **validated at runtime**: a rule that describes container runtime state gets a check in `scripts/validate_rule_premises.py`, which proves the insecure state is Docker's *default* (for absence rules) or that the flagged config produces the insecure behavior (for presence rules). That suite runs in CI (`rule-premises` job), and asserts the daemon is at Docker's defaults before measuring — a premise measured on a departed posture cannot ground a rule. Every finding must be actionable with specific fix guidance.

A new rule also needs its derivation block (with an **Evidence** line naming the premise check or captured observation), a row in `docs/severity.md`'s assignment table, a listing on the README/`docs/index.md`/mkdocs-nav surfaces, and an ATT&CK mapping in `src/compose_lint/attack.py` or a recorded reason none fits. Each is enforced by a test.

## Contributor workflow

CONTRIBUTING.md is the source of truth for commits, signing, and PRs. Key points:
- One logical change per commit, imperative subject under 72 chars, no Conventional Commits prefixes
- All commits signed (SSH). Verify with `git log --format='%h %G? %s'` — every commit shows `G`
- All changes go through a PR, squash-merge to main
- Maintainer side of an outside contribution — approving fork CI, review states, pre-merge checks — is `docs/MAINTAINING.md`
- Releases: follow `docs/RELEASING.md` checklist — version lives in both `pyproject.toml` and `src/compose_lint/__init__.py`

## Rule docs (docs/rules/)

- H1 format: `# CL-XXXX: <directive> — <symptom phrasing>` (query-phrased, id first).
  The docs-site `<title>` comes from the matching nav label in `mkdocs.yml` — keep
  both in sync. `tests/test_cli.py` pins CL-0003's H1; update it if that changes.
- "Reading the failure" symptom tables quote **verbatim, live-captured** error
  strings. Busybox wordings must be re-proven by a mapping check in
  `scripts/validate_rule_premises.py` (see the ADR-016 amendment); other wordings
  (coreutils/bash/application) are captured-but-not-asserted and labeled as such.
  Mechanism claims are observed against a live container, never reasoned from docs.
- **Never add front matter** to any `docs/*.md` — `--explain` prints files raw.
- The docs site builds from `docs/` on every main push (`docs` workflow →
  GitHub Pages). `docs/google*.html` is the Search Console verification file and
  must stay in place permanently.

## Dependency pinning

Pin everything to an immutable ref. Renovate bumps the pins.

- **GitHub Actions**: SHA-pin every `uses:` (including first-party). Tag in trailing comment. Only exception: `uses: ./`.
- **Runtime deps**: SemVer ranges (this is a library — exact pins break downstream resolvers). Lower bound = tested minimum. No upper bound unless we've observed a break.
- **Dev deps + CI installs**: Hash-pinned lockfiles. Every `pip install` in CI uses `pip install --require-hashes -r requirements{,-dev}.lock`. No ad-hoc `pip install pkg==X.Y.Z` in workflows. One exception: `python -m pip install --upgrade pip` bootstrap in security-scan job.
- **Docker base images**: Digest-pin if we ever add a Dockerfile.

### Regenerating lockfiles

```bash
uv pip compile pyproject.toml \
  --universal --python-version=3.11 \
  --generate-hashes --output-file=requirements.lock

uv pip compile pyproject.toml \
  --extra=dev --extra=lint --extra=security --extra=publish \
  --universal --python-version=3.11 \
  --generate-hashes --output-file=requirements-dev.lock

uv pip compile pyproject.toml --extra=container \
  --universal --python-version=3.11 \
  --generate-hashes --output-file=requirements-build.lock

uv pip compile pyproject.toml --extra=docs \
  --universal --python-version=3.11 \
  --generate-hashes --output-file=requirements-docs.lock
```

`--python-version=3.11` matches `requires-python` so backport deps for older matrix legs are included. Commit lockfiles and `pyproject.toml` together.

Use the `=`/`--output-file=` flag form (not `--extra dev` / `-o`). Renovate's
`pip-compile` manager parses the `uv` command recorded in each lock's header to
manage its pins; it only accepts the equals/long-flag form and silently skips a
lockfile whose header uses space-separated `--extra`/`--python-version` or the
short `-o`, leaving those pins unmanaged (they then drift from `pyproject.toml`
until caught by pip-audit). It does not yet understand `--universal`, but that
is non-fatal — it's ignored, and extraction still succeeds.

## Publishing

Trusted Publishers (OIDC) only — no manual `twine upload`. Sigstore attestations enabled. Wheel must not contain `.env`, `.git/`, `AGENTS.md`, `CLAUDE.md`, memory/session/IDE files.

## Docs surfaces

`docs/dockerhub-overview.md` is the Docker Hub description — hard 25000-byte cap (CI-enforced by the `readme-size` job; Docker Hub 400s over it) and deliberately free of version pins so it never needs a per-release bump. `README.md` is GitHub/PyPI-facing, not synced anywhere, and has no byte cap — but its integration snippets carry version pins that the RELEASING.md checklist bumps each release (as does `docs/hardening.md`).

Prose that states how many rules there are is a different kind of pin: it goes stale when a rule lands, not when a version ships, so no release checklist catches it. Four surfaces make that claim and `tests/test_rule_surfaces.py` holds all four to the registry count.

## Things to avoid

- No AI authorship attribution (no `Co-Authored-By` for AI, no "Generated by" notices, no "built with AI" badges)
- No runtime deps beyond PyYAML without discussion
- No ruamel.yaml (see ADR-003)
- No reusing or retiring rule IDs — the pre-1.0 reclamation window is closed (ADR-028); removal goes through the deprecation lifecycle
- No rules without authoritative grounding
- No unactionable findings
- No inline suppression syntax unless explicitly planned
- No private/internal tooling references in a public repo
- No mutable refs in CI (see pinning section above)
