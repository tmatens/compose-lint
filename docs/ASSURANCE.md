# Security Assurance Case

This document is the single-page assurance case for compose-lint: what it
defends, against whom, where the trust boundaries are, and which design
choices and tooling enforce each claim. It is the artifact the OpenSSF
Best Practices Silver `assurance_case` criterion asks for, and the doc to
read first if you are evaluating whether to depend on compose-lint in a
security-sensitive pipeline.

For the narrower question of *what compose-lint will and will not detect
in your Compose files*, see [SECURITY-EXPECTATIONS.md](SECURITY-EXPECTATIONS.md).
For the vulnerability-reporting process, see [SECURITY.md](../.github/SECURITY.md).

## What compose-lint is

compose-lint is a local static analyzer for Docker Compose files. A user
runs `compose-lint docker-compose.yml`; the tool reads the file, applies
a fixed set of rules, prints findings to stdout (text, JSON, or SARIF),
and exits 0 / 1 / 2. It does not connect to a network, does not modify
its inputs, and does not run as a daemon.

## Trust boundaries

```
┌──────────────────────┐                ┌──────────────────────┐
│  UNTRUSTED INPUT     │   safe-load    │   TRUSTED CORE       │
│  - Compose YAML file │ ─────────────▶ │   - Parser (engine)  │
│  - Config YAML file  │                │   - Rule predicates  │
│  - CLI args          │                │   - Formatters       │
└──────────────────────┘                └──────────┬───────────┘
                                                   │
                                                   │  text / JSON / SARIF
                                                   ▼
                                        ┌──────────────────────┐
                                        │  TRUSTED OUTPUT      │
                                        │  - stdout / stderr   │
                                        │  - exit code         │
                                        └──────────────────────┘
```

There is exactly one untrusted boundary: the YAML and config files the
user hands the tool, plus CLI argument strings. Everything else — the
Python interpreter, the venv, the rule implementations, the runtime
image — is trusted by construction (pinned, signed, reproducible).

There is no network input, no credential store, no multi-tenant mode,
and no privileged escalation surface. The runtime image has no shell,
no package manager, and runs as UID 65532.

## Threat model

The realistic adversary is **a malicious or carelessly authored Compose
file** reaching `compose-lint`. The user has chosen to run the tool
against it; the file came from a repo, a PR, a CI job, or a pasted
snippet.

| # | Attacker goal                                                   | Mechanism                                                       | Mitigation                                                                                                       |
|---|-----------------------------------------------------------------|-----------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| 1 | Execute attacker code in the linter process                     | YAML deserialization gadget; embedded Python tag                | All YAML is parsed via `yaml.SafeLoader` (compose) or `yaml.safe_load` (config). No `yaml.load`, no `eval`/`exec` on parsed values. Custom `LineLoader` is asserted to subclass `SafeLoader` at import time. |
| 2 | Crash the linter or hang it indefinitely                        | Pathological YAML structures (deep nesting, billion-laughs)     | Parser traversals are iterative, not recursive (fix for #61). Continuous fuzzing on parser + engine via ClusterFuzzLite (`cflite-pr.yml` per-PR, `cflite-batch.yml` weekly).                |
| 3 | Cause a false negative — slip a real misconfig past the linter  | Hardened-but-unusual syntax, alternate-form constructs          | Every rule ships positive *and* negative tests; `tests/compose_files/safe_*.yml` enforces hardened-but-unusual fixtures (CONTRIBUTING.md §"Adding a new rule"). Corpus snapshot (`tests/corpus_snapshot.json.gz`) locks output across 1,500+ real-world Compose files; PRs that change findings show the diff. Rule-loader test catches mutation-untested code paths via `mutmut`. |
| 4 | Cause a false positive — make the linter fail benign files      | Adjacent-but-clean configs (named volumes, sub-form syntax)     | Same negative-test discipline as #3, plus the corpus snapshot regression gate.                                    |
| 5 | Exfiltrate data from the linter or its host                     | Make the linter open a network connection                       | Product code performs no network I/O. Documented hardened `docker run` recipe pins `--network none` and is exercised in CI (`docker-smoke` matrix).                                            |
| 6 | Compromise the linter via a poisoned dependency                 | Tampered package on PyPI                                         | All deps and dev-tools are hash-pinned in `requirements*.lock`; CI installs with `pip install --require-hashes`. Renovate updates lockfiles weekly; `pip-audit`, `dependency-review`, and OpenSSF Scorecard run continuously.   |
| 7 | Substitute a malicious build of compose-lint downstream         | Tampered wheel or container image post-publish                  | PyPI dists are Sigstore-signed (PEP 740 attestations + GitHub Release `.sigstore.json` bundles, post-release verified by `verify-release-signatures`). Container manifests are cosign-signed; SLSA build provenance attached to every artifact; SBOM (SPDX) and OpenVEX attested to images. |
| 8 | Compromise the runtime image                                    | Vulnerable shell / package manager / interpreter                 | Runtime image is `gcr.io/distroless/python3-debian13:nonroot` (no shell, no apt, UID 65532). Two-stage Dockerfile strips pip binaries from the runtime venv; only `.dist-info` is retained for SCA visibility. Documented hardened-run flags pin `--read-only --cap-drop ALL --security-opt no-new-privileges:true --user 65532:65532 --pids-limit 256`, all exercised in CI. See ADR-009. |
| 9 | Tamper with a release tag in transit                            | Push a malicious tag that triggers `publish.yml`                | `publish.yml` `verify-tag` requires the tag to be annotated (`git tag -s` produces this), reachable from `origin/main`, and (gated by `.github/allowed_signers`) cryptographically verified via `git verify-tag`. |

## Secure-design principles applied

- **Least privilege.** Distroless `:nonroot` runtime; documented hardened
  `docker run` flags; CI workflows declare `permissions: {}` at the
  workflow level and grant per-job scopes only.
- **Economy of mechanism.** PyYAML is the sole runtime dependency
  (CONTRIBUTING.md "Code standards"). The product is pure Python.
- **Fail-safe defaults.** `--fail-on high` is the default. Unknown YAML
  shapes exit 2 instead of being silently ignored. SafeLoader is the
  default — there is no unsafe-load path.
- **Defense in depth.** Image hardening *and* runtime-flag hardening
  *and* lint-time rule enforcement; a defect in any one layer does not
  remove the others.
- **Reproducibility.** Hash-pinned Python lockfiles, digest-pinned
  Docker base images, SHA-pinned third-party GitHub Actions. Renovate
  bumps the pins.
- **Tag-rooted provenance.** SSH-signed annotated git tags root the
  Sigstore attestation chain. The `verify-tag` job in `publish.yml`
  refuses to publish from anything else.

## Implementation-weakness coverage

Common Python-level weakness classes and their mitigations:

| Weakness class                                       | Mitigation                                                                  |
|------------------------------------------------------|------------------------------------------------------------------------------|
| Unsafe deserialization (CWE-502)                     | `yaml.SafeLoader` everywhere; custom loader asserts subclass at import time. |
| Command injection / shell-out (CWE-78, CWE-77)       | Product code calls no subprocess, no `os.system`. Bandit enforces.           |
| Path traversal on input (CWE-22)                     | All file paths are user-supplied targets; the tool only *reads* them. No path is constructed from untrusted YAML content. |
| Resource exhaustion (CWE-400)                        | Iterative parser traversals; ClusterFuzzLite runs as a continuous gate.     |
| Type confusion in rule predicates                    | `mypy --strict` on every commit; rules receive plain types only (AGENTS.md). |
| Logic bug in a rule (false negative or positive)     | Per-rule positive + negative + hardened-but-unusual fixtures; corpus snapshot regression gate; mutation testing on rule predicates via `mutmut`. |
| Outdated dependency with known CVE                   | `pip-audit`, `dependency-review`, Renovate weekly; OpenVEX document for stripped-component CVEs (ADR-012). |
| Tampered release artifact                            | Sigstore + cosign + SLSA provenance + SBOM + post-release `verify-release-signatures` job. |

## Continuous-assurance tooling

Every claim above is enforced by automation that runs without human
prompting:

- **CI gate (every PR + push)**: `ruff`, `ruff format --check`,
  `mypy src/`, `pytest` matrix on Python 3.10–3.14, `bandit`,
  `pip-audit`, `actionlint`, `dependency-review`, `dockerfile-digests`
  manifest-list check, `docker-smoke` (clean fixture exits 0, insecure
  fixture exits 1, SARIF is valid JSON), `action-smoke`, DCO trailer
  check, no-AI-attribution check, version-string consistency,
  CHANGELOG-bump gate.
- **Static analysis**: CodeQL (security-and-quality queries) on push,
  PR, and weekly schedule; Bandit per push.
- **Fuzzing**: ClusterFuzzLite per-PR (`cflite-pr.yml`) and weekly
  batch (`cflite-batch.yml`) against the parser and engine.
- **Supply-chain scoring**: OpenSSF Scorecard on push and weekly.
- **Release-time gates** (`publish.yml`): annotated-tag check, tag-
  reachable-from-main check, SSH tag-signature verification (via
  `.github/allowed_signers`), TestPyPI smoke, multi-arch Docker smoke
  under hardened flags, manual `release-gate` approval, post-release
  Sigstore identity verification, cosign signature verification on the
  pushed manifest, version-matches-tag verification on the published
  image.

## Out-of-scope concerns

The following are not within compose-lint's assurance perimeter:

- **The Compose file's runtime behavior.** compose-lint statically
  analyzes the YAML; it does not start containers. Runtime exploits
  rooted in image contents, network policy, or kernel CVEs are out of
  scope.
- **Image-content vulnerabilities.** Pair compose-lint with Trivy or
  Docker Scout for image CVE scanning.
- **Dockerfile lint.** Pair with Hadolint.
- **Compose schema validity.** Pair with dclint. compose-lint flags
  insecure configurations *that are valid YAML*; it does not gate on
  Compose schema correctness.
- **Multi-tenant or service-mode operation.** compose-lint runs
  per-invocation as a CLI; there is no daemon, queue, or shared
  process state.

These boundaries are restated in [SECURITY-EXPECTATIONS.md](SECURITY-EXPECTATIONS.md)
in user-facing language.

## Maintenance and review

This assurance case is reviewed each MINOR release (per
[docs/RELEASING.md](RELEASING.md)). If a release adds a new attack
surface — a network call, a new untrusted-input source, a new
dependency, a runtime mode — the corresponding row in the threat-model
table must be updated in the same PR. CHANGELOG entries with a
`Security` heading should reference the row they relate to.

The single-maintainer continuity question (what happens if the
maintainer is unavailable) is addressed in
[docs/CONTINUITY.md](CONTINUITY.md).
