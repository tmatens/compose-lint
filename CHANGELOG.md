# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-10

First public release.

### Added

- 10 security rules grounded in OWASP Docker Security Cheat Sheet and the CIS
  Docker Benchmark:
  - **CL-0001**: Docker socket mounted (CRITICAL)
  - **CL-0002**: Privileged mode enabled (CRITICAL)
  - **CL-0003**: Privilege escalation not blocked (MEDIUM)
  - **CL-0004**: Image not pinned to version (MEDIUM)
  - **CL-0005**: Ports bound to all interfaces (HIGH)
  - **CL-0006**: No capability restrictions (MEDIUM)
  - **CL-0007**: Filesystem not read-only (MEDIUM)
  - **CL-0008**: Host network mode (HIGH)
  - **CL-0009**: Security profile disabled (HIGH)
  - **CL-0010**: Host namespace sharing (HIGH)
- CVSS-aligned severity model with a documented scoring matrix (`docs/severity.md`).
- Output formatters: `text` (colored, with fix guidance and references), `json`
  (for CI integration), and `sarif` (SARIF 2.1.0, for GitHub Code Scanning).
- GitHub Action (`tmatens/compose-lint@v0.2.0`) with optional SARIF upload to the
  Code Scanning tab.
- Auto-discovery of `compose.yml` / `docker-compose.yml` (and their `.yaml` /
  `.override.*` variants) when no file arguments are given.
- Configuration via `.compose-lint.yml`: disable rules, override severity, record
  an exception `reason` that flows through to all output formats.
- Suppressed-finding reporting with `--skip-suppressed` to hide them from output.
- Documented exit code contract (0 = clean, 1 = findings at/above threshold,
  2 = usage error) and `--fail-on` flag to set the threshold.
- Pre-commit hook support via `.pre-commit-hooks.yaml`.
- Python 3.10–3.13 support.

### Security

- PyPI releases use Trusted Publishing (OIDC) with Sigstore build attestations.
  No long-lived API tokens.
- TestPyPI publish gates the real PyPI publish — a TestPyPI failure aborts the
  release before a version number is burned on the real index.
- Supply chain hardening: CodeQL (python + actions), OpenSSF Scorecard, Bandit,
  pip-audit, and Dependabot all run on every push and weekly.
- GitHub Actions workflows are pinned, scoped to least-privilege permissions, and
  use `persist-credentials: false` on checkout. The composite action passes user
  inputs through `env:` rather than direct `${{ }}` interpolation to prevent
  shell injection.

[0.2.0]: https://github.com/tmatens/compose-lint/releases/tag/v0.2.0
