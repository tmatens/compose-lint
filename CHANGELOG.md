# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-04-12

### Added

- 9 new security rules, bringing the total to 19:
  - **CL-0011**: Dangerous capabilities added — `cap_add` with SYS_ADMIN,
    SYS_PTRACE, NET_ADMIN, SYS_MODULE, SYS_RAWIO, SYS_TIME, or
    DAC_READ_SEARCH (HIGH)
  - **CL-0012**: PIDs cgroup limit disabled — `pids_limit: 0` or `-1` (MEDIUM)
  - **CL-0013**: Sensitive host paths mounted — bind mounts of `/etc`, `/proc`,
    `/sys`, `/boot`, or `/root` in short or long syntax (HIGH)
  - **CL-0014**: Logging driver disabled — `logging.driver: none` (MEDIUM)
  - **CL-0015**: Healthcheck disabled — `healthcheck.disable: true` (LOW)
  - **CL-0016**: Dangerous host devices exposed — `/dev/mem`, `/dev/kmem`,
    `/dev/port`, `/dev/sd*`, `/dev/nvme*`, `/dev/disk/*` (HIGH)
  - **CL-0017**: Shared mount propagation — `:shared` suffix or
    `bind.propagation: shared` (MEDIUM)
  - **CL-0018**: Explicit root user — `user: root` or `user: "0"` overrides
    image USER instruction (MEDIUM)
  - **CL-0019**: Image tag without digest — version tag present but no
    `@sha256:` pin; non-overlapping with CL-0004 (MEDIUM)

### Changed

- **CL-0010** now also detects `uts: host` (CIS 5.21 — sharing the host's UTS
  namespace lets a container change the host's hostname).

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

[0.3.0]: https://github.com/tmatens/compose-lint/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tmatens/compose-lint/releases/tag/v0.2.0
