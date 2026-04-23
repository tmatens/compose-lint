# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2026-04-23

### Security

- Container image no longer ships `pip` or its `dist-info`. `pip` was
  only used at build time against `--require-hashes` lockfiles and was
  unreachable at runtime (distroless, no shell, nonroot entrypoint),
  but its presence in the runtime layer surfaced ongoing Docker Scout
  alerts (CVE-2025-8869, CVE-2026-1703 against pip 25.1.1) and would
  have generated more on every future pip CVE. The runtime venv now
  contains only PyYAML, compose_lint, and the Python interpreter
  symlinks; image drops ~17 MB. (#116)

### Fixed

- `parser.load_compose` now wraps `RecursionError` as `ComposeError`.
  PyYAML's composer is recursive; deeply-nested flow input like
  `[[[[...]]]]` exhausted the interpreter stack from inside `yaml.load`
  and raised `RecursionError` — a `RuntimeError`, not a `YAMLError` —
  bypassing the existing wrapper and crashing the CLI with an unhandled
  exception instead of returning exit code 2. Surfaced by ClusterFuzzLite
  (#114). (#115)

### Added

- SLSA build provenance attestations on PyPI sdist + wheel and the
  Docker image, providing verifiable supply-chain proof that release
  artifacts were built from this repository's tagged source. (#107)

## [0.4.0] - 2026-04-19

### Added

- Per-service rule exclusions in `.compose-lint.yml`. A rule's
  `exclude_services` key accepts either a mapping (service name →
  reason) or a list of service names. Excluded services still produce
  findings marked suppressed, with the per-service reason flowing to
  `suppression_reason` (JSON), SARIF `justification`, and the text
  formatter's `SUPPRESSED` trailer. Global `enabled: false` takes
  precedence over per-service exclusions. Unknown service names in
  `exclude_services` warn on stderr rather than erroring. Closes #5.
  See [ADR-010](docs/adr/010-per-service-rule-overrides.md).

### Changed

- v0.4 roadmap repointed from Linux package distribution to
  configuration depth and a Homebrew tap. ADR-008 deferred: no
  demand signal, and GitHub-Releases-hosted `.deb`/`.rpm` have
  strictly worse upgrade UX than pip/Docker without hosted-repo
  infrastructure.

## [0.3.7] - 2026-04-18

### Changed

- CL-0003 fix guidance now warns that `no-new-privileges` breaks
  images whose entrypoint switches users via `gosu`/`su-exec` (e.g.
  official `postgres`, `redis`, `minecraft-server`). The finding's
  `fix` field gains a one-line caveat; full compatibility notes and
  a testing workflow live in `docs/rules/CL-0003.md`. Closes #2.
- CL-0007 fix guidance now describes the writable-path discovery
  workflow (`docker diff`) and the chown-on-startup pitfall seen on
  `netdata` and `valkey`. The finding's `fix` field gains a one-line
  caveat; details live in `docs/rules/CL-0007.md`. Closes #3.

No rule logic, severity, or finding-shape changes. A compose file
that passed on 0.3.6 passes identically on this revision; only the
`fix` field text and rule docs changed.

## [0.3.6] - 2026-04-18

### Fixed

- Dockerfile `FROM` lines now pin the multi-arch OCI image index
  (manifest list) digest instead of the per-arch amd64 manifest
  digest. The 0.3.5 per-arch pins resolved correctly during the
  single-arch `docker-smoke` but failed in `docker-publish`'s arm64
  leg because the pinned digest referenced an amd64-only manifest.

### Changed

- `docker-smoke` in `publish.yml` now runs as a native-runner matrix
  across `linux/amd64` (`ubuntu-latest`) and `linux/arm64`
  (`ubuntu-24.04-arm`). Each leg builds the image without QEMU
  emulation and runs the full fixture battery (version check, clean,
  insecure, SARIF). Multi-arch regressions — per-arch digest pins,
  native-wheel mismatches, future base-image surprises — now fail
  the release-gate instead of surfacing mid-release during the
  production Docker Hub push.
- New `ci.yml` job `dockerfile-digests` runs
  `scripts/verify-dockerfile-digests.sh` on every PR. The script
  HEADs each `FROM ...@sha256:` in the Dockerfile and fails if the
  `Content-Type` is not an OCI image index or Docker manifest list
  — catching the per-arch-pin mistake at review time rather than
  release time. No image pulls; ~1s total.

No CLI, config, or finding-shape changes. Exit codes (0/1/2) are
preserved. A Compose file that passed on 0.3.5 passes identically on
0.3.6.

## [0.3.5] - 2026-04-17

### Changed

- Runtime Docker image switched from `python:3.13-alpine` to
  `gcr.io/distroless/python3-debian13:nonroot`. The image no longer
  ships `/bin/sh`, `apk`, or busybox — only the Python interpreter,
  stdlib, libc, and the project venv. Attack surface in the event of
  a container escape is significantly reduced. See
  [ADR-009](docs/adr/009-runtime-base-image.md) for the rationale.
- `docker run` examples in the README now show `--read-only --cap-drop
  ALL --security-opt no-new-privileges --network none` with a
  read-only mount, modelling the least-privilege posture the linter
  itself recommends. The simpler form still works.

### Fixed

- Parser post-YAML traversals (`_collect_lines`, `_strip_lines`) no
  longer recurse one Python frame per nesting level, so pathologically-
  deep input raises `ComposeError` (or lints cleanly) instead of
  crashing with an uncaught `RecursionError`. Found by ClusterFuzzLite.

### Security

- Dockerfile sets `USER 65532:65532` explicitly at the runtime stage.
  Distroless `:nonroot` already enforces this; the redundancy survives
  a future base-image swap that might not default to nonroot.

No CLI, config, or finding-shape changes. Exit codes (0/1/2) are
preserved. A Compose file that passed on 0.3.4 passes identically on
0.3.5.

## [0.3.4] - 2026-04-13

### Changed

- Text output now opens with a branded one-line header showing the tool
  version and active parameters (`files`, `config`, `fail-on`) so runs are
  self-describing in CI logs.
- Severity labels in findings are padded to 8 chars so rule IDs line up
  across `MEDIUM`, `HIGH`, `CRITICAL`, and `LOW` rows.
- "No issues found" message is now green instead of dim gray.
- Multi-file text runs end with an aggregate `N files scanned · N issues
  (...)` line.
- Every text run ends with an explicit verdict relative to `--fail-on`:
  `✓ PASS · threshold: high` or `✗ FAIL · N findings at or above high`.
- Suppressed counts are separated from the severity breakdown and labeled
  `(not counted)` so the severity totals reconcile at a glance.

JSON and SARIF output shapes are unchanged. Exit codes (0/1/2) are
preserved.

## [0.3.3] - 2026-04-12

### Added

- Docker Hub image (`composelint/compose-lint`) — multi-stage build on
  `python:3.13-alpine`, multi-arch (`linux/amd64`, `linux/arm64`), runs as
  non-root, signed with cosign (Sigstore keyless).
- Docker usage section in README.
- README rules table now lists all 19 rules (CL-0011–CL-0019 were missing).
- Automated TestPyPI smoke test in publish workflow — installs from TestPyPI,
  verifies `--version`, runs fixture tests. Real PyPI publish is gated on it.
- Automated post-push verification in Docker publish workflow — pulls by
  digest, verifies cosign signature, checks version output.

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

[0.3.6]: https://github.com/tmatens/compose-lint/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/tmatens/compose-lint/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/tmatens/compose-lint/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/tmatens/compose-lint/compare/v0.3.0...v0.3.3
[0.3.0]: https://github.com/tmatens/compose-lint/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tmatens/compose-lint/releases/tag/v0.2.0
