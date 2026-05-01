# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- New rule **CL-0020** — credential-shaped env keys with literal values.
  Flags `environment:` entries whose key matches a credential convention
  (`PASSWORD`, `TOKEN`, `SECRET`, `API_KEY`, `ACCESS_KEY`, `PRIVATE_KEY`,
  `CREDENTIAL`, plus suffix-anchored `_PASS`, `_PWD`, `PASSWD`, `_SALT`,
  `_DSN`) and whose value is a non-empty literal string. Exempts the
  `*_FILE` secrets-mount convention, `ALLOW_EMPTY_*` / `RANDOM_*`
  boolean toggles, and bool/numeric values. Skips `${VAR}` substitutions.
  Severity HIGH. Fires on 17.9% of real-world Compose files in the
  corpus. See [docs/rules/CL-0020.md](docs/rules/CL-0020.md). (#190)
- New rule **CL-0021** — credentials embedded in connection-string env
  values. Flags `environment:` values containing a literal
  `scheme://user:password@host` userinfo regardless of the key name.
  Skips when either userinfo half is a `${VAR}` substitution. Catches
  inline credentials in `DATABASE_URL`, `MONGO_URL`,
  `AIRFLOW__DATABASE__SQL_ALCHEMY_CONN`, etc. — the largest detection
  class CL-0020's key-pattern matching misses. Severity HIGH. See
  [docs/rules/CL-0021.md](docs/rules/CL-0021.md). (#193)
- Mutation testing via `mutmut` configured in `pyproject.toml` against
  `src/compose_lint/rules/` and `src/compose_lint/_image.py`. Baseline
  documented in `docs/mutation-testing.md`. New `tests/test_rule_loader.py`
  exercises rule auto-discovery so loader-logic mutants are caught. (#172)
- Corpus regression snapshot at `tests/corpus_snapshot.json.gz` plus
  `scripts/snapshot.py` (`generate` / `diff` / `verify` subcommands) that
  digests compose-lint output across a real-world Compose corpus into a
  `(rule_id, service, line)` fingerprint per file. A CI-gated schema test
  prevents the digest from accidentally carrying third-party content; an
  opt-in pytest entry (`COMPOSE_LINT_CORPUS=<cache-root>`) verifies the
  snapshot against the latest local run. See `LICENSE-corpus.md` for the
  licensing posture and `CONTRIBUTING.md` for the regen workflow. (#173)
- Negative-coverage fixtures (`tests/compose_files/safe_*.yml`) asserting that
  hardened-but-unusual Compose patterns do not trigger false positives:
  `cap_drop: [ALL]` + targeted `cap_add` for CL-0006/CL-0011, the short-form
  `no-new-privileges` security option for CL-0003, `CMD-SHELL` healthchecks
  for CL-0015, and named-volume mounts for CL-0017. (#174)

### Changed

- `CL-0005 _is_wildcard_ip` no longer carries an unreachable defensive
  branch for `[0.0.0.0]` / `[*]` — Docker doesn't accept those forms and
  no test exercised them. `[::]` continues to match via the wildcard set.
  (#172)
- Release docker-smoke jobs (`publish.yml`, `publish-channel.yml`) now
  exercise the image with the full hardening flag set documented in the
  README (`--read-only`, `--cap-drop ALL`, `--security-opt
  no-new-privileges:true`, `--network none`, `--user 65532:65532`,
  `--pids-limit 256`, plus `:ro` on bind mounts). A copy-paste regression
  in the documented recipe will now fail the release gate. (#196)
- README "Running with full hardening" snippet now uses
  `composelint/compose-lint:0.6.0` instead of the
  `composelint/compose-lint@sha256:<digest>` placeholder, so the recipe
  is copy-paste runnable. A new note points users at Docker Hub or
  `docker buildx imagetools inspect` if they want to substitute a digest
  pin for full CL-0004 / CL-0019 satisfaction. The new tag form is
  tracked as a fourth version sync point in `docs/RELEASING.md`.

## [0.6.0] - 2026-04-26

### Added

- `-v` / `--verbose` flag for the text formatter. Default text output now
  prints the fix block and reference URL only on the first occurrence of
  each rule id within a file; subsequent occurrences carry
  `(see fix above)` instead. `-v` restores today's per-finding fix
  repetition for IDE tooling or local fix-it-now workflows. JSON and
  SARIF output are unaffected. (#156)

### Changed

- Text formatter groups findings by service under a per-file header.
  Presence rules (e.g. CL-0001, CL-0002, CL-0005, CL-0019) render a
  one-line source excerpt under the finding so the offending value is
  visible inline. Pure-absence rules (CL-0003/4/6/7) skip the excerpt —
  the violation is the absence — and rely on the fix block to show the
  remediation. (#156)
- `docs/severity.md` now distinguishes "absence" rules (fire when a
  hardening directive is missing — high real-world hit rate) from
  "explicit-disable" rules (fire only when a service opts into a
  dangerous configuration — deliberately low hit rate by design). A
  zero-hit run on an explicit-disable rule is expected, not a bug. (#159)
- Multi-file invocations no longer fail-fast on the first parse error.
  The CLI now records the failure, continues scanning the remaining
  files, and exits 2 only after every input has been attempted. Per-file
  error messages include the filepath; the text-mode aggregate footer
  and verdict report how many files were skipped; SARIF output surfaces
  parse failures via `runs[].invocations[].toolExecutionNotifications`
  and sets `executionSuccessful: false`. A single-file invocation that
  fails to parse still exits 2 with the same `Error:` line. (#158)
- Compose v1 files (services declared at the top level) and structural
  fragments (files with only `volumes:` / `networks:` / `configs:` /
  `secrets:` / `x-*` keys) are now skipped with exit 0 and a per-file
  stderr note rather than hard-failing the whole invocation. The v1
  format was retired by Docker in 2023; fragments are typically merged
  with `-f overlay.yml` and not meaningful to lint in isolation.
  Genuinely unrecognised shapes still exit 2. Combined with the
  multi-file change above, `compose-lint **/*.yml` over a monorepo no
  longer dies on the first v1 file or overlay it encounters. See
  [ADR-013](docs/adr/013-missing-services-key.md). (#163)
- SARIF `result.fixes[]` removed in favor of `result.properties.fix`.
  SARIF 2.1.0 § 3.55 requires `artifactChanges` on every fix object,
  and compose-lint's `Finding.fix` is human-readable prose, not a
  machine-applicable patch — emitting `fixes[]` without `artifactChanges`
  produced documents that strict validators (`check-jsonschema`
  against the canonical OASIS schema) rejected. Lenient consumers
  reading `result.fixes[0].description.text` should switch to
  `result.properties.fix`. GitHub Code Scanning, Sonar, and other
  major consumers tolerated the missing field but the document was
  schema-invalid. (#168, fixes #166)

### Fixed

- Findings on YAML sequence items (e.g. one entry in `ports:`,
  `volumes:`, `cap_add:`, `devices:`, `security_opt:`) now report the
  line of the offending item, not the line of the parent mapping key.
  Previously every finding on a sequence item attributed to the parent
  key — three unbound ports all showed the `ports:` line, sensitive
  mounts pointed at `volumes:` instead of the mount itself. The parser
  now records per-item line numbers in `LineLoader` (sidecar keyed on
  `id(list)` on the loader instance, kept off the list itself to avoid
  changing list semantics), and `_collect_lines` emits `...[N]`
  entries. CL-0009, CL-0011, CL-0013, CL-0016, and CL-0017 were
  updated to consult the per-item entry with parent-key fallback;
  CL-0001 and CL-0005 already used this pattern and now resolve
  correctly. Fixes #157.
- `_collect_lines` no longer fans out `O(branching^depth)` across YAML
  alias graphs. Chained anchors (`b: {p: *a, q: *a, ...}; c: {p: *b,
  ...}; ...`) previously revisited the same container along every alias
  path; ClusterFuzzLite hit this with a sub-4KB input that grew RSS
  past 3 GB and OOMed the linter. Mirrors the `id()`-keyed visited-set
  pattern already in `_strip_lines`. The same input now completes in
  &lt;1 ms / 13 MB. (#161, fixes #154)

## [0.5.2] - 2026-04-25

### Fixed

- **CL-0009** now detects SELinux disabled via `security_opt:
  [label:disable]`. The rule's description and references promised
  SELinux coverage but the implementation only checked seccomp and
  AppArmor — `label:disable` turns off SELinux type enforcement for
  the container and was silently ignored. Description updated to
  reflect actual coverage; messages now read "SELinux" rather than
  "label profile". `label:user:...`, `label:type:...`, `label:role:...`
  and `label:level:...` overrides remain unflagged since they
  reconfigure rather than disable confinement.
- **CL-0004** and **CL-0019** now parse OCI image references via a
  shared `split_image_ref` helper that recognizes `registry:port/name`
  prefixes. The previous naive `image.rsplit(":", 1)` mistook the
  registry port for a tag separator, causing two related bugs:
  (a) `localhost:5000/foo` was treated as tag-pinned by CL-0004, so
  the "no tag, defaults to :latest" finding never fired; and
  (b) CL-0019 fired on the same input with a misleading message
  ("pinned to a tag but not a digest") for an image that had no tag at
  all. Verified for `localhost:5000/foo`, `localhost:5000/foo:latest`,
  `localhost:5000/foo:v1`, and digest variants of each.
- **CL-0005** now detects IPv6 wildcard binds in short syntax
  (`"[::]:8080:80"`) — the previous regex's IP capture group rejected
  any colon-containing prefix, causing the rule to silently skip the
  port. Bracketed IPv6 prefixes are now stripped before the main pattern
  runs.
- **CL-0005** now detects explicit wildcard `host_ip` values in long
  syntax (`host_ip: "0.0.0.0"`, `host_ip: "::"`). The previous
  implementation treated *any* non-empty `host_ip` as a real bind, so
  operators who explicitly wildcarded their long-syntax bind got no
  warning. Loopback (`127.0.0.1`, `::1`) and specific addresses still
  suppress the finding.
- **CL-0005** also detects IPv4 wildcard short syntax (`"0.0.0.0:8080:80"`)
  — incidental fix; the previous `_is_ip_address` helper accepted
  `0.0.0.0` as a "real" IP and suppressed the finding.
- **CL-0013** now detects mounting the entire host root filesystem
  (`"/:/host"`, `"/:/host:ro"`) at CRITICAL severity — previously the
  short-syntax regex required at least one non-colon character after `/`
  and silently skipped the most dangerous bind possible.
- **CL-0013** now detects long-syntax binds where `source:` is an absolute
  path even when `type: bind` is omitted. Compose infers bind mounts from
  absolute-path sources, but the rule previously gated on `type` and missed
  this realistic configuration.
- **CL-0013** sensitive-paths list extended with `/var/lib/docker`,
  `/var/run`, and `/home`. The existing `/root` entry already covered
  `/root/.ssh` and `/root/.aws` via subpath matching.
- **CL-0011** now flags `cap_add: [ALL]` (and lowercase `[all]`) at
  CRITICAL severity. Granting all Linux capabilities is functionally
  equivalent to `--privileged` for capability isolation, but the rule
  previously only knew the seven named caps and silently ignored the
  catch-all. Named caps (`SYS_ADMIN`, `NET_ADMIN`, etc.) continue to
  fire at HIGH; the rule now emits per-finding severity so `--fail-on`
  thresholds against the named caps are unchanged.
- **CL-0015** now flags `test: ["NONE"]` and the string form
  `test: NONE`, the idiomatic way to disable a healthcheck inherited
  from a base image. Lowercase `["none"]` deliberately does not fire
  — Docker's runtime treats only uppercase `NONE` as the disable
  sentinel; lowercase is executed as a command and is a different
  problem (a broken healthcheck, not a disabled one). Severity stays
  at LOW.
- **CL-0018** now detects the cross-spec root forms `root:0`, `0:root`,
  `root:1000`, and `0:1000` by parsing `user:` rather than matching a
  fixed allowlist. The previous `{"root", "0", "root:root", "0:0"}`
  set silently passed any value where a non-root group was paired with
  a root user, even though the container still runs as UID 0. The
  inverse (`user: "1000:0"` — non-root UID with root group) correctly
  does not fire.
- OpenVEX product identifier in `.vex/compose-lint.openvex.json` now uses
  `repository_url=index.docker.io/composelint/compose-lint`. The previous
  `docker.io/...` form loaded successfully but matched zero scanned
  images: Trivy, Grype (per anchore/grype#2818), and Scout all canonicalise
  Docker Hub to `index.docker.io` for VEX product matching. Confirmed
  locally with Trivy 0.70.0 against the published image.
- Every VEX statement now ships two `products[]` entries —
  `pkg:oci/compose-lint?repository_url=index.docker.io/composelint/compose-lint`
  for Trivy and Grype, plus a bare `pkg:docker/composelint/compose-lint`
  for Docker Scout, whose own "Create exceptions" docs example uses the
  `pkg:docker/` form. Trivy honoured the single-PURL form from PR #143
  but Scout did not — verified empirically on commit `5abd036`'s
  `scout-scan.yml` dispatch where `Loaded 1 VEX document` was followed
  by all three pip CVEs still flagged. OpenVEX explicitly invites
  multi-identifier products for exactly this scanner-disagreement case.
- Every `docker/scout-action` step that passes `vex-location` now passes
  `vex-author: .*`. Scout's default `--vex-author` allowlist is
  `<.*@docker.com>` and silently drops statements signed outside that
  pattern. PR #143's first override (`<.*@gmail\.com>`) was also
  silently dropped — Scout appears to use full-string regex match on
  the author field rather than substring, so the bracket-anchored shape
  did not match the full author string `Todd Matens <tmatens@gmail.com>`.
  `.*` accepts any author and is safe because the document is also
  cosign-attested to the image manifest. Applied to both `scout-scan.yml`
  steps and the `docker-smoke` Scout step in `publish.yml`.

### Added

- VEX statement covering CVE-2026-3219 (pip 25.1.1 — incorrect file
  installation due to improper archive handling). Same
  `vulnerable_code_not_present` mitigation as the existing pip CVEs:
  pip's runtime code is removed from the container image during build,
  only `.dist-info` metadata remains for SCA scanner identification.

### Changed

- VEX document `version` bumped to 3 and `timestamp` refreshed. See
  ADR-012 (`docs/adr/012-vex-product-identifier.md`) for the full
  rationale on the product-identifier and author-allowlist decisions,
  including the empirical evidence from PR #143's first attempt.

### Security

- CI `pip-audit` step ignores `CVE-2026-3219` (pip 26.0.1) until pip
  26.0.2+ ships on PyPI and the dev lockfile is regenerated. pip is a
  dev-only transitive of `pip-audit` here — it is not in
  `requirements.lock` and is stripped from the runtime container image
  (only `.dist-info` metadata is kept for SCA attribution). The same
  CVE is declared `not_affected` against the published image via the
  OpenVEX document on the same `vulnerable_code_not_present` grounds
  as the existing pip CVEs.

## [0.5.1] - 2026-04-24

### Changed

- Container image strips the `pip` package code and `pip` CLI binaries
  from the runtime venv but keeps pip's `.dist-info` metadata. 0.4.1
  stripped all of it to silence Docker Scout alerts on unreachable pip
  CVEs, but deleting the `.dist-info` also removed the signal SCA
  scanners use to identify pip — making the image appear vuln-free by
  metadata deletion rather than by code removal. Keeping the metadata
  while dropping the code gives honest reporting: scanners still see
  pip and flag CVE-2025-8869 / CVE-2026-1703, and the code that would
  host those CVEs is gone from the runtime layer. The CVEs also remain
  unreachable by execution path — distroless base, no shell, entrypoint
  is `/venv/bin/compose-lint`. The `activate*` shell-script stripping
  from 0.4.1 stays.

### Added

- OpenVEX document (`.vex/compose-lint.openvex.json`) published as a
  release asset alongside the SBOM, Sigstore bundles, and SLSA
  provenance, **and** attached to the container image manifest as a
  cosign in-toto attestation (predicate type `openvex`). Declares the
  known pip CVEs (CVE-2025-8869, CVE-2026-1703) as `not_affected`
  against the container image with justification
  `vulnerable_code_not_present`. Scanners invoked with `--vex` on the
  release asset, or attestation-aware scanners (Docker Scout; Trivy /
  Grype in attestation-discovery modes), render those CVEs as
  non-exploitable rather than either hiding pip or flagging reachable
  risk. New pip CVEs get added to the VEX when verified as covered by
  the same mitigation; CVEs in any actually-reachable code path do
  not.

## [0.5.0] - 2026-04-23

### Added

- `--explain CL-XXXX` prints the per-rule prose documentation
  (`docs/rules/CL-XXXX.md`) to stdout so reviewers can read the full
  rationale, references, and fix guidance without context-switching to
  the browser. Accepts any case, exits 2 on unknown or malformed rule
  ids, and refuses to run alongside FILE arguments. The rule-doc
  markdown ships inside the wheel under `compose_lint/rule_docs/`.

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
