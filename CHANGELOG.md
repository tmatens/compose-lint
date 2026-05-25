# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0] - 2026-05-25

### Added

- The `fix` subcommand is promoted out of experimental and onto the documented,
  SemVer-covered surface (ADR-014, Phase 3). It now lists in `compose-lint
  --help` and has a README section. Behavior is unchanged: dry-run by default
  (prints a unified diff, writes nothing), `--apply` writes fixes in place via
  an atomic swap, `--only CL-XXXX` scopes to named rules, suppressed findings
  are never touched, and every apply is guarded by a re-parse plus a
  verify-apply pass that refuses to write anything that wouldn't re-lint clean.
  Promotion follows a full-corpus soak over ~6.4k real Compose files with zero
  re-parse failures, zero non-idempotent fixes, and zero new findings
  introduced.

### Changed

- Structured SARIF `fixes[]` (machine-applicable `artifactChanges`, which GitHub
  Code Scanning renders as suggested changes) now ship unconditionally in
  `check --format sarif`. They were previously gated behind
  `COMPOSE_LINT_EXPERIMENTAL=1`; that environment variable is now a no-op.
- `fix` no longer prints a per-invocation "experimental" warning to stderr — it
  is part of the stability contract from this release.

## [0.10.0] - 2026-05-25

### Added

- SARIF results now carry a stable `partialFingerprints` value
  (`composeLintFinding/v1`). GitHub Code Scanning uses it to deduplicate
  uploads and track an alert across commits; without it, direct SARIF uploads
  produced duplicate alerts and lost continuity when code moved. The digest is
  derived from the finding's logical identity (file, rule, service, message) and
  deliberately excludes the line number, so an alert survives unrelated line
  shifts. Additive to the SARIF contract (ADR-015). (#278)

### Security

- ClusterFuzzLite hygiene (issue #279). The `cflite-pr` and `cflite-batch`
  workflow checkouts now set `persist-credentials: false` like every other
  workflow, so the `GITHUB_TOKEN` is not left in `.git/config` while PR-author
  code runs during fuzzing. The fuzz image's `COPY .` no longer ingests
  `CLAUDE.md` / `AGENTS.md` — they are added to `.dockerignore`. (#279)

### Fixed

- Parser line-map robustness (issue #279 E2/E3). A service (or any key) named
  `__lines__` is no longer silently dropped: the loader's line map now hangs off
  a private non-string sentinel key instead of the literal string `"__lines__"`,
  so it can't collide with user data — a security linter must not skip a service.
  And a service that both defines a YAML anchor and is aliased elsewhere now
  resolves its own line: previously the alias and the anchor-definer shared one
  dict, and only whichever the traversal reached first got its keys recorded, so
  the other (often the definer — the most obvious location) reported `line=None`.
  Line numbers are now recorded per reachable path while the subtree is still
  walked once, so the chained-alias DoS guard (issue #154) is preserved. (#279)

- Documentation and grounding drift corrected (issue #279 D1–D6). OWASP
  renumbered the Docker Security Cheat Sheet and switched its anchors to a
  single-dash slug, so every citation was either pointing at the wrong rule or
  landing at page top. All OWASP deep links (rule docs, the README table, and
  the embedded `references=` URLs in code) now use the live single-dash anchors,
  and four drifted citations are corrected: CL-0002 and CL-0011 → Rule #3 (Limit
  capabilities, where `--privileged` is discussed), CL-0003 → Rule #4 (Prevent
  in-container privilege escalation), CL-0018 → Rule #2 (Set a user), CL-0020 and
  CL-0021 → Rule #12 (Utilize Docker Secrets). CL-0002's finding message no
  longer overclaims "functionally equivalent to host root" — it now matches the
  doc's "trivially escapable to host root." The CL-0018 doc now reflects that
  the rule fires on any root *user portion* regardless of group (`root:1000`),
  and the CL-0015 doc now documents the `test: ["NONE"]` branch the code already
  implements. (#279)

- Rule coverage gaps closed (issue #279 R3/R4/R5). CL-0001 now flags any
  container-runtime control socket — `containerd.sock`, `crio.sock`, and
  `podman.sock` in addition to `docker.sock` (podman/crio were caught by no
  rule before); the rule is retitled "Container runtime socket mounted" and its
  message names the runtime. CL-0020 adds `PASSPHRASE` and `ENCRYPTION_KEY` to
  the credential-key list (a generic `_KEY` suffix is deliberately not matched
  — it false-positives on `LICENSE_KEY` etc.). CL-0011 adds the `SYS_BOOT`,
  `DAC_OVERRIDE`, and `BPF` capabilities; CL-0016 adds the `/dev/fuse` and
  `/dev/kmsg` devices. (#279)

- SARIF rule descriptors are now correct in three ways. `helpUri` is set only
  to a reference that is actually a URI — rules grounded in a CIS benchmark
  (CL-0012, CL-0015, CL-0016, CL-0017) emitted the benchmark *prose* as
  `helpUri`, which SARIF 2.1.0 declares `"format": "uri"` and strict validators
  / GitHub Code Scanning reject; the prose still appears in `help.text`. A
  config `severity:` override now reaches `defaultConfiguration.level` and
  `properties.security-severity` on the rule descriptor, not just the per-result
  `level` — GitHub derives an alert's severity column from the rule, so an
  override to e.g. `critical` no longer showed Medium while JSON and SARIF
  disagreed. And a finding's structured `fixes[]` are matched to the finding by
  logical identity (rule, line, service, message) rather than `id()`, so a
  future refactor that copies findings can't silently drop every fix. (#279)

- A rule that raises no longer aborts the entire run. Previously an uncaught
  exception from any rule escaped as a traceback and exited 1 —
  indistinguishable from a normal "findings at/above threshold" result, and in a
  directory sweep every remaining file was lost. The engine now isolates each
  rule per service: a failure is reported to stderr and the run continues, and
  the CLI maps it to exit 2 ("compose-lint itself couldn't run", ADR-006) so a
  crash is never mistaken for a clean lint failure. (#279)

- CL-0005 now flags a bare short-syntax port with no colon (`"3000"`, `3001`, a
  `"3000-3005"` range). Docker still publishes it — `docker compose up` assigns a
  random (ephemeral) host port bound to all interfaces (`0.0.0.0` and `[::]`) —
  so it is the same exposure class the rule targets, and it is the most common
  port form in real homelab files. The finding notes the host port is ephemeral
  and the guidance binds it to localhost with `127.0.0.1::<port>`. The in-scalar
  autofixer refuses this form (it can't synthesize the empty-host-port syntax).
  (#279)

- CL-0021 now flags a password-only userinfo (`scheme://:password@host`). The
  regex required a non-empty username, but RFC 3986 §3.2.1 permits an empty one
  and `redis://:password@host` is the standard Redis URL form. The
  password-is-a-`$VAR` skip is unchanged. (#279)

- `.compose-lint.yml` no longer silently ignores misconfiguration that would
  leave a security control at its default. An unknown rule id (a typo'd
  `CL-001` or a retired `CL-9999`), an unrecognized top-level key (a misplaced
  `fail_on:`), or an unknown per-rule key (`severty:`) now prints a stderr
  warning instead of being dropped — mirroring the existing unknown-service
  warning. And `enabled` must be a real boolean: a quoted `'false'` or a `0` is
  now a hard error (exit 2) rather than a silent no-op that left the rule
  running while the user believed it off. (YAML's bare `false`/`no`/`off` still
  parse to a real boolean and work.) (#279)

- Text output: the `SUPPRESSED` marker no longer pushes a suppressed finding's
  rule and message columns out of alignment — the severity column is padded to
  fit the marker so every row lines up. CL-0020 and CL-0021 (credential-shaped
  env keys and inline connection-string credentials) now render the source
  excerpt and underline like the other value-naming rules; they had been left
  out of the presence-rule set. `FORCE_COLOR=0`/`false` (case-insensitive) now
  disables color and any other set value — including the empty string — enables
  it, matching the chalk/supports-color convention (previously `FORCE_COLOR=false`
  turned color *on*). The excerpt underline now matches the value at a token
  boundary and measures display width (East-Asian wide and combining characters),
  so it no longer mis-points on a value that is a substring of a longer token or
  contains CJK/accented characters. (#278)

- SARIF no longer emits a misleading `ruleIndex` for an unregistered rule.
  `ruleIndex` defaulted to `0`, so a result whose rule was absent from the
  registry pointed at the first rule (CL-0001) while `ruleId` named the real one
  — a SARIF §3.52.5 contradiction. It is now emitted only when the rule is in
  the registry. A result with an unknown or non-positive line likewise omits its
  `region` instead of fabricating `startLine: 1`, which had mislocated the alert
  at the top of the file. (#278)
- SARIF `$schema` now points at the canonical, immutable OASIS errata01 URL
  (`docs.oasis-open.org/.../sarif-schema-2.1.0.json`) instead of a
  `raw.githubusercontent.com` `main`-branch link — the schema's own `$id`, and
  no longer a mutable ref. (#278)

- SARIF `artifactLocation.uri` is now a conformant, GitHub-resolvable URI
  reference. Paths were emitted verbatim, so an absolute path would not resolve
  on GitHub Code Scanning and a space or non-ASCII byte
  (`/tmp/my dir/café.yml`) was not a legal RFC-3986 URI reference at all. Files
  under the working directory are now emitted as percent-encoded repo-relative
  paths tagged with a `SRCROOT` `uriBaseId`, declared once per run in
  `originalUriBaseIds` alongside `invocations[].workingDirectory`; out-of-tree
  paths fall back to an absolute, percent-encoded `file:` URI. (#278)

- JSON output now emits `service` as a string and never emits bare `NaN`/
  `Infinity`. A service name is a YAML mapping key, so a key like `true`, a bare
  number, or `.nan` resolved to a non-string scalar: `.nan` produced invalid
  JSON (`"service": NaN`, which RFC 8259 forbids) while `true`/`123` produced a
  wrongly-typed `service` field (ADR-015 contracts it as a string). The formatter
  now coerces `service` to `str`, and both the JSON and SARIF dumps use
  `allow_nan=False` so a stray non-finite float raises instead of writing invalid
  JSON. (#278)

- Duplicate mapping keys are now rejected with a parse error, matching Docker
  (which refuses them). Previously PyYAML silently let the last value win, so a
  service with `privileged: true` followed by `privileged: false` — a file
  Docker will not load — reported clean, and the line map pointed at the wrong
  occurrence. Detection runs before merge-key (`<<`) flattening, so an
  `extends`/anchor merge that overrides an inherited key is not misreported as a
  duplicate. (#277)

- CL-0011 now flags `CAP_`-prefixed capabilities (`CAP_SYS_ADMIN`, `CAP_ALL`,
  ...). Docker treats the `CAP_` prefix as optional, but the rule keyed on the
  bare name and missed the prefixed form entirely. (#277)
- CL-0017 now flags `rshared` mount propagation in both short and long syntax,
  not just `shared`. `rshared` is the recursive — and more common — form that
  still propagates container mounts to the host. (#277)
- CL-0005 now evaluates the bind-address slot when the host port is a `${VAR}`
  substitution (`${HOSTPORT}:80`). Previously a var-valued host port failed the
  port pattern and the whole entry was skipped, hiding a wildcard publish. (#277)
- CL-0021 now flags an inline connection-string credential when the username is
  a `${VAR}` but the password is a literal (`postgres://${DB_USER}:secret@db`).
  Only a var-valued *password* means the secret is parameterized. (#277)
- CL-0020 now flags an unquoted numeric credential value (`DB_PASSWORD:
  12345678`). The value decodes to an int and was skipped; it is coerced to its
  string form before the checks, while YAML boolean toggles stay exempt. (#277)

- `security_opt` directives are now matched with their `=` separator treated as
  equivalent to `:`, the way Docker accepts them. CL-0009 was missing an
  `=`-form profile disable (`seccomp=unconfined`, `label=disable`) and CL-0003
  was firing on a service already hardened with `no-new-privileges=true`. A
  shared `normalize_security_opt` helper canonicalizes the separator (and case)
  before every membership/prefix check across the rules and the fix engine.
  (#277)
- CL-0005 no longer misses short-syntax ports whose host and container sides are
  both `<= 59` (`22:22`, `25:25`, `53:53`, ...). PyYAML's YAML 1.1 resolvers
  parsed these as a single base-60 integer (`22:22` → `1342`), so the rule's
  `str(port)` saw no colon and reported the file clean. `LineLoader` now drops
  the sexagesimal `int`/`float` resolver alternatives and the `timestamp`
  resolver (a bare date like `2024-01-01` was becoming a non-JSON-serializable
  `datetime.date`), while keeping YAML 1.1 booleans — Docker coerces
  `yes`/`no`/`on`/`off` to booleans for boolean-typed fields, so keeping them
  preserves CL-0002/CL-0007 parity with `docker compose config`. (#277)
- Compose override-file tags `!reset` and `!override` no longer make a valid
  file fail to parse (exit 2). `LineLoader` (a `SafeLoader` subclass) had no
  constructor for them, so it raised a `ConstructorError`; it now constructs the
  underlying value and ignores the merge directive, which is all the linter
  needs. (#277)
- A non-UTF-8 (e.g. latin-1) file now raises a per-file `ComposeError` instead
  of an uncaught `UnicodeDecodeError`. Previously one bad-encoding file aborted
  an entire directory sweep. (#277)
- The `fix` engine no longer adds `no-new-privileges:true` to either side of an
  `extends` relationship. Docker concatenates list fields like `security_opt`
  across an `extends` merge, so adding the entry to a service that `extends:`
  another — or to a base another service extends — could produce a duplicated
  item that `docker compose config` rejects. The duplicate only exists after
  Docker's merge (our parser does not resolve `extends`), so the post-apply
  reparse guard could not catch it. Both the per-finding CL-0003 fixer and the
  CL-0003/CL-0009 coordination pass now refuse both sides and leave the chain
  for manual review. (#276, #277)

## [0.9.0] - 2026-05-24

### Added

- **Experimental `fix` subcommand** (ADR-014) that auto-remediates the
  mechanically-safe findings — CL-0003, CL-0005, CL-0007, CL-0009,
  CL-0014, and CL-0015. Dry-run by default (prints a unified diff and
  flags behavior-changing edits); `--apply` writes fixes in place;
  `--only` restricts to named rules; `.compose-lint.yml` suppressions are
  honored; and SARIF output can carry the edits as `fixes[]`. It is
  reachable without `COMPOSE_LINT_EXPERIMENTAL` but stays hidden from
  `--help`, prints an experimental warning on every run, and is excluded
  from the SemVer contract until promoted.
  (#246, #247, #250, #251, #253, #255, #260, #263, #264, #265, #266,
  #267, #268, #269, #270)
- `check` as an explicit subcommand, with the CLI routed through argparse
  subcommands; bare `compose-lint <file>` still works as an implicit
  `check`, and `--explain CL-XXXX` prints a rule's documentation
  (ADR-011). (#248)
- `skip-suppressed`, `quiet`, and `verbose` inputs on the GitHub Action,
  mirroring the CLI flags. (#258)
- A published compatibility and stability policy
  (`docs/compatibility.md`) documenting what SemVer does and does not
  cover, including the JSON `version` field. (#254)

### Changed

- **Breaking (JSON consumers):** `--format json` is now a versioned
  envelope — an object with `version`, `tool`, `findings`, and `errors`
  — instead of a bare findings array. Read findings from `.findings`, and
  `.version` for the schema (ADR-015). (#252)
- `--explain` is rejected when combined with `--format json` or
  `--format sarif`, which produced meaningless output. (#257)
- CIS Docker Benchmark rule citations re-grounded to v1.7.0 and
  corrected — e.g. CL-0015 now cites 5.26 (was 5.27) and CL-0019 drops a
  miscited 5.27. (#249, #256)

## [0.8.0] - 2026-05-23

### Added

- Full *State of Docker Compose Security* report content in
  `docs/state-of-compose.md` — an empirical study of security
  misconfigurations across a 6,444-file corpus of public Compose files,
  with per-tier SVG charts in `docs/assets/` generated by
  `scripts/corpus/charts.py` (new maintainer-only `[corpus]` extra). The
  README hero stat now cites the corpus headline and links to the report.
- A recorded terminal demo (GIF) in the README hero, regenerated
  deterministically from `scripts/demo/`. (#235)
- `-q` / `--quiet` text mode: one line per finding, dropping the fix
  block, reference URL, source excerpt, and suppression reason. The
  inverse of `-v`, and mutually exclusive with it. (#239)
- `NO_COLOR` and `FORCE_COLOR` are honored: `NO_COLOR` disables color
  even on a terminal, `FORCE_COLOR` forces it through a pipe (e.g. into a
  pager or an ANSI-rendering CI log). (#239)
- `--help` now lists the valid `--fail-on` values
  (`{low,medium,high,critical}`) instead of a bare `FAIL_ON`. (#239)

### Changed

- Text output readability (no change to JSON or SARIF): findings now
  render highest-severity first within each service; a column header
  labels the `line / severity / rule / message` columns; the offending
  value is marked with a severity-colored box-drawing underline instead
  of a red caret; parse failures (exit 2) show a distinct `⚠ ERROR`
  verdict rather than the `✗ FAIL` used for threshold breaches (exit 1);
  and a passing run names its sub-threshold findings
  (`✓ PASS · threshold: critical · below: 1 high, 15 medium`). (#239)

### Fixed

- Text-mode stdout is flushed so the header and findings can no longer
  appear after stderr when both streams are captured together (`2>&1`),
  which scrambled combined CI logs. (#239)
- The aggregate summary pluralizes correctly: `1 file scanned`, not
  `1 files scanned`. (#239)

## [0.7.1] - 2026-05-21

### Added

- `GOVERNANCE.md`, `MAINTAINERS.md`, `docs/ASSURANCE.md`,
  `docs/SECURITY-EXPECTATIONS.md`, and `docs/CONTINUITY.md` documenting
  the project's governance model, single-page assurance case (threat
  model, trust boundaries, mitigations), user-facing security promises,
  and continuity-of-access plan. Closes the OpenSSF Silver
  `governance`, `roles_responsibilities`, `documentation_security`,
  `assurance_case`, and `access_continuity` criteria. (#202)
- Statement coverage gate at >=80% (new `coverage` CI job; thresholds
  configured in `pyproject.toml [tool.coverage.report]` and duplicated
  at the workflow level). Closes the OpenSSF Silver
  `test_statement_coverage80` criterion. (#202)
- `docs/state-of-compose.md` canonical landing page for the forthcoming
  State of Compose security report. README and corpus tooling already
  reference this path. (#210)

### Changed

- Corpus pipeline scripts (`fetch`, `retier`, `enrich`, `run`, and the
  per-tier fetchers) now live in-repo under `scripts/corpus/` so the
  State of Compose numbers are reproducible from a clean checkout. The
  corpus cache stays at `~/.cache/compose-lint-corpus/` and remains
  outside git — the repo never accumulates third-party Compose files.
  (#206)
- Corpus pipeline now classifies parse-error stderr into stable buckets
  (`missing-services-key`, `services-not-mapping`, `service-not-mapping`,
  `top-level-not-mapping`, `empty-file`, `invalid-yaml`, `other`) and
  emits a per-tier × class matrix alongside the existing rule tables.
  `scripts/corpus/README.md` documents the longtail sampling design and
  its four known biases (GH-search ranking, single-source, filename-
  pinned, public-only). (#209)

### Security

- Release tags must now cryptographically verify against
  `.github/allowed_signers` before any publish step runs. The new third
  check in `publish.yml`'s `verify-tag` job runs `git verify-tag` with
  the maintainer's authorized SSH signing key; an attacker who pushed
  a tag from a stolen GitHub credential can no longer trigger a
  release. Closes the OpenSSF Silver `version_tags_signed` criterion.
  (#202)
- Dropped `--ignore-vuln CVE-2026-3219` from CI `pip-audit`. pip 26.1.1
  fixes both CVE-2026-3219 and CVE-2026-6357; `pip-audit --skip-editable`
  against the regenerated `requirements-dev.lock` reports no known
  vulnerabilities. pip is dev-only here (transitive of `pip-audit`) and
  is stripped from the runtime container image; the OpenVEX statements
  for the published image are unaffected. (#208)
- Dockerfile build stage now upgrades the venv-seeded pip to the latest
  release before stripping pip's code from the runtime image. The
  retained `.dist-info` metadata now reports a patched version, so
  Docker Scout reports genuine remediation (not just `not_affected`)
  for CVE-2025-8869, CVE-2026-1703, and CVE-2026-6357. CVE-2026-3219
  has no upstream fix and stays VEX-covered. (#217)
- OpenVEX document (v4) adds a fourth `not_affected` statement covering
  CVE-2026-6357 with the same `vulnerable_code_not_present`
  justification used for the other pip CVEs, and drops the `@25.1.1`
  pin from every pip subcomponent PURL. The mitigation is
  version-independent — pip's executable code is removed at build time
  regardless of which pip the build seeds — so the statements continue
  matching after the bundled-pip upgrade in #217. (#216)
- urllib3 bumped to 2.7.0 in `requirements-dev.lock` for CVE-2026-44431
  and CVE-2026-44432. urllib3 is a transitive dev/publish dependency
  only (via `id`, `requests`, `tuf`, `twine`); the runtime package
  depends only on PyYAML, so published-package users are unaffected.
  (#214)
- idna bumped to 3.15 in `requirements-dev.lock` for CVE-2026-45409,
  and `pip-audit` now ignores the disputed `PYSEC-2025-183` advisory
  against pyjwt 2.12.1 (the pyjwt maintainers dispute it because JWT
  signing key length is chosen by the consuming application, not the
  library; no fix version exists). Both packages are dev/publish
  transitives; the runtime image is unaffected. (#224)

## [0.7.0] - 2026-05-01

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

[Unreleased]: https://github.com/tmatens/compose-lint/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/tmatens/compose-lint/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/tmatens/compose-lint/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/tmatens/compose-lint/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/tmatens/compose-lint/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/tmatens/compose-lint/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/tmatens/compose-lint/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/tmatens/compose-lint/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/tmatens/compose-lint/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/tmatens/compose-lint/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/tmatens/compose-lint/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/tmatens/compose-lint/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/tmatens/compose-lint/compare/v0.3.7...v0.4.0
[0.3.7]: https://github.com/tmatens/compose-lint/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/tmatens/compose-lint/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/tmatens/compose-lint/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/tmatens/compose-lint/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/tmatens/compose-lint/compare/v0.3.0...v0.3.3
[0.3.0]: https://github.com/tmatens/compose-lint/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tmatens/compose-lint/releases/tag/v0.2.0
