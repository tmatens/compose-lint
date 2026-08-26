# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.25.0] - 2026-08-26


### Added

- **CL-0025 now grades a writable bind of the host's module and library tree**
  ([ADR-033](docs/adr/033-library-tree-is-root-equivalent-by-containment.md),
  the disposition #737 deferred). `/lib/modules` and `/usr/lib/modules` are
  matched by descent — everything below is a file the host kernel loads by
  name, as root, on demand, so a replaced module is kernel-mode code on the
  host with no capability needed. `/usr/lib`, `/lib` and `/lib64` are matched
  exactly, the `/var/lib` mechanism: `systemd/system` and `ld.so` sit below
  them, but so do `python3`, `node_modules` and `jvm`. Measured on Docker
  29.7.2 at defaults, unprivileged: every path accepted a write through an rw
  bind and refused it through an ro bind, and module lookup works through
  `:ro`. New premise check `_cl0025_module_tree` plants a file in the running
  kernel's module directory, observes it from a second container and removes
  it; the kernel is never asked to load it. Same cell as `/etc`: Direct × Host,
  CRITICAL, no override.

  On the corpus this is **7 new CRITICAL findings, all WireGuard / strongSwan
  services** binding `/lib/modules` without `:ro`. They are true positives
  with a one-token fix — the container only reads module files — so the
  finding's fix text leads with `:ro` rather than "remove the mount", and the
  read-only form `/lib/modules:/lib/modules:ro` is clean under every rule (the
  tree is world-readable by design, so it is exempt from CL-0013 too, as the
  executable tree is). `/usr/lib/systemd` and the multiarch library
  directories are recorded as real grants with no corpus incidence, not
  matched by descent yet.

- **CL-0025 now grades a writable bind of the host's executable tree**
  ([#737](https://github.com/tmatens/compose-lint/issues/737)). `/usr/bin`,
  `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/bin` and `/sbin` are
  matched by descent — `/usr/bin/docker:/usr/bin/docker`, the corpus idiom for
  driving the host's CLI, counts — and bare `/usr` is matched exactly, the
  `/var/lib` mechanism: it is root-equivalent for what it *contains*, and by
  descent it would also have priced `/usr/src`, `/usr/share/zoneinfo` and
  site-packages as host root (6 of the 27 writable `/usr`-family binds in the
  corpus, 22%). Both spellings are listed because matching is lexical on what
  the document wrote, while Docker resolves the merged-`/usr` symlink at mount
  time. Measured on two hosts at Docker defaults, unprivileged: each member
  accepted a write through an rw bind and refused it through an ro bind, and a
  root-owned `755` file planted through `-v /usr` into `/usr/local/bin` — ahead
  of `/usr/bin` on root's `PATH`, so nothing need be overwritten — was on the
  host afterwards. New premise check `_cl0025_exec_tree` plants, observes from
  a second container, and removes it. Same cell as `/etc`: Direct × Host,
  CRITICAL, no override. On the corpus this is 20 new CRITICAL findings.

  Two boundaries recorded rather than guessed: a **read-only** bind of the
  executable tree is exempt from CL-0013 as well — every file in it is
  world-readable by design, so `:ro` discloses nothing (the timezone-file shape,
  one tier up); and the **library tree** (`/usr/lib`, `/lib/modules`) is
  deferred to an ADR, because by descent it would sweep `/usr/lib/python3` and
  the standard `/lib/modules` bind of every VPN workload, and the corpus holds
  nothing else to shape a narrower match on.
- **A host file handed over through `secrets:` or `configs:` `file:` is now a
  bind mount to every mount rule**
  ([#736](https://github.com/tmatens/compose-lint/issues/736)). Outside swarm,
  `secrets: dsock: file: /var/run/docker.sock` is a read-only bind of that host
  file at `/run/secrets/dsock` — measured on Docker 29.7.2 / Compose 5.4.0: the
  container saw the host inode, the daemon answered through the secret, and the
  write stayed refused even with `mode: 0666`. Neither channel was read by any
  mount rule, so a service could hand itself the Docker socket and pass
  CL-0001 clean. `iter_bind_mounts` now yields each referenced `file:` entry
  as a read-only bind (`BindMount.origin` names the channel), so the existing
  partition grades it without a new rule: a socket or socket directory is
  CL-0001 CRITICAL, a root-equivalent or credential path is CL-0013's read-only
  disclosure at HIGH, and CL-0025 never applies because the channel cannot be
  writable. A project-relative `file: ./secrets/…` — the CL-0020 remediation —
  is not a host path and is not graded, matching the line `volumes:` draws;
  `external: true` and `environment:`-sourced entries have no host path. New
  premise check `_cl0001_secret_socket` drives `docker compose` and asserts
  both `ro` and a live daemon through the secret. Corpus: 73 `file:` entries,
  none absolute, so no existing finding changes.

- **Three bump classes the judgment-call cheat sheet did not price**
  ([docs/RELEASING.md](docs/RELEASING.md#judgment-call-cheat-sheet)). The
  sharpest is a rule's **evidence** derivation: it never appears in text output
  so it reads as an implementation detail, but it is the input to the SARIF
  `partialFingerprints` digest — the *identity* of a Code Scanning alert
  ([ADR-024](docs/adr/024-finding-identity-is-not-prose.md)). Change one and
  every existing alert for that rule closes as "fixed" while the same findings
  reopen as new, with no field renamed and no shape moved. No document assigned
  it a bump class; it is a MINOR, announced under `Changed`, and
  `docs/compatibility.md` gains an *Alert identity* section saying so in
  user-facing terms. The other two: retiring a rule admitted on *judgment*
  (new in this release, and previously harder to remove than a grounded rule),
  and amending the policy itself — ADR-030's
  clarification/tightening/loosening ladder governs every other row in the
  table but was only findable in prose elsewhere.


- **A test gates the `Development Status` classifier against the major
  version.** `docs/RELEASING.md` says to flip `4 - Beta` to
  `5 - Production/Stable` in the same commit that sets `version = "1.0.0"`, but
  nothing enforced it — the classifier was referenced nowhere in `tests/`,
  `scripts/` or the workflows. PyPI metadata is immutable per version, so a
  missed flip would have published 1.0.0 permanently labelled Beta with 1.0.1
  as the only remedy.
- **`x-` prefixed top-level keys are accepted in `.compose-lint.yml`.** Compose's
  extension-field convention, already honoured in the documents compose-lint
  lints. It is the other half of merge-key support — a `<<:` needs an anchor to
  merge *from*, and the idiomatic place to hold one is a top-level `x-` block,
  which previously warned and, under `--strict-config`, failed the run. Because
  `x-` is a deliberate marker it costs no typo detection: a mistyped `rulez:`
  still warns.

### Changed

- **A rule admitted on judgment may be withdrawn on judgment**
  ([ADR-032](docs/adr/032-rule-retirement-is-minor-with-lifecycle.md)
  condition 1, widened). ADR-032 made retirement MINOR only where evidence
  refutes the rule's premise. CL-0014's premise *holds* — `docker logs` under
  `driver: none` really does fail — so that bar could never be met for it, and
  the thin part is its grounding, which is a different defect. The effect was
  that a rule the project itself declines to ground was *harder* to remove than
  one that is grounded and later refuted, which is backwards; dropping it would
  have cost a MAJOR. The exception reaches only rules
  [ADR-028](docs/adr/028-pre-1.0-rule-id-sweep.md) records as admitted on
  judgment — a set closed at the 1.0 sweep, currently `{CL-0014}` — so "evidence,
  not preference" is unchanged for every rule admitted on evidence. Withdrawal
  still needs its own ADR and still runs the full deprecation lifecycle. Landed
  before the tag because the direction only goes one way: admitting this ground
  later is a loosening and costs a MAJOR, while removing it later is a
  tightening and costs a MINOR.

- **JSON `file` and `line` now name the same document, and the envelope is
  schema `"2"`.** `file` had always named the document being *graded* while
  `line` indexed wherever the evidence actually came from, so on a merged run
  (default since [ADR-025](docs/adr/025-lint-the-merged-configuration.md)) or
  one reading an `env_file:` (default since
  [ADR-027](docs/adr/027-grade-env-file-where-the-document-routes-it.md)) the
  pair named a real line of the *wrong file* — an overlay's CL-0002 was
  reported at the base file's line 3, which is its `image:` key. SARIF was
  already corrected this way after the same mismatch made Code Scanning
  annotate an unrelated line of the base file; JSON was the last format
  emitting an incoherent pair. `file` now names the document the evidence is
  in, the graded document moved to the new conditional `graded_file`, and
  `source_file` stays as a deprecated alias for consumers written against
  schema 1. **This is a breaking change to a required field**, which is why it
  ships before the 1.0 freeze — after the tag the same correction would be a
  MAJOR. ADR-015 and `docs/configuration.md` now document the complete emitted
  field list, including `severity_overridden_from` and the closed `severity`
  set, neither of which the frozen contract had named.


### Fixed

- **`fix --only` now normalizes case and reports an id that names no rule.**
  `--only cl-0014` — the correct id, lower-cased — matched nothing, printed
  "nothing to fix" and exited 0, which is indistinguishable from a clean repo;
  so did `--only CL-9999` and `--only banana`. A CI remediation step pinned to a
  typo therefore went green forever. `--explain` already normalized case, so one
  CLI was answering the same input two different ways. An id that matches no
  rule is now a `Warning:` naming it, promoted to an error by `--strict-config`
  — the same treatment an unknown rule id in `.compose-lint.yml` already gets.

- **`fix --apply` on a read-only file is now exit 2, not exit 0.** The three
  sibling write refusals — a symlink target, a hard link, an unwritable
  directory — all report exit 2, as does `init --force` on the same predicate.
  Only this case reported success, so the documented Docker recipe
  (`docker run -v "$(pwd):/src" … fix --apply`, where the image runs as UID
  65532) wrote nothing and told a gate it had succeeded.
- **`compose-lint init` no longer writes a config `check` then refuses.** A
  service named `no`, `yes`, `on`, `123`, `1.5` or `null` was emitted unquoted:
  the plain-scalar pattern said the *characters* were safe, but YAML 1.1
  resolves those *tokens* to booleans, ints and None, and `config.py` requires
  `exclude_services` keys to be strings. `init` reported success and the next
  `check` in that directory exited 2 until someone hand-edited the file — the
  exact failure the emitter's own docstring says it exists to prevent, arriving
  through the token rather than the characters. A candidate is now emitted
  unquoted only if PyYAML reloads it as the same string.

- **A `<<:` merge key in `.compose-lint.yml` no longer aborts the run.** The
  config loader called `construct_object` on every key node and PyYAML has no
  constructor for the merge tag, so a config using YAML's own merge syntax died
  with `could not determine a constructor for the tag 'tag:yaml.org,2002:merge'`
  and named no fix. `parser.py` already skipped the tag for Compose documents,
  so `<<:` was legal in the file being linted and fatal in the config beside it.

- **`--format json` and `--format sarif` now emit a document for every exit-2
  path.** "No Compose files found" and a missing `--config` exited before any
  formatter ran, producing **zero bytes** on stdout — while a missing file, a
  parse error and a directory argument all produced a full envelope. A `jq`
  pipeline therefore broke or not depending on which kind of exit 2 it hit, and
  both silent cases are the commonest CI misconfigurations: the wrong working
  directory and a typo'd config path.


- **Four published claims corrected to match what the tool does.** Under
  [ADR-030](docs/adr/030-the-policy-is-part-of-the-contract.md) the policy is
  part of the frozen contract, so a claim that is wrong at the tag is expensive
  to walk back later. `docs/ASSURANCE.md` said compose-lint "does not modify
  its inputs" — `fix --apply` has rewritten files in place since 0.11.0 — and
  its CWE-22 row said "the tool only *reads* them" and "No path is constructed
  from untrusted YAML content", when `env_file:` targets and `COMPOSE_FILE`
  entries are exactly that (ADR-026, ADR-027); the row now describes both path
  classes and the two containment gates that guard the document-supplied one.
  `docs/compatibility.md` promised a config naming a retired rule ID "keeps
  working, `--strict-config` included"; it loads, but the override is reported
  as an unknown ID and `--strict-config` promotes that to an error, which the
  page now says. `docs/configuration.md` told users to pass a `--pattern` flag
  that does not exist — globbing is the GitHub Action's `pattern:` input, not a
  CLI flag.
- **A crashed rule now reports itself in JSON and SARIF, not only on stderr.**
  A rule that raises is isolated rather than aborting the run
  ([ADR-006](docs/adr/006-exit-codes.md)), and it already set exit 2 and printed
  to stderr — but `run_errors` omitted `rule_errors`, so the machine output said
  nothing. JSON reported `errors: []` and SARIF reported
  `executionSuccessful: true` while that rule's findings were silently absent
  from a document the GitHub Action uploads. For Code Scanning that is worse
  than an omission: a *declared* rule with zero results reads as "every alert
  for this rule is fixed", so a crash closed the alerts instead of reporting
  itself. Crashed rules now ride the same structured channel as parse errors and
  coverage gaps.
- **Contract tests for three frozen surfaces that no test pinned.** Found by
  mutation: each change below left the entire suite green before this release.
  Halving `_KNOWN_RULE_KEYS` to `{enabled, reason}` passed — `severity:` and
  `exclude_services:` would have started warning as unknown keys, and *erroring*
  under `--strict-config`. Regrading SARIF `security-severity` for HIGH
  (`7.5`→`3.0`) and MEDIUM (`5.5`→`0.5`) passed, and both drop a full tier in
  GitHub's bands — the formatter's own comment records that Code Scanning
  derives an alert's severity column from that number alone. And changing the
  evidence derivation in CL-0017, CL-0020, CL-0021, CL-0025, CL-0028 or CL-0030
  passed *whenever the values stayed distinct*: evidence is the SARIF
  fingerprint, so that silently re-keys every alert, and the existing collision
  test only catches the degenerate case where values collapse together. Each is
  now pinned, with a guard-the-guard companion. Separately, `ci.yml`'s path
  filter now includes `docs/`, `README.md` and `mkdocs.yml`, which are asserted
  against by tests and could previously break on a docs-only PR that merged
  green.

- **A failed stdout write is now exit 2, not an undocumented exit 120 or a
  false exit 1.** Every path that could raise mid-run had been hardened to the
  0/1/2 contract; the channel all of them write through had not. A full disk
  (`> /dev/full`), a reader that closed early (`compose-lint check f.yml |
  head`) or a descriptor closed at startup (`>&-`) let the error escape
  `main()`: CPython reported an unraisable error from its own final flush and
  exited **120** — a code [ADR-006](docs/adr/006-exit-codes.md) does not define
  and which `docs/compatibility.md` prices at a MAJOR to add — or, when the
  write failed earlier, exited **1**, which reads as "findings at or above the
  threshold" on a file that is clean. Piping a clean run into `head` was
  therefore a red merge gate. Writes now report
  `Error: could not write output: <reason>` and exit 2, which is what that code
  already means: compose-lint could not complete the run.
- **A tiny Compose file can no longer buy an unbounded amount of work.** Two
  vectors, both reachable from a pull request in the CI merge gate the tool
  ships as. `MAX_SCAN_LEN` bounds what a pass *scans*; nothing bounded what
  substitution *produces* — `${A}${A}` is four characters whose result is twice
  whatever `A` holds, so a ladder of definitions each referencing the one below
  doubles per rung, and thirty rungs is a **489-byte** `.env` whose expansion
  exhausts memory. The new `MAX_SUBSTITUTED_LEN` bounds the result as it is
  built, returning the same "unknowable" answer both call sites already return
  for a name they cannot resolve. Separately, `str()` on an alias-expanded
  nested list serializes the DAG as a tree: `security_opt: [*l26]` is **690
  bytes** on disk and took 35s. `compose_lint._scalar` exists to refuse exactly
  that and `_caps.iter_cap_add` already applied it to `cap_add`; the CL-0003 /
  CL-0009 `security_opt` normalizer and CL-0010's namespace comparison now do
  too — 35.85s to 90ms. A list is not a value any of those fields can hold, so
  the entry is skipped rather than compared.
- **A pull request can no longer choose its own lint scope through a quoted
  `.env` value.** godotenv — and therefore Compose — lets a quoted value span
  lines, so the physical lines after the opening quote are value *text*, not
  entries. `_scan` read them as entries, which handed an untrusted contributor
  the one thing [ADR-026](docs/adr/026-read-the-sibling-env-file.md) §4 forbids:
  a `COMPOSE_FILE` compose-lint honours and Compose never sees. Three committed
  files were enough — a `.env` whose value text carries
  `COMPOSE_FILE=compose.yml:scrub.yml`, and a `scrub.yml` that `!reset`s the
  dangerous keys — turning a privileged, socket-mounting service from two
  CRITICAL findings into `✓ PASS` and exit 0, including in the explicit-file
  form the GitHub Action and the pre-commit hook use. `docker compose config`
  was never fooled; only compose-lint was. The scanner is now value-aware for
  both quote styles, with double-quote escapes honoured, and an unterminated
  quote consumes the rest of the file exactly as Compose does. This is the same
  failure `_split_env_lines` already closed for `\r`, by the route left open
  for `\n`.
- **A committed symlink no longer walks through the project-containment
  guard.** The guards in `_selection` and `_service_env` are deliberately
  lexical — whether a path *says* it leaves the project is a fact about the
  document, identical on every platform
  ([ADR-023](docs/adr/023-deploy-host-independent-claims.md) §1) — and a
  symlink says nothing. `probe.env` is spelled like a project-relative file
  and passes every lexical test while the link beside it points at
  `/home/runner/.aws/credentials`: exactly the scenario
  [ADR-027](docs/adr/027-grade-env-file-where-the-document-routes-it.md) §7
  names and `README.md` promises to refuse. In a pull request that put
  out-of-project env-key names into CL-0020/CL-0021 findings, and a line of an
  arbitrary host file into the SARIF uploaded to Code Scanning. A second gate
  now asks the *filesystem* — after the lexical test, at the moment of
  resolution — for both `env_file:` targets and `COMPOSE_FILE` entries.
  Symlinks themselves are still followed; only ones resolving outside the
  project are refused, with the existing `outside-project` note.

- **A parse error no longer reproduces the line it failed on.** PyYAML renders
  a snippet of the document under a caret, which reached `errors[].message`,
  the SARIF `toolExecutionNotifications` uploaded to Code Scanning, and the job
  log. A syntax error on a line carrying a credential therefore republished the
  credential. The diagnosis and the line/column position are kept — they say
  what is wrong and exactly where — and only the quoted bytes are dropped.

## [0.24.0] - 2026-08-24

### Changed

- **Python 3.11 is now the minimum supported version** (issue #643). Python
  3.10 reaches upstream end-of-life in October 2026, and dropping a version is
  a MINOR pre-1.0 but a MAJOR after — so the drop lands before the 1.0 freeze
  rather than letting a routine EOL force a 2.0. The deprecation was announced
  in 0.22.0, which also added the stderr warning, because the drop itself is
  silent: `requires-python` does not fail an install — pip resolves a 3.10
  interpreter to the last release that allowed it, so `pip install -U
  compose-lint` on 3.10 now stays on 0.23.0 with nothing printed. Pin
  `compose-lint==0.23.0` to be explicit about staying there. The CI matrix is
  now 3.11–3.14, and the lockfiles are regenerated at the new floor (the only
  change is that 3.10-only backport dependencies drop out; no version moves).

- **A scheduled Python-EOL drop is now MINOR, post-1.0 included**
  ([ADR-029](docs/adr/029-scheduled-python-drops-are-minor.md)). MAJOR
  signals surprise; a drop whose date CPython published years ahead, that
  warned on stderr for at least 180 days and one MINOR of grace, and that
  ships no earlier than upstream EOL, surprises nobody — and
  `requires-python` cannot break an existing environment (pip resolves an
  affected interpreter to the last release that allowed it). An
  off-schedule drop stays MAJOR. This closes the trap #643 had to
  outrun, permanently: 3.11's October 2027 EOL will be a routine MINOR,
  not a forced 2.0.

- **The compatibility policy is now part of the contract**
  ([ADR-030](docs/adr/030-the-policy-is-part-of-the-contract.md)). Amending
  it requires an ADR; clarifications ship in any release, tightenings are a
  MINOR, and loosenings are a MAJOR and never retroactive — the promise can
  no longer be weakened by a docs-only patch. Alongside it, the PATCH
  definition is clarified (a false-positive fix removes *incorrect* findings
  and stays a PATCH) and the severity-upgrade rule records its sanctioned
  MINOR alternative, the ADR-028 split pattern.

- **A post-1.0 severity upgrade is a MINOR with a one-release runway, not a
  MAJOR** ([ADR-031](docs/adr/031-severity-upgrades-are-minor-with-runway.md)).
  The release before the move announces it; the next MINOR applies it; the
  two-axis derivation model must produce the new number either way. A new
  HIGH rule already fails a threshold-gated pipeline as a MINOR, so
  upgrades-as-MAJOR guarded a door the contract holds open elsewhere —
  while making it impossible to correct an under-graded risk signal without
  a 2.0. Deliberately the watch-and-see position: under ADR-030, tightening
  to MAJOR later is cheap, and the reverse would not have been.

- **Retiring a refuted rule is a MINOR post-1.0, through the deprecation
  lifecycle** ([ADR-032](docs/adr/032-rule-retirement-is-minor-with-lifecycle.md)).
  A rule leaves the registry only when live evidence refutes its premise —
  the bar that removed CL-0012/0015/0023 pre-1.0 — and pricing that removal
  at a 2.0 would force the tool to keep emitting findings it knows are
  false. Announce, one MINOR of grace, then remove; the ID stays fallow
  forever, the doc page stays as a tombstone, and a config referencing the
  retired ID keeps working, `--strict-config` included (a precondition the
  config layer gains before the first such retirement). "Noisy" remains a
  non-reason (ADR-028).
- **`rule_id` / `ruleId` in machine output is declared opaque.** Every value
  today matches `CL-\d{4}`, but the pattern was never promised and is now
  explicitly excluded from the 1.0 contract: match exact ids, not the
  prefix. Declared before the freeze, while it is still a clarification
  rather than a contract change; it keeps a future rule source with
  differently-shaped ids (e.g. shellcheck's `SC` codes, ADR-007) additive.

### Removed

- **The Python 3.10 deprecation warning** added in 0.22.0. It existed to reach
  3.10 users while a release could still reach them; from this release pip no
  longer installs compose-lint on 3.10, so there is no interpreter left for the
  warning to run on.

- **CL-0022 no longer flags the `dev` tmpfs option.** The pre-1.0 rule-ID sweep
  ([#645](https://github.com/tmatens/compose-lint/issues/645),
  [ADR-028](docs/adr/028-pre-1.0-rule-id-sweep.md)) measured each of the rule's
  three tokens on rootful Docker at defaults. `exec` and `suid` remove a real
  default and stay. `dev` removes `nodev` and changes nothing a container can
  do: a block node created on a `tmpfs:dev` is refused by the **device cgroup**
  (`Operation not permitted`) exactly as it is on the rootfs and in `/dev`,
  neither of which carries `nodev` either; where the cgroup is off
  (`privileged`), `/dev` already permits the node. A finding on `dev` described
  a configuration that changed nothing — the failure mode that removed
  CL-0023 — so the token is gone, with a premise check (`_cl0022_dev_inert`)
  that re-proves the cgroup refusal on every CI run. A file whose only CL-0022
  finding was `:dev` now passes; `exec` and `suid` findings are unchanged. The
  rule's name is now "tmpfs mount re-enables exec/suid".

  The rule doc is corrected at the same time: OWASP Rule #8 recommends the
  `read_only` + `tmpfs` pattern and says nothing about mount options, so it is
  now cited for the pattern the rule protects, with the option semantics
  grounded by the live checks. The doc also states what `noexec` does not
  stop — `memfd_create`, interpreters, and a root workload's writable `/dev` —
  which is why the rule is LOW.

- **The pre-1.0 rule-ID reclamation window is closed.** ADR-028 records a
  disposition for every one of the 27 rules against the four questions #645
  set — would we ship it today, is its grounding container-context, is it
  false-positive-prone beyond what the premise check sees, is the ID right —
  with corpus prevalence and the live measurements behind each. All 27 are
  kept; no ID is reclaimed; CL-0012, CL-0015 and CL-0023 stay fallow
  permanently (already enforced by `tests/test_rule_surfaces.py`). One rule,
  CL-0014, is recorded as retained on maintainer judgment rather than on the
  grounding bar, so the divergence is visible rather than folklore.

## [0.23.0] - 2026-08-23

### Added

- **CL-0020 and CL-0021 now read the `env_file:` targets a service names**, and
  fire on a credential written in one. Compose merges those files into the
  container's process environment, so moving a line out of `environment:` and
  into an `env_file:` silenced both rules without changing what deploys — the
  silent false negative
  ([#665](https://github.com/tmatens/compose-lint/issues/665)) opened on. The
  decision and its grounding are
  [ADR-027](docs/adr/027-grade-env-file-where-the-document-routes-it.md): a
  value is graded where the document routes it, and an `env_file:` is a
  declaration that every key in the named file becomes a literal in that
  service's process environment.

  Files clean on 0.22.0 may report new HIGH findings. This is the documented
  MINOR behaviour, with the documented escape hatches: pin the version, or gate
  on `--fail-on`. 414 of the 5,417-file corpus (7.64%) name an `env_file:`, and
  496 of the 924 references name the sibling `.env` itself.

  Measured by rebuilding real projects — fetching the targets their repositories
  commit and running the rules with and without them — **55% of projects whose
  env file could be read gained at least one finding**: 538 findings across 90 of
  163 projects, 491 CL-0020 and 47 CL-0021. That is a floor on a biased sample:
  only 44% of named targets are committed at all, and the gitignored remainder is
  where credentials concentrate. If your compose file names an `env_file:` and
  that file is present when compose-lint runs, expect roughly a coin-flip chance
  of a new HIGH finding.

  **No credential value reaches any output surface.** `evidence` is the key
  name, as it always was, and the message names the key and the file. The text
  formatter no longer reads — let alone excerpts — a file that is not a Compose
  document, so the line a key was written on is never printed.

  Paths resolving outside the project directory are refused rather than read,
  and say so on stderr. Compose reads them; an `env_file:` naming a lint-host
  path in a pull request would otherwise put that host's key names into a
  report.

- A note when an `env_file:` target contributed nothing, naming which one and
  why: absent, unreadable, outside the project directory, or a path still
  carrying an unresolved `${VAR}`. A malformed line is noted too, with its line
  number: Compose refuses a whole env file over one, while compose-lint keeps
  the well-formed entries — refusing the file would drop real findings for every
  other key, which is the silent false negative this work exists to remove. A *required* target's absence says Compose
  refuses to start such a project, so the credential rules went unevaluated; an
  optional one's absence says Compose ships the service without it, which is the
  configuration that was graded. This replaces the blanket note added earlier in
  this release cycle, which told every service naming an `env_file:` that the
  rules had not been evaluated — true when nothing was opened, misleading beside
  the findings that now fire. Stderr only, and it never touches the exit code.

### Changed

- `--no-env` now covers both env files beside the Compose file: the sibling
  `.env` and every `env_file:` a service names. The flag's promise is that it
  reproduces the previous release's behaviour, and after this change that
  behaviour includes the `env_file:` read.

### Fixed

- **A v1-shaped or compose-lint-config overlay is now an error instead of a
  silent pass.** Either one in a merge set made compose-lint skip the whole
  project and report `PASS` at exit 0, dropping every finding in the base file.
  Docker Compose *refuses* a project that includes either, so unlike the
  fragment case (#671) there is no configuration to grade and merging is not
  the answer: the run now exits 2 and names the file that caused it. The
  own-config half mattered most — a file whose entire purpose is to disable
  rules could, if named in `COMPOSE_FILE`, silence the linter completely
  rather than disabling one rule
  ([#673](https://github.com/tmatens/compose-lint/issues/673)).

  This also settles the second defect in #671: the skip handler attributed the
  message to the primary path, so a valid v2 base was reported as the
  unlintable file. The error now names the overlay.

  A file linted **on its own** is unchanged — a bare v1 file or a stray
  `.compose-lint.yml` in a sweep still skips quietly at exit 0, which is
  ADR-013 and the reason that policy exists. Only the merge-set case moves.
  Projects that were passing on an overlay Compose would reject will start
  failing, which is the point: they were never graded.

- A fragment overlay carrying only top-level structural keys such as
  `volumes:` or `networks:`, or just `{}`, now merges into the linted
  configuration instead of skipping the whole project. Compose folds it
  into its base and deploys the result, but compose-lint let the
  fragment raise out of the merge and reported `PASS` at exit 0 without
  grading anything in the base file: a two-byte overlay could silence
  every finding, CRITICAL ones included
  ([#671](https://github.com/tmatens/compose-lint/issues/671)).

  Findings only move toward coverage here, the same shape that #648,
  #657 and #668 shipped under: affected projects see previously
  withheld findings. The merge direction does not care which half
  holds the `services:` — a fragment *base* beside an overlay that
  carries them now lints too, where it previously skipped whole. A
  merge set where every selected file is a
  fragment still skips at exit 0, files linted on their own are
  unchanged, and v1-shaped or own-config overlays keep their current
  behavior until their separate error path lands (#673).

  Thanks [@krishna3554](https://github.com/krishna3554) ([#675](https://github.com/tmatens/compose-lint/pull/675)).

- A parse error in an automatically merged `compose.override.yml` is now
  reported against the file that actually failed in text, JSON, and SARIF. It
  previously named the base file at a line number that did not exist there
  ([#666](https://github.com/tmatens/compose-lint/issues/666)).

  Thanks [@nightcityblade](https://github.com/nightcityblade) ([#670](https://github.com/tmatens/compose-lint/pull/670)).

- Every Compose substitution operator now resolves against a sibling `.env`,
  not just `${VAR:-default}` and `${VAR-default}`. `${VAR:?err}`, `${VAR?err}`,
  `${VAR:+alt}` and `${VAR+alt}` fetched the `.env` value and then discarded it,
  so a `${BIND:?required}` that Compose resolves to `0.0.0.0` reached the rules
  as source text and CL-0005 could not fire. The same function also shipped the
  empty string for `${VAR:-default}` where `.env` sets `VAR=` and Compose ships
  the default — a `:`-prefixed operator treats an empty value as unset. All
  eighteen operator/state combinations are now pinned by a differential test
  against the Compose binary
  ([#664](https://github.com/tmatens/compose-lint/issues/664)).

  Findings only change for a project that ships a `.env`: with none, every
  operator was and remains unresolved. The 5,417-file corpus produces a byte-
  identical result set.

- CL-0020 now exempts additional credential-shaped quantity knobs, including
  work factors, retry counters, lengths, strength values, and cost knobs when
  their values are bare quantities ([#681](https://github.com/tmatens/compose-lint/issues/681)).

  Thanks [@AdhravRai](https://github.com/AdhravRai) ([#685](https://github.com/tmatens/compose-lint/pull/685)).

## [0.22.0] - 2026-08-22

### Upgrading

**A `.env` beside a Compose file now chooses which documents are linted.**
Compose reads a sibling `.env` for `COMPOSE_FILE`, which replaces its file
discovery *and* suppresses the automatic `compose.override.yml` merge. compose-
lint read neither, so a project configured that way had its real documents
ungraded while an override Compose never loads contributed findings — under a
warning stating that Compose merges it automatically, which was false there.

Values are resolved from it too, so a `${VAR}` a rule consumes now grades as
what deploys rather than as unknowable. Expect new findings on such projects,
including CRITICAL ones, and some existing findings to disappear where the
`.env` supplies a value that clears them (a pinned image tag, for instance) —
the documented MINOR behaviour for tightened coverage.

Expect the reported file list to change on such projects, in both directions.
`--no-env` restores the previous selection exactly, including that false merge.
A `.env` can only *add* documents to a file you named on the command line, never
remove it, so nothing you asked for is skipped ([ADR-026](docs/adr/026-read-the-sibling-env-file.md)).


**Files with a `compose.override.yml` beside them are now graded as the
configuration Compose runs.** `docker compose up` merges that overlay with no
flag and no opt-in, and compose-lint read only the base — so a control-socket
mount added by an overlay was never reported, and the base's own findings were
graded against a document nobody deploys.

Expect new findings on such projects, including CRITICAL ones. That is the
documented MINOR behaviour for tightened coverage; pin the version or gate on
`--fail-on` if a pipeline needs determinism. `--no-merge-overrides` restores
the previous single-file grading exactly.

### Added
- `check` and `fix` read `COMPOSE_FILE` and `COMPOSE_PATH_SEPARATOR` from a
  `.env` in the Compose file's own directory, select the documents it names, and
  merge them in its order. The run states what it selected and why on stderr,
  and the header names every document read. The ambient shell environment stays
  out of scope: a `COMPOSE_FILE` exported in a session and never written down is
  host state, and honouring it would make the same checkout lint differently
  depending on who ran the command. The separator defaults to `:` on every
  platform rather than to the host's, because a `.env` naming two documents
  describes the project wherever it is linted from; Compose's own default is
  the host's path separator, so this deliberately differs on a Windows lint
  host, in the same direction ADR-023 already took for path semantics.
- `--no-env` ignores a sibling `.env` entirely, reproducing the previous file
  selection. A run that skips one says so, because an escape hatch that
  silently changes what is graded is the failure the hatch exists to prevent.
- A note when a bind source is *only* unresolved references (`"${MOUNT}:/data"`
  with nothing supplying `MOUNT`). Compose refuses to start a project with an
  empty bind source, so the document being graded is not one that deploys and
  the mount rules were never evaluated for it. Deliberately narrow — 3.3% of a
  5,417-file corpus, against the 22% that carry *some* defaultless `${VAR}` —
  and it is a note on stderr, so the exit code is unchanged.

- Contract tests pin the JSON envelope and the SARIF log shape, the two
  surfaces `docs/compatibility.md` freezes at 1.0 that nothing enforced.
  `SCHEMA_VERSION` is pinned to its literal value, so a silent bump fails;
  additive keys stay allowed, renames and removals now require editing the
  contract on purpose.
- `check` and `fix` merge a sibling `compose.override.yml` and lint the
  effective configuration (ADR-025). The run header names both documents, and
  a note on stderr states what was merged; the exit code is unchanged, because
  merging is coverage achieved rather than a coverage gap.
- `--no-merge-overrides` on `check` and `fix` opts out.
- Findings carry the document their evidence is written in. Text excerpts are
  read from that file, SARIF points `artifactLocation` there, and JSON gains a
  conditional `source_file` key — additive, so `SCHEMA_VERSION` is unchanged.

### Changed

- `fix` edits only findings written in the file it is fixing when an overlay is
  merged; findings from the overlay are reported for manual review, and the
  overlay is never a write target.

### Deprecated

- **Python 3.10 is deprecated.** It reaches upstream end-of-life in October
  2026, and compose-lint will require 3.11 or newer before its 1.0 release.
  Running on 3.10 now prints a one-line warning to stderr naming the version
  you are on and the version to pin if you need to stay there. Nothing else
  changes yet: 3.10 remains in the test matrix and fully supported until the
  drop lands.

  The warning exists because the drop itself is silent. `requires-python` does
  not fail an install on an unsupported interpreter — pip resolves to the last
  release that allowed it, so after the floor moves `pip install -U
  compose-lint` leaves a 3.10 user on a frozen version with nothing printed in
  either direction. This is the last chance to say so.

### Fixed
- Credential rules are unaffected by a `.env`. A value there is never
  substituted into an `environment:` value, so `POSTGRES_PASSWORD: "${PW}"`
  stays clean however `PW` is set — otherwise CL-0021 would flag the exact
  pattern its own fix text recommends. A written default is still graded:
  `${PW:-changeme}` ships to every clone and keeps firing. Names referenced only
  from `environment:` are not read out of the `.env` at all.
- An overlay is no longer merged into a project whose `.env` sets
  `COMPOSE_FILE`. Compose does not load `compose.override.yml` when
  `COMPOSE_FILE` is set, so those findings described a document that never runs,
  and the accompanying warning asserted the opposite.

- CL-0005 includes a non-default protocol in a long-syntax port's evidence.
  Two publishings of one container port that differ only by protocol — the
  standard shape for a DNS service — derived the same evidence, so SARIF gave
  them one `partialFingerprints` digest and Code Scanning displayed one alert
  instead of two. `tcp` is still not spelled out, so no existing alert is
  re-keyed. Text and JSON always reported both findings.
- `extends:` no longer concatenates every sequence. Compose merges `volumes`
  and `devices` by container path, replaces `command`/`entrypoint`, and
  deduplicates the append-style sequences; concatenating reported a CRITICAL
  socket mount against a service that had replaced that mount at the same
  container path, pointing at the line that replaced it.

## [0.21.0] - 2026-08-20

### Upgrading from 0.20.x

**SARIF consumers: your Code Scanning alerts will be re-keyed once.** The
`partialFingerprints` key moves from `composeLintFinding/v1` to `/v2`, and
the digest no longer includes the finding's message. On the first upload
after upgrading, GitHub closes every existing compose-lint alert and opens a
replacement — dismissal state on those alerts is lost. This happens once.

The reason is that v1 made prose part of the alert's identity: rewording any
rule message silently closed and reopened every matching alert in every
consuming repository, so improving a message was a breaking change with no
warning. Identity is now structured data (file, rule, service, and the
specific offending value), and message text is free to change (ADR-024).

Nothing to do beyond expecting the one-time churn. If you dismiss alerts,
re-dismiss after the first post-upgrade scan.

### Added

- **SARIF results now name the service.** A finding carries the service as a
  `logicalLocation` (`services.<name>`) and names it in the alert title.
  Previously SARIF results carried only rule, file and line, so a Code
  Scanning user disambiguated a multi-service file by line number while a
  terminal user was told the service outright — even though the service was
  already part of the alert's fingerprint.

- **`check` and `fix` now say when no config was in effect.** A run that
  reports findings — or a `fix` that has changes to make — with no
  `.compose-lint.yml` found and none passed via `--config` prints a one-line
  note on stderr naming the directory it looked in. This is aimed at the
  Docker case: the image's working directory is `/src`, so a run that mounts
  only the compose file leaves the config outside the container and silently
  drops every suppression. Passing runs, and runs that found a config, stay
  quiet.

### Changed

- **SARIF alert identity no longer includes the finding's message.** The
  `partialFingerprints` key moves from `composeLintFinding/v1` to `/v2`, and
  the digest is now `[uri, rule_id, service, evidence]` rather than
  `[uri, rule_id, service, message]`. `evidence` is a new internal field
  holding the specific offending value in normalized form, so a rule that
  fires more than once for one service still distinguishes its hits without
  making prose part of the alert's identity (ADR-024). See Upgrading above
  for the one-time re-key.

- **The published image moves to a newer distroless base.**
  `gcr.io/distroless/python3-debian13:nonroot` is repinned from
  `sha256:eff0a605…` to `sha256:4376456c…`, picking up the base image's own
  updates. This landed after `release-prep` snapshotted the changelog but
  before the tag, so it shipped in the 0.21.0 image without being recorded
  here at the time.

### Fixed

- **CL-0005 now flags `::ffff:0.0.0.0` on every supported interpreter.** The
  IPv4-mapped spelling of the unspecified address was classified by
  `ipaddress.is_unspecified`, whose handling of IPv4-mapped addresses varies
  with the CPython build — so a port published on all interfaces was reported
  on some hosts and missed on others, with no way for a user to tell which
  they had. The mapping is now unwrapped explicitly. A compose file binding
  `[::ffff:0.0.0.0]` that previously passed on macOS or Windows will now
  correctly report CL-0005.
- **GitHub Action: installing a just-released version no longer fails on
  PyPI index lag.** PyPI's JSON API sees a release within seconds of the
  publish, but the `/simple/` index pip resolves against can lag it by
  minutes — so `uses: tmatens/compose-lint@<sha>` pinned to a version
  released moments earlier could fail with "No matching distribution
  found". The action's install now retries with backoff for ~100s, and
  says so if it gives up instead of leaving a bare non-zero exit.

## [0.20.0] - 2026-08-18

### Upgrading from 0.19.x

**On Windows lint hosts, files that passed may now fail.** Bind-source
resolution is now lexical segment math in POSIX notation on every platform
(ADR-023), so the whole-root (CL-0001) and root-equivalent (CL-0025) claims
now fire on a `..`-climb source that Windows path semantics previously left
unmatched. This closes a platform gap rather than adding a new claim: the
same file already failed on Linux and macOS, and the miss shipped as a known
limitation in 0.19.0 ([#588](https://github.com/tmatens/compose-lint/issues/588)).

Two Windows-only spelling changes come with it. A resolved relative source is
now reported `/`-rooted instead of with the lint host's separators and drive
letter, and a `~` source is left as written rather than expanded against a
Windows home directory — which is no proxy for the POSIX home of the host the
compose file actually deploys to. Anything that pattern-matches compose-lint's
reported source paths on Windows needs updating.

**On Linux and macOS, nothing changes** — verified across the 5,417-file
corpus: zero findings changed.

`fix` also now preserves a CRLF file's line endings, so re-running it on a
file it previously touched can produce a different, correct diff. No action
needed.

### Changed

- Bind-source resolution is now lexical segment math in POSIX notation on
  every platform (ADR-023): findings assert facts about the document that
  hold on any plausible deploy host, instead of borrowing the linting
  machine's path semantics. On Linux/macOS behavior is unchanged (verified:
  zero findings changed across the 5,417-file corpus). On Windows lint
  hosts, resolved relative sources are now spelled `/`-rooted, and `~`
  sources are left as written rather than expanded against a Windows home
  that is no proxy for a POSIX deploy home.

### Fixed

- **`fix` now respects a CRLF file's line endings end to end.** The
  line-inserting fixers spliced bare-LF lines into CRLF files, shipping a
  mixed-endings result that editors and VCS `autocrlf` flag on every line;
  inserted text now adopts the file's dominant ending. And the dry-run diff
  no longer renders every line of a CRLF file with a trailing `\u000d`
  escape — a CR that is part of the line-ending convention is not content,
  while a *lone* CR (the smuggling shape the output sanitizer exists for)
  still surfaces escaped.
- **Windows lint hosts no longer miss climb-to-root bind mounts.** A
  `..`-climb source resolved with Windows path semantics never matched the
  whole-root (CL-0001) and root-equivalent (CL-0025) claims — the known
  limitation shipped in 0.19.0's notes (#588). Climbs now saturate at the
  root of whatever filesystem contains the compose file and are claimed on
  every platform.

## [0.19.0] - 2026-08-18

### Added

- GitHub Action: `upload-sarif` input (default `"true"`). Set to `"false"` to
  write the file requested via `sarif-file` without uploading it to GitHub
  Code Scanning — for runners without Code Scanning (Forgejo) or jobs that
  lack the `security-events: write` permission the upload needs.
- GitHub Action: `sarif-written` output — `"true"` when the SARIF file was
  written and non-empty, empty otherwise.

### Fixed

- **Windows: every invocation crashed with `AttributeError: module 'os' has
  no attribute 'O_NONBLOCK'` in 0.18.0.** The bounded-read hardening opened
  files with the POSIX-only `O_NONBLOCK` flag (its FIFO-open-blocking rationale
  does not exist on Windows). File opens now apply `O_NONBLOCK` only where the
  platform has it, and add Windows' `O_BINARY` so CRT newline translation
  cannot corrupt reads that ask for the file's real bytes. Found by the new
  macOS/Windows CI smoke on its first run.
- **Windows: any run with findings crashed with `UnicodeEncodeError`.**
  Windows pipes and redirected files inherit the locale code page (usually
  cp1252), which cannot encode the report's ⚠/·/│ characters. The CLI now
  reconfigures stdout/stderr to UTF-8 when they aren't already — a no-op on
  every other platform and on interactive Windows consoles — so piped and
  redirected output is UTF-8 everywhere. Also found by the macOS/Windows
  smoke.

### Known limitations

- **On Windows hosts, bind-source path resolution uses the host's path
  semantics**, so the climb-to-root detections (CL-0001, CL-0025) can miss
  findings that the same file produces on Linux/macOS, and a bind source
  containing `${VAR:?err}` can surface an OS error. Tracked in
  [#588](https://github.com/tmatens/compose-lint/issues/588). Linting the
  same files on Linux CI is unaffected.

## [0.18.0] - 2026-08-14

### Upgrading

**A file compose-lint cannot fully see is now an error (exit 2), not a pass.**
`include:` and cross-file `extends: {file: ...}` reference services in other
files, and compose-lint reads single files without following them — so those
services were never linted. The gap was reported on stderr for `include:` and
not at all for `extends:`, while the verdict, exit code, JSON `errors` and SARIF
`executionSuccessful` all said the run was clean. A base carrying
`privileged: true` and `network_mode: host` could sit unlinted behind a green
check.

Measured over the 5,417-file corpus: **31 files (0.6%) change exit code — 20
from pass to error, 11 from fail to error.** Findings for the local services are
still reported; the file is graded on what could be seen *and* the gap is
recorded.

```bash
# Cover everything by linting the merged output (compose-lint reads files,
# not stdin, so write it out first):
docker compose config > merged.yml && compose-lint merged.yml

# Or accept the gap and grade only what is visible:
compose-lint --allow-partial-coverage docker-compose.yml
```

`fix` reports gaps but never fails on them — it is not the merge gate.

**Rules now grade `${VAR:-default}` as the value it deploys, so files that
passed may now fail.** With no `.env` and the variable unset, Compose ships the
default — `privileged: ${P:-true}` deploys `privileged: true` — but only bind
sources were being resolved, so every other rule compared its dangerous-value
set against the literal text `"${P:-true}"` and found no match. Writing a
dangerous value in interpolated form was a general-purpose bypass of twelve
rules.

Measured over the 5,417-file corpus: **286 files (5.3%) change findings, and
100 (1.8%) go from pass to fail at the default `--fail-on high`.** One file
goes the other way.

| Trigger | before | after |
|---|---|---|
| `POSTGRES_PASSWORD: ${PW:-hunter2}` | *none* | **CL-0020** high |
| `DATABASE_URL: postgres://${U:-u}:${P:-p}@db` | *none* | **CL-0021** high |
| `image: nginx:${TAG:-latest}` | CL-0019 medium | **CL-0004** medium |
| `ports: ["${BIND:-0.0.0.0}:80:80"]` | *none* | **CL-0005** medium |
| `user: "${UID:-0}:${GID:-0}"` | *none* | **CL-0018** medium |
| `mem_limit: "${MEM:-0}m"` | *none* | **CL-0026** medium |
| `privileged: ${P:-true}` | *none* | **CL-0002** critical |

The `image:` row is a reclassification, not a new failure: CL-0004 replaces
CL-0019 at the same location and severity, because the tag resolves to the
mutable `latest` rather than to an opaque `${TAG}`.

Two changes go the other way and **remove** findings, both fixing false
positives: a port whose default binds loopback (`"${PORT:-127.0.0.1:80}:80"`)
no longer trips CL-0005, and an empty placeholder in a list-form entry
(`- API_KEY=""`) no longer trips CL-0020 — the mapping form `API_KEY: ""` was
already exempt.

If a finding is genuinely parameterized in your deployment, that is what
`.compose-lint.yml` suppressions are for. Writing the reference without a
default (`${PW}` rather than `${PW:-hunter2}`) also stays exempt, because
Compose then ships nothing.

### Changed

- **Coverage gaps are reported on every channel a consumer reads.** An
  unresolved `include:` or cross-file `extends: {file: ...}` now produces a JSON
  `errors[]` entry, a SARIF `toolExecutionNotifications` record with
  `executionSuccessful: false`, and exit 2 — previously a stderr warning for
  `include:` and complete silence for `extends:`. `parser.coverage_gaps(data)`
  exposes the same list to library callers. The text verdict counts them
  separately from parse failures, because those files parsed fine and saying
  otherwise would misdescribe the run. See **Upgrading** above.
- **New `--allow-partial-coverage` flag on `check`** to accept a coverage gap
  and grade what is visible. It waives the gap, not the findings: a local
  CRITICAL still fails the gate.
- **`${VAR:-default}` is resolved document-wide before rules run.** The parser
  normalizes every string leaf to the value Compose ships when the variable is
  unset, so a rule classifies the deployed configuration instead of the source
  text. Substitution had been wired into one call site (bind sources), leaving
  CL-0002, CL-0004, CL-0005, CL-0008, CL-0009, CL-0010, CL-0011, CL-0014,
  CL-0016, CL-0018, CL-0020, CL-0021, CL-0022, CL-0024, CL-0026 and the
  capability rules grading a string that is never deployed. Doing it once in the
  parser is what keeps it from being re-litigated per rule: a rule that adds a
  dangerous literal to its set gets the interpolated spellings for free. See
  **Upgrading** above for the measured impact. A reference with no default is
  still left as written — Compose ships nothing for it, so there is nothing to
  grade.
- **The credential rules' interpolation exemption is stated as what Compose
  does.** CL-0020 and CL-0021 previously skipped any value *containing* a
  reference, so appending one character to a literal (`hunter2$X`) silenced
  them, while Compose ships `hunter2`. The exemption is now "Compose resolves
  this value to nothing", which also correctly exempts a quoted reference in a
  list-form entry (`- SECRET_KEY="${KEY}"`, where the quotes are literal
  characters) that a stricter shape test would have flagged.
- **CL-0021's rule description** now says the password half is skipped when
  Compose resolves it to nothing, and that a defaulted password still fires.
  Visible in `--explain CL-0021`, the docs site and SARIF rule metadata.
- **CL-0026 no longer treats an unparseable dollar-bearing value as a limit.**
  `mem_limit: "${MEM:-0}m"` resolves to `0m`, which Docker reads as unlimited,
  and now fires; a bare `${MEM_LIMIT}` stays exempt as genuinely unknowable.
- Scalars longer than 8 KB are no longer scanned for interpolation. The two
  substitution regexes are quadratic (measured 80 KB → 0.49 s, 160 KB →
  1.94 s), and the pass above runs them over every string rather than bind
  sources alone; past the cap the conservative answer is returned unscanned.
- **A Compose file containing an ambiguous line break is now refused** (exit 2,
  reported per file, with a SARIF `toolExecutionNotifications` entry) instead of
  being linted with line numbers nothing else agrees with. A lone `\r`, U+0085,
  U+2028 or U+2029 is a line break to the YAML parser but not to editors, SARIF
  viewers or CI annotations, so on such a document *any* reported line number is
  wrong for one side or the other — and the fix engine would splice at a line
  the user is not looking at. There is no line numbering to fall back on, so the
  file is refused rather than mislabeled. None of the 5,417 files in the corpus
  contains one, and CRLF and LF are unaffected.
- **The parser now reads files without universal-newline translation**, so
  `check` and `fix` parse the same bytes for the same file. `fix` has always
  read with `newline=""` to preserve line endings, while the parser rewrote a
  lone `\r` to `\n` — a second, quieter version of the same disagreement.
  Verified no behavior change: LF and CRLF documents produce byte-identical
  findings and line numbers, and a full corpus run is unchanged.

### Fixed

- **CL-0021 no longer reports a connection string whose credential is entirely
  a variable reference.** The `user:password@` split ran on the first `:`,
  which for `postgresql://${DB_USER:?error}:${DB_PASSWORD:?error}@db/x` lands
  inside the substitution — leaving a "password" of `?error}:${DB_PASSWORD:?error}`,
  which is not wholly a reference and so read as a shipped literal. The split
  now happens at substitution depth zero, the same thing `parser` already did
  for short-syntax volumes, and each half is length-bounded rather than
  relying on a regex quantifier to bound it.

- **CL-0020 no longer reads a token's *lifetime* as the token.**
  `JWT_ACCESS_TOKEN_EXPIRE_MINUTES: 30` matched on the `TOKEN` substring and
  fired at `high` — a finding with no fix, since the value is a duration.
  A key naming a quantity about the credential (`TTL`, `EXPIRE`, `EXPIRY`,
  `VALIDITY`, `ROTATION`, `INTERVAL`, `RETENTION`, `_MINUTES`/`_DAYS`,
  `MIN_LENGTH`, `MIN_CHAR`, `_LIMIT`, `_SIZE`, `POLICY`, plural `TOKENS`,
  `_PORT`) is now exempt **when its value is also a bare quantity** (`30`,
  `900s`, `30m`).

  Both halves are required, and deliberately so. Exempting on the value alone
  — the shape a bare integer suggests — would have reverted the numeric-secret
  fix: `POSTGRES_PASSWORD: 1234` is a weak credential and must keep firing.
  Exempting on the key alone would skip `AUTH_TOKENS: your_token_here`.

  Measured over the 5,417-file corpus: **30 findings removed across 18 files,
  every one a knob; all 40 numeric-valued credentials kept; no other rule's
  output changes.** Three files stop failing at the default `--fail-on high`,
  having failed only on this. This class grew with the interpolation change
  above — `TOKEN_TTL: ${TTL:-60}` resolves to `60` and began firing where the
  unresolved reference had not.

  Four knob keys holding non-quantity values still fire (a banned-password
  *list filename*, a `5/hour` rate, an arithmetic expression, a placeholder
  token); judging those needs the content scanner this rule declines to be.

- **Nested interpolation defaults resolve the way Compose resolves them.**
  `${A:-x${B:-y}z}` was rewritten by a single regex pass whose default group
  stopped at the *first* `}` — the inner one — so
  `${DB_URL:-postgres://u:${PW:-s3cret}@db/x}` normalized to
  `postgres://u:${PW:-s3cret@db/x}`, a string Compose never ships, with the
  userinfo boundary moved and the brace relocated past the host. Every rule
  reads the normalized document, so the corruption reached bind sources
  (`${GOPATH:-${HOME}/go}/pkg/mod/cache`) as well as the credential rules. 98
  values across 34 corpus files are written this way. Resolution is now
  innermost-first with balanced brace counting, checked against
  `docker compose config` on Compose 5.4.0 with no `.env`:

  | written | shipped | before |
  |---|---|---|
  | `${A:-front-${B:-back}-tail}` | `front-back-tail` | `front-${B:-back-tail}` |
  | `${OUTER:-postgres://u:${IN:-pw}@db/x}` | `postgres://u:pw@db/x` | `postgres://u:${IN:-pw@db/x}` |
  | `${CONF:-{"a":1}}` | `{"a":1}` | `{"a":1}` |

  Nesting is bounded at 32 levels, deeper values being left as written: because
  resolution recurses per level, `${A:-` repeated 1,200 times — 7 KB, under
  `MAX_SCAN_LEN` — otherwise exhausted the interpreter stack and the parser
  reported that as a usage error, so a 7 KB scalar turned a clean lint into
  exit 2.

  Measured over the 5,417-file corpus: **5 files (0.09%) change findings and
  none go from pass to fail.** Two stop failing at the default `--fail-on high`,
  each losing a single CL-0021 false positive; one drops a CL-0020 on
  `MINIO_ROOT_PASSWORD: ${S3_SECRET_ACCESS_KEY:-${S3_SECRET_KEY:-}}`, which
  Compose ships empty; and one file's five `${IMG:-repo/app:${TAG:-latest}}`
  images move from CL-0019 to CL-0004 at the same MEDIUM severity, because the
  tag now resolves to the mutable `latest` rather than to an opaque reference.

- **`init` no longer writes a config that does not parse.** A service name
  carrying a newline produced a `.compose-lint.yml` with a bare line break
  inside a mapping key — and `init` reported success writing it, so every later
  run in that directory failed with `Invalid YAML in config file` at exit 2
  until someone found the file by hand. Durable corruption from one lint of one
  hostile file. Quoting is now delegated to PyYAML rather than hand-rolled
  (the previous version escaped `\` and `"` and nothing else), and the
  plain-scalar test is anchored with `\Z` rather than `$` — in Python `$` also
  matches *before* a trailing newline, so `"web\n"` was emitted unquoted.
  Ordinary names are still emitted unquoted.

- **`init --force` no longer overwrites a read-only config.** A 0444
  `.compose-lint.yml` is an explicit "do not modify" on the file that decides
  which security rules are suppressed, and `os.replace` would swap it out
  through the writable parent directory regardless. `fix --apply` had honoured
  that mode all along; the init path did not. The guard is now one shared
  helper called by both, with a test that fails if either loses it.

- **A small file can no longer buy a large amount of work.** Nine defects
  shared that shape: input that parses in milliseconds and then costs seconds
  or gigabytes downstream, while producing no finding and exiting 0 — so
  nothing in the output signalled it. Measured at 800 services, `fix` went from
  2.67 s to 0.65 s and SARIF from 2.37 s to 0.36 s, and both are now linear in
  service count rather than approaching quadratic.

  - **Reading a path that is not a bounded regular file.** `.exists()` is true
    of a FIFO and of `/dev/zero`, and a repository can commit a *symlink* to
    either — it survives clone and checkout, and the runner resolves it.
    Reading one hung the job forever; the other allocated until the runner
    died. Both the Compose loader and the config loader now check the resolved
    file's shape before reading a byte, with the descriptor opened
    `O_NONBLOCK` — a plain `open()` on a FIFO blocks *before* any check can
    run — and the read bounded at 8 MB.
  - **`str()` on a YAML container.** Aliases share nodes by reference, so a
    22-level doubling chain is under 1 KB on disk and 22 nodes in memory, but
    `str()` serializes it as a *tree*: 4M elements from one call. Eleven rule
    sinks and three config fields did that to whatever the document handed
    them. They now refuse a container rather than render it — a list is not a
    capability, a port, a mount spec, or a suppression reason.
  - **Repeated work over one document.** `split_lines` was called once per
    fixer and re-split the whole file each time (2.24 s of a 2.58 s run at 800
    services); `extends_targets` walked every service once per *finding*; and
    `_merge_extends` re-walked a shared alias subtree once per path through the
    DAG (805 B → 5.4 s). All three are now memoized per document, and
    `split_lines` takes a C-speed path when the text contains none of the five
    characters `str.splitlines()` breaks on and PyYAML does not.
  - **Quadratic scanning of a long scalar.** CL-0021's userinfo pattern
    retried from every offset (20 KB → 1.1 s, 40 KB → 4.1 s). Its quantifiers
    are now bounded and the scalar is capped before scanning.
  - **The edit-conflict check** compared every pair of fix units. It now sweeps
    spans sorted by offset and stops as soon as a later span begins past the
    current one's end.
  - **SARIF output that a consumer would reject.** 1,500 aliased services in
    29 KB produced a document over GitHub Code Scanning's 10 MB ceiling — and
    an artifact that large is *rejected*, so the run showed no alerts at all.
    Output is capped at 5,000 results, the omission is stated in
    `toolExecutionNotifications`, `executionSuccessful` is false, and the run
    exits 2 so a gate cannot read success from a knowingly incomplete artifact.
    Use `--format json` for the complete set.

- **Malformed input is a per-file failure, never a traceback.** Four paths let
  an exception escape the fail-loud boundary: the CLI printed a Python
  traceback, exited **1** — which reads as "I linted it and it failed" rather
  than "I could not lint it" — and abandoned every remaining file in the batch.
  All four now surface as a clean error at exit 2 with the rest of the run
  intact. Each had a correct sibling already in the repo.

  - **Deep recursion in the post-parse passes.** The loader's
    `RecursionError` guard covered the *parse* only, so a 2000-deep `extends:`
    chain or a self-referential `${A:-${A:-…}}` in a bind source blew the stack
    after the loader returned. The boundary now covers every pass that walks
    the document.
  - **`ReaderError` from the loader constructor.** `Reader.__init__` runs the
    printable-character check, so a document carrying a C0 byte raises at
    construction — which happened *outside* the `try`. The constructor is now
    inside it.
  - **`RecursionError` in the config loader.** `except yaml.YAMLError` does not
    catch it, since it is a `RuntimeError`. The Compose loader already
    translated this; the config loader did not.
  - **Write failures from `fix --apply` / `init`.** An unwrapped `OSError` — a
    read-only directory, a full disk — aborted the batch and printed the
    absolute workspace path in a traceback. Failures are now attributed to the
    file they belong to, and later files still lint. The message reports the
    condition (`Permission denied`) rather than the errno decoration and the
    internal temp filename the caller never chose.
  - A write target that exists but is **not a regular file** is now named as
    such. A directory has `st_nlink >= 2`, so it was previously reported as a
    hard link, which is not what is wrong with it.

- **`fix --apply` could edit the wrong line and silently delete config.** The
  fix engine's offset table counted only `\n`, while the line numbers it
  converted come from PyYAML, which also breaks on a lone `\r`, U+0085,
  U+2028 and U+2029. One such codepoint inside a quoted scalar shifted every
  later splice a line, so a fix could remove a line the user never selected —
  and because the result was still valid Compose, every safety net passed and
  the run exited 0. `compose_lint._lines` now owns a single definition of a
  line break, with `split_lines` and `line_starts` derived from one scan so
  they cannot disagree; the fixers, the fix engine and the text formatter's
  source excerpt all use it. A CI guard fails the build on a bare
  `str.splitlines()` in `src/`. Documents free of those four codepoints —
  effectively all real Compose files — are unaffected: a 5,417-file corpus run
  shows zero change in findings, exit codes or errors.
- **A file whose fixes could not be computed no longer destroys the batch.**
  The same desync could push a line number past the offset table and raise a
  bare `IndexError`, which aborted the whole run: `check --format sarif` then
  emitted a 0-byte document, discarding the findings of every other file
  scanned alongside it. Out-of-range positions now raise a
  `LineOutOfRangeError` that the CLI reports as a per-file failure (exit 2,
  the usage-error code) while the rest of the batch still lints and still
  ships its findings.

### Security

- **The release layer no longer has a weaker path than its main one.**

  - **One tag gate, called by both publish paths.** `publish.yml` verified
    three things about a release tag: annotated, reachable from `main`, and
    signed by a key in `.github/allowed_signers`. `publish-channel.yml` — the
    manual escape hatch, which ships with the same credentials — carried its
    own copy that did the first two and omitted the third, so a tag signed by
    nobody could reach the publishing jobs. The signature check is the
    cryptographic root of the Sigstore provenance chain. It now lives once, in
    a reusable `verify-tag.yml` that both paths call, and every
    credential-bearing job depends on it. A test walks the `needs:` graph and
    fails if any job touching a publishing credential does not reach the gate.
  - **The release smoke no longer resolves dependencies from TestPyPI.** `-i`
    makes an index *primary*, and pip then prefers the highest version across
    all configured indexes — so with TestPyPI primary, anyone who claims a
    dependency name in that open namespace at a higher version supplies code
    into the release. The closure is now installed from the hash-pinned lock
    first, and TestPyPI is used only with `--no-deps` for the one artifact
    under test. Verified against a local squat: PyYAML resolves from the lock,
    not the planted 99.0.0. A test fails any workflow `pip install` that reads
    from a non-default index without `--no-deps`.
  - **The manual Docker Hub description sync runs default-branch code.**
    `workflow_dispatch` can name any ref and `uses: ./…` runs whatever is in
    the workspace, so the dispatcher chose the code that reads a
    Read+Write+Delete token. The checkout is pinned to the default branch: a
    dispatch now chooses when it runs, not what runs.
  - **The corpus report escapes third-party repository and path strings.**
    They come from code-search results over arbitrary public repositories, and
    only a path's *basename* is filtered when fetching — so a directory
    component could contain `|`, backticks and HTML, forge extra columns, and
    write rows that looked like compose-lint's own findings. Backticks are
    replaced rather than escaped, because Markdown does not honour backslash
    escapes inside a code span.

  Two related items need repository and Docker Hub settings rather than code,
  and are written up in `docs/RELEASING.md`: moving the Docker Hub secrets into
  a default-branch-scoped environment, and splitting the single
  Read+Write+Delete PAT into read, write and admin tokens.

- **Four places where the tool reported a state that was not true.**

  - **`fix --apply` no longer claims to have fixed a file it did not touch.**
    `os.replace` swaps the directory entry, not the inode behind it, so on a
    **symlink** it dropped a regular file over the link and left the file the
    stack actually deploys unchanged — while the run reported the fix applied.
    On a **hard link** it broke the link and let the two names diverge in
    silence. Both are now refused with an error naming the reason; the rest of
    the batch continues. `setuid`/`setgid`/sticky bits are no longer carried
    onto the replacement inode.
  - **A `severity:` override leaves an audit record.** It was the one
    suppression channel with none: `enabled: false` and `exclude_services` both
    mark findings SUPPRESSED with a reason, but a re-graded finding was
    indistinguishable from one the rule declared at that level — so three lines
    in a policy file could take a CRITICAL below the default gate invisibly.
    Now reported as `(severity overridden from critical)` in text,
    `severity_overridden_from` in JSON, and `properties.severityOverriddenFrom`
    in SARIF. Re-stating a rule's own severity records nothing, because nothing
    changed.
  - **Duplicate keys in `.compose-lint.yml` are a config error.** YAML resolves
    them last-wins in silence, so a policy that disables a rule with a reason
    and re-enables it further down read, to a human, as the first entry and
    behaved as the second. The Compose parser already refuses duplicates for
    this reason; the config loader was the door left open.
  - **A line lookup never returns a line belonging to a different node.**
    Joining path segments with `.` is lossy when a segment contains one: a
    service named `web.logging` and service `web`'s `logging:` child both spell
    `services.web.logging`, and last-write-wins handed one of them the other's
    line — so a fixer evaluated its anchor/merge-key refusal against a
    different service and applied an edit every fixer is required to refuse.
    Colliding paths are now dropped from the map, so the lookup returns `None`
    and the fixer fails closed. 17 corpus files use dotted service names
    (`llama.cpp`, `smartwardrobe.api`); none of them collides, so nothing real
    loses its line numbers.

- **Everything compose-lint prints about a file is now sanitized at the sink.**
  Escaping lived in a private helper inside the text formatter, so it covered
  that formatter's own fields and nothing else: 26 other print sites emitted
  attacker-derived text raw — service names, file paths, and parse-error text
  that quotes the document — and a terminal or CI log renders control sequences.
  The full CSI repertoire reaching stderr means the file being linted can erase
  findings already on screen.

  Escaping now lives in `compose_lint._output` and **every** stderr write goes
  through `emit()`, so it is the default rather than something each new call
  site must remember; a test fails the build on a raw
  `print(..., file=sys.stderr)` anywhere in `src/`.

  - **A newline can no longer forge a report line.** `_sanitize` passed `\n`
    through "so excerpt layout survives", but the sink is a newline-delimited
    report — a service name carrying one put attacker text in the report's own
    left margin, indistinguishable from a line compose-lint wrote. Values
    rendered as a single record are now escaped with `sanitize_line`, and
    multi-line diagnostics indent their continuation lines so nothing after an
    embedded newline can occupy column zero.
  - **The `fix` dry-run diff is sanitized.** It is the surface a human reads to
    authorise a destructive write, and it printed file content verbatim —
    bidi and zero-width codepoints are YAML-printable, so they survive the
    parser's own check and could display a line in an order the file does not
    have. Sanitizing happens in `render_file_diff`, so all three emit sites are
    covered at once. Display only: `fix --apply` still writes the original
    bytes.
  - **`format_header` sanitizes the config path**, the one unsanitized *stdout*
    site — it sat immediately beside a correctly sanitized `files` argument.

  Measured over the corpus: no findings, exit codes or errors change. Text
  output is byte-identical on 299 of 300 sampled files; the exception is
  PyYAML's parse-error context, whose continuation lines gain two spaces of
  indent. Of the 16 corpus files containing a sanitizable codepoint (all
  zero-width space or BOM), the only visible change is that a leading BOM now
  shows as `\ufeff` in a `fix` diff instead of being invisible — which is the
  point of the fix.

- **The GitHub Action no longer passes where the CLI would fail.** Six defects
  shared that shape, and `action.yml` is fixed as one block.

  - **"No Compose files found" is an error, not a green check.** The lint step
    was gated on `if: steps.find-files.outputs.files != ''`, so a `pattern:`
    that matched nothing skipped the step entirely and the job reported
    success — while the CLI exits 2 for exactly that input. The decision now
    lives inside the script, where it can fail. New `allow-no-files: true`
    input for the case where an empty result is expected.
  - **A SARIF artifact is never uploaded unless it was written.** The re-run
    redirected straight at the target — truncating it before the command ran —
    and `|| true` reported failure as success, so `always()` uploaded a 0-byte
    document and Code Scanning showed no alerts. Output now goes to a
    temporary file that is moved into place only once it holds a complete
    document; a run that produces nothing fails the step, and the upload is
    gated on the file having been written rather than on `always()`.
  - **`sarif-file` is validated to stay inside the workspace.** `>` truncates
    before the command runs, so an unvalidated path let a caller-supplied
    value destroy a file anywhere the runner could write.
  - **The install is pinned by default.** A consumer who SHA-pins `uses:` is
    asking for a reproducible check, but the action installed whatever PyPI
    served at that moment. It now installs the version it was released with;
    `version: latest` opts back in to tracking PyPI.
    `scripts/bump-version.sh` keeps the pin in step and
    `tests/test_action_contract.py` fails if it drifts.
  - **No attacker-controlled text reaches `$GITHUB_OUTPUT`.** Discovered paths
    are written NUL-separated to a file under `RUNNER_TEMP` and only that
    file's path crosses the step boundary, so a filename containing a newline
    can no longer forge output records. Discovery uses `find -print0`, so
    paths containing spaces survive too.
  - **The documented consumer workflow ships a `permissions:` block** —
    workflow-level deny-all plus the two scopes the job actually uses.

- **Five rules now classify the normalized value instead of the spelling.**
  Each decided what a value *was* by matching the raw token, so an equivalent
  spelling walked past it. All five were verified against
  `docker compose config`, and none of the 5,417 files in the corpus uses any
  of them — these are evasion spellings, not things people write by accident,
  so the added coverage costs no false positives.

  | Spelling | before | after |
  |---|---|---|
  | `o: rbind` in `driver_opts` | *silent* | **CL-0001** critical (also CL-0013, CL-0025) |
  | `//dev/sda`, `/dev/./sda` | *silent* | **CL-0016** critical |
  | `privileged: y` / `Y` | *silent* | **CL-0002** critical |
  | `[::0]`, `[0:0:0:0:0:0:0:0]`, `[::ffff:0.0.0.0]` | *silent* | **CL-0005** medium |
  | `read_only: !reset true` | credited as hardened | **CL-0003/0006/0007** |

  - **`o: rbind`** is a recursive bind of the same host path. Bind detection now
    keys off the shape the kernel acts on — `type: none` with an absolute
    `device` under the local driver — rather than the `o:` string being exactly
    `bind`. `type: nfs` and `type: tmpfs` are still not claimed as host paths.
  - **Device paths** run through `normalize_host_path` before the sixteen
    `^/dev/`-anchored patterns see them.
  - **`_TRUE`/`_FALSE`** cover YAML 1.1's single-letter forms. `privileged: y`
    is emitted as `privileged: true` by `docker compose config`, so one
    character hid the tool's highest-severity finding. `n`/`N` are added for
    symmetry; they failed safe.
  - **Bind addresses** are parsed, not matched against a literal set. Every
    spelling of the unspecified address is now recognized in both families; a
    value that is not an address (a hostname) is still not a wildcard.
  - **`!reset` deletes the key it is attached to**, which is what Compose does:
    a file carrying `read_only: !reset true`, `cap_drop: !reset [ALL]` and
    `security_opt: !reset [...]` deploys a service with none of them. Keeping
    the underlying value credited the service with hardening Docker removes, so
    the absence rules stayed silent on an unhardened container. `!override`
    still keeps its value — it changes how a value merges, not what it is.

- **The shipped harnesses now terminate the option namespace with `--`.** A
  repository can contain a directory named `--config=cfgdir` holding a
  `compose.yml`; the resulting path `--config=cfgdir/compose.yml` matches the
  pre-commit hook's `files:` pattern and the Action's discovery, so a harness
  that globbed repo paths straight into argv handed argparse something it read
  as an option. The crafted file left the lint set *and* an attacker-authored
  policy disabling every rule was installed for the run — the gate went green
  over a `privileged` stack mounting `/var/run/docker.sock`. Confirmed
  end-to-end: the pre-commit hook reported `Passed` before this change and
  `Failed` after, on the same repository.

  The pre-commit hook ships `args: [--]` and the Action passes `--` before the
  file list in both invocations (the text run and the SARIF re-run). Setting
  `args:` in your `.pre-commit-config.yaml` replaces the default, so keep `--`
  last if you pass flags — see README.

  The separator is deliberately **not** inserted by the CLI's argv shim: it
  cannot tell a genuine `--config=x` from a file named that, and terminating
  before the first positional would break the documented
  `compose-lint init docker-compose.yml -o ci.yml` form.

## [0.17.0] - 2026-08-12

### Upgrading from 0.16.x

**Four capabilities that passed on 0.16.0 now fail; nothing else moved.**
`SYS_NICE`, `IPC_LOCK` and `LEASE` are flagged by the new CL-0029, and
`SYSLOG` by the new CL-0030 — all four at HIGH, and all four ungraded on
0.16.0, where no rule covered them.

| Trigger | 0.16.0 | 0.17.0 |
|---|---|---|
| `cap_add: SYS_NICE` / `IPC_LOCK` / `LEASE` | *none* | **CL-0029** HIGH |
| `cap_add: SYSLOG` | *none* | **CL-0030** HIGH |

Unlike 0.15.x → 0.16.0, no existing finding changes rule or severity, so a
waiver written against 0.16.0 still covers what it named. The only new
suppressions you may need are for the four capabilities above.

### Added

- **CL-0029 — host-availability capability added** (HIGH): flags `cap_add`
  of `SYS_NICE`, `IPC_LOCK` or `LEASE`. Each reaches the host with nothing
  else in the file and costs availability alone — `SYS_NICE` puts the
  container's threads above every ordinary host process on a scheduler that
  is not namespaced, `IPC_LOCK` pins host RAM past `RLIMIT_MEMLOCK` that
  cannot be reclaimed or swapped, and `LEASE` stalls the host's own `open()`
  on any bind-mounted path for the kernel's lease-break timeout. Each member
  was measured on Docker 29.4.3 holding only that capability under
  `--cap-drop ALL`. The fix text points at `deploy.resources` and at bounding
  a workload that keeps the capability, since SPDK and DPDK ask for
  `SYS_NICE` and `IPC_LOCK` together.
- **CL-0030 — host-disclosure capability added** (HIGH): flags
  `cap_add: SYSLOG`, which reads the host kernel ring buffer — `dmesg` is not
  namespaced, so the container sees the host's boot, hardware and driver log,
  including kernel pointers where `kptr_restrict` allows them. Independence
  from the host's `kernel.dmesg_restrict` was measured rather than assumed:
  with that sysctl at 0, a capless container still read 0 lines against 2,028
  with the capability, because Docker's default seccomp profile admits
  `syslog(2)` only for `CAP_SYSLOG`. The gate is the capability, on any host.

  With SYSLOG graded, every Linux capability now carries a rule or a recorded
  reason it needs none — `test_rule_membership.py`'s ungraded set is empty.

### Changed

- CL-0013's remedy for `/dev/shm` and `/dev/hugepages` is now something the
  reader can actually follow. Both kept firing correctly — a host bind of
  either exposes segments belonging to the host and every other container —
  but the guidance said to drop the mount and "use a named volume", which
  provides neither facility. It now names the real alternatives, each
  verified against Docker 29.4.3 rather than taken from documentation:
  `shm_size:` for a larger segment, `ipc: shareable` plus `ipc: service:` for
  two services that must share one, and a `hugetlbfs` volume for huge pages
  (bounded with `deploy.resources.limits`, since the pool stays host-wide). A
  workload that genuinely needs the host's own huge-page files is told to
  suppress with a reason rather than pretend the mount is safe. Over the
  archived 5,417-file corpus this changed 39 fix texts and zero findings.
- CL-0024's doc now states what the `SYS_ADMIN` judgment call actually
  decides, rather than implying a broader choice than the rule makes.
- `docs/state-of-compose.md` and its four charts are regenerated on a 0.16.0
  baseline, so the published corpus figures reflect the current severity
  model rather than 0.15.x pricing.
- The examples library is refreshed against 0.16.0 — each worked example
  re-linted so its quoted findings, ids and severities match what the release
  actually emits.
- The demo GIFs are re-rendered on 0.16.0.
- Rule counts stated in prose are now held to the registry by
  `tests/test_rule_surfaces.py`. Four surfaces had gone on claiming 25 rules
  after CL-0029 and CL-0030 landed — the mkdocs `site_description` search
  engines index, the Docker Hub overview that syncs on every default-branch
  push, `SECURITY-EXPECTATIONS.md`, and the roadmap inventory — because such
  counts go stale when a rule lands, not when a version ships, so neither the
  release checklist nor CI's version-pin check reached them.

## [0.16.0] - 2026-08-11

### Upgrading from 0.15.x

**Your CI verdict may change in both directions, on files you have not
touched.** This release re-derived every severity and moved findings between
rules, so a gate that passed may fail and a gate that failed may pass. Nothing
here is a parser change: the same file is being read the same way and priced
differently.

**The hazard worth reading twice: a waiver can still parse and no longer
cover anything.** A retired rule id warns on load —
`config: unknown rule id 'CL-0012'; the override has no effect` — and
`--strict-config` turns that into an error. But a waiver naming a rule that
still *exists* is silent, even when the finding it was written for has moved:

```yaml
rules:
  CL-0011:
    reason: "we need SYS_ADMIN for the FUSE mount"   # no longer covers it
```

`SYS_ADMIN` is CL-0024 now. The config is valid, nothing warns, and the finding
comes back at CRITICAL. Check every waiver against the table below.

#### Where findings moved

Generated by linting one trigger per row under both versions.

| Trigger | 0.15.2 | 0.16.0 |
|---|---|---|
| `cap_add: ALL` | CL-0011 CRITICAL | **CL-0024** CRITICAL |
| `cap_add: SYS_ADMIN` / `SYS_MODULE` / `SYS_RAWIO` | CL-0011 HIGH | **CL-0024 CRITICAL** |
| `cap_add: PERFMON` / `SYS_TIME` | CL-0011 HIGH | **CL-0028** HIGH |
| `cap_add: SYS_PTRACE` / `DAC_READ_SEARCH` | CL-0011 HIGH | **CL-0027 MEDIUM** |
| `cap_add: NET_ADMIN` / `BPF` / `SYS_BOOT` | CL-0011 HIGH | CL-0011 HIGH *(unchanged)* |
| `cap_add: DAC_OVERRIDE` | CL-0011 HIGH | *none — Docker default* |
| whole-root mount `/`, either mode | CL-0013 CRITICAL | **CL-0001** CRITICAL |
| writable `/etc`, `/root`, `/boot`, `/proc` | CL-0013 HIGH | **CL-0025 CRITICAL** |
| read-only `/etc` and friends | CL-0013 HIGH | CL-0013 HIGH *(unchanged)* |
| `devices: /dev/sda` and other host disks | CL-0016 HIGH | CL-0016 **CRITICAL** |
| `devices: /dev/fuse` | CL-0016 HIGH | *none — needs `SYS_ADMIN`, which CL-0024 flags* |
| `userns_mode: host` | CL-0010 HIGH | *none — a no-op at Docker's default posture* |

#### Newly flagged — a passing file can now fail

| Trigger | 0.16.0 |
|---|---|
| writable `/var/lib` or `/var/lib/containerd` | CL-0025 CRITICAL |
| `/run` or `/var/run` mounted whole | CL-0001 CRITICAL |
| a path below them — `/run/udev`, `/var/run/libvirt/libvirt-sock` | CL-0013 HIGH |
| `~/.ssh`, `~/.aws`, `~/.docker`, `~/.kube`, `~/.gnupg` | CL-0013 HIGH |
| a relative source that climbs out — `../../../..` | CL-0001 CRITICAL |
| a bind-backed named volume (`driver_opts: {device: …, o: bind}`) | CL-0001 CRITICAL |
| `devices: /dev/md0`, `/dev/vd*`, `/dev/xvd*`, `/dev/mmcblk*` | CL-0016 CRITICAL |

#### No longer flagged — a failing file can now pass

`cap_add: DAC_OVERRIDE` · `userns_mode: host` · `devices: /dev/fuse` ·
`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom` ·
a project directory under a home dir (`/home/alice/proj/data`) ·
`/var/lib/mysql`, `/var/lib/postgresql/data` and other service state dirs ·
anything that was CL-0012, CL-0015 or CL-0023.

#### Check your own files rather than reasoning about this list

```bash
compose-lint check --format json . > before.json   # on 0.15.x
pip install --upgrade compose-lint
compose-lint check --strict-config .               # dead rule ids become errors
compose-lint check --format json . > after.json
diff <(jq -S '[.findings[]|{rule_id,line,service}]' before.json) \
     <(jq -S '[.findings[]|{rule_id,line,service}]' after.json)
```

The diff catches the moved-waiver case, which no warning can reach.

### Added

- **CL-0026 — no memory or CPU resource limits** (MEDIUM). Docker imposes
  neither by default: a container's `memory.max` is `max` and its `cpu.max` is
  `max 100000` unless a limit is set. Fires when a service declares no memory
  limit, no CPU limit, or neither, and names which is missing. Reservations
  (`mem_reservation`, `cpu_shares`) express priority under contention and do not
  satisfy it; `cpu_quota` does. Covers both halves of ATT&CK T1496 Resource
  Hijacking — the memory-exhaustion denial of service and the CPU-bound
  cryptomining that a memory limit does not bound at all.
- Every rule page carries a derivation block — baseline, precondition, impact,
  qualifier, derived, shipped, and an **Evidence** line naming a premise check
  or a captured observation. A test asserts the page and the severity table
  state the same derivation.
- `scripts/validate_rule_premises.py` asserts the daemon under test is at
  Docker's defaults before measuring anything, and aborts if it is not — a
  premise measured against a hardened or loosened daemon returns a confidently
  wrong answer. Five new premise checks: a `:ro` socket is still a working API
  endpoint, a raw host-disk read at default capabilities, the `/dev`-bind
  negative control for it, `core_pattern` writable through an rw `/proc` bind,
  and memory/CPU unbounded by default.
- CI smoke-tests `.pre-commit-hooks.yaml` with the real tool
  (`precommit-smoke`). `action.yml`, the image and the wheel each had an
  end-to-end smoke job; the pre-commit hook had none, which is how issue #465 —
  a `files` pattern that made the hook unable to pass — reached a user.
  `pre-commit try-repo` runs the manifest from the working tree, so `entry`,
  `language` and hook installation are exercised on the PR that changes them.
  `.pre-commit-hooks.yaml` was also missing from the `code` path filter, so a
  manifest-only edit previously skipped the jobs that check it.

### Changed

- **BREAKING — the severity model was rebuilt, and rule ids moved with it.**
  Severities are now *derived* from a documented two-axis matrix under a stated
  attacker baseline and a stated Docker posture, and any rule shipping a
  different value declares an override from a closed reason list. See
  `docs/severity.md`, [ADR-020](docs/adr/020-severity-scoping-and-overrides.md),
  [ADR-021](docs/adr/021-critical-tier-posture.md) and
  [ADR-022](docs/adr/022-threat-model-grounding.md).

  **Severity changes:** CL-0016 HIGH → CRITICAL; CL-0005 HIGH → MEDIUM;
  CL-0007, CL-0014 and CL-0017 MEDIUM → LOW. Only CL-0005 crosses the default
  `--fail-on high` gate: a file whose only finding at or above HIGH was an
  all-interfaces port bind now passes. That is deliberate — CI stops failing on
  intended-public exposure. Use `--fail-on medium`, or override CL-0005 back to
  HIGH in `.compose-lint.yml`, to keep the old behaviour.

  **Rules split.** `cap_add` is now four rules by what the capability grants:
  CL-0024 (CRITICAL: `ALL`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`), CL-0011
  (HIGH, unchanged id: `NET_ADMIN`, `BPF`, `SYS_BOOT`), **CL-0028** (HIGH:
  `PERFMON`, `SYS_TIME`) and CL-0027 (MEDIUM: `SYS_PTRACE`, `DAC_READ_SEARCH`).
  CL-0028 is new: both its members reach the host with no other key in the file
  and nothing from the image — `SYS_TIME` writes the host's wall clock, because
  Docker does not namespace `CLOCK_REALTIME`, and `PERFMON` opens a host-wide
  `perf_event_open` at the upstream kernel default. A service adding either now
  crosses the default gate where it previously reported MEDIUM. The severity
  model gains an `integrity-only` qualifier (one tier down) alongside
  `read-only` and `availability-only`, which is what the impact axis was missing
  for a host effect that corrupts without disclosing or granting control.

  Host paths are two rules: CL-0025 (CRITICAL) for writable mounts of `/etc`,
  `/root`, `/boot`, `/proc`, `/var/lib/docker`, `/var/lib/containerd` and
  `/var/lib`, and CL-0013 (HIGH, unchanged id) for `/sys`, `/dev`, the home tree
  and read-only mounts of CL-0025's paths. A whole-root mount (`/`) is CL-0001's
  in either mode, because it contains the daemon control socket. Neither rule
  branches severity any more, which fixes the SARIF descriptor/finding mismatch
  in #503.

  **Suppression migration.** A `CL-0011` waiver now covers only `NET_ADMIN`,
  `BPF` and `SYS_BOOT`; the other capabilities move to CL-0024, CL-0027 and
  CL-0028 and are no longer covered by it. A `CL-0027` waiver does not cover
  `PERFMON` or `SYS_TIME` — re-waive as CL-0028. A `CL-0013` waiver no longer
  covers a writable root-equivalent path (CL-0025) or a `/run`-family mount
  (CL-0001), and a waiver of a whole-root mount moves to CL-0001 (from CL-0025
  when writable, or from CL-0013 when read-only). Waivers for CL-0012, CL-0015
  and `/var/lib/kubelet` are dead and can be deleted.

- **CL-0013 matches the home tree by depth, not by subtree.** `/home` and a
  single user's home directory (`/home/alice`) are still flagged in either mode,
  and so are the credential directories `~/.ssh`, `~/.docker`, `~/.aws`,
  `~/.kube` and `~/.gnupg` together with everything below them. A deeper project
  path — `/home/alice/projects/app/data` — is the application's own directory
  and is no longer flagged. **Fewer findings** on absolute
  `/home/<user>/<project>/…` mounts, **new findings** on `~/.ssh`-style
  credential mounts. This pairs with relative-source resolution below: `./data`
  resolves to an absolute path under wherever the compose file sits, which for
  most projects is under `/home`, so a subtree match would have flagged the
  commonest bind idiom in Compose.

- CL-0016's device list is reconciled with what a device actually grants. It
  **gains** `/dev/vd*`, `/dev/xvd*`, `/dev/mmcblk*` and `/dev/md*` — the host
  root disks of KVM and Proxmox guests, EC2 instances, Raspberry Pis and mdraid
  arrays, which needed no capability and were not flagged at all. It **drops**
  `/dev/mem`, `/dev/port` and `/dev/fuse`, each live only alongside a capability
  CL-0024 or CL-0009 already flags, and `/dev/kmem` and `/dev/raw`, for which
  Docker refuses to create the container. Suppressions for the dropped devices
  are dead and can be deleted.

- CL-0001 flags any mount that exposes a host control socket, including a
  directory that merely contains one — `/run`, `/var/run`, `/run/containerd`,
  `/run/systemd`, or the whole root `/` — and is mode-independent, because `:ro`
  applies to the socket file rather than to the read-write API behind it. A
  read-only `/` used to be graded CL-0013 HIGH, a tier below the socket it
  exposes. It also matches a socket name on the **host** side of a mount only:
  `- /tmp/fake:/var/run/docker.sock` is no longer reported as a socket mount,
  since the container path is where a socket would land, not where it comes from.

- Host paths are normalised before the mount rules match them, so `.` and `..`
  segments no longer hide a mount. `- /.:/host`, `- /..:/host` and `- /./:/host`
  are whole-root mounts and now report CL-0001 CRITICAL instead of passing
  clean; `/run/.` is matched like `/run`, and `/etc/..` is treated as root
  rather than as CL-0013's HIGH.

- CL-0026 no longer accepts a non-positive value hidden in an interpolation
  default. `mem_limit: ${MEM:-0}` and `cpus: ${CPUS:-0}` describe an unbounded
  container and are now flagged; a bare `${MEM}` still counts as a limit,
  because its value is genuinely unknowable from the file.

- CL-0006 and the `cap_add` rules share one capability normaliser, so
  `cap_drop: [CAP_ALL]` and `cap_drop: ["  ALL  "]` are read the same way
  `cap_add` reads them. `cap_add: [CAP_ALL]` is no longer flagged at all:
  Docker rejects that spelling outright, so the file could never start.

### Removed

- **CL-0012 (PIDs cgroup limit disabled)** — the premise does not hold. On the
  grounded target, `pids_limit: -1`, `pids_limit: 0` and omitting the key all
  produce the same `pids.max` (systemd's `DefaultTasksMax`), so the explicit
  opt-out the rule flagged does not leave the process count unbounded.
- **CL-0015 (healthcheck disabled)** — no runtime delta, and its citations
  mandate the case it declines to flag.
- **`uts: host` and `userns_mode: host`** from CL-0010. Both are no-ops under
  the grounded posture: `sethostname()` needs `CAP_SYS_ADMIN`, which is not in
  Docker's default set, and `userns_mode` only means anything against a
  `--userns-remap` daemon.
- **`/var/lib/kubelet`** from CL-0013 — its danger is entirely conditional on
  Kubernetes being present, so it cannot be premise-checked on the grounded
  target.

  The ids CL-0012, CL-0015 and CL-0023 stay fallow and will not be reused.

### Fixed

- **The mount rules see host paths they were missing.** Each of these mounted a
  real host path and reported clean:
  - **A relative or `~` source.** Compose resolves a relative mount source
    against the compose file's directory and expands a leading `~`; the source
    was matched as written, so `- ../../../../../..:/host` mounted the host root
    filesystem and reported nothing. `./data:/data` and other in-project mounts
    are unaffected.
  - **An interpolated default.** With no `.env` and no exported variable,
    Compose substitutes the default, so `${DOCKER_SOCKET_PATH:-/var/run/docker.sock}`
    mounts the live control socket. A reference with **no** default (`${VAR}`,
    `${VAR:?err}`, `$VAR`) is still left alone — the host path is not knowable
    from the file, and guessing one would invent a finding.
  - **A bind-backed named volume.** `driver_opts: {type: none, device: <host
    path>, o: bind}` is the standard way to pin a bind mount's options, and the
    host path lives in the top-level `volumes:` block, which the mount rules
    never read. `external: true` volumes are left alone, since their host path
    is not in the file.
  - **A writable `/var/lib`** (CL-0025 CRITICAL; read-only, CL-0013 HIGH). It
    contains the container store, so a mount of it grants what `/var/lib/docker`
    does — verified on Docker 29.4.3, a container given only `-v /var/lib` read
    and modified a second container's files. It is matched **exactly**, because
    its grant comes from what it contains rather than from what lies below it:
    `-v /var/lib/mysql`, `/var/lib/postgresql/data` and other service data
    directories are *not* flagged. `/var/lib/containerd` is a member in its own
    right and is matched by descent.
  - **A path below `/run` or `/var/run`** (CL-0013 HIGH) — `/var/run/dbus`,
    which reaches systemd and PolicyKit; `/var/run/libvirt/libvirt-sock`, which
    is VM control; `/run/udev`, `/var/run/utmp`, `/run/systemd/journal`. CL-0001
    owns those directories and their ancestors, because those hold the control
    socket; what sits strictly below holds host service state instead. A
    descendant that *is* a socket stays CL-0001's at CRITICAL.
  - **`/dev/md/<name>`** (CL-0016). mdadm creates a named symlink per array
    alongside the numeric node, and `^/dev/md\d` cannot match it — the character
    after `md` is `/`, not a digit — so a named array passed clean while
    `/dev/md0` beside it was CRITICAL. Added as a second pattern rather than by
    loosening the first, which is what keeps `/dev/mdadm` out.

- **`/dev/null` and the other inert character devices are no longer flagged**
  (CL-0013). `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random` and
  `/dev/urandom` disclose no host state and grant no access — mounting
  `/dev/null` over a config file the image expects is a near-universal idiom,
  and the `/dev` descent match priced it HIGH. The rest of `/dev`, including
  `/dev/shm`, is unchanged.

- CL-0011 no longer flags `DAC_OVERRIDE`, which inverted the default gate
  (issue #492). `DAC_OVERRIDE` is one of Docker's 14 default capabilities, so a
  container holds it whether or not the file names it — flagging it on `cap_add`
  scored the declaration rather than the runtime state. The effect was that
  hardening a service made it fail: `cap_drop: [ALL]` plus
  `cap_add: [DAC_OVERRIDE]` — one capability — exited 1 at the default
  `--fail-on high`, while the same service with no `cap_drop` at all — fourteen
  capabilities, `DAC_OVERRIDE` among them — exited 0. The fastest way back to
  green was to delete the hardening. CL-0011 already excluded `MKNOD` and
  `SYS_CHROOT` for exactly this reason; `DAC_OVERRIDE` was the one default
  capability the list still carried. CL-0006 now names it among the retained
  defaults, so both rules describe the same capability the same way.

- CL-0020 and CL-0021 no longer skip credentials containing `$$`, Compose's
  escape for a literal dollar (issue #502). CL-0020's variable-reference regex
  read the second dollar of `pa$$w0rd` as starting a `$w0rd` substitution, and
  CL-0021 exempted any value containing `$` at all — so exactly the passwords a
  careful user escaped correctly went unchecked, and the two rules disagreed on
  values like `hunter2$`. Both now share one classifier that consumes `$$`
  escapes left-to-right, as Compose does, before testing for a reference.

- Handing compose-lint its own config file no longer fails the run (issue #499).
  `.compose-lint.yml` parses as YAML but has no `services:` key, and its shape
  matched neither of ADR-013's not-applicable buckets, so it fell through to
  `Not a valid Compose file` and exit 2. It is now recognised as a third
  not-applicable shape and skipped with exit 0, like fragments and Compose v1
  files. This is the root cause behind issue #465: `compose-lint init` followed
  by a pre-commit sweep could never pass. Genuinely malformed Compose files
  still exit 2; the check requires *every* non-meta top-level key to be a config
  key, so it cannot swallow a broken file.

- Fourteen false claims across the rule docs, each re-verified against a live
  daemon. The worst was CL-0006's documented `## Fix`, which crash-looped:
  `cap_drop: [ALL]` plus `cap_add: [NET_BIND_SERVICE]` exits with
  `chown("/var/cache/nginx/client_temp") failed (Operation not permitted)`. Also
  corrected: seccomp and AppArmor *do* survive `execve` of a setuid binary;
  `bpf` and `init_module` are capability-gated rather than blocked outright;
  `SYS_BOOT` does not load a kernel via kexec; `pid: host` does not expose
  `/proc/[pid]/environ` at default capabilities; `uts: host` cannot change the
  hostname; a `/dev` bind is not equivalent to `devices:`; `read_only` does not
  prevent persistence through a volume; and `user: root` does not undo a
  gosu/su-exec image's privilege drop.

- CL-0019 was ungrounded — its only citation contained no digest guidance at
  all. It now cites Docker's pull-by-digest documentation and CIS 5.28.

## [0.15.2] - 2026-08-08

### Changed

- Rule-doc headings are now phrased for the queries users actually search
  (issue #471): every `docs/rules/` H1 leads with the rule id then names the
  directive and the symptom it produces (e.g. "CL-0007: read_only — fixing
  'Read-only file system' errors"), and the docs-site nav labels — which set
  each page's `<title>` — are synced to match. Affects the site, the GitHub
  view, and `--explain` output; rule ids and content are unchanged.

### Fixed

- CL-0003's compatibility guidance claimed root-dropping entrypoints
  (`gosu`/`su-exec`: postgres, redis, mysql, …) crash-loop under
  `no-new-privileges` — **live-verified false**: nnp blocks privilege *gain*
  at `execve` (sudo, setuid bits, file capabilities), not a root process's
  downward `setuid()`, and a su-exec image (valkey) runs healthy under the
  flag. The doc and fix text are rewritten around the verified semantics,
  and a CI premise check now pins the drop-unaffected fact so the wrong
  claim cannot silently return.
- Fixed file matching in `.pre-commit-hooks.yaml` that was incorrectly including
  `.compose-lint.yml` if present in the commits. This generated errors
  meaning pre-commit will always fail (issue #465). The hook now matches only
  names beginning `compose` or `docker-compose`, and an `exclude` pattern skips
  compose-lint's own config in either spelling — `.compose-lint.yml` and the
  dotless `compose-lint.yml` that `init -o` can write — with either extension.
  **Note** environment specific files, e.g. `compose-dev.yml`, still match, but
  files with prefixes, e.g. `dev-compose.yml`, no longer do.

  Thanks [@jhomer-hscl](https://github.com/jhomer-hscl) ([#495](https://github.com/tmatens/compose-lint/pull/495)).

### Changed

- CL-0003 gains the "Reading the failure" treatment (the last rule from the
  symptom-table survey): sudo's explicit nnp message (captured live), the
  silent case — a setuid `execve` under nnp *succeeds* with privileges
  unchanged (CI-proven: exit 0, euid intact), so failures surface later as
  ordinary permission errors — the `NoNewPrivs` `/proc` confirmation step,
  and an explicit warning not to confuse the crash-looping `cap_drop`
  symptom (CL-0006's `SETUID` row) with this setting.

### Changed

- CL-0012, CL-0018, and CL-0022 get the symptom → remedy treatment
  (issue #479, same pattern as CL-0006/CL-0007): each rule doc gains a
  "Reading the failure" table quoting verbatim, live-captured error messages.
  CL-0012 maps the fork-failure wordings (chronically misattributed to
  `ulimit -u`) to the pids cgroup with a `pids.max`/`pids.current`
  confirmation step; CL-0018 maps non-root `Permission denied` writes by
  mount type, backed by two CI-proven facts — a tmpfs over an existing image
  directory inherits its root ownership (use `uid=`/`gid=`), and named-volume
  initial ownership follows Docker's copy-up rules; CL-0022 frames the
  `noexec` exec failure as relocate-first, `:exec`-with-documented-reason
  last, since the naive fix is the finding. Six new CI premise checks prove
  the busybox rows live. CL-0002's fix text now points at CL-0006's
  capability-determination guide instead of stopping at `<SPECIFIC_CAP>`.

## [0.15.1] - 2026-08-08

### Added

- Documentation site at <https://tmatens.github.io/compose-lint/> (issue
  #470) — the rule docs, configuration guide, severity model, hardening
  walkthrough, and State of Compose report, built by mkdocs from the same
  `docs/` markdown that `--explain` prints (single source, no duplicated
  pages) and deployed to GitHub Pages by the new `docs` workflow on every
  push to `main`. The docs toolchain is hash-pinned in
  `requirements-docs.lock` (new `docs` extra).

### Fixed

- The README's *State of Compose* report link was relative, so it 404'd in
  the PyPI rendering of the project description; it now points at the docs
  site, as do the rule-table and hardening-guide links (previously GitHub
  blob URLs).

### Changed

- CL-0007's guidance gets the same symptom → remedy treatment as CL-0006
  (issue #474): the rule doc gains a "Reading the failure" table mapping
  verbatim `Read-only file system` errors to remedies **by path type** —
  ephemeral paths to `tmpfs:`, persistent data to a named volume (never
  `tmpfs`, which silently erases it on restart), plus the masked
  `No such file or directory` symptom when the image lacks the directory.
  The finding's `fix` text carries the path-type rule and points at
  `--explain CL-0007`. Four new CI premise checks prove the busybox rows
  live, including that named volumes stay writable under `read_only`.

- The CL-0006 symptom → capability table now covers 11 mappings — added
  `NET_ADMIN`, `SYS_NICE`, `SYS_TIME`, `FOWNER`, `KILL`, and `IPC_LOCK` — and
  quotes the verbatim error messages real tools emit, captured from live
  container runs (issue #468). Every mapping is re-proven on each CI run by
  new checks in `scripts/validate_rule_premises.py` — the operation must fail
  under `cap_drop: [ALL]` (busybox wordings asserted verbatim; coreutils
  variants captured live but not CI-asserted) and succeed with only the
  mapped capability added — so an engine default change that invalidates a
  row (as Docker 20.10's `ip_unprivileged_port_start=0` did for the old
  "low ports need `NET_BIND_SERVICE`" folklore) fails CI instead of aging
  silently in the docs.

- CL-0006's fix guidance now teaches how to *determine* an image's required
  capability set instead of stopping at a `<SPECIFIC_CAP>` placeholder
  (issue #4). The finding's `fix` text gains the drop-and-observe method and
  the common `Operation not permitted` → capability mappings, and
  `docs/rules/CL-0006.md` (also served by `--explain CL-0006`) gains a full
  "Determining required capabilities" section covering the symptom→capability
  table, the `capable` BPF tool, `docker diff`, and entrypoint inspection.
  Both stress verifying *function*, not just startup: capability failures are
  often non-fatal, silently degrading a feature (e.g. DHCP device discovery
  under a dropped `NET_RAW`) while the container stays "healthy" — so review
  logs and exercise background behaviors after every change.
  Guidance-only per [ADR-019](docs/adr/019-withdraw-security-profile-catalog.md):
  no per-image capability data is bundled.

## [0.15.0] - 2026-08-07

### Removed

- **Profile enrichment has been withdrawn** ([ADR-019](docs/adr/019-withdraw-security-profile-catalog.md),
  superseding ADR-017 and ADR-018). The `compose_lint.profiles` package, the
  `scripts/validate_profiles.py` validator, the `profile-validate` CI gate, the
  `profiles` config block, and `run_rules`' `profile_lookup` parameter are all
  gone — roughly 2,200 lines across source, tests and docs.

  The feature matched a service's `image:` against a catalog of csd-derived
  security profiles and appended an image-specific hint to a finding's `fix`
  text. It shipped as an opt-in experimental preview, and the automation that
  ADR-017 §7 requires before any profile may be endorsed as `validated` (issue
  #360) was never built — it depends on csd emitting the catalog schema and on a
  BPF-capable runner. compose-lint was therefore carrying a complete consumer of
  a catalog that does not exist, behind a flag whose only honest setting was off.

  **Upgrade impact is limited to configuration.** A leftover `profiles:` block in
  `.compose-lint.yml` is now simply an unrecognized top-level key: it takes the
  standard warn-and-continue path, printing a stderr warning and leaving the exit
  code unchanged, so ordinary runs keep working. Under `--strict-config` it is a
  hard error (exit 2), as any unrecognized key is. No finding, severity, exit
  code, or output format changes — enrichment was additive-only, so nothing that
  was reported before is reported differently now.

  `CL-0009` ("Security profile disabled") is **unaffected**: it covers seccomp
  and AppArmor `security_opt` settings and is unrelated to this catalog.

### Fixed

- The GitHub Action snippet in `README.md` now pins the current release.
  `publish.yml`'s `bump-marketplace-smoke-pin` job rewrote the
  `tmatens/compose-lint@<sha> # vX.Y.Z` pin only in
  `.github/workflows/marketplace-smoke.yml`, so the copy-paste snippet users
  actually take from the README stayed a release behind every time — it was
  still on v0.14.0 after v0.14.1 shipped. The job now rewrites both files,
  and the stale pin is corrected.
- `release-prep.yml` now bumps the self-referencing version pins in
  `README.md` and `docs/` as part of the version-bump commit. The
  `version-consistency` job has required those pins to match
  `pyproject.toml` since #443, but release-prep only touched
  `pyproject.toml`, `__init__.py`, and `CHANGELOG.md` — so the release PR it
  opened failed its own required check on every release and needed a
  hand-pushed fixup commit.
- The sdist no longer ships whatever happens to sit in the maintainer's
  working tree. `[tool.hatch.build.targets.sdist]` was a denylist of nine
  known paths, but hatchling ships everything the *root* `.gitignore` does
  not exclude and does not read nested `.gitignore` files — so a local
  virtualenv, which writes its own `.gitignore: *` and is therefore
  invisible to `git status`, was swept in: 158 of 445 entries, 35% of a
  3.5 MB archive, including `bin/python` as an absolute symlink into the
  build machine's filesystem. Such an archive is not merely untidy but
  unusable — uv rejects it as an invalid tar — and nothing caught it:
  `twine check` validates metadata, not contents, and `publish.yml`'s
  content guard inspects the wheel alone. The sdist target is now a
  root-anchored allowlist, and `publish.yml` gates the sdist on symlinks
  and virtualenv markers. Published artifacts were never affected: release
  builds run from a clean checkout, and the wheel packages `src/` only.

### Changed

- Documentation no longer describes auto-fixable findings as "safe". `README.md`,
  `docs/dockerhub-overview.md`, and `docs/SECURITY-EXPECTATIONS.md` said `fix`
  applies "safe, mechanical edits", which invites the reading that applying them
  is harmless. Per ADR-014 the guarantee is a property of the *edit* — one
  unambiguous value, no collateral change, still-valid YAML — not of the
  outcome: `read_only: true` and the `127.0.0.1` port rebind both change runtime
  behavior by design, and are surfaced with a `⚠ behavior-changing` caveat
  rather than withheld. The docs now say "mechanically unambiguous", state the
  edit/outcome distinction explicitly, and show the caveat line a user will see.

## [0.14.1] - 2026-07-31

### Fixed

- `fix --apply` now prints the `⚠ behavior-changing` caveats for the fixes it
  applied, in the same form the dry-run diff uses. Previously the caveats were
  rendered only on the dry-run path, so a one-shot `compose-lint fix --apply`
  (the CI and script-pipeline case) wrote behavior-changing edits and printed
  only `applied N fix(es)` — the warning never reached the user at the moment
  it mattered. Runs whose edits all carry no caveat print no banner; stdout
  stays data-clean. Reported from the r/selfhosted feedback thread (#425,
  #428).

## [0.14.0] - 2026-07-29

### Added

- **Profile schema 1.6: optional per-dimension `derivation.features` — the
  feature ledger.** A drop-test proves the minimum only for what its correctness
  check exercises; the ledger records, as structured data instead of criteria-doc
  prose, which of the image's *privilege-relevant* features the workload did
  (`driven: true` + evidence) and did not (`driven: false` + the honest reason)
  drive. Human-authored, bounded by asking "what is each requested privilege
  FOR?" (1–3 entries per image in practice). Opt-in evidence, not a tax: with no
  ledger a profile's workload-coverage claim simply stays `partial` (ADR-018).
  Optional and additive — all 1.0–1.5 documents remain valid. See ADR-017 §13.
- **Profile schema 1.5: optional top-level `reference_url`.** An HTTPS link to the
  profile's rendered, human-readable page — the full derivation context (evidence
  table, invocation, criteria prose, provenance) that a one-line enrichment hint
  cannot carry. When present, enrichment surfaces it on the enriched finding's
  `references` (first, so the text formatter's `ref:` line shows the image-specific
  page rather than the rule's generic citation; JSON carries all references). The
  reference catalog publishes these pages at
  [tmatens.github.io/container-security-profiles](https://tmatens.github.io/container-security-profiles/).
  Optional and additive — all 1.0–1.4 documents remain valid. See ADR-017 §12.

- **Profile schema 1.4: optional `derivation.run_config.sysctls`.** Records the
  kernel sysctl posture a *posture-dependent* capability minimum was derived under.
  The canonical case is `net.ipv4.ip_unprivileged_port_start`: Docker defaults it
  to 0 (all ports unprivileged, so a low-port bind needs no cap and NET_BIND_SERVICE
  reads falsely-removable), while the kernel default of 1024 makes the cap required —
  the "works on my Docker, breaks in k8s" divergence. csd already pins the hardened
  posture and emits the `sysctls` list; this field lets the published profile state
  which posture its minimum assumes, so a consumer can reconcile against their own
  runtime instead of guessing. Optional and additive — all 1.0–1.3 documents remain
  valid; absent/empty means no sysctl was pinned. See ADR-017 §11.
- **`check --strict-config` / `fix --strict-config`.** Opt-in strict mode that
  turns config diagnostics that are normally stderr warnings — an unknown or
  typo'd rule id (`CL-001` vs `CL-0001`), an unknown top-level or per-rule key,
  an unknown `profiles` key — into hard errors (exit 2). Without it, a malformed
  config's warning can be lost in a redirect and silently disable the wrong rule;
  strict mode fails the run loudly instead. Default behavior is unchanged.

### Fixed

- **`check --format sarif` and `fix` no longer abort a batch when a file becomes
  unreadable mid-run.** Both re-read the source after parsing (for SARIF fix
  edits / to apply fixes); if the file was deleted, unmounted, or had its
  permissions changed between the parse and that second read, the `OSError` is
  now recorded per-file and the scan continues to the remaining files instead of
  crashing the whole run.

## [0.13.0] - 2026-07-05

### Added

- **Validated profiles must declare immutable version tags.** The profile ci-smoke
  gate (`scripts/validate_profiles.py`) now rejects a `status: validated` profile
  whose `applies_to.tags` includes a mutable rolling tag (`latest`, `stable`,
  `edge`, `main`, `nightly`, …): such a tag points to a different image over time,
  so a derivation done against it cannot be trusted to still apply to the image a
  consumer later pulls. Exploratory profiles are unaffected, and no existing catalog
  profile uses a mutable tag, so this guards against a future mistake without
  changing current data.
- **Profile schema 1.3: `app_tier_verified`.** An optional top-level block on a
  profile recording that the whole hardening was verified at the **service** level
  — the multi-container stack brought up with every dimension applied and a real
  service-level check passed — a stronger signal than the per-dimension workload,
  which exercises only one container. Fields: `service`, `service_version`,
  `method`, `check`, `verified_date`, `result`, and an optional `over_hardening`
  (`applied` + `result`) that proves the check catches a too-tight config (not a
  rubber stamp). Requires `status: validated` (schema) and `result: pass`
  (ci-smoke gate). Optional and additive — all 1.0–1.2 documents remain valid, and
  it never substitutes for the per-dimension `validated_via` evidence. ADR-017 §10.

### Fixed

- **Profile-enrichment hints no longer collapse across services in text output.**
  The fix-block dedup keyed on `rule_id` alone, so when two services were flagged
  by the same rule but enrichment gave them **different** image-specific guidance
  (e.g. postgres → `cap_add: [CHOWN, DAC_OVERRIDE, SETGID, SETUID]`, caddy →
  `cap_add: [NET_BIND_SERVICE]`), the second service was rendered
  `(see fix above)` — pointing at the *first* service's wrong-image recommendation.
  The dedup now keys on `(rule_id, fix, references)`, so distinct hints each print
  in full while identical fixes still collapse.

### Changed

- **Profile enrichment is now labeled experimental.** The feature is already
  opt-in and off by default (`profiles.enabled`); this makes its provisional
  status explicit. When enrichment is active, compose-lint prints a one-line
  stderr reminder that fix recommendations are advisory, derived for a specific
  invocation, and not validated against your runtime — and the config docs mark
  the section experimental. No behavior change to the findings themselves.
- **Clearer profile-enrichment caveat.** The provenance tail `not independently
  verified here` is replaced with `compose-lint can't see your runtime, confirm
  it fits your setup` — it names the actual limit (a static linter reads the
  compose text, not the running container, and can't confirm the recommendation
  matches your invocation) rather than a vague disclaimer.

### Added

- Profile schema **1.2** (ADR-017 §9): an optional `derivation.run_config` block
  recording the invocation a minimum was derived under — `user`, `command`,
  `entrypoint`, `network`, `pid`, `devices`, `security_opt`, `mounts`, and `env`
  (keys only, never values). A derived minimum is only valid for its invocation
  (postgres run with `user:` set skips the root→user drop and needs none of the
  startup caps a default-invocation profile lists), so a consumer can diff a
  target service against it and downgrade to a hint on divergence. Emitted by
  csd's drop-test producer, not hand-authored. Additive — all 1.0/1.1 documents
  remain valid.
- Opt-in profile enrichment (ADR-017). Set `profiles.enabled: true` and point
  `profiles.path` at a catalog of container-sec-derive (csd) profiles you trust;
  findings from CL-0006/0007/0002/0011/0016 then gain image-specific fix guidance
  — e.g. the observed minimum `cap_add` for that image. Enrichment is advisory
  and additive only (it never creates, drops, or reclassifies a finding) and the
  hint is attributed and marked unverified. Off by default. Per ADR-017 §7,
  compose-lint ships **no catalog of its own** — the catalog is a user-configured
  external source, so the linter neither grows nor endorses profile data.
- Profile contribution path (ADR-017): `scripts/validate_profiles.py` (the
  ci-smoke gate — schema, validated/exploratory invariants, and workload-hash
  verification), a `profile-validate` CI job that runs it on catalog changes, and
  a contributor guide (`docs/profiles.md`).

## [0.12.2] - 2026-06-13

### Security

- CL-0021 no longer exhibits quadratic (ReDoS) behavior on crafted env values.
  A value shaped like `scheme://<many chars>:<many chars>` with no terminating
  `@` made the connection-string regex rescan the tail from every offset —
  O(n^2) on attacker-controlled input, a cheap DoS when sweeping untrusted
  Compose files. The rule now bails before scanning when the value contains no
  `@` (the pattern requires one, so this changes no findings).
- The text formatter now escapes terminal-unsafe code points — C0/C1 controls
  (ANSI/escape-sequence injection), DEL, and bidirectional/zero-width formatting
  characters — in every string derived from an untrusted Compose file (finding
  messages, fix text, service names, paths, and the on-disk source excerpt). A
  crafted image or service name could previously smuggle a U+202E override (to
  make a malicious tag render as a benign one) or, via the source excerpt that
  is read straight off disk and bypasses the parser's printable-character check,
  a raw ANSI escape into a terminal or CI log. They now render as visible
  `\uXXXX` escapes. JSON and SARIF output were already safe (`ensure_ascii`).
- The corpus fetcher (`scripts/corpus/`, development tooling) now pins the
  download host and refuses redirects. It rewrites `github.com` blob URLs to
  `raw.githubusercontent.com`, but a candidate whose prefix didn't match was
  left intact and fetched verbatim, and `urlopen` follows redirects by default —
  so a malformed or hostile candidate URL could have turned a download into a
  request against an internal or attacker-chosen host (SSRF). The fetcher now
  rejects any non-`https://raw.githubusercontent.com/` URL before opening it and
  uses an opener that does not follow redirects. Candidate URLs come from the
  GitHub API, so this is defense-in-depth.

### Added

- ADR-016 records the runtime rule-premise validation bar — the second,
  `docker run`-based arm of rule grounding that `scripts/validate_rule_premises.py`
  and the `rule-premises` CI job already enforce. It captures *why* the policy
  exists (the CL-0022 rework and CL-0023 removal), which previously lived only in
  the CHANGELOG and the script's docstring, and extends ADR-002.
- A registry-wide consistency test (`tests/test_rule_consistency.py`) that fails
  if any rule's emitted `Finding.rule_id`/`severity` drift from its
  `metadata.id`/`severity`. Each rule states these twice and nothing else tied
  them together, so a typo could desynchronise the SARIF rule descriptor's
  `security-severity` from a result's `level`. Deliberate per-finding escalation
  (CL-0011, CL-0013) is declared in an allow-list; adding it elsewhere is a test
  failure by design.

## [0.12.1] - 2026-05-25

### Changed

- CL-0022 is reworked. As shipped in 0.12.0 it flagged tmpfs entries *missing*
  `noexec`/`nosuid`/`nodev` — but Docker mounts every tmpfs with all three by
  default (verified across the short, list, and long forms, and with `size=`
  set), so the old rule fired on already-secure configs and missed the real
  weakening. It now flags the *presence* of `exec`, `suid`, or `dev`, which
  explicitly remove those defaults, at LOW (was MEDIUM). A plain `tmpfs: [/tmp]`
  is no longer flagged; `tmpfs: [/tmp:exec]` is. The auto-fix is dropped — the
  option is set deliberately, so reverting is left to manual review.

- CL-0012's message no longer asserts a container can "create unlimited
  processes" and fork-bomb the host. A container's `pids.max` is bounded by the
  cgroup hierarchy (often a high parent cap, occasionally unbounded), so the
  finding now says the limit is left to whatever that hierarchy allows. The rule
  is unchanged — it still flags an explicit `pids_limit` of 0 or negative.

### Removed

- CL-0023 (dangerous network sysctls), shipped in 0.12.0, is removed. Verified
  against real Docker, its premise did not hold: `net.ipv4.ip_forward` and
  `net.ipv4.conf.all.send_redirects` are already `1` by default in every
  container (so flagging them flagged the platform default), and Docker rejects
  `net.*` sysctls under host networking — so the rule's "acute under host
  networking" case is a configuration Docker refuses to start. Hit rate was 0%
  across the corpus. Pre-1.0, the `CL-0023` id is freed and may be reassigned to
  a future rule. The remaining net.* deviations (`accept_source_route`,
  `accept_redirects`, IPv6 forwarding) are too niche and weakly grounded to
  carry a rule on their own.

## [0.12.0] - 2026-05-25

### Added

- The `init` subcommand generates a starter `.compose-lint.yml` from a Compose
  file's findings (ADR-011). Each finding becomes a per-service
  `exclude_services` entry with a placeholder reason for triage — never a global
  `enabled: false`, so a service added later still trips the rule. All
  severities are emitted and annotated; it writes `.compose-lint.yml` in the
  current directory by default (`-o PATH` to override), refuses to overwrite an
  existing config without `--force`, writes nothing for a clean file, and sends
  status to stderr. Takes a single `FILE`. Bare `compose-lint <file>` and
  `compose-lint check` are unaffected.

- CL-0022 flags `tmpfs:` mounts that omit `noexec`, `nosuid`, or `nodev`
  (MEDIUM). A writable, executable in-memory mount is a payload-staging surface,
  especially under `read_only: true` where tmpfs is often the only writable
  path. Covers the short string/list `tmpfs:` form (the long `volumes:` form
  can't express these flags through Compose); the message names the missing
  flags. `compose-lint fix` appends them in place, preserving existing options
  like `size=`, with a caveat that `noexec` is behavior-changing.

- CL-0023 flags services that enable an escape-adjacent `net.*` sysctl —
  `ip_forward`, IPv6 `forwarding`, `accept_source_route`, and ICMP
  `accept_redirects`/`send_redirects` (MEDIUM). Enabling these turns the
  container into a network pivot, most acutely with host networking (CL-0008)
  or multiple networks. Handles the map and list `sysctls:` forms; a value of
  `0` and unlisted sysctls are not flagged. No auto-fix — the parameter is set
  deliberately when present, so removal is left to manual review.

### Changed

- CL-0011 now flags the `PERFMON` capability (HIGH), completing the pair split
  out of `SYS_ADMIN` in Linux 5.8 (`BPF` shipped in 0.10.0). A service with
  `cap_add: [PERFMON]` that previously passed will now report a finding.

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

[Unreleased]: https://github.com/tmatens/compose-lint/compare/v0.25.0...HEAD
[0.25.0]: https://github.com/tmatens/compose-lint/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/tmatens/compose-lint/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/tmatens/compose-lint/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/tmatens/compose-lint/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/tmatens/compose-lint/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/tmatens/compose-lint/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/tmatens/compose-lint/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/tmatens/compose-lint/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/tmatens/compose-lint/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/tmatens/compose-lint/compare/v0.15.2...v0.16.0
[0.15.2]: https://github.com/tmatens/compose-lint/compare/v0.15.1...v0.15.2
[0.15.1]: https://github.com/tmatens/compose-lint/compare/v0.15.0...v0.15.1
[0.15.0]: https://github.com/tmatens/compose-lint/compare/v0.14.1...v0.15.0
[0.14.1]: https://github.com/tmatens/compose-lint/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/tmatens/compose-lint/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/tmatens/compose-lint/compare/v0.12.2...v0.13.0
[0.12.2]: https://github.com/tmatens/compose-lint/compare/v0.12.1...v0.12.2
[0.12.1]: https://github.com/tmatens/compose-lint/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/tmatens/compose-lint/compare/v0.11.0...v0.12.0
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
