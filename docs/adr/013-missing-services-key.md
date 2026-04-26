# ADR-013: Handling Compose Files Without a Top-Level `services:` Key

**Status:** Accepted

**Context:** Running compose-lint 0.5.2 over a 1,554-file real-world corpus
from public GitHub repos showed that **18% of files (286 / 1,554)** failed
with `Not a valid Compose file: missing 'services' key` and exited 2. Those
files fall into two broadly recognisable buckets that a sweep-mode user
(`compose-lint **/*.yml`, pre-commit, CI lint over a monorepo) does not
care about:

1. **Compose v1 files** — services declared at the top level, no
   `services:` wrapper. Docker
   [retired Compose v1 in 2023](https://www.docker.com/blog/new-docker-compose-v2-and-v1-deprecation/#compose-v-1-so-long-and-farewell-old-friend),
   but plenty of v1 files are still in the wild.
2. **Fragments / overrides** — partial files designed to be merged via
   `extends:` or layered with `-f override.yml`. Top-level `volumes:`,
   `networks:`, `version:`, or `x-*` blocks only.

The status-quo behaviour conflated both of these with genuinely malformed
input, made directory sweeps noisy, and — combined with multi-file
fail-fast (issue #158) — silently dropped findings on later files in argv.
Issue #155 enumerated four options for the policy. This ADR records the
chosen one.

**Decision:** Adopt **Option D** from #155: distinguish "not a v2/v3
Compose file" from "broken Compose file" at the parser layer, and route
the not-applicable case to a per-file skip with **exit 0**. Genuinely
malformed input continues to **exit 2**.

Concretely:

- `parser.ComposeNotApplicableError` is introduced as a `ComposeError`
  subtype. Existing callers that catch `ComposeError` continue to handle
  the new case (no breakage); callers that want to special-case "skip"
  catch the subtype.
- `_validate_compose` invokes `_classify_missing_services(data)` when
  `services:` is absent, returning either the new subtype (skip) or the
  existing `ComposeError` (hard fail).
- The CLI catches `ComposeNotApplicableError` per file, prints a
  `<filepath>: Skipped: …` line to stderr, and `continue`s. The file is
  not counted as a failure for exit-code purposes.

**Heuristic for classifying a missing-`services:` file:**

```text
non_meta = top-level keys, excluding `__lines__`, fragment-skeleton keys
           {version, name, volumes, networks, configs, secrets, include},
           and anything starting with `x-`

if non_meta is empty                                  → fragment skip
elif every non_meta value is a mapping containing
     at least one key from the v1 service-marker set  → v1 skip
else                                                  → hard error
                                                        ("missing 'services' key")
```

The v1 service-marker set is the set of v1-schema keys that strongly
identify a top-level mapping value as a service definition (`image`,
`build`, `command`, `entrypoint`, `ports`, `volumes`, `environment`,
`env_file`, `depends_on`, `container_name`, `restart`, `links`, `expose`,
`working_dir`, `user`, `cap_add`, `cap_drop`, `privileged`, `read_only`,
`devices`, `security_opt`, `network_mode`, `networks`, `extends`).

**Skip messages:**

- Fragment: `Skipped: file appears to be a Compose fragment (no 'services:'
  key; only top-level structural keys present). Fragments are typically
  merged via 'extends:' or '-f' overlays and have no services to lint on
  their own.`
- v1: `Skipped: file appears to be Compose v1 (services declared at the
  top level, no 'services:' wrapper). Docker retired Compose v1 in 2023;
  compose-lint targets v2/v3. Migrate the file under a top-level
  'services:' key to enable linting.`

**Alternatives rejected:**

- **Option A — status quo (hard-fail every missing-`services:` file).**
  Loses 18% of real-world inputs in sweep mode. Conflates v1 and fragments
  with malformed input under one error message users read as "your file is
  broken."
- **Option B — soft-skip everything as an info-level finding (exit 0).**
  Hides genuinely broken files behind a low-severity finding. CI gates
  scanning for non-zero exit codes wouldn't notice a malformed compose
  that happens to drop `services:`.
- **Option C — auto-detect v1 and lint it as if it were v2.** Recovers
  more signal (v1 files do have hardening issues to flag), but commits
  compose-lint to maintaining a v1-to-v2 shim for a format Docker has
  retired. Adds a heuristic that will silently mis-lint borderline cases.
  Worth revisiting only if users explicitly ask for v1 support; until
  then, "skip with a clear migration message" is the right default.
- **Lumping v1 and fragments under one skip message.** The v1 case has
  remediation guidance (migrate under `services:`); the fragment case
  does not. Two messages cost a few extra lines and pay off in clarity.

**Rationale:**

- Sweep-mode UX. `compose-lint **/*.yml` over a monorepo no longer
  exits 2 on the first v1 file or `-f` overlay it encounters. This is
  the workflow the corpus run exposed as broken.
- Honest semantics. Exit 2 keeps meaning "the linter could not run on
  this input"; exit 0 + skip means "the linter ran, this file is outside
  scope, nothing to report." Distinct outcomes get distinct exit codes.
  A single-file invocation against a v1 file exits 0 with a clear stderr
  message — the file isn't broken, the linter just doesn't apply.
- Defence-in-depth against masking real bugs. The "hard error" branch is
  preserved for the unrecognised case (top-level mapping with non-meta
  keys whose values aren't service-shaped). A user with a typo'd
  `srvices:` still gets exit 2.
- Public API stability. `ComposeNotApplicableError` subclasses
  `ComposeError`, so library callers that already do
  `except ComposeError` keep their behaviour; only callers that *want*
  to discriminate need the new type.

**Interaction with other work:**

- **ADR-006 (exit codes)** is unchanged. Exit 2 still means "usage /
  file errors"; this ADR carves out a subset that exits 0 because the
  file isn't actually a usage error.
- **#158 (multi-file fail-fast for `ComposeError`)** is independent. The
  new skip path uses `continue`; the existing hard-fail path still calls
  `sys.exit(2)`. When #158 lands, both paths will collect into the same
  per-file outcome bookkeeping and the exit-code policy will be revisited
  end-to-end.
- **#156 (grouped text output)** will eventually want a "skipped files"
  count in the aggregate footer. Out of scope here; the per-file stderr
  line is enough signal until #156 lands.

**Implementation notes (non-binding):**

- `parser.py` exposes `_TOP_LEVEL_FRAGMENT_KEYS` and `_V1_SERVICE_MARKERS`
  as module-private frozensets so the heuristic can be tuned in one
  place.
- Fixtures live alongside the existing invalid-Compose files in
  `tests/compose_files/`: `fragment_volumes_only.yml` and
  `legacy_v1_compose.yml`. The pre-existing `invalid_no_services.yml`
  was repurposed to cover the unrecognised-shape branch (no `services:`,
  no fragment-skeleton keys, no v1-shaped values).
- The heuristic is intentionally narrow on the fragment side: a top-level
  mapping with `version: "3"` and a single `volumes:` block is a
  fragment; a top-level mapping with `mystery_key: 5` is not. False
  positives on fragment detection silently lose findings, so the
  whitelist of "what counts as fragment scaffolding" stays small and
  obvious. The v1 side is broader because v1 files have visibly
  service-shaped top-level values, which gives a cleaner positive
  signal.
