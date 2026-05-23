# ADR-014: `fix` — Automated Remediation of Auto-Fixable Findings

**Status:** Proposed

**Context:** compose-lint tells a user what is wrong and how to fix it, but
today the fix is prose the user applies by hand. Milestone 3 of the roadmap
(`docs/ROADMAP.md`) proposes turning the unambiguous subset of findings into
edits the tool applies itself. This is the project's strongest differentiation
against KICS/Checkov/Trivy, which report Compose issues but do not remediate
them.

Three prior decisions constrain how `fix` can be built, and one open tension
shapes how it should ship:

- **ADR-003 (no ruamel.yaml).** The runtime depends only on PyYAML, and
  `CommentedMap`/`CommentedSeq` round-trip types are explicitly banned from
  leaking into the codebase. PyYAML's `safe_dump` discards comments, reflows
  quoting, and reorders keys — so the "parse → mutate object → re-serialize"
  remediation strategy is not available. A fixer must not destroy the parts of
  the file it isn't fixing.
- **ADR-011 (subcommand model).** `fix` is already named there as the
  motivating case for `add_subparsers` — "a destructive variant with its own
  flag set." That ADR supersedes the roadmap's older `--fix --apply` flag
  spelling: `fix` is a subcommand, not a flag on `check`.
- **SARIF history (#168).** `result.fixes[]` was *removed* in 0.6.0 because
  SARIF 2.1.0 requires `artifactChanges` on every fix object, and
  `Finding.fix` is human prose, not a machine-applicable patch. Re-introducing
  SARIF fixes requires producing real structured edits — the same artifact a
  fixer produces to write to disk.
- **1.0 tension.** Per `docs/RELEASING.md`, 1.0 is a *contract freeze* (CLI,
  config schema, JSON/SARIF shape), not a feature checklist. `fix` is additive
  and correctness-risky. We do not want a half-built, destructive fixer to
  become part of the frozen 1.0 surface, nor do we want to block 1.0 on it.

The intent of this ADR is to decide the *mechanism*, *edit model*, *CLI shape*,
*safe-rule set*, *refusal policy*, and *release strategy* for `fix`. The exact
text each rule emits (placement within a service block, comment annotations) is
left to implementation, except where it forces a decision here.

**Decision:** Eight decisions.

1. **Edit mechanism — surgical text patching, not re-serialization.** `fix`
   computes minimal byte-range replacements against the original file text and
   splices them in. It never re-dumps the document. Everything outside a
   touched span is preserved byte-for-byte.
2. **Edit model — a shared `TextEdit`.** A rule's fixer returns structured
   edits `(start_line, start_col, end_line, end_col, replacement)` (1-indexed,
   SARIF region convention). The same model renders three ways: a unified diff
   (dry-run), an in-place write (`--apply`), and SARIF `artifactChanges`.
3. **CLI shape — `compose-lint fix [FILE ...]`,** a subcommand per ADR-011.
   Dry-run is the default and prints a unified diff to stdout; `--apply` writes
   in place. `--only CL-XXXX` (repeatable) narrows the rule set.
4. **Safe-rule set — every finding with a *mechanically safe* fix** (Part 4): a
   single rewrite, determined entirely by the file, that resolves the finding
   and leaves valid Compose — by adding a hardening directive or deleting a
   security-weakening override. All 21 rules were evaluated; six qualify:
   CL-0003, CL-0005, CL-0007, CL-0009, CL-0014, CL-0015. CL-0003 is
   hardening-only; the other five change runtime behavior and ship a **mandatory
   per-fix caveat** in the dry-run (Parts 3–4). Behavioral risk is carried to the
   user via the caveat + experimental warning, not by excluding the fix. The
   remaining fifteen stay report-only (ambiguous value, external lookup, granted
   resource, secret relocation, or architectural).
5. **1.0 relationship — `fix` does not gate 1.0.** Per `docs/RELEASING.md`, 1.0
   is a contract freeze, and the contract (CLI, config, JSON/SARIF) is ready
   independently of `fix`. 1.0 ships on stability; `fix` is promoted as the
   headline of a later MINOR (target 1.1). The roadmap's remediation thesis is
   satisfied by `fix` shipping in 1.x, not by it landing in `1.0.0`
   specifically.
6. **Release strategy — ship undocumented and experimental, gated in stages.**
   `fix` lands on main behind a hidden subcommand (`argparse.SUPPRESS`) with a
   loud stderr experimental warning, **explicitly excluded from the SemVer
   contract**, and **gated behind `COMPOSE_LINT_EXPERIMENTAL=1` in its first
   (single-rule) phase**. The gate relaxes in three stages (Part 5) as corpus
   evidence accrues. This lets it merge incrementally and be dogfooded against
   the corpus without making promises or blocking 1.0.
7. **Refusal policy — refuse, never guess.** When a finding sits on an
   anchored/merged service, in flow style that can't be edited unambiguously,
   or anywhere the correct edit is not unique, `fix` leaves the file untouched
   and reports the finding as manual-only. A wrong fix is worse than no fix.
8. **SARIF — reintroduce `artifactChanges`** rendered from the `TextEdit`
   model, restoring (correctly) what #168 removed.

---

## Part 1 — Edit mechanism

### Option A — Surgical text patching *(chosen)*

Treat the file as text; compute minimal `(region → replacement)` edits from the
finding's location and splice them into the original bytes.

Pros:
- Honors ADR-003. No new dependency, no `CommentedMap` leakage, no need to
  revisit the parser library decision.
- Non-destructive by construction. Comments, key order, quoting style, blank
  lines, and trailing whitespace outside the edited span are preserved. The
  resulting diff is the diff a careful human would have written.
- Reuses existing groundwork. `LineLoader` already captures per-key and
  per-sequence-item positions (`parser.py`); `fix` is the write-side mirror of
  that read-side tracking.
- Produces the structured edit SARIF needs anyway (Part 7). One artifact, three
  renderings.

Cons:
- Indentation, flow-vs-block style, and insertion-point must be inferred from
  surrounding text rather than handed to us by a serializer. This is real work
  and the source of most of the test surface.
- Each fixer carries some text-shaping logic instead of just mutating a dict.
  Mitigated by a shared helper layer (indent inference, list-item insertion,
  scalar replacement) so individual rules stay small.

### Option B — Parse, mutate, re-serialize with PyYAML

Pros:
- Fixers are trivial: mutate the dict, dump.

Cons:
- Destroys comments, reorders keys, reflows quoting and string styles across
  the *entire* file, not just the fixed span. The diff is enormous and the user
  cannot trust it. Disqualifying on its own.
- Cannot represent "add `read_only: true` *here*" — only "the whole file now
  looks like this."

### Option C — Adopt ruamel.yaml round-trip mode

Pros:
- Purpose-built for comment-preserving round-trips.

Cons:
- Directly violates ADR-003 and the CLAUDE.md "no ruamel.yaml" rule (packaging
  instability, round-trip types leaking into rule code). Reopening that decision
  is out of scope and unjustified when text patching covers the safe-rule set.

### Rationale (mechanism)

The no-ruamel constraint already decided this; the ADR's job is to make it
explicit and name the consequence: `fix` is a **text-patching engine, not a
YAML emitter.** The cost (style inference) is bounded and testable; the benefit
(trustworthy minimal diffs) is the whole point of an auto-fixer a user will run
against files they care about.

---

## Part 2 — Edit model and the fixer interface

A fixer is an optional capability a rule advertises. The proposed interface:

```python
@dataclass(frozen=True)
class TextEdit:
    start_line: int      # 1-indexed, SARIF region convention
    start_col: int       # 1-indexed
    end_line: int
    end_col: int
    replacement: str     # may be multi-line; "" for pure deletion
    caveat: str | None = None   # behavioral note; set on behavior-changing fixes

class BaseRule:
    def fix(self, finding: Finding, data, lines, text: str) -> list[TextEdit] | None:
        """Return edits that remediate `finding`, or None if not auto-fixable
        / not safe to fix in this file (see refusal policy)."""
        return None  # default: rule is report-only
```

Binding properties:

- **Idempotent.** Applying the output of `fix --apply` and re-running `fix` must
  produce zero edits. Re-linting a fixed file must not re-fire the same rule.
  Both are asserted in the corpus regression gate (Part 6).
- **Non-overlapping within a file.** Edits are collected across all rules, sorted
  by position, and checked for overlap before application. Overlapping edits on
  the same region are a refusal, not a merge.
- **Applied bottom-up.** Edits are spliced from the last position to the first so
  earlier offsets stay valid as later text changes length.
- **Engine-owned application.** Rules produce `TextEdit`s; a single
  `apply_edits(text, edits) -> str` in the engine performs the splice. Rules
  never write files.
- **Behavior-changing fixes carry a `caveat`.** A fixer whose edit alters what
  the container does at runtime — not merely its hardening posture — MUST set
  `caveat` to the failure mode it introduces (what can break, and how to avoid
  it). The dry-run renderer surfaces it and marks the hunk (Part 3); hardening-
  only fixes leave it unset.

Rationale: a single position-based edit model is the common denominator of the
three things we must produce — a diff, a write, and SARIF `artifactChanges` —
and keeps the destructive operation in one auditable place rather than smeared
across 21 rules.

---

## Part 3 — CLI shape and write semantics

`compose-lint fix [FILE ...]`, registered alongside `check` and `init` via the
`add_subparsers` work ADR-011 already calls for.

Flags (v-experimental):

| Flag | Behavior |
|------|----------|
| *(none)* | Dry-run. Print a unified diff of proposed edits to **stdout**; status to stderr. Writes nothing. |
| `--apply` | Write edits in place. |
| `--only CL-XXXX` | Restrict to the named rule(s); repeatable. |
| `--config PATH` | Honor `.compose-lint.yml` so suppressed/excluded findings are not "fixed" (see Part 6). |

### Behavior-changing fixes are flagged in the diff

A fix that only tightens posture without changing what the container does at
runtime (CL-0003) renders as an ordinary hunk. A fix that *changes runtime
behavior* — CL-0005 alters network reachability, CL-0007 makes the rootfs
unwritable — renders with a `⚠ behavior-changing` marker and its `caveat`
printed inline above the hunk:

```
⚠ behavior-changing · CL-0007: read_only:true breaks the container if it writes
  to its root filesystem. Declare writable paths via tmpfs/volumes first.
--- docker-compose.yml
+++ docker-compose.yml
@@ services.web @@
     image: nginx:1.27
+    read_only: true
```

This is in addition to the global experimental warning (Part 5). The intent: a
reader of the dry-run sees at a glance *which* edits are pure hardening and
*which* could break their workload, before deciding to `--apply`. The same
caveat text rides into SARIF as a `note`-level message on the fix (Part 7) so
Code Scanning consumers see it too.

### Write-flag naming — `--apply` *(chosen)*

ADR-011 floated `--in-place`; the roadmap wrote `--apply`. This ADR settles on
**`--apply`** and supersedes ADR-011's illustrative spelling.

Pros:
- Pairs with the dry-run mental model: *preview the diff, then apply it.*
- Avoids sed's `-i`/`--in-place` connotation of unconditional, backup-free
  mutation.

Cons:
- `-w`/`--write` (gofmt, prettier) is a common alternative spelling some users
  will reach for first. Acceptable; documented in `fix --help`.

### Exit codes (extends ADR-006)

- Dry-run: **0** on success (diff printed or nothing to do), **2** on
  usage/parse error. It does *not* exit 1 when edits are available — a deferred
  `--check` mode (Out of scope) is the right home for "fail CI if unfixed."
- `--apply`: **0** on a successful write (the findings were remediated), **2** on
  usage/parse/write error.
- Residual non-auto-fixable findings do **not** make `fix` exit 1. Consistent
  with `init` (ADR-011): for `fix`, findings are the input, not the failure
  signal. Use `check` for the pass/fail gate.

Rationale: `fix` is an operation that produces an artifact (a diff or a modified
file), like `init`, not a gate like `check`. Its exit codes follow the artifact
model, and stdout/stderr follow the CLAUDE.md split (diff = data on stdout,
status = stderr) — the second stdout-emitting mode CLAUDE.md and ADR-011
anticipated. This is the point at which the text-mode banner gate in `cli.py`
must either extend to cover `fix` or status lines move to stderr permanently;
`fix` chooses the latter for its own output (no banner; diff only).

---

## Part 4 — Safe-rule set

Auto-fix is offered for every finding with a **mechanically safe** fix:

> a single rewrite, determined entirely by the file (no external lookup, no
> value the author must choose), that resolves the finding and leaves a valid
> Compose file — either by **adding a hardening directive** or by **deleting a
> security-weakening override so the platform's secure default re-applies.**

Behavioral risk is not handled by narrowing this set; it is handled by surfacing
a caveat per fix and the global experimental warning (Parts 3, 5). Six rules
qualify:

| Rule | Edit primitive | Runtime behavior | Caveat |
|------|----------------|------------------|--------|
| **CL-0007** read-only fs | Insert `read_only: true` | **Changes** — rootfs becomes unwritable; breaks containers that write to it | **Required** |
| **CL-0003** no-new-privileges | Append `no-new-privileges:true` to `security_opt:`, or create the list | Hardening-only — blocks setuid escalation; near-zero breakage | None |
| **CL-0005** unbound ports | Prepend `127.0.0.1:` to the host side | **Changes** — drops non-local reachability; breaks intended LAN/remote access | **Required** |
| **CL-0009** unconfined profile | Delete the `seccomp:unconfined` / `apparmor:unconfined` entry | **Changes** — default seccomp/AppArmor profile re-applies; a workload needing a blocked syscall may fail | **Required** |
| **CL-0014** logging disabled | Delete `driver: none` | **Changes** — default logging driver re-enabled; logs collected again (disk/IO) | **Required** |
| **CL-0015** healthcheck disabled | Delete the healthcheck `disable` | **Changes** — image's default healthcheck re-enabled; an unhealthy status can affect `depends_on`/orchestration | **Required** |

Only CL-0003 is hardening-only; the other five change runtime behavior and ship
a **mandatory dry-run caveat** (Part 3). Implementation groups by edit primitive,
not severity: insertion (CL-0007) is the vertical slice, then the deletions
(CL-0009/0014/0015 — structurally simplest, see below), then list-append/create
(CL-0003), then the in-scalar edit (CL-0005, the riskiest to parse).

**Why these six and not the other deletion rules.** The line is *revert a
guardrail vs. revoke a granted resource*:

- CL-0009/0014/0015 turn a **platform security default back on.** seccomp, logging,
  and healthchecks apply whether or not the file mentions them; the finding is an
  explicit *opt-out*, and deleting it restores the default. No compensating change
  is needed for the service to stay well-formed.
- CL-0002 (privileged), CL-0008 (host network), CL-0010 (host namespaces), CL-0011
  (`cap_add`), CL-0013 (sensitive mount), CL-0016 (devices), CL-0017 (mount
  propagation) **grant the container access to a host resource or capability** it
  otherwise would not have. Deleting that strips function the author added on
  purpose, the secure "default" restores no equivalent, and a compensating change
  (specific caps, explicit port maps) is usually required. They fail the
  definition and stay report-only.

**Deletion fixers must leave a valid block or remove it whole.** Removing the sole
entry of `security_opt:` / `logging:` must drop the now-empty parent key, not
leave `security_opt: []`. If a deletion would leave a structurally partial block
it cannot fully resolve (e.g. `logging.driver: none` alongside `logging.options`),
the fixer **refuses** (Part 6) rather than emit a broken file.

**Out of auto-fix scope (report-only).** The other fifteen rules fail the
definition:

- **Ambiguous value / external lookup:** CL-0004 (which version?), CL-0019 (digest
  needs a registry), CL-0006 (which capabilities? — issue #4), CL-0012 (which
  limit?), CL-0018 (which user? — deletion may not even resolve it).
- **Revokes a granted resource** (above): CL-0002, CL-0008, CL-0010, CL-0011,
  CL-0013, CL-0016, CL-0017.
- **Context-dependent secret relocation:** CL-0020, CL-0021.
- **Architectural:** CL-0001 (socket-proxy sidecar).

Rationale: "mechanically safe" is a property of the *edit*, not the *risk* — every
qualifying fix is unambiguous and leaves a valid file. Where the edit also changes
behavior, the caveat carries that risk to the user rather than hiding the fix from
them. Rules whose correct fix needs information the file doesn't contain stay
report-only, where prose guidance already serves.

---

## Part 5 — Release strategy: undocumented and experimental

`fix` is destructive and correctness-risky, and we want it on main early for
incremental review and corpus dogfooding without (a) advertising a half-built
fixer, (b) making SemVer promises about it, or (c) entangling it with the 1.0
contract freeze. The decision is to ship it **hidden and experimental**, then
promote.

### Option A — Hidden subcommand + experimental warning, excluded from contract *(chosen)*

- Registered with `help=argparse.SUPPRESS`, so it does not appear in
  `compose-lint --help`. Absent from README and docs (except this ADR).
- Every invocation prints a one-line stderr warning:
  `warning: 'fix' is experimental and unstable; output and flags may change
  without notice. Review the diff before --apply.`
- `docs/RELEASING.md` is amended to state that **experimental subcommands are
  not part of the SemVer contract** — their behavior, flags, and existence may
  change in any release, including patch. 1.0 can freeze the rest of the surface
  while `fix` matures behind this carve-out.
- **Exposure relaxes in three stages** as corpus evidence accrues, never the
  reverse:
  1. *Phase 1* (engine + CL-0007): registration is **gated behind
     `COMPOSE_LINT_EXPERIMENTAL=1`** *and* `SUPPRESS`ed — it cannot be
     discovered or invoked by accident at all.
  2. *Phase 2* (all six rules, corpus regression green): drop the env gate;
     keep the subcommand hidden and the stderr warning.
  3. *Phase 3* (promotion criteria met): remove `SUPPRESS`, document in README
     and `--help`, enable SARIF fixes, announce in CHANGELOG, and bring `fix`
     under the SemVer contract.

Pros:
- Mergeable in small slices (Part 6 phasing) with real CI and corpus testing,
  not stranded on a long-lived branch.
- No user relies on unfinished behavior; the curious can opt in; the contract is
  untouched.
- Cleanly decouples `fix` from the 1.0 decision — answers the open tension
  directly: 1.0 ships when the contract is ready, `fix` promotes when *it's*
  ready, independently.

Cons:
- A hidden command still exists in shipped artifacts; a determined user can find
  and run it. The stderr warning and (optional) env gate are the mitigations —
  acceptable for a non-default, dry-run-by-default operation.
- Two states to track (experimental vs. promoted) and a documented promotion
  step. Lightweight; the promotion criteria below make it mechanical.

### Option B — Documented from day one, marked "experimental" in the docs

Pros: honest discoverability; users can find and try it.

Cons: invites bug reports and CI adoption against a moving target; pressure to
keep early flag spellings; risks the surface drifting into the 1.0 freeze before
it's ready. Premature for a destructive feature.

### Option C — Long-lived feature branch until complete

Pros: zero exposure.

Cons: no CI on main, painful rebases, no incremental dogfooding against the
corpus, big-bang merge risk. Worst option for a correctness-sensitive feature
that benefits most from running against real files early.

### Promotion criteria (experimental → documented + contract-covered)

`fix` graduates — removing `SUPPRESS`, adding README/`--help` docs, enabling
SARIF fixes (Part 7), announcing in CHANGELOG — when all hold:

1. All six safe rules implemented, each with the corpus regression gate green.
2. Corpus run: every auto-fixable finding either fixed-and-clean or explicitly
   refused; **zero** fixed files fail to re-parse; **zero** non-idempotent fixes.
3. Refusal policy (Part 6) exercised by tests for anchors, merge keys, and flow
   style.
4. `fix --apply` round-trips: fixed file re-lints with the targeted rules
   silenced and no new findings introduced.
5. **Full-corpus soak:** `fix` runs clean against at least one *fresh* full
   corpus pull (the ~6.4k-file fetch, not just the committed snapshot fixtures).
   The long-tail file shapes the snapshot can't capture must be exercised — and
   refusal rate measured — before promotion.

Until then, treat `fix` like an internal tool that happens to ship in the wheel.

---

## Part 6 — Refusal policy and the corpus gate

**Refuse (leave untouched, report as manual-only) when:**

- The finding's service inherits via merge key (`<<:`) or YAML anchor/alias, so
  the edit's correct target (anchor vs. service) is ambiguous.
- The relevant block is in flow style (`security_opt: [...]`,
  `ports: ["8080:80"]`) and the minimal edit isn't unambiguous.
- Two fixers want overlapping regions.
- `${VAR}` interpolation sits inside the span to be edited (the resolved value
  is unknown; CL-0005's port host could be a variable).

**Respect suppression.** A finding suppressed or service-excluded via
`.compose-lint.yml` (ADR-010) is never fixed — suppression is a deliberate human
decision. `fix` loads config like `check` does.

**Corpus regression gate** (new test, runs against `~/.cache/compose-lint-corpus/`
fixtures, mirrors `test_corpus_snapshot`): for every file, fix → assert it still
parses, re-lints with the targeted rules cleared, and a second `fix` is a no-op.
This is the safety net that makes shipping `fix` defensible, and the reason
experimental-on-main (Part 5) beats a branch.

---

## Out of scope for this ADR

- **`fix --check`** (exit 1 if edits would be made, à la `black --check`) — a
  CI-gate convenience; additive, defer until requested.
- **`--backup` / `.bak` files** — rely on the user's VCS for v-experimental;
  revisit if requested.
- **Expanding the safe-rule set** beyond CL-0003/0005/0007 — each addition is its
  own decision against the Part 4 bar.
- **Capability profiles for CL-0006** (issue #4) — a prerequisite for ever
  auto-fixing CL-0006, tracked separately.
- **Interactive / per-finding confirmation** (`fix -i`) — adds a TTY dependency
  story; the dry-run-then-apply flow covers the need.
- **Exact emitted text and comment annotations** per rule — implementation
  detail, except the style-matching constraints stated above.

## Implementation notes (non-binding)

- `cli.py`: register `fix` under the ADR-011 subparser with
  `help=argparse.SUPPRESS`; emit the experimental stderr warning in its handler.
  Guard registration on `COMPOSE_LINT_EXPERIMENTAL` for the first (single-rule)
  phase; drop the env guard at Phase 2 (see Part 5 exposure stages).
- Engine: add `apply_edits(text, edits) -> str` (sort, overlap-check, splice
  bottom-up) and an edit-collection pass that calls `rule.fix(...)` for each
  finding whose rule advertises a fixer.
- Reuse `LineLoader` positions; where a fixer needs a column the loader doesn't
  retain, extend the sidecar rather than re-parsing.
- Diff rendering: stdlib `difflib.unified_diff` over original vs. patched text.
  No new dependency.
- SARIF: a `region` (`startLine`/`startColumn`/`endLine`/`endColumn`) plus
  `artifactChanges[].replacements[]` built from each `TextEdit`; gate emission on
  promotion so experimental edits don't leak into a contract-shaped artifact.
- Phasing: (1) edit engine + CL-0007 behind the env gate; (2) deletions
  CL-0009/0014/0015 + CL-0003; (3) CL-0005; (4) corpus gate; (5) SARIF +
  promotion.
- Tests: per-rule fix fixtures (block & flow style, 2- and 4-space indent,
  present/absent target block), idempotency, refusal cases (anchor, merge key,
  `${VAR}` in span), suppression respected, bare/`check`/`fix` argv routing,
  exit codes.

## Consequences

- compose-lint gains remediation — the roadmap's strongest differentiator —
  without a new runtime dependency and without reopening ADR-003.
- The work merges to main in reviewable slices and is continuously validated
  against real-world files, rather than accumulating on a branch.
- 1.0 is unblocked: the contract can freeze with `fix` deliberately carved out as
  experimental, and `fix` promotes on its own timeline via a documented,
  mechanical criteria check.
- A new destructive code path exists. It is dry-run by default, hidden,
  warned-on, refusal-first, and corpus-gated — the mitigations are
  proportionate, and `apply_edits` centralizes the risk in one tested function.
