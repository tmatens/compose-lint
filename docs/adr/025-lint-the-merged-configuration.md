# ADR-025: Lint the Configuration Compose Runs, Not the File on Disk

**Status:** Accepted

**Context:** `docker compose up` with no `-f` loads the base file **and**, if a
`compose.override.yml` sits beside it, merges that on top. No flag, no opt-in.
The merged result is what runs, and the convention puts the portable definition
in the base and the local changes — published ports, bind mounts, socket
mounts, relaxed hardening — in the overlay.

compose-lint read the base alone. Measured on a hardened base with a two-line
overlay adding `ports:` and a `/var/run/docker.sock` mount, it reported one
MEDIUM about an unpinned digest. **CL-0001, the highest-severity rule in the
tool, was silent on a stack that would run with the host control socket
exposed**, and the banner said `files: compose.yml` with nothing to indicate
that half the effective configuration had never been read.

The gap ran in both directions, which the original report missed. A base with
no `read_only` reported CL-0007 on its own; with an overlay supplying
`read_only: true` the deployed container is read-only and the finding is
false. So the behaviour was not merely "the overlay is unexamined" — the base
was **graded against a view the user never runs**.

This is the same class as the coverage gaps [ADR-023](023-deploy-host-independent-claims.md)
refuses loudly. It was the only one that was silent.

Three findings from a spike changed how the options cost out:

1. **`extends:` merges identically to multi-file overlays.** Twelve field
   behaviours probed against `docker compose config` match exactly, so one
   table serves both. The existing `_merge_extends` concatenated every
   sequence, which is wrong for Compose in both — it reported a CRITICAL
   socket mount against a service that had *replaced* that mount at the same
   container path, pointing at the line that replaced it. The merge table was
   therefore required to fix a shipped false positive, independent of overlays.

2. **Cross-file provenance is cheap, not the blocker it was costed as.**
   Rules never touch the line map; they receive a flat `{path: line}` dict and
   hand the result to `Finding.line`. Making the line number an `int` subclass
   that carries its own document path threads the answer through every rule,
   formatter and fixer untouched. The field-specific merge table is the
   expensive half; provenance is roughly thirty lines.

3. **Merging is MINOR, not breaking.** [compatibility.md](../compatibility.md)
   states that new findings are not a breaking change — rules are added and
   tightened in MINOR releases and a clean file may report findings in the
   next one. Reading more of the stack produces exactly that.

**Decision:** When a Compose file is linted and the overlay Compose would merge
into it sits beside it, compose-lint merges the pair and grades the result —
option C of the three considered. The merge is field-specific, derived from
`docker compose config` rather than from the specification prose, and shared
with `extends:`.

1. **Merging is announced, and does not change the exit code.** The header
   names both documents (`files: compose.yml + compose.override.yml`) and a
   note states what was merged. Unlike an unresolved `include:`, this is
   coverage *achieved* rather than missed, so it must not turn a green
   pipeline red. Exit stays finding-driven.

2. **Findings name the document their evidence is written in.** A merged run
   grades two files and a line number belongs to one of them. The text
   excerpt is read from that file, and SARIF points its `artifactLocation`
   there. Base-file findings keep the URI they had, and with it their
   `partialFingerprints` ([ADR-024](024-finding-identity-is-not-prose.md)) —
   the findings that move are ones that were never reported at all before, so
   no existing alert is re-keyed.

3. **`fix` edits only what it can attribute.** A finding written in the file
   being fixed is safe to edit: its line is a line in that text, and an
   absence finding fires only when the key is missing from the *merged*
   document, so adding it to the base genuinely hardens what runs. Findings
   from the overlay are reported for manual review — the overlay is never a
   write target. Verification re-merges the candidate, because the properties
   being verified are properties of the document Compose runs.

4. **Values merge as written.** Compose normalises short volume syntax to
   long, list `environment` to a mapping, and so on. The merge does not,
   because every rule reads the spelling the user typed and a normalising
   merge would change what they see.

5. **`--no-merge-overrides` opts out**, for a base deliberately graded in
   isolation and as an escape hatch if the merge is ever wrong. It reproduces
   the previous output exactly. This is opt-*out*: the default is the
   configuration that runs.

**Alternatives considered:**

- **Do nothing, document it.** The gap stays silent, which is the part that
  sits worst against ADR-023 — a user with an overlay has no way to learn
  their socket mount was never examined. It also leaves the base graded
  against a view nobody deploys.

- **Detect and warn (coverage gap, exit 2).** Smaller, and consistent with the
  `include:` precedent, but it buys less than it appears to: it makes the
  silence loud without making the grading right, and it introduces an exit-2
  condition that this decision would later remove — turning a pinned
  pipeline red, then green again. The doctrinal difference is the deciding
  one: an unresolved `include:` is a gap because compose-lint *cannot* read
  the file; a sibling overlay is a gap because it *does not*. Being loud about
  what you cannot do is honest; warning about something you could simply do is
  a placeholder.

- **An opt-in flag.** Defers the question, adds a surface, and leaves the
  default grading a document that is not deployed.

**Consequences:**

- Files clean on a previous release may report findings, including CRITICAL
  ones. This is the documented MINOR behaviour, and the escape hatches are the
  documented ones: pin the version, or gate on `--fail-on`.
- `Finding` gains `source_file`, emitted in JSON only when a finding's evidence
  is in a document other than the file being reported. Additive and
  conditional, so `SCHEMA_VERSION` does not move.
- Naming a file absent from the repository is safe for SARIF. Verified against
  real Code Scanning: every result ingested with no analysis warning and the
  alert stayed queryable at the overlay's path. `sarif-ingestion.yml` re-checks
  it weekly, since GitHub can tighten ingestion with no commit here.
- **Accepted limitation.** GitHub renders source previews from the commit tree,
  so an alert located in an untracked overlay shows its location without a code
  snippet and can never appear as a PR diff annotation. That degrades a panel
  rather than losing a finding, and it requires an overlay generated during the
  build to arise at all — a gitignored overlay is absent from a CI checkout, so
  nothing merges one there.
- The merge table is now a compatibility surface with Compose itself.
  `tests/test_merge_semantics.py` re-derives it from the `docker compose`
  binary on every run rather than trusting comments, so a Compose release that
  changes a merge rule fails there instead of silently mis-grading a stack.

**Scope:** This ADR covers the overlay Compose merges by filename convention.
It does **not** cover `COMPOSE_FILE`, which replaces discovery entirely, or
`.env`, which supplies interpolation values — both change the effective
configuration and both are unread today. They turn on whether a file beside the
compose file counts as project state or host state under ADR-023, which is a
different question with a different answer, and are tracked separately.
