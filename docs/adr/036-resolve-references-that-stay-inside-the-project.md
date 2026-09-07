# ADR-036: Resolve `include:` and `extends:` References That Stay Inside the Project

**Status:** Accepted

**Context:** Four constructs in a Compose document point at another file. Two
are graded by *where the path resolves*; two are refused as coverage gaps
without the path ever being inspected.

| Construct | Resolves inside the project | Resolves outside |
|---|---|---|
| `env_file:` | read | note, exit 0 ([ADR-027](027-grade-env-file-where-the-document-routes-it.md) §7) |
| `COMPOSE_FILE` (via `.env`) | honoured | refused ([ADR-026](026-read-the-sibling-env-file.md) §4) |
| `extends: {file: ...}` | **coverage gap, exit 2** | coverage gap, exit 2 |
| `include:` | **coverage gap, exit 2** | coverage gap, exit 2 |

The containment rule the first two rows use is already implemented, tested and
shipped: `_service_env._project_relative()`'s lexical segment math, then
`_safe_read.escapes_project()`'s filesystem gate, then
`_safe_read.read_text_bounded()` for the FIFO / `/dev/zero` / size hazards.
"Project" is the directory containing the file being linted (`_selection.py`),
which is also what Compose defaults its project directory to. Both gates must
pass; resolution failure counts as escaping, so it fails closed. The hard
questions — where the boundary is, and what to do about a committed symlink
that passes lexically — were settled there, not here.

**The refusal has a real cost, and it is not theoretical.** A coverage gap is
not a finding, so `--fail-on` does not gate it: an unresolved reference exits 2
at every threshold, `critical` included. The only flag that clears it,
`--allow-partial-coverage`, is run-level — a project with one same-directory
`extends:` must downgrade *every* gap in that run, including genuinely
unreviewed ones. The condition entered in 0.18.0, so a pipeline pinned below it
and gated on `--fail-on` went red on the upgrade, on a document the tool never
claimed was insecure, with neither escape hatch `docs/compatibility.md` named
able to help. That is how this was found: the Compose file was changed, because
changing the Compose file was the only remedy the documented contract offered.

**Corpus evidence** (Corpus 2.0, 11,111 files; ~10,400 parsing as Compose
documents with a `services:` map). `extends: {file: ...}` appears in 75
documents / 291 references: 231 same-directory, 55 subdirectory, 5 climbing
above the file, 0 absolute, 0 interpolated — **98.3% inside**. `include:`
appears in 30 documents / 273 references, and those split across two distinct
code paths:

| Population | Docs | Refs | Subdir | Same dir | Climbs |
|---|---:|---:|---:|---:|---:|
| `include:` alongside `services:` (coverage gap, exit 2) | 21 | 28 | 7 | 13 | 8 |
| include-only files (parse-time rejection, exit 2 under every command) | 9 | 245 | 241 | 2 | 2 |

The headline "96% inside" for `include:` is carried by nine include-only
monorepo roots, one with 117 entries. For the coverage-gap population alone,
29% of references climb out. So resolving `include:` is only worth the work if
it also lifts the include-only rejection — which decision 2 does.

Stated plainly, the corpus stores files individually under content-hashed names
with no sibling context, so it measures the **shape of the reference path**,
not whether the target was present in the source repository. It bounds how
often the escape case arises, not how often resolution would succeed.

**The [ADR-023](023-deploy-host-independent-claims.md) objection.** That ADR
lists this refusal as one of its four founding precedents, and its third
decision says a rule that follows document references through the lint host's
filesystem is claiming a deploy-host fact it cannot know. The objection does
not survive contact with the two constructs:

- An `include:` or `extends:` target is *another Compose document*, and Compose
  itself refuses to run without it (a missing include target is `open …: no
  such file or directory`, exit 1). A reference that resolves inside the
  project is therefore part of the shipped configuration by necessity, not by
  the lint host's luck — the divergence ADR-026 and ADR-027 had to reason about
  for `.env` and `env_file:` is much smaller here.
- ADR-027 §7 already crossed this line for `env_file:` on a weaker case, and
  drew the boundary at the same place: inside the project directory is the
  document set that travels with the file; outside it is lint-host context.

What ADR-023 actually forbids is *resolving through the host* — following
symlinks, expanding the host's `~`, asking the host's environment. The
filesystem gate here rejects a symlink that leaves the project rather than
following it, and the lexical gate is identical on every platform. The
principle is kept; the precedent is amended.

**Decision:**

1. **Apply the existing two-gate containment rule to both `extends: {file}`
   and `include:`** — `_project_relative()` lexically, `escapes_project()` at
   resolution time, `read_text_bounded()` for the read. Project is the
   directory of the file being linted.
2. **Lift the include-only parse-time rejection** when every entry resolves
   inside and is present. Any entry unresolved keeps exit 2: nothing at all was
   linted, and a 0 there would be the [#516](https://github.com/tmatens/compose-lint/issues/516)
   false pass.
3. **Reporting follows [ADR-025](025-lint-the-merged-configuration.md)'s
   shape.** The header lists every merged document; findings name the file the
   evidence is written in. `.compose-lint.yml` and suppressions are read once,
   from the primary file's directory — an included file must not be able to
   narrow the gate's scope (ADR-026 §4's principle). `fix` keeps rewriting only
   the primary file, with the existing "Only findings written in this file can
   be fixed here" note.
4. **Recursion follows `include:` and `extends:` chains as Compose does**,
   under a depth cap of 8 and a file-count cap of 64, reusing the existing
   recursion guard and bounded reader. A cycle or an exceeded cap is a coverage
   gap. A `compose.override.yml` or `.env` beside an *included* file is **not**
   merged: override discovery stays a property of the primary file.
5. **Interpolation for an included file uses its own directory** — its default
   `.env` there, or the object form's `env_file` when that resolves inside. An
   `env_file` or `project_directory` that leaves the project is a gap.
   `--no-env` widens to cover them, following ADR-027 §8. The object form's
   `path` is honoured as string or list.
6. **Duplicate service names across included files mirror Compose.** If Compose
   errors, it is a gap at exit 2; if it warns and keeps one, take the same one
   and note it. No third behaviour is invented.
7. **What stays a coverage gap:** a reference that climbs out, an absolute or
   `~` path, an interpolated path, a missing target, a bounded-read refusal, a
   symlink failing the filesystem gate, a cycle or an exceeded cap, and
   (pending 6) a duplicate service. The message says *which* — "outside the
   project directory", "not found" — rather than today's "not resolved", and
   keeps the caller-scoped remedy sentence from
   [#784](https://github.com/tmatens/compose-lint/pull/784): `check` names
   `--allow-partial-coverage`, `fix` does not.
8. **The bump policy gains the two rows this issue exposed**, in
   `docs/RELEASING.md`'s cheat sheet, and `docs/compatibility.md` names
   `--allow-partial-coverage` as the third escape hatch beside pinning and
   `--fail-on`. Both land before the 1.0 tag, per
   [ADR-030](030-the-policy-is-part-of-the-contract.md).

| Change | Post-1.0 class |
|---|---|
| Add an exit-2 coverage-gap condition | MINOR, announced one release ahead as a warning (stderr + machine note), enforced the next release — [ADR-031](031-severity-upgrades-are-minor-with-runway.md)'s runway pattern |
| Retire an exit-2 coverage-gap condition | MINOR |

A gap cannot be absorbed by `--fail-on`, so a bare MINOR would turn a
threshold-gated pipeline red with no documented hatch; the runway gives the
same one release of warning ADR-031 gives a severity upgrade. The strict MAJOR
reading was considered and declined: it would make every future coverage
improvement that first has to be *detected* unshippable without a 2.0, and it
would retroactively classify 0.18.0 as breaking.

**Verified against Compose 5.5.0** on a synthetic fixture, because two of these
decisions turn on resolution semantics a spec reading got wrong:

1. Relative paths inside an *included* file resolve against the included file's
   directory.
2. Relative paths inside a cross-file `extends:` base resolve against the
   *base* file's directory, not the extending file's. The spec sentence
   "relative to the location of the main Compose file" describes the `file:`
   value itself, not the paths inside the base.
3. A missing include target makes Compose itself exit 1.
4. Compose *accepts* an `extends:` base outside the project directory. Refusing
   it is the linter's containment choice, exactly as in ADR-027 §7.

**Consequences:**

- Bind-source resolution needs a **per-document base directory**.
  `_resolved_bind_source` takes one `base_dir` today; merged documents must
  each carry their own. Attribution is already solved — findings carry their
  source document via `SourcedLine`.
- Exit codes move only for *resolved* references, identically under every
  command. `check` on an inside, present `include:`/`extends:` goes from 2 to
  the ordinary 0/1 findings verdict; an include-only file whose entries all
  resolve becomes lintable under `check`, `check --allow-partial-coverage` and
  `fix` alike. Every residual in decision 7 keeps today's code, so the
  exit-code contract itself is untouched.
- A resolved base can surface a finding that was previously invisible, so a
  file can go 0 → 1. That is the new-findings class, and it is why retiring a
  gap is a MINOR rather than a PATCH. JSON `errors[]` and SARIF
  `toolExecutionNotifications` lose the entry for a resolved reference, and
  `executionSuccessful` becomes true.
- ADR-023's context list is amended: `include:`/`extends:` is no longer one of
  its four precedents for refusing to read.
- Shipped in three steps, policy first: this ADR and the two doc amendments;
  then `extends:` (containment plus the per-document base dir, the smallest
  step that proves the plumbing); then `include:`, including include-only
  roots, the object form, own-directory interpolation, the recursion caps and
  decision 6's fixture result.
