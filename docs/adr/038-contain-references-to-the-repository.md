# ADR-038: Contain References to the Repository, Not the Project Directory

**Status:** Accepted

**Context:** Every file a run opens because a document named it — an
`include:` or `extends: {file:}` target, an `include:` entry's
`project_directory:`, an `env_file:`, the `.env`, a `COMPOSE_FILE` entry, a
Compose file that is itself a symlink — passes a two-gate containment test:
what the path *says* (lexical segment math, [ADR-023](023-deploy-host-independent-claims.md)
§1) and where it *resolves* on this filesystem (`_safe_read.out_of_reach`).
[ADR-036](036-resolve-references-that-stay-inside-the-project.md) put the
lexical gate at the **project directory**, the directory of the file being
linted. Its 0.32.0 amendment and the one after it put the physical gate at the
project directory *or the directory the run started in*, so that a committed
symlink into a monorepo's shared directory would be followed.

Those are two different lines, and the gap between them refused the layout
Compose is most often deployed in. Measured on 0.33.0, from a repository root,
with the Compose project in `svc/`:

| Reference in `svc/compose.yml` | compose-lint | Compose 5.5.0 |
|---|---|---|
| `include: [sub/part.yml]` | followed | accepts |
| `include: [linked-shared.yml]` (link to `../shared/part.yml`) | followed | accepts |
| `include: [../shared/part.yml]` | **gap, exit 2** | accepts |
| `extends: {file: ../shared/base.yml, service: base}` | **gap, exit 2** | accepts |
| `include: [{path: sub/part.yml, project_directory: ..}]` | **gap, exit 2** | accepts |
| `env_file: ../shared/app.env` | not opened, `unread_input` | accepts |

The same file is followed through a symlink and refused when spelled with
`..`. ADR-036's corpus could not see this: it stored files singly, with no
sibling context, so it measured the shape of reference paths and not whether
multi-file layouts work. A run over 1,821 Compose projects from 388 public
multi-file repositories, each linted from the repository root as CI does, did:
Compose accepts 1,324 of them, and 0.33.0 exits 2 on 243 — **235 of those for
exactly this reason**, a `..` path whose target is inside the checkout. The
shapes are a sibling stack directory (`include: ../common/compose.yaml`), a
shared base at the repository root, and end-to-end test cases extending
`../../base-compose.yml`. The sample is biased toward multi-file layouts, so
18% is an upper bound for the user base; single-file projects are unaffected.

**None of the reasons recorded for the project-directory line argues against a
target that stays inside the repository.** [ADR-027](027-grade-env-file-where-the-document-routes-it.md)
§7's concern is lint-host leakage: a pull request making the linter read
`/home/runner/.aws/credentials`, a file *outside* the checkout.
[ADR-026](026-read-the-sibling-env-file.md) §4 is about a document *narrowing*
what is graded; following a reference adds graded content. ADR-023 already
admitted following a reference whose target is part of the configuration
Compose requires to run. ADR-036 adopted the project directory from the
`env_file:` rule because it was there, and its own justification for following
links — "content the change under review can already see" — applies word for
word to a `..` path inside the same checkout.

**The run directory is the wrong root to widen to.** It is the checkout in CI
but wherever the command was typed locally: run from `$HOME`, "inside the run
directory" would cover all of `$HOME`, and a `..` path is a plain string where
a link at least has to be committed. The repository is the boundary the
argument actually rests on, so the root is the repository.

**Decision:**

1. **One containment root for every read** (`_safe_read.containment_root`):
   the nearest directory at or above the project holding a `.git` entry — a
   directory in a checkout, a file in a worktree or a submodule, so a
   submodule is its own root. Found by walking parents, never by running
   `git`: the answer is the same whether or not git is installed, and nothing
   executes on the lint host's behalf. Without a repository, the directory the
   run started in, if it contains the project — a tarball checkout linted from
   its top keeps what the 0.32.0 link rule gave it — and never a filesystem
   root, since a run from `/` would otherwise reach every file on the machine.
   Failing both, the project directory, which is where the rule started.
2. **Both gates measure against that root.** The lexical walk
   (`project_relative`) is seeded with the writing document's directory
   *under the root*, so `../shared/part.yml` written in `svc/` cleans to
   `shared/part.yml` and stays inside, while `../../outside/part.yml` pops
   past the root and leaves. The physical gate (`out_of_reach`) refuses a
   link whose target resolves outside the root. This applies to `include:`,
   cross-file `extends:`, `project_directory:`, `env_file:`, the `.env` of
   the project and of included files, a linked Compose file, and the link
   half of `COMPOSE_FILE` and `.compose-lint.yml`. Absolute and `~` paths are
   refused as before; so is a `..` that climbs above the root and comes back
   (`../../repo/shared/x`), because the lexical walk pops past the start.
3. **`.git` is never read**, by either gate: a path naming a `.git` segment
   leaves lexically, and a link resolving into one is out of reach. The
   repository root is defined by its `.git`, and that directory is the one
   thing inside a checkout that is not the change under review — a default
   `actions/checkout` writes the job's credential into `.git/config`. Before
   this decision a committed link into `.git` was followed, and only the
   parse error's wording — a position, not the line — stood between the file
   and the log. That is a property of error formatting, not of containment.
   Now it is containment.
4. **The merged document stays in Compose's frame.** Inherited `env_file:`
   paths are re-expressed relative to the *project directory*, not the root:
   a base at `shared/` writing `./app.env` for a project at `svc/` becomes
   `../shared/app.env`, which is what the primary would have to write. The
   oracle harness hands our merge to Compose from the project directory, and
   a root-relative spelling made Compose open `svc/svc/app.env`. Containment
   is measured against the root; paths are written for Compose.
5. **`COMPOSE_FILE` keeps the project-directory line for what it *says*.** A
   `..` entry is still refused lexically, while a link in the list follows
   the new root with every other read. Its refusal rests on ADR-026 §4 — the
   `.env` choosing which documents the run lints — which is a different
   argument from leakage, and this decision does not reopen it. If the
   corpus shows the shape matters, it gets its own decision.
6. **Messages name the new line.** The lexical refusal reads "outside the
   repository"; the physical one "resolves through a symlink to a target
   outside the repository". The caller-scoped remedy sentence is unchanged.
7. **Policy class: MINOR**, as ADR-036's bump table already says for retiring
   a coverage-gap condition. A reference that is now followed can surface
   findings that were invisible, which is the new-findings class; nothing
   that was graded before is graded differently. No runway is needed, because
   nothing turns red: exit 2 becomes a verdict.

**What a widened root can and cannot disclose**, checked against 0.33.0 on
synthetic fixtures before deciding:

- A finding quotes the document's *spelling*, never a substituted value. With
  `TOKEN=nginx:MARKER` in a `.env`, the verdict moved from CL-0004 to CL-0019
  and the message still read `Image '${TOKEN}'`. Zero marker hits across the
  sibling, linked-directory and `include:` cases, in text and JSON.
- A parse error quotes a position, not a line.
- `env_file:` reports key names only; values are never retained (ADR-026 §5).
- So the residual channel is a one-bit oracle per rule on a value's shape,
  plus the key names of an env file. Both already existed for anything inside
  the project directory, and for anything in the checkout through a link.

**Residuals accepted, and written down because no hook catches them:**

- *Untracked files inside the checkout.* A CI step that writes a `.env` with
  secrets into the workspace before linting puts it inside the root, and a
  hostile pull request could point an `env_file:` at it to list key names.
  The 0.32.0 link rule already allowed this; the boundary is "the checkout",
  not "tracked content", and the defence is the value-free report above.
  Checking tracking status would need a git subprocess, which decision 1
  rules out.
- *A dotfiles-managed `$HOME`.* On a developer machine whose home directory is
  a repository, the root is `$HOME`. The content is the user's own and the
  report is their own; CI runners do not do this.
- *A tarball linted from elsewhere* falls back to the project directory:
  today's behaviour, no regression.
- *A `..` that leaves the root and returns* stays refused, as decision 2
  says. Compose accepts it; no corpus project does it.

**Verified:**

- The oracle harness now writes every generated tree as a repository and
  starts the run *above* it, so the root is found from the marker and not
  from the run directory. The seeds that carried a registered policy gap
  (`project_directory: ..` above the Compose project, still inside the tree)
  flip to agreement with Compose 5.5.0, and the one registered divergence,
  `include-outside-the-project`, is re-pointed at a fixture whose project is
  its own repository so that it keeps asserting both halves.
- Over the multi-file sample, compared against the same commit without this
  change: the 235 projects become graded (126 exit 0, 109 exit 1); 8 of the
  1,324 Compose-accepted projects still exit 2, all for other reasons (six
  remote `include:` targets, one interpolated path, one chain opening more
  than 64 files); no project graded before exits 2 now; and among the 1,478
  projects graded by both, the only findings that changed are new CL-0020
  findings in 7 projects whose `env_file:` above the project directory is now
  read instead of reported as `unread_input`.
- Over the single-file corpus, zero findings changed: those files have no
  sibling context, so nothing there could be followed.

**Consequences:** ADR-036 §7's "outside the project directory" residual
becomes "outside the repository"; its two link-rule amendments are
superseded by one root. ADR-027 §7 and ADR-023 §3 (as amended by #780) are
amended to say "repository". `docs/compatibility.md`'s gap list,
`docs/what-a-run-reads.md`, `docs/how-it-works.md` and the README describe
the new line. `_safe_read.escapes_project` is unchanged and still the one
physical test; `containment_root` is the only place the root is chosen.
