# ADR-044: `-f` Names the Files of One Project

**Status:** Accepted (adds a third selection path beside
[ADR-025](025-lint-the-merged-configuration.md) and
[ADR-026](026-read-the-sibling-env-file.md)).

**Context:** Compose picks the documents of a project three ways, in this
order of precedence: an explicit `-f`, a `COMPOSE_FILE`, and discovery of a
canonical filename with the `compose.override.yml` beside it. compose-lint
followed the second and third. Several files could be merged into one project
only when compose-lint found the list itself, in a sibling override or in the
`COMPOSE_FILE` of a sibling `.env`.

A project split across a base file and many overlays did not fit either
(#1315). Each overlay adds its own services and also extends a shared service
from the base, for example to attach a reverse proxy to that overlay's
network. `docker compose -f compose.yaml -f a.yaml up` merges them.
`compose-lint compose.yaml a.yaml` lints each file as its own project, so the
overlay's stub of the shared service is graded as a whole service and flagged
for everything it leaves to the base. With 40 overlays the shared service is
reported 40 more times.

The `.env` route did not cover it. Where the file list is built by a command
in a make or just recipe, `.env` cannot hold it, and `COMPOSE_FILE` exported
in the shell is not read, on purpose (ADR-026 section 3).

The merge itself needed nothing new. A `COMPOSE_FILE` list already merges any
number of files in order, against the first file's directory, and attributes
each finding to the file it was written in. What was missing was a way to name
the list.

Each behaviour below was measured on a synthetic fixture with Docker Compose
5.5.0 and again with 5.8.0. The two agreed on all of them.

| Question | What Compose does |
| --- | --- |
| Does `-f compose.yaml` alone merge the `compose.override.yml` beside it? | No. A run with no `-f` does. |
| Does `-f` honour a `COMPOSE_FILE` in the project's `.env`? | No. |
| With `-f a.yaml -f sub/b.yaml`, which `.env` supplies values? | The one beside `a.yaml`. |
| Where do a relative bind mount, `env_file`, `extends: file:` and `include:` written in `sub/b.yaml` resolve? | Against the directory of `a.yaml`. |
| What if an overlay is outside the first file's directory? | The same. It resolves against the first file's directory. |
| What happens to a file named twice? | It is merged twice. `-f a -f b -f a` gives the value from `a` where `a` and `b` both set it. |
| What happens when a named file is missing? | The project is refused. |
| Which directory is the project directory when the first file is a symlink? | The link's, not its target's. |

A 41-file project (one base and 40 overlays, 46 services) merged by
compose-lint matched `docker compose config` service for service on the keys
the rules read. The one difference was a `depends_on` entry Compose adds by
itself for `network_mode: service:<name>`.

**Decision:** `check`, `fix` and `init` take a repeatable `-f FILE` /
`--file FILE`. The files named are one project.

1. **The list is merged as given.** The files are merged in the order named.
   The first is the base, its directory is the project directory, and it is
   the file a report is headed by. Nothing is removed from the list. A file
   named twice is merged twice, because that is what Compose does and the
   result can differ.

2. **`-f` takes precedence, as it does for Compose.** A `COMPOSE_FILE` in the
   sibling `.env` does not select documents, and the `compose.override.yml`
   beside the first file is not merged. The run says so in a note when either
   is present. The note for `COMPOSE_FILE` only checks that the key is set. The
   list is not resolved, so an entry that would have been refused cannot fail
   a run that never uses it. `--no-merge-overrides` has nothing to act on and
   is accepted.

3. **The `.env` beside the first file is still read for values,** and
   `--no-env` still turns that off. One that exists and cannot be read is the
   same coverage gap it is for any other project.

4. **Positional files keep their meaning.** Each is its own project, which is
   what `compose-lint **/compose.yml`, the pre-commit hook and the Action
   pass. `-f` together with a positional file is a usage error (exit 2),
   because the two have no single reading.

5. **A file the run will not open stops the whole project.** A `-f` file that
   is a symlink resolving outside the repository is refused, as any Compose
   file is ([ADR-038](038-contain-references-to-the-repository.md)). Then
   nothing is merged and the run exits 2, with or without
   `--allow-partial-coverage`. A missing file is a parse error for the
   project, named by its own path.

   Merging the remaining files was considered and rejected. Every smaller set
   is a project Compose never loads. If the refused file is the base, the
   second file would become the base, which moves the project directory, the
   `.env` that is read and where each relative path resolves. Each overlay's
   stub would also be graded as a whole service again, which is the result
   this ADR exists to remove.

   This differs from a refused `COMPOSE_FILE` list, which falls back to the
   default selection and grades that. A `-f` run has no default to fall back
   to: the user named the whole set.

6. **`init` takes `-f` in place of `FILE`.** `FILE` becomes optional. Naming
   both, or neither, is a usage error. The config is written beside the first
   file, where `check` looks for it first.

**How this sits with ADR-026 section 4.** That section keeps the artifact
under inspection from choosing its own scope: a `.env` may add documents to a
named file's merge and may never remove the file from the run. A `-f` list is
typed by the person running the linter. Nothing in the repository adds to it
or takes from it, so the scope of the run is exactly what was asked for.

**Where a `-f` run differs from Compose, on purpose:**

- The shell environment is not read (ADR-026 section 3). A `${VAR}` whose
  value arrives only at deploy time is graded as written. Whether a run
  should say so is tracked in #1319.
- A file that links outside the repository is refused where Compose follows
  it (ADR-038).
- A service behind a profile is graded whether or not the profile is active.
  Compose leaves it out unless the profile is on.
- `--project-directory` and `--env-file` have no equivalent. A recipe that
  passes either to Compose gets a different project directory or different
  values from the ones compose-lint uses.

**Not done:**

- `fix` edits the first file only, as it does for every merged project.
  Findings written in the other files are listed to fix by hand. On the
  41-file project that was 253 findings.
- The GitHub Action and the pre-commit hook pass files positionally and get no
  new input. A pre-commit user can set `pass_filenames: false` and put `-f` in
  `args`.
- A project with optional overlays has many valid combinations. Each is its
  own run. The recipe that deploys a combination already holds its file list.
- Reading a Compose file from standard input (#1316).

**Consequences:**

- The CLI surface gains one flag on three commands, which is a MINOR change
  under the compatibility policy.
- A report for a `-f` project is headed by the first file, and a finding
  written in another file names that file, as for any merged project. JSON
  `file` and the SARIF location carry the overlay's path.
- A link refused under decision 5 fails the run even with
  `--allow-partial-coverage`. That follows the existing rule that the flag
  cannot produce a verdict when nothing was graded.
- `fix` verifies a patch by merging the patched base with the other files
  again. When the list names the base a second time, that later copy is the
  patched text too. Read from disk it would put the old text back over the
  fix.
