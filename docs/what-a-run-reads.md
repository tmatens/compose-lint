# What a run reads

For a single Compose file with no siblings, a run reads that file and nothing
else. When there is more, compose-lint grades the configuration Compose
actually runs, not just the file you name: the sibling `compose.override.yml`
is merged, the sibling `.env` is resolved, `env_file:` targets are graded,
`include:` and cross-file `extends:` are followed — and a part of the stack it
*cannot* see is an error, never a silent pass.

Everything it opens is a document the one you named routes it to, and every
one of them has to resolve inside that file's own directory or, through a
symlink, inside the checkout. Nothing outside either is read, no matter what
the document says, and no registry, daemon or image is consulted at all.

That holds for the files a run *finds* as well as the ones a document names.
A discovered `compose.yml`, its `compose.override.yml`, and the
`.compose-lint.yml` in the working directory are part of the checkout, and so
is a Compose file named on the command line, since CI hands the linter paths
the checkout chose. One committed as a symlink is followed only while its
target stays inside the directory the run started in (the checkout, in CI:
the Action runs in the workspace and pre-commit at the repository root) or
inside the link's own directory. A shared file symlinked into a monorepo's
service directories is therefore graded when you run from the repository
root, and its relative paths resolve beside the link, as Compose resolves
them. A target outside both is refused rather than followed: exit 2, a
coverage gap for a Compose document. The policy file is contained to the
working directory, and one that leaves it is a configuration error. A plain
path you type is read as given, and so is `--config`.

The same link rule holds for every file a document routes the run to: the
`.env`, a `COMPOSE_FILE` entry, an `include:` or `extends:` target, an
`env_file:`, and an `include:` entry's `project_directory:`. A monorepo that
links `svc/.env` to a shared `.env` at the repository root is graded as
Compose deploys it when you run from the root. What a path *says* is a
separate test: a reference written with `..` that climbs out of the project,
or an absolute one, is refused whether or not a link is involved.

| Source | Read because | Switch it off |
|---|---|---|
| Sibling `compose.override.yml` | `docker compose up` merges it with no flag | `--no-merge-overrides` |
| Sibling `.env` | Compose reads it for `${VAR}` and `COMPOSE_FILE` | `--no-env` |
| `env_file:` targets | Compose merges them into the container environment | `--no-env` |
| `include:` / `extends: {file: ...}` | Compose merges them into the project | — (a gap is reported instead) |

## Overlays are merged

`docker compose up` merges a `compose.override.yml` sitting beside the base
file, with no flag and no opt-in, so compose-lint grades the merged pair: the
run header names both documents, and each finding reports the file its
evidence is written in
([ADR-025](adr/025-lint-the-merged-configuration.md)).
`--no-merge-overrides` grades the base alone; `fix` only ever edits the file
it is fixing.

The override's spelling does not have to match the base's. Compose pairs any
of `compose.yml`, `compose.yaml`, `docker-compose.yml` and
`docker-compose.yaml` with whichever override is there, and when several are,
it takes the first of `compose.override.yml`, `compose.override.yaml`,
`docker-compose.override.yml`, `docker-compose.override.yaml` (measured on
Compose 5.5.0). compose-lint pairs them the same way.

## A sibling `.env` is read, because Compose reads it

([ADR-026](adr/026-read-the-sibling-env-file.md)). Its `COMPOSE_FILE`
chooses the documents, exactly as it does for Compose, and `${VAR}`
references resolve to what it supplies — `volumes: ["${MOUNT}:/data"]` with
`MOUNT=/var/run/docker.sock` is graded as the control-socket mount it
deploys. Two deliberate limits: values under `environment:` are never
resolved from a `.env` (that is where secrets live), and the ambient shell
environment is never read, so the same checkout lints the same on every
machine. `--no-env` ignores env files entirely.

A value the `.env` supplies is graded but not printed: wherever a finding,
its fix guidance or a note would quote it, the report shows the reference
instead (`${DB_PASSWORD}`), in text, JSON and SARIF alike. One limit: a value
shorter than 8 characters is shown as written. Short values (`true`,
`latest`, `1000`) are also words the guidance itself uses, and replacing
them there would corrupt it.

A `.env` that is there but cannot be read — not UTF-8, or larger than the
256 KiB read cap — is not treated as absent. Compose reads it as raw bytes with
no cap, so its values still deploy, and a run that graded the rest without them
could pass a stack whose real configuration it never saw. It is a coverage
gap: exit 2, a JSON `errors[]` entry of kind `coverage_gap`, and a SARIF
notification with `executionSuccessful: false`. `--allow-partial-coverage`
accepts it and grades the rest. The same holds for an included file's own
`.env`, which Compose reads for that file.

A `.env` that resolves outside both the project and the directory the run
started in — a committed symlink to a file elsewhere on the machine — is not
read at all, the same containment every other file a run opens gets, and is
the same coverage gap. So is an `include:` entry whose `project_directory:`
cannot be placed — written with `..` out of the project, absolute,
interpolated, or a directory symlink out of reach: Compose reads that
directory's `.env` and resolves the entry's paths from it, so every file in
the entry is reported rather than graded against a directory Compose does not
use.

## An `env_file:` is read too, and its keys are graded

([ADR-027](adr/027-grade-env-file-where-the-document-routes-it.md)).
Compose merges those files into the container's process environment, so a
credential written there reaches every surface CL-0020 describes — moving a
line out of `environment:` no longer silences CL-0020/CL-0021 without
changing what deploys. Only those two rules read env files; a finding names
the key and the file, **never the value**, and a path resolving outside the
project directory is refused rather than read. A refusal is reported as an
`unread_input` warning, so a JSON or SARIF consumer sees it as well as a
reader of stderr; it does not fail the run, because only those two rules read
the keys. A `COMPOSE_FILE` entry refused for leaving the project, or missing,
is a coverage gap instead: the whole list is ignored, so the documents graded
are not the ones Compose loads. An
`env_file:` written in an included or extended document is read from beside
that document, as Compose reads it.

## `include:` and cross-file `extends:` are followed when they stay inside the project

([ADR-036](adr/036-resolve-references-that-stay-inside-the-project.md)),
under the same containment rule as `env_file:`: the referenced documents are
read and merged, so hardening they declare counts and danger they declare is
found. An include-only root — no services of its own, the monorepo idiom — is
lintable rather than refused. Each document's own relative paths resolve
against its own directory, and the merge order follows Compose's, which is not
the one `-f a -f b` uses: the including file wins, and an earlier `include:`
entry beats a later one.

Every `extends:` merge — in-file, cross-file, or inside an included document —
is the same field-by-field merge Compose uses for overlays, so a child's
`!reset` deletes an inherited key and `!override` replaces an inherited value
instead of adding to it. A service an included document declares with
`extends:` is resolved once, against that document's directory, and is not
resolved again by the including file.

## Coverage gaps

What is *not* followed is still an error rather than a quiet pass, because
reporting clean over a partial view is the one failure mode a merge gate
cannot have: a reference that leaves the project directory, is missing, is
interpolated, is a cycle, or fails the bounded read, an `include:` entry
whose `project_directory:` cannot be placed — and an in-file
`extends:` naming a service the file does not declare, or forming a cycle,
both of which Compose refuses outright. A gap means exit 2, a
JSON `errors[]` entry, and a SARIF `toolExecutionNotifications` record, and
the message says which of those it was. Lint the merged output (`docker
compose config`) to cover everything, or pass `--allow-partial-coverage` to
accept the gap and grade what is visible.

A gap is not a finding, so `--fail-on` does not gate it; the stability rules
for adding or retiring a gap condition are in
[Compatibility](compatibility.md#coverage-gaps-are-not-findings).

## Which files are graded

compose-lint targets the [Compose
Specification](https://github.com/compose-spec/compose-spec) used by Compose
v2 and v3: any file with a top-level `services:` key, or an `include:`-only
root. Three shapes are skipped with a stderr note rather than failing the run:

- **Compose v1 files** — services declared at the top level, no `services:`
  wrapper. Docker [retired Compose v1 in
  2023](https://www.docker.com/blog/new-docker-compose-v2-and-v1-deprecation/).
- **Structural fragments** — files containing only `volumes:` / `networks:` /
  `configs:` / `secrets:` / `x-*` keys, typically merged via `-f overlay.yml`.
- **compose-lint's own `.compose-lint.yml`**, if a glob happens to sweep it in.

A skipped file contributes no findings and does not change the exit code.
Genuinely unrecognised shapes still exit 2.

### YAML that Compose accepts and compose-lint refuses

compose-lint parses with PyYAML, and three shapes that Docker Compose 5.5.0
deploys are refused by that parser. Each one fails closed: the file is
reported as invalid YAML with exit 2, which `--fail-on` does not gate, so it
can hold a pipeline red but never reports a clean pass over a file it did not
read.

- **A tab as the whitespace before a comment**: `privileged: true<TAB># note`.
  Compose treats the tab as separating whitespace; PyYAML stops at it. Use a
  space before the `#`.
- **More than one document in a file**: a `---` line followed by a second
  document. Compose merges the documents, later ones winning; compose-lint
  expects exactly one. Split them into files and lint them together, or lint
  `docker compose config` output.
- **A bare `=` as a value**: `A: =`. Compose reads it as the string `"="`;
  PyYAML resolves it to a YAML 1.1 type it cannot construct. Quote it:
  `A: "="`.

The stability rules for lifting one of these are in
[Compatibility](compatibility.md#yaml-compose-accepts-that-compose-lint-refuses).
