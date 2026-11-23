# What a run reads

For a single Compose file with no siblings, a run reads that file and nothing
else. When there is more, compose-lint grades the configuration Compose
actually runs, not just the file you name: the sibling `compose.override.yml`
is merged, the sibling `.env` is resolved, `env_file:` targets are graded,
`include:` and cross-file `extends:` are followed — and a part of the stack it
*cannot* see is an error, never a silent pass.

![compose-lint on a project of three files: `cat compose.yaml` shows a `web` service hardened as written (read_only, cap_drop ALL, no-new-privileges, memory and CPU limits, an image pinned by digest) publishing `"${BIND:-127.0.0.1}:8080:8080"`; `cat compose.override.yml` shows the override setting `privileged: true`, and `cat .env` shows `BIND=0.0.0.0`. Then `compose-lint` with no arguments: the header reads `files: compose.yaml + compose.override.yml · env: .env`, a warning says the override was merged because Compose merges it automatically, and the report shows a CRITICAL privileged-mode finding (CL-0002) marked `in: compose.override.yml (merged into this run)` and a MEDIUM port finding (CL-0005) for `0.0.0.0:8080:8080`, quoting the `${BIND:-127.0.0.1}` line it came from, above the FAIL verdict.](assets/demo-stack.gif)

Everything it opens is a document the one you named routes it to, and every
one of them has to resolve inside that file's own directory or, through a
symlink, inside the checkout. Nothing outside either is read, no matter what
the document says, and no registry, daemon or image is consulted at all.

That holds for the files a run *finds* as well as the ones a document names.
A discovered `compose.yml`, its `compose.override.yml`, and the
`.compose-lint.yml` beside it or in the working directory are part of the checkout, and so
is a Compose file named on the command line, since CI hands the linter paths
the checkout chose. One committed as a symlink is followed only while its
target stays inside the directory the run started in (the checkout, in CI:
the Action runs in the workspace and pre-commit at the repository root) or
inside the link's own directory. A shared file symlinked into a monorepo's
service directories is therefore graded when you run from the repository
root, and its relative paths resolve beside the link, as Compose resolves
them. A target outside both is refused rather than followed: exit 2, a
coverage gap for a Compose document. The policy file is contained to the
working directory — or, when it was found beside a Compose file outside it, to
that file's directory — and one that leaves it is a configuration error. A plain
path you type is read as given, and so is a plain `--config` path. A `--config`
path that is itself a link is treated like a linked Compose file: followed while
its target stays inside the repository that holds the link, and a configuration
error when it leaves. To use a policy file kept elsewhere, name that file.

The same rule holds for every file a document routes the run to: the `.env`,
a `COMPOSE_FILE` entry, an `include:` or `extends:` target, an `env_file:`,
and an `include:` entry's `project_directory:`. Each may reach anywhere inside
the **repository** that holds the Compose file — the nearest directory above
it with a `.git` entry — whether written with `..` or reached through a link,
so a monorepo whose `svc/compose.yml` includes `../shared/compose.yml` or
links `svc/.env` to the `.env` at the repository root is graded as Compose
deploys it, from whichever directory you run. Without a repository, the
boundary is the directory compose-lint was run from when that contains the
project, and otherwise the project directory. What a path *says* is still a
separate test: a reference written out of the repository, or an absolute one,
is refused whether or not a link is involved, and the `.git` directory itself
is never read, under any spelling a filesystem opens it by (`.GIT` where case
is ignored) ([ADR-038](adr/038-contain-references-to-the-repository.md)).
`COMPOSE_FILE` is the one list that is still read relative to the project
directory alone: an entry written with `..` is refused, though a linked entry
follows the repository rule.

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

## Several files as one project

`docker compose -f compose.yaml -f a.yaml up` merges the files it is given.
Name them the same way and compose-lint grades that merged project
([ADR-044](adr/044-name-a-project-with-f.md)):

```bash
compose-lint -f compose.yaml -f a.yaml
```

Without `-f`, each file on the command line is its own project. That is right
for `compose-lint **/compose.yml` and wrong for a base file with overlays,
where an overlay that only adds a network to a shared service is graded as a
whole service.

The list is used exactly as written, measured against Compose 5.5.0 and
5.8.0:

- The files merge in the order given, and a later file wins. A file named
  twice is merged twice.
- The first file's directory is the project directory. Its `.env` supplies
  values, and a relative mount, `env_file`, `extends: {file:}` or `include:`
  written in any of the files resolves from there.
- Nothing else selects a document. A `COMPOSE_FILE` in the sibling `.env` is
  not used, and the `compose.override.yml` beside the first file is not
  merged. The run says so in a note when either is there.
- `-f` cannot be combined with a positional file.

A file that is missing, or that is a symlink out of the repository, stops the
whole project and the run exits 2. Merging the rest would grade a project
Compose never loads.

`fix` edits the first file only and lists findings written in the other files
to fix by hand. `init -f ...` writes the config beside the first file.

Four things differ from what Compose does with the same list, on purpose:

- The shell environment is not read. A `${VAR}` supplied only at deploy time,
  by a recipe or a secrets tool, is graded as written.
- A service behind a profile is graded whether or not the profile is active.
- A file that links outside the repository is refused.
- `--project-directory` and `--env-file` have no equivalent. If your recipe
  passes either to Compose, the project directory or the values compose-lint
  uses will differ from the ones Compose uses.

## A sibling `.env` is read, because Compose reads it

([ADR-026](adr/026-read-the-sibling-env-file.md)). Its `COMPOSE_FILE`
chooses the documents, exactly as it does for Compose — and, as for Compose,
the first file's directory is the project directory for all of them, so an
overlay listed as `ops/dev.yml` resolves `./data`, its `extends: {file:}` and
its `${VAR}`s from there rather than from `ops/` — and `${VAR}`
references resolve to what it supplies — `volumes: ["${MOUNT}:/data"]` with
`MOUNT=/var/run/docker.sock` is graded as the control-socket mount it
deploys. `--no-env` ignores env files entirely.

Two limits are deliberate:

- **A `.env` value never fills in a value under `environment:`.** That is
  where credentials are usually set, so the credential rules
  ([CL-0020](rules/CL-0020.md), [CL-0021](rules/CL-0021.md)) grade what the
  Compose file itself says there. `TOKEN: ${TOKEN}` is not reported, whatever
  the `.env` holds, and `TOKEN: ${TOKEN:-changeme}` is, because the default is
  written in the file.
- **The shell environment is never read**, so the same checkout lints the
  same on every machine. A value that a wrapper such as `sops exec-env` puts
  in the environment is not seen.

A value the `.env` supplies is graded but not printed: wherever a finding,
its fix guidance or a note would quote it, the report shows the reference
instead (`${DB_PASSWORD}`), in text, JSON and SARIF alike. The same holds for
a value an `env_file:` target was filled in with, from the `.env` or from a
file listed before it. Where a finding quotes the document, any run of 8 or
more characters of the value is replaced, so a piece of it is not printed
either ([ADR-042](adr/042-rules-mark-the-document-text-they-quote.md)). One
limit: a value shorter than 8 characters is shown as written. Short values (`true`,
`latest`, `1000`) are also words the guidance itself uses, and replacing
them there would corrupt it.

A `.env` that is there but cannot be read — not UTF-8, or larger than the
256 KiB read cap — is not treated as absent. Compose reads it as raw bytes with
no cap, so its values still deploy, and a run that graded the rest without them
could pass a stack whose real configuration it never saw. It is a coverage
gap: exit 2, a JSON `errors[]` entry of kind `coverage_gap`, and a SARIF
notification with `executionSuccessful: false`. `--allow-partial-coverage`
accepts it and grades the rest. The same holds for an included file's own
`.env`, which Compose reads for that file. When an `include:` entry names an
`env_file:`, Compose reads those files in the `.env`'s place and so does
compose-lint; one it cannot read is the same coverage gap.

A `.env` that resolves outside the repository — a committed symlink to a
file elsewhere on the machine — is not read at all, the same containment
every other file a run opens gets, and is the same coverage gap. So is an
`include:` entry whose `project_directory:` cannot be placed — written with
`..` out of the repository, absolute, interpolated, or a directory symlink
out of reach: Compose reads that
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
repository is refused rather than read. A refusal, and a target that
exists but could not be read (not UTF-8, over the size cap, not a regular
file), is reported as an `unread_input` warning, so a JSON or SARIF consumer
sees it as well as a reader of stderr. A missing target is a note only,
because Compose refuses a required one and deploys without an optional one.
Neither fails the run, because only those two rules read the keys. A `COMPOSE_FILE` entry refused for leaving the project, or missing,
is a coverage gap instead: the whole list is ignored, so the documents graded
are not the ones Compose loads. An
`env_file:` written in an included or extended document is read from beside
that document, as Compose reads it.

A top-level job's `env_file:` is read the same way, because a job is a
container Compose starts like a service. A `pre_start` hook's is not: the
spec allows the key on a hook, and Compose 5.6.1 accepts it and does not
apply it (measured: the hook did not see the file's variable), so there is
nothing a rule could grade. A premise check re-proves that on every CI run,
so a Compose release that starts applying it fails there first.

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
cannot have. The complete list of conditions is in [coverage gaps are not
findings](compatibility.md#coverage-gaps-are-not-findings). A gap means exit 2,
a JSON `errors[]` entry, and a SARIF `toolExecutionNotifications` record, and
the message says which condition it hit, and what to do about it:

- When compose-lint could not follow a reference that Compose can, such as a
  base outside the repository or a chain past the depth bound, lint the
  merged output (`docker compose config`) to cover everything.
- When Compose refuses the reference too, as it does an `extends:` or
  `include:` whose target is missing or that loops, there is no merged output
  to lint. The message says so: correct the reference.

### Linting `docker compose config` output

The rendered output is one document with every reference already followed,
which is why it covers a gap. It is not the same input as your source files,
and a lint of it differs in two ways (measured on Compose 5.5.0):

- **A service behind an inactive profile is left out.** `docker compose
  config` renders only the services Compose would start, so a profiled
  service and its findings are missing. Render with every profile on:

  ```bash
  docker compose --profile '*' config > rendered.yaml
  compose-lint rendered.yaml
  ```

- **Values are resolved, and the text report quotes them.** Compose fills in
  each `${VAR}` from the shell and `.env`, and copies `env_file` values in
  under `environment:`. A credential that was a reference in your source is
  a literal in the output, so CL-0020 and CL-0021 report it, and the text
  report prints the line it is on. JSON and SARIF do not print the value.
  Treat the rendered file and a text report of it as you would the secrets
  themselves.

Line numbers are those of the rendered file, and `fix` has no source file to
write to. Where the reason for rendering is several files that make one
project, name them with `-f` instead
([Several files as one project](#several-files-as-one-project)).

Either way, `--allow-partial-coverage` accepts the gap and grades what is
visible.

A gap is not a finding, so `--fail-on` does not gate it; the stability rules
for adding or retiring a gap condition are in
[Compatibility](compatibility.md#coverage-gaps-are-not-findings).

## Size limits

A few inputs are refused outright, not because Compose refuses them but
because grading them would take gigabytes of memory. Each is exit 2 with a
JSON `errors[]` entry of kind `parse`, and `--allow-partial-coverage` does not
accept it, because nothing in that document was graded:

- a Compose file larger than 8 MiB (an included or extended file that large is
  a [coverage gap](compatibility.md#coverage-gaps-are-not-findings) instead);
- a document declaring more than 4,096 services, hooks and jobs, counted
  again once its `include:` files are merged in. Each hook list counts once
  per service that uses it;
- a document whose `<<:` merge keys copy more than 65,536 key/value pairs into
  the mappings that use them.

Real files are far below each: across an 11,111-file corpus the most services
in one document is 64, and the most merged pairs 968. A document that produces more than
20,000 findings is different: the findings graded before the stop are still
reported, so it is a coverage gap rather than a refusal. So are the limits that
bound the work behind a document: a value too long (8 KiB) or too deep to
interpolate, interpolation that would add more than 8 MiB to it, and a line map past 262,144 repeated records, where a `!reset` or
`!override` tag reached again is no longer applied. The most repeated records in
the corpus is 1,225.

## Which files are graded

compose-lint targets the [Compose
Specification](https://github.com/compose-spec/compose-spec) used by Compose
v2 and v3: any file with a top-level `services:` or `jobs:` key, or an
`include:`-only root. Three shapes are skipped with a stderr note rather than failing the run:

- **Compose v1 files** — services declared at the top level, no `services:`
  wrapper. Docker [retired Compose v1 in
  2023](https://www.docker.com/blog/new-docker-compose-v2-and-v1-deprecation/).
- **Structural fragments** — files containing only `volumes:` / `networks:` /
  `configs:` / `secrets:` / `x-*` keys, typically merged via `-f overlay.yml`.
  Reached through `include:` or as an overlay, a fragment is merged like any
  other document, as Compose merges it; only linted on its own is it skipped.
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
  `docker compose config` output
  ([what changes when you do](#linting-docker-compose-config-output)).
- **A bare `=` as a value**: `A: =`. Compose reads it as the string `"="`;
  PyYAML resolves it to a YAML 1.1 type it cannot construct. Quote it:
  `A: "="`.

The stability rules for lifting one of these are in
[Compatibility](compatibility.md#yaml-compose-accepts-that-compose-lint-refuses).
