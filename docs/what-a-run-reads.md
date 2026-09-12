# What a run reads

For a single Compose file with no siblings, a run reads that file and nothing
else. When there is more, compose-lint grades the configuration Compose
actually runs, not just the file you name: the sibling `compose.override.yml`
is merged, the sibling `.env` is resolved, `env_file:` targets are graded,
`include:` and cross-file `extends:` are followed — and a part of the stack it
*cannot* see is an error, never a silent pass.

Everything it opens is a document the one you named routes it to, and every
one of them has to resolve inside that file's own directory. Nothing outside
the project is read, no matter what the document says, and no registry, daemon
or image is consulted at all.

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

## A sibling `.env` is read, because Compose reads it

([ADR-026](adr/026-read-the-sibling-env-file.md)). Its `COMPOSE_FILE`
chooses the documents, exactly as it does for Compose, and `${VAR}`
references resolve to what it supplies — `volumes: ["${MOUNT}:/data"]` with
`MOUNT=/var/run/docker.sock` is graded as the control-socket mount it
deploys. Two deliberate limits: values under `environment:` are never
resolved from a `.env` (that is where secrets live), and the ambient shell
environment is never read, so the same checkout lints the same on every
machine. `--no-env` ignores env files entirely.

## An `env_file:` is read too, and its keys are graded

([ADR-027](adr/027-grade-env-file-where-the-document-routes-it.md)).
Compose merges those files into the container's process environment, so a
credential written there reaches every surface CL-0020 describes — moving a
line out of `environment:` no longer silences CL-0020/CL-0021 without
changing what deploys. Only those two rules read env files; a finding names
the key and the file, **never the value**, and a path resolving outside the
project directory is refused rather than read.

## `include:` and cross-file `extends:` are followed when they stay inside the project

([ADR-036](adr/036-resolve-references-that-stay-inside-the-project.md)),
under the same containment rule as `env_file:`: the referenced documents are
read and merged, so hardening they declare counts and danger they declare is
found. An include-only root — no services of its own, the monorepo idiom — is
lintable rather than refused. Each document's own relative paths resolve
against its own directory, and the merge order follows Compose's, which is not
the one `-f a -f b` uses: the including file wins, and an earlier `include:`
entry beats a later one.

## Coverage gaps

What is *not* followed is still an error rather than a quiet pass, because
reporting clean over a partial view is the one failure mode a merge gate
cannot have: a reference that leaves the project directory, is missing, is
interpolated, is a cycle, or fails the bounded read. A gap means exit 2, a
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
