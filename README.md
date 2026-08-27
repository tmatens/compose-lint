# compose-lint

**Security-focused linter for Docker Compose files.** Catches dangerous misconfigurations before they reach production — and auto-fixes the unambiguous ones, dry-run first. Grounded in OWASP and the CIS Docker Benchmark.

[![CI](https://github.com/tmatens/compose-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/tmatens/compose-lint/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/compose-lint)](https://pypi.org/project/compose-lint/)
[![Docker](https://img.shields.io/badge/docker-composelint%2Fcompose--lint-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/composelint/compose-lint)
[![Docs](https://img.shields.io/badge/docs-tmatens.github.io-blue)](https://tmatens.github.io/compose-lint/)
[![Python](https://img.shields.io/pypi/pyversions/compose-lint)](https://pypi.org/project/compose-lint/)
[![License](https://img.shields.io/github/license/tmatens/compose-lint)](https://github.com/tmatens/compose-lint/blob/main/LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/tmatens/compose-lint/badge)](https://scorecard.dev/viewer/?uri=github.com/tmatens/compose-lint)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12472/badge)](https://www.bestpractices.dev/projects/12472)
[![Mentioned in Awesome Docker](https://awesome.re/mentioned-badge-flat.svg)](https://github.com/veggiemonk/awesome-docker#security)

Static-analysis checks for `docker-compose.yml` and `compose.yaml`, covering privileged containers, unpinned images, host-network sharing, sensitive bind mounts, hard-coded credentials, and more. Full rule documentation lives at **[tmatens.github.io/compose-lint](https://tmatens.github.io/compose-lint/)** (the same pages `--explain` prints offline).

In a scan of 5,417 public Docker Compose files on GitHub, **91% of those that parse had at least one security finding.** Nearly all skip basic capability restrictions, 49% run images without a pinned digest, and 64% bind ports to all interfaces. compose-lint catches these in CI before they ship. **[Read the full *State of Docker Compose Security* report →](https://tmatens.github.io/compose-lint/state-of-compose/)**

<!-- Demo GIF. Regenerate with scripts/demo/ — see scripts/demo/README.md. -->
![compose-lint scanning a docker-compose.yml with two services: under `service: watchtower`, a CRITICAL mounted Docker socket (CL-0001) with a box-drawing underline, fix block and reference URL, above a MEDIUM image pinned to a tag but not a digest (CL-0019); then under `service: db`, a HIGH plaintext credential (CL-0020) with `POSTGRES_PASSWORD: hunter2` underlined — then the FAIL verdict, and `compose-lint --explain CL-0001` reading the offline rule docs in a pager: the title, severity derivation and references hold on the first page, then a page-down continues into the doc.](https://raw.githubusercontent.com/tmatens/compose-lint/main/docs/assets/demo.gif)

**What it catches:**

- Privilege flaws — `privileged: true`, missing `cap_drop`, `no-new-privileges` not set, root user, host namespace sharing
- Network exposure — wildcard port binds, `network_mode: host`
- Supply-chain — unpinned images, missing digest pins
- Filesystem and credential leaks — Docker socket mounts, sensitive host paths, plaintext credentials in `environment:`

Built for anyone whose Compose file **is** production — a company stack or a homelab closet. If it runs real services, compose-lint is the pre-merge gate that catches the misconfiguration before it ships. Fast is measured, not vibes: per-file work is sub-millisecond, a run is dominated by interpreter startup, and start-to-verdict stays a fraction of a second whether you lint one Compose file or a hundred — pre-commit never waits on it. Fits the same niche as [Hadolint, the Dockerfile linter](https://github.com/hadolint/hadolint) and [dclint, the Compose schema linter](https://github.com/zavoloklom/docker-compose-linter): zero-config, opinionated, fast, and grounded in the [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) and [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).

## Installation

**pip**

```bash
pip install compose-lint
```

Or run it ad hoc without installing anything:

```bash
uvx compose-lint docker-compose.yml        # or: pipx run compose-lint docker-compose.yml
```

That resolves the newest release at install time. For a reproducible install (CI, production tooling), pin the version and install the dependency set from the repo's hash-pinned lockfile, which release automation keeps current:

```bash
curl -fsSLO https://raw.githubusercontent.com/tmatens/compose-lint/v0.26.0/requirements.lock
pip install --require-hashes -r requirements.lock   # dependencies, hash-pinned
pip install --no-deps compose-lint==0.26.0          # the tool, version-pinned
```

**Docker** — [composelint/compose-lint](https://hub.docker.com/r/composelint/compose-lint)

```bash
docker run --rm -v "$(pwd):/src" composelint/compose-lint:0.26.0
```

The Docker image is distroless, multi-arch, and runs nonroot — see [Security posture](#security-posture) below for SLSA, Sigstore, and OpenVEX details.

### Running with full hardening

Want to dogfood compose-lint's own rules against the container that runs it? See [the hardening guide](https://tmatens.github.io/compose-lint/hardening/) for the fully-hardened `docker run` invocation, the flag-to-rule mapping, and digest-pinning instructions.

## Quick Start

Run without arguments to auto-detect `compose.yml`, `compose.yaml`, `docker-compose.yml`, or `docker-compose.yaml` in the current directory:

```bash
compose-lint
```

Or pass files explicitly:

```bash
compose-lint docker-compose.yml docker-compose.prod.yml
```

Preview the auto-fixable findings as a unified diff, then apply them — reading the `⚠ behavior-changing` labels first (see [Fixing findings](#fixing-findings)):

```bash
compose-lint fix              # dry-run diff, writes nothing
compose-lint fix --apply      # write the fixes in place
```

Don't recognize a rule ID in the output? `--explain` prints the full rule doc — what it catches, why it matters, the fix, and the OWASP/CIS reference — without leaving the terminal:

```bash
compose-lint --explain CL-0005
```

Docker equivalent:

```bash
docker run --rm -v "$(pwd):/src" composelint/compose-lint:0.26.0 docker-compose.prod.yml
```

### Compose compatibility

compose-lint targets the [Compose Specification](https://github.com/compose-spec/compose-spec) used by Compose v2 and v3. Compose v1 files (services declared at the top level) are skipped with a stderr note rather than failing the run — Docker [retired Compose v1 in 2023](https://www.docker.com/blog/new-docker-compose-v2-and-v1-deprecation/). Structural fragments (files containing only `volumes:` / `networks:` / `configs:` / `secrets:` / `x-*` keys, typically merged via `-f overlay.yml`) are skipped for the same reason, as is compose-lint's own `.compose-lint.yml` config if a glob happens to sweep it in. Genuinely unrecognised shapes still exit 2.

Python 3.11+ is required for the pip install path; the Docker image is self-contained.

## Adopting on an existing repo

Most established stacks don't start clean — in the [State of Compose
scan](https://tmatens.github.io/compose-lint/state-of-compose/), 91% of public
Compose files that parse had at least one finding. You don't have to fix
everything before the gate goes in: `compose-lint init` turns a file's current
findings into a `.compose-lint.yml` baseline you then triage, so the gate can
go in today without hand-authoring suppressions from the schema:

```bash
compose-lint init docker-compose.yml          # writes ./.compose-lint.yml
compose-lint init docker-compose.yml -o ci.yml # write somewhere else
compose-lint init docker-compose.yml --force   # overwrite an existing config
```

Each finding becomes a per-service `exclude_services` entry with a placeholder
reason — never a global `enabled: false`, so a service you add later still trips
the rule instead of being silently uncovered. It refuses to overwrite an
existing config without `--force`, writes nothing for a clean file, and sends
status to stderr. Replace each `TODO` reason with a real justification or delete
the entry and fix the issue. See
[docs/configuration.md](https://github.com/tmatens/compose-lint/blob/main/docs/configuration.md#generating-a-starter-config)
for the full behavior.

## What a run actually reads

compose-lint grades the configuration Compose actually runs, not just the
file you name: the sibling `compose.override.yml` is merged, the sibling
`.env` is resolved, `env_file:` targets are graded — and a part of the stack
it *cannot* see is an error, never a silent pass.

**Overlays are merged.** `docker compose up` merges a `compose.override.yml`
sitting beside the base file, with no flag and no opt-in, so compose-lint
grades the merged pair: the run header names both documents, and each finding
reports the file its evidence is written in
([ADR-025](docs/adr/025-lint-the-merged-configuration.md)).
`--no-merge-overrides` grades the base alone; `fix` only ever edits the file
it is fixing.

**A sibling `.env` is read, because Compose reads it**
([ADR-026](docs/adr/026-read-the-sibling-env-file.md)). Its `COMPOSE_FILE`
chooses the documents, exactly as it does for Compose, and `${VAR}`
references resolve to what it supplies — `volumes: ["${MOUNT}:/data"]` with
`MOUNT=/var/run/docker.sock` is graded as the control-socket mount it
deploys. Two deliberate limits: values under `environment:` are never
resolved from a `.env` (that is where secrets live), and the ambient shell
environment is never read, so the same checkout lints the same on every
machine. `--no-env` ignores env files entirely.

**An `env_file:` is read too, and its keys are graded**
([ADR-027](docs/adr/027-grade-env-file-where-the-document-routes-it.md)).
Compose merges those files into the container's process environment, so a
credential written there reaches every surface CL-0020 describes — moving a
line out of `environment:` no longer silences CL-0020/CL-0021 without
changing what deploys. Only those two rules read env files; a finding names
the key and the file, **never the value**, and a path resolving outside the
project directory is refused rather than read.

**Coverage gaps.** Beyond that overlay, compose-lint follows no references out of a file, so `include:` and cross-file `extends: {file: ...}` leave part of the stack unlinted. Reporting a pass over a partial view is the one failure mode a merge gate cannot have, so a gap is an error: exit 2, a JSON `errors[]` entry, and a SARIF `toolExecutionNotifications` record. Lint the merged output (`docker compose config`) to cover everything, or pass `--allow-partial-coverage` to accept the gap and grade what is visible.
## How it compares

| Tool | Compose security rules | Auto-fix | Scope | Zero config |
|------|----------------------|----------|-------|-------------|
| **compose-lint** | Yes | Yes — dry-run diff first | Docker Compose | Yes |
| **KICS** | Yes | Yes (`remediate` command) | Broad IaC (Terraform, K8s, Compose, ...) | No |
| **Hadolint** | No — Dockerfile only | No | Dockerfile | Yes |
| **dclint** | Yes — schema/structure only | Style/formatting only | Docker Compose | Yes |
| **Trivy** | No — image/CVE + IaC misconfig scanning, no dedicated Compose ruleset | No | Dockerfiles, images, IaC | Yes |
| **Checkov** | No — no dedicated Compose ruleset | No | Broad IaC (Terraform, K8s, ...) | No |

*A capability snapshot, verified July 2026 — check each tool's docs for current state.*

If you need broad IaC coverage across Terraform, Kubernetes, and more, KICS covers Docker Compose and is worth evaluating. If you want a lightweight, focused tool with zero config and actionable fix guidance for Compose files specifically, this is it.

**Not in scope**: compose-lint does not validate Compose schema, scan images for CVEs, or lint Dockerfiles. Pair it with [dclint](https://github.com/zavoloklom/docker-compose-linter) for schema/structure, [Hadolint](https://github.com/hadolint/hadolint) for Dockerfiles, and [Trivy](https://github.com/aquasecurity/trivy) for image CVEs.

## Example Output

Given this `docker-compose.yml`:

```yaml
services:
  traefik:
    image: traefik:v3.0@sha256:aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899990
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 256m
    cpus: 0.5
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    ports:
      - "8080:80"

  db:
    image: postgres:16@sha256:bbbbccccddddeeeeffff000011112222333344445555666677778888999900001
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 1g
    cpus: 1.0
    environment:
      POSTGRES_PASSWORD: hunter2
    volumes:
      - pgdata:/var/lib/postgresql/data
    tmpfs:
      - /tmp
      - /run

volumes:
  pgdata:
```

and this `.compose-lint.yml` (suppressing CL-0001 for `traefik` with a tracked reason):

```yaml
rules:
  CL-0001:
    exclude_services:
      traefik: "SEC-1234 approved — socket proxy planned for 2026-Q3"
```

running `compose-lint docker-compose.yml` produces:

```
files: docker-compose.yml  ·  config: .compose-lint.yml  ·  fail-on: high

docker-compose.yml

  service: traefik  (line 10)
    line  severity    rule     message
      10  SUPPRESSED  CL-0001  Docker runtime socket mounted via '/var/run/docker.sock:/var/run/docker.sock'. This gives the container full control over the Docker runtime — equivalent to root on the host.
          reason: SEC-1234 approved — socket proxy planned for 2026-Q3
      12  MEDIUM      CL-0005  Port '8080:80' is bound to all interfaces. Docker bypasses host firewalls (UFW/firewalld), potentially exposing this port to the public internet.
          12 │       - "8080:80"
             │          ───────
          fix: Bind to localhost: 127.0.0.1:8080:80
               If public access is needed, use a reverse proxy with TLS.
          ref: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-5a-be-careful-when-mapping-container-ports-to-the-host-with-firewalls-like-ufw

  service: db  (line 22)
    line  severity    rule     message
      22  HIGH        CL-0020  Service has credential-shaped env key 'POSTGRES_PASSWORD' with a literal value. Env vars are exposed via `docker inspect`, `/proc/<pid>/environ`, `docker compose config`, process listings, and CI logs — any process or operator with daemon access can read them.
          22 │       POSTGRES_PASSWORD: hunter2
             │       ─────────────────
          fix: Move 'POSTGRES_PASSWORD' to Compose's `secrets:` primitive. If the image supports the `*_FILE` convention (Postgres, MySQL, MariaDB, MinIO, etc.), set `POSTGRES_PASSWORD_FILE: /run/secrets/<name>` and declare the secret under the top-level `secrets:` block sourced from a gitignored file or `external: true`. Otherwise, have the entrypoint read the secret file at startup and export the value into the workload's environment.
          ref: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-12-utilize-docker-secrets-for-sensitive-data-management
docker-compose.yml: 1 high, 1 medium  ·  1 suppressed (not counted)
✗ FAIL  ·  1 finding at or above high
```

Exit code is `1` (one finding at or above the default `--fail-on high` threshold). Suppressed findings are shown for auditability but do not count toward the threshold. Findings are grouped by service and ordered highest-severity first within each service; the fix block and reference URL print only once per rule id per file — pass `-v` / `--verbose` to repeat them on every finding, or `-q` / `--quiet` for one compact line per finding.

That file is synthetic. For worked remediations of real stacks — the same
CRITICAL socket mount resolved four different ways (delete the service,
re-architect it away, constrain it, or suppress it with the risk written
down), two rules in genuine tension, and a stack that lints clean — see the
[examples gallery](https://tmatens.github.io/compose-lint/examples/).

## Rules

| ID | Severity | Description | Auto-fix | OWASP | CIS |
|----|----------|-------------|:--------:|-------|-----|
| [CL-0001](https://tmatens.github.io/compose-lint/rules/CL-0001/) | CRITICAL | Host control socket exposed | — | [Rule #1](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-1-do-not-expose-the-docker-daemon-socket-even-to-the-containers) | 5.32 |
| [CL-0002](https://tmatens.github.io/compose-lint/rules/CL-0002/) | CRITICAL | Privileged mode enabled | — | [Rule #3][owasp3] | 5.5 |
| [CL-0003](https://tmatens.github.io/compose-lint/rules/CL-0003/) | MEDIUM | Privilege escalation not blocked | ✔ | [Rule #4](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-4-prevent-in-container-privilege-escalation) | 5.26 |
| [CL-0004](https://tmatens.github.io/compose-lint/rules/CL-0004/) | MEDIUM | Image not pinned to version | — | [Rule #13][owasp13] | 5.28 |
| [CL-0005](https://tmatens.github.io/compose-lint/rules/CL-0005/) | MEDIUM | Ports bound to all interfaces | ✔ | [Rule #5a](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-5a-be-careful-when-mapping-container-ports-to-the-host-with-firewalls-like-ufw) | 5.14 |
| [CL-0006](https://tmatens.github.io/compose-lint/rules/CL-0006/) | MEDIUM | No capability restrictions | — | [Rule #3][owasp3] | 5.4 |
| [CL-0007](https://tmatens.github.io/compose-lint/rules/CL-0007/) | LOW | Filesystem not read-only | ✔ | [Rule #8][owasp8] | 5.13 |
| [CL-0008](https://tmatens.github.io/compose-lint/rules/CL-0008/) | HIGH | Host network mode | — | [Rule #5](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-5-be-mindful-of-inter-container-connectivity) | 5.10 |
| [CL-0009](https://tmatens.github.io/compose-lint/rules/CL-0009/) | HIGH | Security profile disabled | ✔ | [Rule #6](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-6-use-linux-security-module-seccomp-apparmor-or-selinux-for-runtime-security) | 5.2, 5.3, 5.22 |
| [CL-0010](https://tmatens.github.io/compose-lint/rules/CL-0010/) | HIGH | Host namespace sharing | — | [Rule #3][owasp3] | 5.16, 5.17, 5.21, 5.31 |
| [CL-0011](https://tmatens.github.io/compose-lint/rules/CL-0011/) | HIGH | Strong host-adjacent capability added | — | [Rule #3][owasp3] | 5.4 |
| [CL-0013](https://tmatens.github.io/compose-lint/rules/CL-0013/) | HIGH | Sensitive host path exposed | — | [Rule #8][owasp8] | 5.6 |
| [CL-0014](https://tmatens.github.io/compose-lint/rules/CL-0014/) | LOW | Logging driver disabled | ✔ | — | — |
| [CL-0016](https://tmatens.github.io/compose-lint/rules/CL-0016/) | CRITICAL | Dangerous host device exposed | — | — | 5.18 |
| [CL-0017](https://tmatens.github.io/compose-lint/rules/CL-0017/) | LOW | Shared mount propagation | — | — | 5.20 |
| [CL-0018](https://tmatens.github.io/compose-lint/rules/CL-0018/) | MEDIUM | Explicit root user | — | [Rule #2](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-2-set-a-user) | — |
| [CL-0019](https://tmatens.github.io/compose-lint/rules/CL-0019/) | MEDIUM | Image tag without digest | — | [Rule #13][owasp13] | — |
| [CL-0020](https://tmatens.github.io/compose-lint/rules/CL-0020/) | HIGH | Credential-shaped env key with literal value | — | [Rule #12][owasp12] | — |
| [CL-0021](https://tmatens.github.io/compose-lint/rules/CL-0021/) | HIGH | Credential embedded in connection-string env value | — | [Rule #12][owasp12] | — |
| [CL-0022](https://tmatens.github.io/compose-lint/rules/CL-0022/) | LOW | tmpfs mount re-enables exec/suid | — | [Rule #8][owasp8] | — |
| [CL-0024](https://tmatens.github.io/compose-lint/rules/CL-0024/) | CRITICAL | Host-code-execution capability added | — | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3-limit-capabilities-grant-only-specific-capabilities-needed-by-a-container) | 5.4 |
| [CL-0025](https://tmatens.github.io/compose-lint/rules/CL-0025/) | CRITICAL | Root-equivalent host path mounted writable | — | [Rule #8][owasp8] | 5.6 |
| [CL-0026](https://tmatens.github.io/compose-lint/rules/CL-0026/) | MEDIUM | No resource limits (memory/CPU) | — | [Rule #7](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-7-limit-resources-memory-cpu-file-descriptors-processes-restarts) | 5.10, 5.11 |
| [CL-0027](https://tmatens.github.io/compose-lint/rules/CL-0027/) | MEDIUM | Bounded-grant capability added | — | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3-limit-capabilities-grant-only-specific-capabilities-needed-by-a-container) | 5.4 |
| [CL-0028](https://tmatens.github.io/compose-lint/rules/CL-0028/) | HIGH | Host-reaching capability added | — | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3-limit-capabilities-grant-only-specific-capabilities-needed-by-a-container) | 5.4 |
| [CL-0029](https://tmatens.github.io/compose-lint/rules/CL-0029/) | HIGH | Host-availability capability added | — | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3-limit-capabilities-grant-only-specific-capabilities-needed-by-a-container) | 5.4 |
| [CL-0030](https://tmatens.github.io/compose-lint/rules/CL-0030/) | HIGH | Host-disclosure capability added | — | [Rule #3](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3-limit-capabilities-grant-only-specific-capabilities-needed-by-a-container) | 5.4 |

Rules marked ✔ have a mechanically unambiguous remediation that `compose-lint
fix` applies for you, dry-run first — see [Fixing findings](#fixing-findings).
Every other rule reports specific fix guidance for a change only you can
choose, and is never auto-edited.

The gaps in the numbering — CL-0012, CL-0015, CL-0023 — are retired ids kept
fallow forever: reusing one would silently change the meaning of a suppression
someone has already written
([ADR-005](docs/adr/005-rule-id-scheme.md),
[ADR-028](docs/adr/028-pre-1.0-rule-id-sweep.md)).

## Severity Levels

Findings are rated **LOW**, **MEDIUM**, **HIGH**, or **CRITICAL**. Each rule's severity is derived from a two-axis matrix — the attacker precondition the misconfiguration creates, and the impact scope it reaches — under a stated attacker baseline and a stated Docker posture. See [docs/severity.md](https://github.com/tmatens/compose-lint/blob/main/docs/severity.md) for the full scoring matrix, the derivation of every rule, and the override mechanism.

## Configuration

Create `.compose-lint.yml` to disable rules, exclude specific services, or adjust severity:

```yaml
rules:
  CL-0001:
    enabled: false
    reason: "SEC-1234 — approved 2026-07-01"
  CL-0003:
    exclude_services:
      minecraft: "entrypoint switches users via su-exec"
  CL-0005:
    severity: medium
```

Disabled and excluded findings still appear marked **SUPPRESSED** with the `reason` flowing to JSON's `suppression_reason` and SARIF's `justification` (recognized by GitHub Code Scanning) — they do not affect exit code. Pass `--skip-suppressed` to hide them. A `severity:` override is reported too, as `(severity overridden from …)` in text and `severity_overridden_from` / `properties.severityOverriddenFrom` in JSON and SARIF, so a re-graded finding is distinguishable from one the rule declared at that level.

See [docs/configuration.md](https://github.com/tmatens/compose-lint/blob/main/docs/configuration.md) for per-service exclusion semantics, precedence rules, and the full output-format mapping.

## CLI Reference

Three subcommands: `check` (the default — a bare `compose-lint` works), `fix`,
and `init`. Every flag is described in `compose-lint --help` and the
[CLI reference](https://tmatens.github.io/compose-lint/cli/), along with color
control (`NO_COLOR` / `FORCE_COLOR`) and end-of-options semantics.

## Fixing findings

`compose-lint fix` auto-remediates the findings whose edit is **mechanically
unambiguous** — one correct value, in one place, with no collateral change to
the rest of the file: adding `read_only: true` or `no-new-privileges:true`,
binding a published port to `127.0.0.1`, restoring a disabled logging driver
or seccomp profile, and similar. It is **dry-run by default**: it
prints a unified diff and writes nothing.

<!-- Fix demo GIF. Regenerate with scripts/demo/ — see scripts/demo/README.md. -->
![compose-lint fix on a docker-compose.yml: the dry-run prints three `behavior-changing` caveat lines (CL-0009's re-applied seccomp profile, CL-0007's read_only, CL-0005's rebind to 127.0.0.1) above a unified diff adding `read_only: true`, replacing `seccomp:unconfined` with `no-new-privileges:true`, and rebinding `"8080:8080"` to `"127.0.0.1:8080:8080"`, summarised as 3 fixes available with 1 finding needing manual review — then `fix --apply` writes the same three edits and `compose-lint check` re-lints to a PASS verdict, the un-auto-fixable tag-only image pin (CL-0019) still reported below the threshold.](https://raw.githubusercontent.com/tmatens/compose-lint/main/docs/assets/demo-fix.gif)

> **Auto-fixable does not mean harmless.** The guarantee is about the *edit*,
> not the *outcome*. `fix` will not corrupt your file, reflow it, or guess at a
> value it cannot derive — but it will happily change how your stack behaves.
> `read_only: true` breaks a container that writes to its root filesystem;
> rebinding a published port to `127.0.0.1` cuts off every client outside the
> host. Those edits are still offered, because withholding them would hide a
> real finding. Instead each one is labelled `⚠ behavior-changing` in the diff
> with the specific breakage named:
>
> ```
> ⚠ behavior-changing · CL-0007: read_only: true breaks the container if it
>   writes to its root filesystem; declare writable paths via tmpfs/volumes first.
> ```
>
> Read those lines before you `--apply`, and roll the result out to a staging
> stack before production. Treat `fix` as a patch author, not an approver.

```bash
compose-lint fix docker-compose.yml            # preview the diff, write nothing
compose-lint fix --apply docker-compose.yml    # write the fixes in place
compose-lint fix --only CL-0007 --apply .      # restrict to one rule
```

Dry-run is the default and `--apply` writes via an atomic swap; only
mechanically unambiguous fixes are applied — a context-dependent finding
(CL-0006 capability lists, CL-0001 socket mounts) is reported for manual
review, and a file using YAML anchors, merge keys, or `${VAR}` interpolation
in the affected region is refused rather than risk a wrong rewrite. Suppressed
findings are never touched, and `--format sarif` carries each fix as a
structured suggested change GitHub renders inline on the PR. The full design
contract — refusal rules, re-lint-before-write, the stdout/stderr split — is
in the [fix guide](https://tmatens.github.io/compose-lint/fix/).

## Versioning & stability

compose-lint follows [Semantic Versioning](https://semver.org/). From 1.0, the CLI, exit codes, config schema, and JSON/SARIF output are stable. New and tightened rules ship in MINOR releases, so pin a version or use `--fail-on` if you need deterministic CI. See [docs/compatibility.md](https://github.com/tmatens/compose-lint/blob/main/docs/compatibility.md) for the full stability promise and deprecation policy.
Release-by-release changes are in
[CHANGELOG.md](https://github.com/tmatens/compose-lint/blob/main/CHANGELOG.md);
planned work is on the [roadmap](https://tmatens.github.io/compose-lint/ROADMAP/).

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above the `--fail-on` threshold |
| 1 | One or more findings at or above the `--fail-on` threshold |
| 2 | compose-lint couldn't run, or couldn't see the whole stack (invalid args, file not found, invalid Compose file, a rule crashed, or a coverage gap — see [What a run actually reads](#what-a-run-actually-reads)) |

The default threshold is `high` — medium and low findings don't fail CI unless you opt in:

```bash
compose-lint --fail-on low docker-compose.yml   # fail on everything
compose-lint --fail-on critical docker-compose.yml  # only critical
```

## CI Integration

### GitHub Actions

The easiest path — runs compose-lint and uploads findings to GitHub Code Scanning. Pinned to immutable SHAs for reproducible CI; [Renovate](https://docs.renovatebot.com/) keeps the pins current:

```yaml
# .github/workflows/lint.yml
name: Compose Lint
on: [push, pull_request]

permissions: {}

jobs:
  compose-lint:
    runs-on: ubuntu-latest
    permissions:
      contents: read          # checkout
      security-events: write  # upload the SARIF to Code Scanning
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - uses: tmatens/compose-lint@cb12b5313ff1fb182ff3c832b41ff3d574a68c6b # v0.25.0
        with:
          sarif-file: results.sarif
```

The `uses:` line pins a commit SHA with the version in a trailing comment —
the supply-chain-rigorous form (it is what OpenSSF Scorecard grades for, and
Renovate/Dependabot keep the pin fresh). From 1.0 a floating major tag also
exists — `uses: tmatens/compose-lint@v1` — for setups that prefer automatic
updates: it is a mutable pointer moved by the release pipeline, deliberately
*not* part of the signed-tag guarantee that release tags carry, which is the
same trade this linter itself prices in CL-0004/CL-0019. Pick the form that
matches your threat model; the SHA pin is the recommended default.

The `permissions:` blocks are part of the recipe, not decoration. Without them the
job inherits the repository default, which on many repositories is still
read-write for every scope — so a linting job that needs only `contents: read`
and `security-events: write` runs holding a token that can push code and edit
releases. Denying everything at the workflow level and granting the two scopes
the job actually uses keeps a compromised dependency in this job from reaching
anything else.

Drop `security-events: write` if you are not uploading SARIF. To write the
SARIF file without the Code Scanning upload — for example to attach it as a
build artifact instead — set `upload-sarif: "false"` alongside `sarif-file`
(and drop the scope).

Or install from PyPI directly:

```yaml
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - run: pip install compose-lint
      - run: compose-lint docker-compose.yml
```

### Forgejo Actions

compose-lint runs on Forgejo Actions too — with two practical differences from
GitHub (cross-instance action URLs, and a checkout/node quirk in job
containers). The recipe lives in the
[Forgejo guide](https://tmatens.github.io/compose-lint/forgejo/), and is
executed against a live Forgejo weekly by the
[forgejo-smoke workflow](.github/workflows/forgejo-smoke.yml), which fails if
the guide and the versions it ran on disagree.

### SARIF output

```bash
compose-lint --format sarif docker-compose.yml > results.sarif
```

## Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/tmatens/compose-lint
    rev: v0.26.0
    hooks:
      - id: compose-lint
```

The hook ships `args: [--]`, and setting `args:` **replaces** that default —
keep `--` last if you pass flags, so a repository path can never be read as
an option (the [CLI
reference](https://tmatens.github.io/compose-lint/cli/#end-of-options)
documents the attack this blocks):

```yaml
      - id: compose-lint
        args: [--fail-on, low, --]
```

## Security posture

compose-lint is built to be safe to depend on:

- **Runtime image**: [distroless Python](https://github.com/GoogleContainerTools/distroless) on Debian, multi-arch (`linux/amd64` + `linux/arm64`), nonroot UID 65532, no shell or package manager at runtime. See [ADR-009](https://github.com/tmatens/compose-lint/blob/main/docs/adr/009-runtime-base-image.md).
- **Supply chain**: every release ships SLSA build provenance and Sigstore attestations. Published to PyPI via Trusted Publishers (OIDC) — no manual `twine upload`, no long-lived API tokens.
- **Vulnerability transparency**: each release ships an [OpenVEX](https://openvex.dev/) document declaring known pip CVEs `not_affected` with justification `vulnerable_code_not_present` — pip code is stripped from the runtime venv and only `.dist-info` metadata is retained for SCA scanner attribution.
- **External audit**: tracked on [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/tmatens/compose-lint) and [OpenSSF Best Practices Baseline 2](https://www.bestpractices.dev/projects/12472); CodeQL runs on every PR, ClusterFuzzLite fuzzes code-touching PRs, and Docker Scout scans the published image daily.
- **Reporting vulnerabilities**: see [SECURITY.md](https://github.com/tmatens/compose-lint/blob/main/.github/SECURITY.md).

## Contributing

See [CONTRIBUTING.md](https://github.com/tmatens/compose-lint/blob/main/CONTRIBUTING.md) for development setup and how to add rules.

## License

[MIT](https://github.com/tmatens/compose-lint/blob/main/LICENSE)

---

**Try it on your own stack right now** — no install, first findings in seconds:

```bash
uvx compose-lint
```

[owasp3]: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-3-limit-capabilities-grant-only-specific-capabilities-needed-by-a-container
[owasp8]: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-8-set-filesystem-and-volumes-to-read-only
[owasp12]: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-12-utilize-docker-secrets-for-sensitive-data-management
[owasp13]: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-13-enhance-supply-chain-security
