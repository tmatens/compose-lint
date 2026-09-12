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

In a scan of 11,111 public Compose files on GitHub, **99% of the real-world files that lint had at least one security finding**, and more than one in four carries a literal credential. **[Read the *State of Docker Compose Security* report →](https://tmatens.github.io/compose-lint/state-of-compose/)**

<!-- Demo GIF. Regenerate with scripts/demo/ — see scripts/demo/README.md. -->
![compose-lint scanning a docker-compose.yml with two services: under `service: watchtower`, a CRITICAL mounted Docker socket (CL-0001) with a box-drawing underline, fix block and reference URL, above a MEDIUM image pinned to a tag but not a digest (CL-0019); then under `service: db`, a HIGH plaintext credential (CL-0020) with `POSTGRES_PASSWORD: hunter2` underlined — then the FAIL verdict, and `compose-lint --explain CL-0001` reading the offline rule docs in its built-in pager: the title, severity derivation and references hold on the first page, the status line naming the controls — `CL-0001 · Space next · b back · q quit` — then a page-down continues into the doc, prompt still in place.](https://raw.githubusercontent.com/tmatens/compose-lint/main/docs/assets/demo.gif)

**What it catches:**

- Privilege flaws — `privileged: true`, missing `cap_drop`, `no-new-privileges` not set, root user, host namespace sharing
- Network exposure — wildcard port binds, `network_mode: host`
- Supply-chain — unpinned images, missing digest pins
- Filesystem and credential leaks — Docker socket mounts, sensitive host paths, plaintext credentials in `environment:`

Zero config, sub-second whether you lint one file or a hundred, and grounded in the [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) and [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker). Full rule docs at **[tmatens.github.io/compose-lint](https://tmatens.github.io/compose-lint/)** — the same pages `--explain` prints offline.

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
curl -fsSLO https://raw.githubusercontent.com/tmatens/compose-lint/v0.28.0/requirements.lock
pip install --require-hashes -r requirements.lock   # dependencies, hash-pinned
pip install --no-deps compose-lint==0.28.0          # the tool, version-pinned
```

Every pip path needs Python 3.11+; the Docker image is self-contained.

**Docker** — [composelint/compose-lint](https://hub.docker.com/r/composelint/compose-lint)

```bash
docker run --rm -v "$(pwd):/src" composelint/compose-lint:0.28.0
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
docker run --rm -v "$(pwd):/src" composelint/compose-lint:0.28.0 docker-compose.prod.yml
```

## Adopting on an existing repo

Most established stacks don't start clean. `compose-lint init` turns a file's
current findings into a `.compose-lint.yml` baseline, so the gate can go in
today and you triage afterwards:

```bash
compose-lint init docker-compose.yml          # writes ./.compose-lint.yml
compose-lint init docker-compose.yml -o ci.yml # write somewhere else
compose-lint init docker-compose.yml --force   # overwrite an existing config
```

Each finding becomes a per-service `exclude_services` entry with a `TODO`
reason — never a global `enabled: false`, so a service you add later still
trips the rule. Replace each reason with a real justification, or delete the
entry and fix the issue. Details:
[generating a starter config](https://github.com/tmatens/compose-lint/blob/main/docs/configuration.md#generating-a-starter-config).

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

Exit code is `1`: one finding at or above the default `--fail-on high`
threshold. Suppressed findings are shown but not counted. That file is
synthetic; for worked remediations of real stacks, see the
[examples gallery](https://tmatens.github.io/compose-lint/examples/).

## Grades what actually deploys

For a single Compose file with no siblings, a run reads that file and nothing
else. When there is more, compose-lint grades the configuration Compose would
actually run, not just the file you named:

- **It merges what Compose merges.** The sibling `compose.override.yml`, the
  sibling `.env` (for `${VAR}` references and `COMPOSE_FILE`, never for
  `environment:` values), `env_file:` targets, and `include:` / cross-file
  `extends:` are all resolved, so a socket mount hidden behind a variable or
  an override is graded as the mount it deploys.
- **It never reads outside the project.** Every document has to resolve inside
  the named file's own directory. The ambient shell environment is not read,
  and no registry, daemon, or image is consulted, so the same checkout lints
  the same on every machine.
- **A part of the stack it cannot see is exit 2, not a silent pass.** A
  reference that is missing, interpolated, or leaves the project is reported
  as a coverage gap. Lint the `docker compose config` output to cover it, or
  pass `--allow-partial-coverage` to grade what is visible.

Any Compose Specification file works: one with a top-level `services:` key, or
an `include:`-only root. Compose v1 files (services at the top level, retired
by Docker in 2023) and structural fragments with no services are skipped with
a stderr note rather than failed.

Full detail, including the merge order and the flags that switch each source
off (`--no-merge-overrides`, `--no-env`):
[What a run reads](https://tmatens.github.io/compose-lint/what-a-run-reads/).

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

Suppressed findings still appear, marked **SUPPRESSED**, with the `reason`
carried into JSON and SARIF; they do not affect the exit code, and
`--skip-suppressed` hides them. A `severity:` override is reported as such.
See [docs/configuration.md](https://github.com/tmatens/compose-lint/blob/main/docs/configuration.md)
for per-service semantics, precedence, and the output-format mapping.

## CLI Reference

Three subcommands: `check` (the default — a bare `compose-lint` works), `fix`,
and `init`. Every flag is described in `compose-lint --help` and the
[CLI reference](https://tmatens.github.io/compose-lint/cli/), along with color
control (`NO_COLOR` / `FORCE_COLOR`) and end-of-options semantics. Text
output prints each rule's fix block once per file; `-v` repeats it on every
finding, `-q` gives one line per finding.

## Fixing findings

`compose-lint fix` auto-remediates the findings whose edit is **mechanically
unambiguous** — one correct value, in one place, with no collateral change to
the rest of the file: adding `read_only: true` or `no-new-privileges:true`,
binding a published port to `127.0.0.1`, restoring a disabled logging driver
or seccomp profile, and similar. It is **dry-run by default**: it
prints a unified diff and writes nothing.

<!-- Fix demo GIF. Regenerate with scripts/demo/ — see scripts/demo/README.md. -->
![compose-lint fix on a docker-compose.yml: the dry-run prints three `behavior-changing` caveat lines (CL-0009's re-applied seccomp profile, CL-0007's read_only, CL-0005's rebind to 127.0.0.1) above a unified diff adding `read_only: true`, replacing `seccomp:unconfined` with `no-new-privileges:true`, and rebinding `"8080:8080"` to `"127.0.0.1:8080:8080"`, summarised as 3 fixes available with 1 finding needing manual review — then `fix --apply` writes the same three edits and `compose-lint check` re-lints to a PASS verdict, the un-auto-fixable tag-only image pin (CL-0019) still reported below the threshold.](https://raw.githubusercontent.com/tmatens/compose-lint/main/docs/assets/demo-fix.gif)

> **Auto-fixable does not mean harmless.** `fix` will not corrupt or reflow
> your file, but it will change how your stack behaves: `read_only: true`
> breaks a container that writes to its root filesystem, and rebinding a port
> to `127.0.0.1` cuts off remote clients. Each such edit is labelled
> `⚠ behavior-changing` in the diff with the breakage named. Read those lines
> before `--apply`, and roll out to staging first.

```bash
compose-lint fix docker-compose.yml            # preview the diff, write nothing
compose-lint fix --apply docker-compose.yml    # write the fixes in place
compose-lint fix --only CL-0007 --apply .      # restrict to one rule
```

Context-dependent findings (capability lists, socket mounts) are reported for
manual review, and a region using YAML anchors, merge keys, or `${VAR}`
interpolation is refused rather than guessed. The full contract is in the
[fix guide](https://tmatens.github.io/compose-lint/fix/).

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

**Not in scope**: compose-lint does not validate Compose schema, scan images for CVEs, or lint Dockerfiles. Pair it with [dclint](https://github.com/zavoloklom/docker-compose-linter) for schema/structure, [Hadolint](https://github.com/hadolint/hadolint) for Dockerfiles, and [Trivy](https://github.com/aquasecurity/trivy) for image CVEs.

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
| 2 | compose-lint couldn't run, or couldn't see the whole stack (invalid args, file not found, invalid Compose file, a rule crashed, or a coverage gap — see [Grades what actually deploys](#grades-what-actually-deploys)) |

The default threshold is `high` — medium and low findings don't fail CI unless you opt in:

```bash
compose-lint --fail-on low docker-compose.yml   # fail on everything
compose-lint --fail-on critical docker-compose.yml  # only critical
```

## CI Integration

### GitHub Actions

Runs compose-lint and uploads findings to GitHub Code Scanning:

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
      - uses: tmatens/compose-lint@d0434054779e9026c6082bc47ecc818ec2aa981d # v0.28.0
        with:
          sarif-file: results.sarif
```

The `uses:` line pins a commit SHA, which is what OpenSSF Scorecard grades
for and what Renovate keeps fresh; from 1.0, `tmatens/compose-lint@v1` floats
with releases instead. The `permissions:` blocks are part of the recipe: the
job holds only the two scopes it uses. If you want the SARIF file without the
Code Scanning upload, set `upload-sarif: "false"` and drop
`security-events: write`. Every input, and the reasoning behind the pin and
the permissions, is in the
[GitHub Action guide](https://tmatens.github.io/compose-lint/github-action/).

Or install from PyPI directly:

```yaml
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - run: pip install compose-lint
      - run: compose-lint docker-compose.yml
```

### Forgejo Actions

compose-lint runs on Forgejo Actions too, with two practical differences
(cross-instance action URLs and a checkout/node quirk in job containers). The
recipe is in the [Forgejo guide](https://tmatens.github.io/compose-lint/forgejo/),
and the weekly [forgejo-smoke workflow](.github/workflows/forgejo-smoke.yml)
runs it against a live Forgejo.

### SARIF output

```bash
compose-lint --format sarif docker-compose.yml > results.sarif
```

## Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/tmatens/compose-lint
    rev: v0.28.0
    hooks:
      - id: compose-lint
```

The hook ships `args: [--]`, and setting `args:` **replaces** that default.
Keep `--` last if you pass flags, so a repository path can never be read as
an option ([why](https://tmatens.github.io/compose-lint/cli/#end-of-options)):

```yaml
      - id: compose-lint
        args: [--fail-on, low, --]
```

## Agent-written Compose

If a coding agent writes Compose in your repo, the two gates above already
cover it: the pre-commit hook catches it before the commit, the Action before
the merge, on the same terms as anyone else's. If you are driving compose-lint
*from* an agent or script, parse `--format json` (a versioned envelope) and
read [Automation and agent use](https://tmatens.github.io/compose-lint/cli/#automation-and-agent-use),
which covers what agents get wrong: exit 2 is a coverage gap, `fix` is a dry
run, there are no inline suppressions, and `--explain` works offline.

## Security posture

compose-lint is built to be safe to depend on:

- **Runtime image**: [distroless Python](https://github.com/GoogleContainerTools/distroless) on Debian, multi-arch (`linux/amd64` + `linux/arm64`), nonroot UID 65532, no shell or package manager at runtime. See [ADR-009](https://github.com/tmatens/compose-lint/blob/main/docs/adr/009-runtime-base-image.md).
- **Supply chain**: every release ships SLSA build provenance and Sigstore attestations. Published to PyPI via Trusted Publishers (OIDC) — no manual `twine upload`, no long-lived API tokens.
- **Vulnerability transparency**: each release ships an [OpenVEX](https://openvex.dev/) document declaring known pip CVEs `not_affected`: pip code is stripped from the runtime image.
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
