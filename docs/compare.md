# compose-lint compared with DCLint, KICS, Checkov, Trivy, Semgrep, DockSec and Hadolint

Which tools actually read a Docker Compose file and check it for security
misconfigurations, and what each one does with it. Of the eight tools people
reach for, five read Compose files — compose-lint, DCLint, KICS, Semgrep's
`p/docker-compose` ruleset and OWASP DockSec — and three do not: Checkov, Trivy
and Hadolint lint Dockerfiles or images, which is a different file. The table
is a capability snapshot checked against each tool's own documentation on
2026-10-08, and then checked again by running all eight on the same broken
Compose file on 2026-10-09 — the run is below, and it corrected the
documentation in three places. Sources are linked under each heading.

| Tool | Reads Compose files | Compose security rules | Auto-fix for Compose | SARIF | Scope |
|---|---|---|---|---|---|
| **compose-lint** | Yes | 27, each citing OWASP, CIS or Docker docs | Six rules, dry-run diff first | Yes | Docker Compose only |
| **DCLint** | Yes | 2 of 15 (unbound port interfaces, explicit image tag) | Formatting and ordering rules | — | Docker Compose style, structure and schema |
| **KICS** | Yes | 21 queries (the limit queries need a `version:` key) | `remediate` command; Compose support not documented | Yes | Terraform, Kubernetes, CloudFormation, Compose and more |
| **Semgrep `p/docker-compose`** | Yes | 6, all requiring a `version:` key | 1 of the 6 carries a fix | Yes | General-purpose code scanner |
| **OWASP DockSec** | Yes (`--compose --scan-only`) | 14 static rules seen in the run | No — `--fix` edits Dockerfiles only | Yes | Dockerfiles, images, Compose |
| **Checkov** | No | 0 — 28 Dockerfile policies, no Compose framework | — | Yes | Terraform, Kubernetes, CloudFormation, Dockerfile and more |
| **Trivy** | No | 0 — misconfiguration scanning covers Dockerfile, Kubernetes, Terraform, CloudFormation, Helm and ARM | — | Yes | Images, filesystems, IaC |
| **Hadolint** | No | 0 | — | Yes | Dockerfile only |

compose-lint's own limits are listed at the end of this page; it is not a
replacement for the image scanner or the Dockerfile linter you already run.

## Run on the same file

Documentation says what a tool *intends* to check; a run says what it checked.
Sixteen services, one deliberate misconfiguration each, no `version:` key
(the form `docker compose` has used by default since v2), scanned by each
tool's published image on 2026-10-09. The fixture and the exact commands are
in [Reproduce it](#reproduce-it).

| Misconfiguration | compose-lint | KICS | DockSec | DCLint | Semgrep | Checkov · Trivy · Hadolint |
|---|---|---|---|---|---|---|
| Docker socket mounted | ✅ | ✅ | ✅ | — | ✗ | ✗ |
| `privileged: true` | ✅ | ✅ | ✅ | — | ✗ | ✗ |
| `no-new-privileges` missing | ✅ | ✅ | ✅ | — | ✗ | ✗ |
| Unpinned `:latest` tag | ✅ | — | ✅ | ✅ | — | ✗ |
| Port published on `0.0.0.0` | ✅ | ✅ | — | ✅ | — | ✗ |
| No `cap_drop: [ALL]` | ✅ | ✅ | — | — | — | ✗ |
| Writable root filesystem | ✅ | — | ✅ | — | ✗ | ✗ |
| `network_mode: host` | ✅ | ✅ | ✅ | — | — | ✗ |
| `seccomp:unconfined` | ✅ | ✅ | ✅ | — | ✗ | ✗ |
| `pid: host` / `ipc: host` | ✅ | ✅ | ✅ | — | — | ✗ |
| Sensitive host path mounted | ✅ | ✅ | ✅ | — | — | ✗ |
| `logging: driver: none` | ✅ | — | — | — | — | ✗ |
| `user: root` | ✅ | — | ✗ | — | — | ✗ |
| Tag without digest | ✅ | — | — | — | — | ✗ |
| Credential in `environment:` | ✅ | ✅ | ✅ | — | — | ✗ |
| No memory/CPU limits | ✅ | ✗ \* | ✅ | — | — | ✗ |
| **Caught, of 16** | **16** | **10** | **11** | **2** | **0** | **0** |

✅ flagged · ✗ not flagged · — no rule for it. \* KICS's memory and CPU
queries fire only when the file carries a `version:` key; with `version: "3.9"`
added it catches 11.

Three things the run showed that the documentation did not:

- **Semgrep's six Compose rules all require a top-level `version:` key** — each
  is written as `pattern-inside: version: … services: …` — so on a
  Compose-Specification file they report nothing at all (Semgrep's own
  summary: six rules run, one file, zero findings). Their own test fixtures carry `version: "3.9"`.
- **KICS's limit queries have the same dependency**, and `No New Privileges Not
  Set` only fires on a service that already has a `security_opt:` list; the
  others get the broader `Security Opt Not Set`. `Pids Limit Not Set` did not
  fire in either form.
- **DockSec's default mode needs the Docker CLI and an OpenAI key** and exits 3
  without them; its static Compose rules run with `--scan-only`, where they
  caught 11 of 16 and added two cross-service "exploit chains" (an
  internet-facing service sharing the default network with one holding a
  committed credential). It does not flag `0.0.0.0` binds, a missing
  `cap_drop`, or an explicit `user: root` — it flags the *absence* of `user:`.

Checkov reported `resource_count: 0` and rejects `--framework docker_compose`
as "Invalid frameworks specified"; Trivy's config scan downloaded its checks
bundle and returned a report with no results section; Hadolint parsed the file
as a Dockerfile and stopped at line 3 with `DL1000`.

Versions: compose-lint 0.34.0 · DCLint 3.1.0 · KICS 2.1.20 · DockSec 2026.8.19
(image tag 2026.9.21) · Semgrep 1.179.0 · Checkov 3.3.26 · Trivy 0.75.0 ·
Hadolint 2.15.1.

## Does Checkov scan docker-compose.yml?

No. Checkov's Docker coverage is its [Dockerfile policy
index](https://www.checkov.io/5.Policy%20Index/dockerfile.html): 28 policies
(`CKV_DOCKER_1` to `CKV_DOCKER_11` and `CKV2_DOCKER_1` to `CKV2_DOCKER_17`),
every one typed `dockerfile`. There is no `docker_compose` framework, and a
`compose.yaml` passed to `checkov` is not inspected as a Compose file. Guides
that show `checkov --framework docker_compose` are describing a flag that
does not exist.

If you run Checkov for Terraform or Kubernetes, keep running it; add
compose-lint for the Compose files it skips.

## Does Trivy lint Docker Compose files?

Not the Compose file itself. Trivy's [misconfiguration
scanner](https://trivy.dev/latest/docs/scanner/misconfiguration/) handles
Dockerfile, Kubernetes, Terraform, CloudFormation, Helm and Azure ARM; Docker
Compose is not among its configuration types. What Trivy does well is the
other half of the problem: the images a Compose file references. compose-lint
never pulls an image or reports a CVE, so the two are complementary —
`trivy image` for what is inside the image, compose-lint for how the Compose
file runs it.

## compose-lint vs DCLint

Different jobs, and the two are routinely run together. DCLint
([zavoloklom/docker-compose-linter](https://github.com/zavoloklom/docker-compose-linter))
validates a Compose file against the schema and applies fifteen
best-practice rules: ordering and formatting (alphabetical services, key
order, quoted ports), structure (no `version:` field, no duplicate container
names or exported ports, a project name) and two that overlap security —
`no-unbound-port-interfaces` and `service-image-require-explicit-tag`. Its
`--fix` applies the formatting rules.

compose-lint does not validate the schema at all; an invalid file is a usage
error, not a finding. Its 27 rules are security-only — capabilities,
`no-new-privileges`, `read_only`, the Docker socket, host namespaces, resource
limits, credentials in `environment:`, digest pinning — and each one ships
with the fix, the error message you will see if the fix breaks something,
and the OWASP or CIS citation that justifies it. Where DCLint and
compose-lint both flag something (an image without a tag, a port bound to
`0.0.0.0`), compose-lint grades it as a security finding with a severity;
DCLint reports it as a lint error.

## compose-lint vs KICS

KICS ([docs.kics.io](https://docs.kics.io/latest/queries/dockercompose-queries/))
is the closest in coverage: 21 Docker Compose queries, including the Docker
socket mount, `no-new-privileges`, privileged containers, unrestricted
capabilities, the default seccomp profile, shared host namespaces, memory,
CPU and PID limits, and `security_opt`. In the run above it caught 10 of the
16 misconfigurations on a `version`-less file and 11 with `version: "3.9"`
added — the memory and CPU queries key off the version number and skip a
Compose-Specification file. It is a broad IaC scanner — Compose is one of
many platforms — and its query pages describe the pattern and show a
compliant and non-compliant sample.

compose-lint is Compose-only and spends its depth on the fix: each rule page
explains what the setting does at runtime, which error messages the hardened
configuration produces when an image was not built for it, and how to tell a
real breakage from a false alarm. Its claims about runtime behaviour are
re-proven against live containers in CI. KICS has a `remediate` command; its
documentation does not say whether Compose files are among the platforms it
rewrites. compose-lint's `fix` edits six rules' findings in place after a
dry-run diff, and reports the rest for manual review.

## compose-lint vs Semgrep's `p/docker-compose` ruleset

Semgrep's registry carries six Compose security rules under
[`yaml/docker-compose/security`](https://github.com/semgrep/semgrep-rules/tree/develop/yaml/docker-compose/security):
the Docker socket as a volume, `no-new-privileges`, privileged services,
seccomp confinement disabled, SELinux separation disabled, and a writable root
filesystem. All six are `WARNING` severity; one (`privileged-service`) carries
an autofix. All six are also written as `pattern-inside: version: … services:
…`, so they match only a file that still carries the obsolete top-level
`version:` key: in the run above they reported nothing on a
Compose-Specification file that trips five of them. If Semgrep already runs in
your CI and your files keep `version:`, enabling the ruleset is one line.

compose-lint covers those six and the rest of its 27 rules — capability tiers,
resource limits, credentials in environment variables and connection strings,
digest pinning, sensitive host paths, mount propagation, logging disabled —
with per-rule severities derived from a stated model rather than a single
level, and with the fix guidance Semgrep's one-line messages do not have room
for.

## compose-lint vs OWASP DockSec

DockSec ([OWASP/DockSec](https://github.com/OWASP/DockSec)) scans
Dockerfiles, images and, with `--compose`, Compose files, and uses an LLM to
explain and prioritise findings. In the run above its static Compose rules
(`--scan-only`, since the default mode needs the Docker CLI for image scanning
and an OpenAI key for the explanation pass) caught 11 of 16 — the socket mount,
`privileged`, host network and namespaces, the sensitive host path, seccomp
unconfined, the plaintext secret, the `:latest` tag, missing
`no-new-privileges`, writable root and missing limits — and it reports
cross-service "exploit chains" that no other tool here attempts. It did not
flag the `0.0.0.0` bind, the missing `cap_drop`, `logging: none`, the missing
digest, or an explicit `user: root`. Its `--fix` applies mechanical Dockerfile
changes only; Compose findings are listed as "needs review".

compose-lint is deterministic — the same file produces the same findings, the
same severities and the same diff on every run, with no model and no network
access — and its auto-fix works on the Compose file. Which trade-off you want
depends on whether the linter is a CI gate (determinism matters) or an
advisor (explanation matters).

## Hadolint

[Hadolint](https://github.com/hadolint/hadolint) lints Dockerfiles and does
not read Compose files. Nothing on this page replaces it. A hardened Compose
file running an image built from an unhardened Dockerfile is half a job, and
the two tools do not overlap.

## What compose-lint does not do

- **Validate the Compose schema.** An invalid file is exit 2, not a finding.
  Pair with [DCLint](https://github.com/zavoloklom/docker-compose-linter).
- **Scan images.** It never pulls an image, inspects layers or reports CVEs.
  Pair with [Trivy](https://github.com/aquasecurity/trivy) or
  [Docker Scout](https://www.docker.com/products/docker-scout/).
- **Lint Dockerfiles.** It reads `compose.yaml` and `docker-compose.yml`,
  never `Dockerfile`. Pair with [Hadolint](https://github.com/hadolint/hadolint).
- **Watch running containers.** It is a static analyzer; see
  [Security expectations](SECURITY-EXPECTATIONS.md) for the full list.

## Reproduce it

The fixture — never run it — is sixteen services with one deliberate
misconfiguration each, named for the compose-lint rule it targets:

```yaml
services:
  socket:            # CL-0001 Docker socket mounted
    image: portainer/portainer-ce:2.21.4
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  privileged:        # CL-0002 privileged: true
    image: busybox:1.36.1
    privileged: true
  nnp:               # CL-0003 no-new-privileges missing (nothing else wrong)
    image: nginx:1.27.2-alpine
    cap_drop: [ALL]
    read_only: true
  latest:            # CL-0004 unpinned tag
    image: redis:latest
  ports:             # CL-0005 published on 0.0.0.0
    image: nginx:1.27.2-alpine
    ports:
      - "8080:80"
  caps:              # CL-0006 no cap_drop ALL
    image: nginx:1.27.2-alpine
    read_only: true
    security_opt: [no-new-privileges:true]
  rootfs:            # CL-0007 writable root filesystem
    image: nginx:1.27.2-alpine
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
  hostnet:           # CL-0008 network_mode: host
    image: nginx:1.27.2-alpine
    network_mode: host
  seccomp:           # CL-0009 seccomp unconfined
    image: nginx:1.27.2-alpine
    security_opt:
      - seccomp:unconfined
  pidhost:           # CL-0010 host PID/IPC namespace
    image: nginx:1.27.2-alpine
    pid: host
    ipc: host
  hostpath:          # CL-0013 sensitive host path
    image: busybox:1.36.1
    volumes:
      - /etc:/host-etc
  nolog:             # CL-0014 logging driver none
    image: nginx:1.27.2-alpine
    logging:
      driver: none
  root:              # CL-0018 user: root
    image: nginx:1.27.2-alpine
    user: root
  nodigest:          # CL-0019 tag without digest (otherwise pinned)
    image: nginx:1.27.2-alpine
  secret:            # CL-0020 plaintext credential in environment
    image: postgres:16.4
    environment:
      POSTGRES_PASSWORD: hunter2
  nolimits:          # CL-0026 no memory/cpu limits
    image: nginx:1.27.2-alpine
```

Each tool ran from its published image with the directory holding the file
mounted read-only at `/src`:

```bash
docker run --rm -v "$PWD:/src:ro" composelint/compose-lint check --format json /src/compose.yaml
docker run --rm -v "$PWD:/src:ro" zavoloklom/dclint -f json /src
docker run --rm -v "$PWD:/src:ro" -v "$PWD/out:/out" checkmarx/kics scan -p /src -o /out --report-formats json -t DockerCompose
docker run --rm -v "$PWD:/src:ro" owasp/docksec:2026.9.21 --compose /src/compose.yaml --format json --scan-only
docker run --rm -v "$PWD:/src:ro" semgrep/semgrep semgrep --config p/docker-compose --json /src
docker run --rm -v "$PWD:/src:ro" bridgecrew/checkov -f /src/compose.yaml -o json
docker run --rm -v "$PWD:/src:ro" aquasec/trivy config /src -f json
docker run --rm -v "$PWD:/src:ro" hadolint/hadolint hadolint -f json /src/compose.yaml
```

compose-lint reports the `hostpath` service as CL-0025 (a writable
root-equivalent host mount) rather than CL-0013; the table counts that as
caught. Its 85 findings are the 16 intended ones plus the baseline hardening
misses on every service that lacks them, which is what the tool is for.

## Keeping this page honest

The counts in the summary table come from the linked documentation as read
on 2026-10-08; the run is from 2026-10-09 with the versions listed above.
Tools change; if a row is out of date, [open an
issue](https://github.com/tmatens/compose-lint/issues) with the link or the
output that shows it and the row will be corrected.
