# compose-lint compared with DCLint, KICS, Checkov, Trivy, Semgrep, DockSec and Hadolint

Which tools actually read a Docker Compose file and check it for security
misconfigurations, and what each one does with it. Of the eight tools people
reach for, five read Compose files — compose-lint, DCLint, KICS, Semgrep's
`p/docker-compose` ruleset and OWASP DockSec — and three do not: Checkov, Trivy
and Hadolint lint Dockerfiles or images, which is a different file. The table
is a capability snapshot checked against each tool's own documentation on
2026-10-08; the sources are linked under each heading.

| Tool | Reads Compose files | Compose security rules | Auto-fix for Compose | SARIF | Scope |
|---|---|---|---|---|---|
| **compose-lint** | Yes | 27, each citing OWASP, CIS or Docker docs | Six rules, dry-run diff first | Yes | Docker Compose only |
| **DCLint** | Yes | 2 of 15 (unbound port interfaces, explicit image tag) | Formatting and ordering rules | — | Docker Compose style, structure and schema |
| **KICS** | Yes | 21 queries | `remediate` command; Compose support not documented | Yes | Terraform, Kubernetes, CloudFormation, Compose and more |
| **Semgrep `p/docker-compose`** | Yes | 6 | 1 of the 6 carries a fix | Yes | General-purpose code scanner |
| **OWASP DockSec** | Yes (`--compose`) | 17, per its README | No — `--fix` edits Dockerfiles only | Yes | Dockerfiles, images, Compose |
| **Checkov** | No | 0 — 28 Dockerfile policies, no Compose framework | — | Yes | Terraform, Kubernetes, CloudFormation, Dockerfile and more |
| **Trivy** | No | 0 — misconfiguration scanning covers Dockerfile, Kubernetes, Terraform, CloudFormation, Helm and ARM | — | Yes | Images, filesystems, IaC |
| **Hadolint** | No | 0 | — | Yes | Dockerfile only |

compose-lint's own limits are listed at the end of this page; it is not a
replacement for the image scanner or the Dockerfile linter you already run.

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
CPU and PID limits, and `security_opt`. It is a broad IaC scanner — Compose
is one of many platforms — and its query pages describe the pattern and show
a compliant and non-compliant sample.

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
an autofix. If Semgrep already runs in your CI, enabling the ruleset is one
line and catches the most common four or five mistakes.

compose-lint covers those six and the rest of its 27 rules — capability tiers,
resource limits, credentials in environment variables and connection strings,
digest pinning, sensitive host paths, mount propagation, logging disabled —
with per-rule severities derived from a stated model rather than a single
level, and with the fix guidance Semgrep's one-line messages do not have room
for.

## compose-lint vs OWASP DockSec

DockSec ([OWASP/DockSec](https://github.com/OWASP/DockSec)) scans
Dockerfiles, images and, with `--compose`, Compose files; its README points to
a reference of 17 Compose rules, naming missing healthchecks, plaintext
secrets in `environment:` and missing network segmentation among them, and it
uses an LLM to explain and prioritise findings. Its `--fix` applies mechanical
Dockerfile changes only; Compose findings are listed as "needs review".

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

## Keeping this page honest

Every count above comes from the linked documentation as read on
2026-10-08: KICS's query index, Checkov's policy index, Trivy's scanner page,
the Semgrep rules repository, and the DCLint and DockSec READMEs. Tools
change; if a row is out of date, [open an
issue](https://github.com/tmatens/compose-lint/issues) with the link that
shows it and the row will be corrected.
