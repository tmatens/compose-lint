# compose-lint compared with DCLint, KICS, Checkov, Trivy, Semgrep, DockSec and Hadolint

Which of these tools read a Docker Compose file and check it for security
misconfigurations? Five do: compose-lint, DCLint, KICS, Semgrep's
`p/docker-compose` ruleset and OWASP DockSec. Three do not: Checkov, Trivy
and Hadolint lint Dockerfiles or images, which is a different file.

Two of the five, Semgrep and KICS, only work fully on files that still carry
the top-level `version:` key from the old Compose file format. The Compose
Specification that Docker Compose has followed since 2020 makes that key
obsolete, and `docker compose` warns when it sees one. The ninth option that
search results keep suggesting, a script of your own, has its own section
below.

The table was checked against each tool's documentation on 2026-10-08. The
next day all eight tools were run against the same deliberately broken
Compose file, and that run corrected the documentation in three places. The
run is described further down. On 2026-10-17 the five tools that read Compose
were run again on stacks spread across several files, where the setting comes
from `extends:`, `include:`, an override file or `.env`. Sources are linked
under each heading.

| Tool | Reads Compose files | Compose security rules it has | Auto-fix for Compose | SARIF | Scope |
|---|---|---|---|---|---|
| **compose-lint** | Yes | 28, each citing OWASP, CIS or Docker docs | Six rules, dry-run diff first | Yes | Docker Compose only |
| **KICS** | Yes | 21 queries | `remediate` command; Compose support not documented | Yes | Terraform, Kubernetes, CloudFormation, Compose and more |
| **OWASP DockSec** | Yes (`--compose`) | 17 | No (`--fix` edits Dockerfiles only) | Yes | Dockerfiles, images, Compose |
| **Semgrep `p/docker-compose`** | Yes | 6 | 1 of the 6 carries a fix | Yes | General-purpose code scanner |
| **DCLint** | Yes | 2 of 15 (unbound port interfaces, explicit image tag) | Formatting and ordering rules | — | Docker Compose style, structure and schema |
| **Checkov** | No | 0 | — | Yes | Terraform, Kubernetes, CloudFormation, Dockerfile and more |
| **Trivy** | No | 0 | — | Yes | Images, filesystems, IaC |
| **Hadolint** | No | 0 | — | Yes | Dockerfile only |
| **A script of your own** (`yq`/`jq`, Conftest/OPA, a custom Semgrep or KICS rule) | Whatever it parses | Whatever you write | Whatever you write | — | See [below](#when-a-script-of-your-own-is-enough) |

The table says which rules each tool documents. The three runs below show
which of them fired on which file. compose-lint's own gaps are listed at the
end of the page. It does not replace the image scanner or the Dockerfile linter you
already run.

## Run on the same file

Documentation describes what a tool is meant to check. A run shows what it
checked. The fixture has sixteen services, each with one deliberate
misconfiguration, written to the Compose Specification, so without the
obsolete `version:` key. Each tool was run from its published image on
2026-10-09. The fixture and the exact commands are in
[Reproduce it](#reproduce-it).

| Misconfiguration | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Docker socket mounted | ✅ | ✅ | ✅ | ✗ † | — |
| `privileged: true` | ✅ | ✅ | ✅ | ✗ † | — |
| `no-new-privileges` missing | ✅ | ✅ | ✅ | ✗ † | — |
| Unpinned `:latest` tag | ✅ | — | ✅ | — | ✅ |
| Port published on `0.0.0.0` | ✅ | ✅ | ✗ ‡ | — | ✅ |
| No `cap_drop: [ALL]` | ✅ | ✅ | — | — | — |
| Writable root filesystem | ✅ | — | ✅ | ✗ † | — |
| `network_mode: host` | ✅ | ✅ | ✅ | — | — |
| `seccomp:unconfined` | ✅ | ✅ | ✅ | ✗ † | — |
| `pid: host` / `ipc: host` | ✅ | ✅ | ✅ | — | — |
| Sensitive host path mounted | ✅ | ✅ | ✅ | — | — |
| `logging: driver: none` | ✅ | — | — | — | — |
| `user: root` | ✅ | — | ✗ | — | — |
| Tag without digest | ✅ | — | — | — | — |
| Credential in `environment:` | ✅ | ✅ | ✅ | — | — |
| No memory/CPU limits | ✅ | ✗ \* | ✅ | — | — |
| **Caught, of 16** | **16** | **10** | **11** | **0** † | **2** |

✅ flagged · ✗ not flagged · — no rule for it. \* KICS's memory and CPU
queries fire only when the file carries the obsolete `version:` key; with
`version: "3.9"` added it catches 11. † Semgrep's rules all require that key;
with it added the same six rules produced 31 findings and caught these 5.
‡ DockSec's all-interfaces rule only covers a fixed list of admin, database
and broker ports, and the fixture publishes 8080.

The run contradicted the documentation in three places:

- **Semgrep's six Compose rules all require a top-level `version:` key.**
  Each one is written as `pattern-inside: version: … services: …`, so on a
  Compose Specification file they report nothing. Semgrep's own summary for
  the run was six rules, one file, zero findings. With `version: "3.9"` added
  and nothing else changed, the same rules produced 31 findings and caught 5
  of the 16. The ruleset's own test fixtures carry `version: "3.9"`. This is
  known upstream as
  [semgrep-rules#4035](https://github.com/semgrep/semgrep-rules/issues/4035)
  (July 2026), with a fix in
  [PR #4037](https://github.com/semgrep/semgrep-rules/pull/4037) waiting for
  review since August. The requirement was added on purpose in 2021 so the
  rules would not match the `services:` block of a GitHub Actions workflow,
  and the fix has to keep that behaviour. When it merges, Semgrep's column
  changes.
- **KICS's limit queries depend on the same key.** The memory and CPU
  queries only fire when `version` is 3 or later, and `Pids Limit Not Set`
  only fires when it is below 3, which means the old version 2 format. On a
  current file none of the three can fire. Its `No New Privileges Not Set`
  query only fires on a service that already has a `security_opt:` list;
  services without one get the broader `Security Opt Not Set` instead.
- **DockSec's Compose rules need only Trivy installed.** Its default mode
  also scans each service's image, which needs the Docker CLI, and runs an
  AI explanation pass, which needs an AI provider key, OpenAI by default.
  Without either, it still reports the Compose findings but exits with
  code 3. The run used `--scan-only`, which skips the AI pass.

Checkov, Trivy and Hadolint were run on the same file too and, as their
documentation says, none of them read it as a Compose file. Their sections
below say what each one checks instead.

Versions, as each tool reported them: compose-lint 0.34.0, DCLint 3.1.0,
KICS 2.1.20, DockSec 2026.8.19 (image tag 2026.9.21; the release declares
2026.9.21 but the tool still reports the older string), Semgrep 1.179.0, Checkov 3.3.26, Trivy 0.75.0,
Hadolint 2.15.1.

## Against the OWASP cheat-sheet rules

The first fixture was built from compose-lint's own rules, so a full score
on it only shows that those rules fire. It says nothing about coverage. The
second fixture is built from the [OWASP Docker Security Cheat
Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
instead, with one service per violation that can be expressed in a Compose
file. That covers Rules 1 to 8, 12 and 13. Rules 0, 9, 10 and 11 concern the
host, the CI pipeline and the daemon. Twenty-one services, same tools, no
`version:` key: twenty were run on 2026-10-09, and the SELinux row was added
on 2026-10-14 against the same image digests. This fixture shows where
compose-lint has no rule.

| OWASP rule — violation | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| 1 — Docker socket mounted | ✅ | ✅ | ✅ | ✗ † | — |
| 2 — `user: root` set explicitly | ✅ | — | ✗ | — | — |
| 2 — no `user:`, image default | — | — | ✅ | — | — |
| 3 — `privileged: true` | ✅ | ✅ | ✅ | ✗ † | — |
| 3 — default capability set, nothing dropped | ✅ | ✅ | — | — | — |
| 3 — `cap_drop: [ALL]` then `cap_add: [SYS_ADMIN]` | ✅ | ✅ | ✅ | — | — |
| 4 — `no-new-privileges` not set | ✅ | ✅ | ✅ | ✗ † | — |
| 5 — `network_mode: host` | ✅ | ✅ | ✅ | — | — |
| 5 — no `networks:`, joins the shared default network | — | — | ✅ | — | — |
| 5a — port published on `0.0.0.0` | ✅ | ✅ | ✗ ‡ | — | ✅ |
| 6 — `seccomp:unconfined` | ✅ | ✅ | ✅ | ✗ † | — |
| 6 — `apparmor:unconfined` | ✅ | — | ✅ | — | — |
| 6 — SELinux `label:disable` | ✅ | — | ✗ | ✗ † | — |
| 7 — no memory or CPU limits | ✅ | ✗ \* | ✅ | — | — |
| 7 — no `pids_limit` | — | ✗ | — | — | — |
| 7 — `restart: always`, unbounded | — | — | — | — | — |
| 8 — root filesystem writable | ✅ | — | ✅ | ✗ † | — |
| 8 — host directory mounted read-write | — | — | — | — | — |
| 12 — credential as a literal `environment:` value | ✅ | ✅ | ✅ | — | — |
| 13 — mutable `:latest` tag | ✅ | — | ✅ | — | ✅ |
| 13 — version tag without a digest | ✅ | — | — | — | — |
| **Flagged, of 21** | **16** | **9** | **13** | **0** † | **2** |
| **No rule for it** | 5 | 10 | 5 | 15 | 19 |
| **Has a rule, missed it** | 0 | 2 | 3 | 6 † | 0 |

✅ flagged · ✗ has a rule for it, did not flag it · — no rule for it.
\* fires with the obsolete `version: "3.9"` key present (10 of 21). † Semgrep's
rules all require that key; with it added they catch these 6. ‡ only for a
fixed list of sensitive ports. Checkov, Trivy and
Hadolint are 0 of 21 on both variants and are left off the table.

compose-lint has no rule for five of the twenty-one. They are listed under
[What compose-lint does not do](#what-compose-lint-does-not-do). It missed
none of the rules it has. DockSec is the closest second and the only tool
that models the shared default network. It misses an explicit `user: root`,
because it checks for the absence of `user:`, its port rule did not
cover the port the fixture publishes, and its disabled-`security_opt` rule
fired on `seccomp:unconfined` and `apparmor:unconfined` but not on
`label:disable`. KICS has queries for two of the three
Rule 7 items and fired neither on a file without `version:`. With
`version: "3.9"` it recovers memory and CPU; its PID query only fires on the
old version 2 format, and it has no query for `restart: always`. No tool
flags a read-write bind mount that could be `:ro`, and none flags
`restart: always`. Only compose-lint flags a missing digest.

## Run on a stack spread across files

Both fixtures above are single, self-contained files. Most stacks are not. A
service inherits from a base with `extends:`, another file is pulled in with
`include:`, `compose.override.yml` is merged on top, and values come from
`.env`. Compose deploys the merged result. A tool that grades each file as
written can miss a setting that only exists after the merge, or report one
the merge has already undone.

The third run tests that. Each scenario puts `privileged: true`, the Docker
socket mount and a port published on all interfaces behind one Compose
mechanism, and `docker compose config` confirmed that each one deploys them.
Four more scenarios look dangerous as written and deploy safely. Every
scenario was run once as written and once with `version: "3.9"` prepended.
KICS, Semgrep and DCLint were given the whole directory, so a base, included
or override file was in front of them as a file of its own. compose-lint and
DockSec were given `compose.yaml`, the file `docker compose` starts from. The
run is from 2026-10-17, with every image pinned by digest; the fixtures and
commands are in [Reproduce it](#reproduce-it).

Each cell lists `privileged`, the socket and the port, in that order.

| Where the settings come from | compose-lint | KICS | DockSec | Semgrep |
|---|---|---|---|---|
| Written inline (control) | ✅ ✅ ✅ | ✅ ✅ ✅ | ✅ ✅ — | ✗ ✗ — † |
| `extends:` a service in the same file | ✅ ✅ ✅ | ◐ ◐ ◐ | ◐ ◐ — | ✗ ✗ — † |
| `extends:` a service in another file | ✅ ✅ ✅ | ◐ ◐ ◐ | ✗ ✗ — | ✗ ✗ — † |
| `include:` of another file | ✅ ✅ ✅ | ✅ ✅ ✅ | ✗ ✗ — | ✗ ✗ — † |
| `compose.override.yml` | ✅ ✅ ✅ | ✗ ✗ ✗ | ✗ ✗ — | ✗ ✗ — † |
| YAML anchor and `<<:` merge key | ✅ ✅ ✅ | ✅ ✅ ✅ | ✅ ✅ — | ✗ ✗ — † |
| `${VAR:-default}` | ✅ ✅ ✅ | ✗ ✗ ✗ | ✗ ✅ — | ✗ ✗ — |
| A value from `.env` | ✅ ✅ ✅ | ✗ ✗ ✅ ‡ | ✗ ✗ — | ✗ ✗ — |

Four more scenarios carry one or two settings each:

| Scenario | compose-lint | KICS | DockSec | Semgrep |
|---|---|---|---|---|
| Socket and port in the long `volumes:` and `ports:` syntax | ✅ ✅ | ✗ ✅ | ✅ — | ✗ — † |
| Socket as `secrets:` with `file: /var/run/docker.sock` | ✅ | ✗ | ✗ | ✗ |
| `seccomp=unconfined` | ✅ | ✗ | ✗ | ✗ |
| `seccomp:unconfined` (control) | ✅ | ✅ | ✅ | ✗ † |

✅ flagged on the service Compose deploys · ◐ flagged on the base service,
not on the service that extends it · ✗ has a rule for it, did not flag it ·
— no rule for it. † Semgrep's rules require the `version:` key; with it
added, Semgrep flags the inline, `include:` and override settings, flags the
base for both `extends:` rows, flags the socket but not `privileged` behind
the anchor, and catches the long-syntax socket and `seccomp:unconfined`. ‡ KICS
also flags the port when `.env` sets it to `127.0.0.1`, so the finding comes
from an address it cannot read rather than from the address Compose deploys.

DCLint is left off these tables because it has a rule for the port only. It
flagged a port set from a variable whether it resolved to `0.0.0.0` or
`127.0.0.1`, and it did not read a base or included file
([compose-lint vs DCLint](#compose-lint-vs-dclint)).

The four scenarios that deploy safely, where ✅ means no finding:

| Looks dangerous, deploys safely | compose-lint | KICS | DockSec | Semgrep |
|---|---|---|---|---|
| `privileged: true`, set back to `false` by `compose.override.yml` | ✅ | ✗ | ✗ | ✅ † |
| Port bound to `${BIND:-127.0.0.1}` | ✅ | ✅ | — | — |
| `no-new-privileges=true`, the `=` spelling | ✅ | ✗ | ✗ | ✅ † |
| Port, socket and `privileged` from a `.env` with safe values | ✅ | ✗ | ✅ | ✅ |

✅ no finding · ✗ reported a setting Compose does not deploy · — no rule for
it. † with the `version:` key added, Semgrep reports both.

What the run shows:

- **`extends:` is not merged.** KICS, DockSec and Semgrep report the base
  service and give the service that extends it only their baseline findings,
  such as a missing healthcheck, so they read that service without merging
  the base into it. When the base is in another file, KICS and Semgrep report
  that file and DockSec, which reads the file it is given, reports nothing.
- **Other files are graded only if the tool happens to scan them.** KICS
  catches `include:` because it scans the included file as a file of its own.
  It parsed one file in the override scenario: `compose.override.yml` was not
  picked up as a Compose file. DCLint read only `compose.yaml` in the
  `extends:` and `include:` scenarios.
- **No other tool reads `.env`.** KICS and DCLint flag a port whose address
  is a variable whether it resolves to `0.0.0.0` or `127.0.0.1`.
- **Spelling matters.** Docker disables seccomp for `seccomp=unconfined` and
  `seccomp:unconfined` alike (`Seccomp: 0` in `/proc/self/status` for both).
  KICS and DockSec catch only the `:` form, and both report
  `no-new-privileges=true` as missing.
- **Only compose-lint flags the socket arriving as a secret.**

The run does not show that YAML anchors are a problem for the other tools:
KICS reports the anchored settings at the anchor's lines and DockSec on the
service. Compose profiles, several `-f` files and `COMPOSE_FILE` were not
tested.

Versions: compose-lint 0.36.0, KICS 2.1.20, DockSec image 2026.9.21,
Semgrep 1.180.0, DCLint 3.1.0.

## Does Checkov scan docker-compose.yml?

No. Checkov's Docker coverage is its [Dockerfile policy
index](https://www.checkov.io/5.Policy%20Index/dockerfile.html): 28 policies
(`CKV_DOCKER_1` to `CKV_DOCKER_11` and `CKV2_DOCKER_1` to `CKV2_DOCKER_17`),
all typed `dockerfile`. There is no `docker_compose` framework, and a
`compose.yaml` passed to `checkov` is not inspected as a Compose file. Guides
that show `checkov --framework docker_compose` describe a flag that does not
exist.

If you already run Checkov for Terraform or Kubernetes, keep running it and
add compose-lint for the Compose files it skips. As of 2026-10-09 there is no
open request for Compose support on Checkov's tracker.

## Does Trivy lint Docker Compose files?

Not the Compose file itself. Trivy's [misconfiguration
scanner](https://trivy.dev/latest/guide/scanner/misconfiguration/) handles
Dockerfile, Kubernetes, Terraform and Terraform plans, CloudFormation, Helm,
Azure ARM and Ansible. Docker Compose is not one of its configuration types. What Trivy does cover is the
images a Compose file references. compose-lint never pulls an image or
reports a CVE, so the two fit together: `trivy image` for what is inside the
image, compose-lint for how the Compose file runs it.

Compose support was requested in April 2025
([aquasecurity/trivy#8729](https://github.com/aquasecurity/trivy/issues/8729)).
A maintainer replied that it could be added but that "there are no checks for
it" to reuse. The most recent comment in the thread, from July 2026, is from
a user surprised that `trivy config` did not catch a port bound to all
interfaces. That is the Rule 5a case in the run above.

## compose-lint vs DCLint

They do different jobs and are often run together. DCLint
([zavoloklom/docker-compose-linter](https://github.com/zavoloklom/docker-compose-linter))
validates a Compose file against the schema and applies fifteen
best-practice rules. Most are about ordering and formatting (alphabetical
services, key order, quoted ports) or structure (no `version:` field, no
duplicate container names or exported ports, a project name). Two overlap
with security: `no-unbound-port-interfaces` and
`service-image-require-explicit-tag`. In both runs it caught exactly those
two. On a [stack spread across files](#run-on-a-stack-spread-across-files)
its port rule flagged an address set from a variable whether it resolved to
`0.0.0.0` or `127.0.0.1`, and it did not read a base file or an included
file. Its `--fix` applies the formatting rules.

compose-lint does not validate the schema. An invalid file is a usage error,
not a finding. Its 28 rules are all security rules: capabilities,
`no-new-privileges`, `read_only`, the Docker socket, host namespaces,
resource limits, credentials in `environment:` and command lines, digest
pinning. Each rule ships with the fix, the error message you will see if the
fix breaks something, and the OWASP or CIS citation behind it. Where both tools flag
the same thing, such as an image without a tag or a port bound to
`0.0.0.0`, compose-lint grades it as a security finding with a severity and
DCLint reports it as a lint error.

## compose-lint vs KICS

KICS ([docs.kics.io](https://docs.kics.io/latest/queries/dockercompose-queries/))
is the closest in coverage, with 21 Docker Compose queries: the Docker
socket mount, `no-new-privileges`, privileged containers, unrestricted
capabilities, the default seccomp profile, shared host namespaces, memory,
CPU and PID limits, and `security_opt`. In the run above it caught 10 of 16
on a file without `version:` and 11 with `version: "3.9"` added, because the
memory and CPU queries key off the version number and skip a Compose
Specification file. KICS is a broad IaC scanner and Compose is one of many
platforms it covers. Each query page describes the pattern and shows a
compliant and a non-compliant sample. The queries compose-lint lacks are
ones it retired or declined with the reason on the rule page: the PID limit
and the missing healthcheck
([ADR-028](adr/028-pre-1.0-rule-id-sweep.md)), the host user namespace and
`cgroup_parent` ([CL-0010](rules/CL-0010.md)), the restart cap
([CL-0026](rules/CL-0026.md)) and privileged host ports
([CL-0005](rules/CL-0005.md)).

Three issues on KICS's tracker matter if you rely on it for Compose. The
maintainers' position, stated in 2023 on
[#6509](https://github.com/Checkmarx/kics/issues/6509), is that the
`version:` key is needed to avoid false positives, and the limit queries
still test it: memory and CPU need version 3 or later, PID a version below 3.
`No New Privileges Not Set` reports a service that uses
the newer `no-new-privileges=true` spelling as missing it
([#7077](https://github.com/Checkmarx/kics/issues/7077), open since 2024;
compose-lint accepts both spellings). An anonymous volume is reported as
`Volume Has Sensitive Host Directory`
([#8047](https://github.com/Checkmarx/kics/issues/8047), open since May
2026).

On a [stack spread across files](#run-on-a-stack-spread-across-files), KICS
reported the base service rather than the one that extends it, did not pick
up `compose.override.yml`, did not resolve `${VAR:-default}` or `.env`,
missed the socket written in the long `volumes:` syntax, and caught
`seccomp:unconfined` but not `seccomp=unconfined`, which Docker treats the
same.

compose-lint is Compose-only and puts its effort into the fix. Each rule page
explains what the setting does at runtime, which error messages the hardened
configuration produces when an image was not built for it, and how to tell a
real breakage from a false alarm. Its claims about runtime behaviour are
re-tested against live containers in CI. KICS has a `remediate` command, but
its documentation does not say whether Compose is one of the platforms it
rewrites. compose-lint's `fix` edits the findings of six rules in place after
a dry-run diff and lists the rest with the fix to make by hand.

## compose-lint vs Semgrep's `p/docker-compose` ruleset

Semgrep's registry has six Compose security rules under
[`yaml/docker-compose/security`](https://github.com/semgrep/semgrep-rules/tree/develop/yaml/docker-compose/security):
the Docker socket as a volume, `no-new-privileges`, privileged services,
seccomp confinement disabled, SELinux separation disabled, and a writable
root filesystem. All six are `WARNING` severity and one
(`privileged-service`) has an autofix. All six match only a file that still
has the obsolete `version:` key; the [run above](#run-on-the-same-file) has
the numbers and the upstream fix. The same reporter filed a second gap, that
an explicit `user: root` is not detected
([#4036](https://github.com/semgrep/semgrep-rules/issues/4036), fix
[PR #4048](https://github.com/semgrep/semgrep-rules/pull/4048)). Until those
merge, the ruleset is one line to enable if Semgrep already runs in your CI
and your files keep `version:`. If you have removed `version:`, as Compose
now recommends, the ruleset does nothing and reports nothing.

Two narrower gaps showed up on a
[stack spread across files](#run-on-a-stack-spread-across-files), both with
`version:` present. The socket rule did not fire on
`/var/run/docker.sock:/sock`, the socket mounted at another path inside the
container. The seccomp rule fired on a `security_opt:` list holding only
`seccomp:unconfined`, and not on one that also held `apparmor:unconfined`.

compose-lint covers those six and the rest of its 28 rules: capability
tiers, resource limits, credentials in environment variables, connection
strings and command-line arguments, digest pinning, sensitive host paths,
mount propagation, logging disabled. Severities are set per rule from a stated model rather than one
level for everything, and each finding carries fix guidance that a one-line
Semgrep message has no room for.

## compose-lint vs OWASP DockSec

DockSec ([OWASP/DockSec](https://github.com/OWASP/DockSec)) scans
Dockerfiles, images and, with `--compose`, Compose files, and uses an LLM to
explain and prioritise findings. Its 17 Compose rules are documented and
need only Trivy installed; the Docker CLI adds a scan of each service's
image and an AI provider key adds the explanation pass. In the run above
its Compose rules caught 11 of 16: the socket mount, `privileged`, host
network and namespaces, the sensitive host path, seccomp unconfined, the
plaintext secret, the `:latest` tag, missing `no-new-privileges`, writable
root and missing limits. It also reported two cross-service "exploit
chains", such as an internet-facing service sharing the default network with
a service that holds a committed credential, which no other tool here
attempts. It did not flag the `0.0.0.0` bind,
because its port rule only covers sensitive ports, the missing `cap_drop`,
`logging: none`, the missing digest, or an explicit `user: root`. Its
`--fix` applies mechanical Dockerfile changes only. Compose findings are
listed as "needs review".

compose-lint is deterministic. The same file produces the same findings,
severities and diff on every run, with no model and no network access, and
its auto-fix works on the Compose file. Which matters more depends on
whether the linter is a CI gate or an advisor. The explicit `user: root` gap
was not on DockSec's tracker as of 2026-10-09.

On a [stack spread across files](#run-on-a-stack-spread-across-files),
DockSec resolved YAML anchors but read only the file it was given: it did not
follow `extends:` into another file, `include:` or `compose.override.yml`. In
the same file it reported the base service rather than the one that extends
it. It caught `seccomp:unconfined` but not `seccomp=unconfined`, and reported
`no-new-privileges=true` as missing.

## When a script of your own is enough

Search results and AI answers for these questions often suggest skipping the
tools and writing the check yourself: `yq '.services[] | select(.privileged
== true)'`, a Conftest policy, a custom Semgrep or KICS rule. For a single
check in a pre-commit hook, such as "nothing in this repository may say
`privileged: true`", that is the right answer. No tool on this page does it
better.

What the script does not give you is the Compose semantics, and the runs
above show what those cost even for funded tools: Semgrep's rules are silent
on every modern file because they anchor on `version:`, KICS gates its limit
queries the same way, and KICS reports `no-new-privileges=true` as missing
over a `:` versus `=` difference. A script that grades what Compose actually
deploys has to:

- resolve `${VAR:-default}` to the value Compose ships when no `.env` is
  present;
- follow `extends:` and `include:` across files and apply their merge order;
- expand YAML anchors and `<<:` merge keys;
- read both the short and the long `ports:` syntax;
- treat `security_opt` as a list where the last entry naming a key wins,
  which is what `extends:` produces when a child un-hardens its base;
- notice that `secrets:` with `file:` is a bind mount of that host file under
  another key, so a socket can arrive that way too.

compose-lint runs each of those checks ([how it works](how-it-works.md),
[what a run reads](what-a-run-reads.md)), and most of them were added
because a real file slipped past a simpler version. The
[run on a stack spread across files](#run-on-a-stack-spread-across-files)
shows the tools above missing several of them too: `extends:`, overrides,
`.env`, the long volume syntax and the socket as a secret. Compose changes over
time, and a script has to change with it.

Custom rules for the tools above inherit the tool's parser, which makes them
a middle path, but only where the tool reads the file. A custom KICS query
(Rego) or Semgrep rule can check anything in a Compose file the tool parses.
A custom Checkov policy cannot help, because Checkov never loads the file.

## Does Hadolint lint Docker Compose files?

No. [Hadolint](https://github.com/hadolint/hadolint) lints Dockerfiles and
does not read Compose files. A request for Compose support from 2025
([hadolint#1091](https://github.com/hadolint/hadolint/issues/1091)) is
still open with no reply from the maintainers; the one answer, from another
user, was to parse the YAML with a script or `yq`. Nothing on
this page replaces it. A hardened Compose file that runs an image built from
an unhardened Dockerfile is only half the work, and the two tools do not
overlap.

## What compose-lint does not do

- **Validate the Compose schema.** An invalid file is exit 2, not a finding.
  Pair it with [DCLint](https://github.com/zavoloklom/docker-compose-linter).
- **Scan images.** It never pulls an image, inspects layers or reports CVEs.
  Pair it with [Trivy](https://github.com/aquasecurity/trivy) or
  [Docker Scout](https://www.docker.com/products/docker-scout/).
- **Lint Dockerfiles.** It reads `compose.yaml` and `docker-compose.yml`,
  never `Dockerfile`. Pair it with [Hadolint](https://github.com/hadolint/hadolint).
- **Watch running containers.** It is a static analyzer. See
  [Security expectations](SECURITY-EXPECTATIONS.md) for the full list.

The second run also shows five things the OWASP cheat sheet asks for that
compose-lint has no rule for:

- **A service with no `user:` at all** (Rule 2). The image's `USER` is not in
  the Compose file, so compose-lint cannot tell a root default from a
  non-root one and does not guess. It flags `user: root` when written.
  DockSec takes the other approach and flags the absence.
- **Services on the shared default network** (Rule 5). Met by construction:
  Compose attaches a project to its own `<project>_default` user-defined
  bridge, so the `docker0` bridge that CIS 5.30 asks not to use is avoided
  without a `networks:` key, and whether two services of one project should
  reach each other is a design decision no rule grades
  ([CL-0008](rules/CL-0008.md)).
- **No `pids_limit`** (Rule 7). CL-0012 flagged this and was retired. On a
  systemd host the limit is bounded by `DefaultTasksMax` whether or not the
  file sets it.
- **`restart: always`** (Rule 7). Docker already delays each restart by
  double the previous delay, and a retry cap turns a restart loop into an
  outage, so no rule asks for one ([CL-0026](rules/CL-0026.md)).
- **A host directory mounted read-write that could be `:ro`** (Rule 8).
  [CL-0013](rules/CL-0013.md) and [CL-0025](rules/CL-0025.md) flag sensitive
  and root-equivalent host paths, where write access is what makes the path
  dangerous. Whether an ordinary path needs writing is a fact about the
  application that the Compose file does not carry, so an ordinary read-write
  bind mount is not a finding.

## Reproduce it

The fixture is sixteen services with one deliberate misconfiguration each,
named for the compose-lint rule it targets. Do not run it.

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
root-equivalent host mount) rather than CL-0013. The table counts that as
caught. Its 85 findings are the 16 intended ones plus the baseline hardening
misses on every service that lacks them, which is what the tool is for.

The OWASP-framed fixture has the same shape, one service per row of its
table, named `rule<N>-<violation>`, with the same images. It was run with
the same commands, once as written and once with `version: "3.9"` prepended.
The SELinux service (`security_opt: [label:disable]`) was run the same way
on 2026-10-14, with each image pinned to the digest the 2026-10-09 run had
recorded.

### The stack spread across files

Each scenario is its own directory. Every image is `nginx:1.27.2-alpine`,
and none of the scenarios is meant to be started.

```yaml
# inline/compose.yaml (control)
services:
  app:
    image: nginx:1.27.2-alpine
    privileged: true
    ports: ["8080:80"]
    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]

# extends-same-file/compose.yaml
services:
  base:
    image: nginx:1.27.2-alpine
    privileged: true
    ports: ["8080:80"]
    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
  app:
    extends: base

# extends-other-file/common.yml holds the base service above;
# extends-other-file/compose.yaml
services:
  app:
    extends:
      file: common.yml
      service: base

# include/sub/stack.yml holds the inline app service;
# include/compose.yaml
include:
  - sub/stack.yml
services:
  web:
    image: nginx:1.27.2-alpine

# override/compose.yaml
services:
  app:
    image: nginx:1.27.2-alpine
# override/compose.override.yml
services:
  app:
    privileged: true
    ports: ["8080:80"]
    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]

# anchor/compose.yaml
x-danger: &danger
  privileged: true
  ports: ["8080:80"]
  volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
services:
  app:
    <<: *danger
    image: nginx:1.27.2-alpine

# interpolation-default/compose.yaml
services:
  app:
    image: nginx:1.27.2-alpine
    privileged: ${PRIV:-true}
    ports: ["${BIND:-0.0.0.0}:8080:80"]
    volumes: ["${SOCK:-/var/run/docker.sock}:/sock"]

# dotenv/compose.yaml, with dotenv/.env holding
# PRIV=true, BIND=0.0.0.0 and SOCK=/var/run/docker.sock
services:
  app:
    image: nginx:1.27.2-alpine
    privileged: ${PRIV}
    ports: ["${BIND}:8080:80"]
    volumes: ["${SOCK}:/sock"]

# long-syntax/compose.yaml
services:
  app:
    image: nginx:1.27.2-alpine
    ports:
      - target: 80
        published: "8080"
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock

# secret-file/compose.yaml
services:
  app:
    image: nginx:1.27.2-alpine
    secrets: [sock]
secrets:
  sock:
    file: /var/run/docker.sock

# seccomp-equals/compose.yaml; seccomp-colon is the same with seccomp:unconfined
services:
  app:
    image: nginx:1.27.2-alpine
    security_opt: ["seccomp=unconfined"]

# socket-elsewhere/compose.yaml (the Semgrep socket-rule probe)
services:
  app:
    image: nginx:1.27.2-alpine
    volumes: ["/var/run/docker.sock:/sock"]
```

The four that deploy safely:

```yaml
# safe-override/compose.yaml
services:
  app:
    image: nginx:1.27.2-alpine
    privileged: true
# safe-override/compose.override.yml
services:
  app:
    privileged: false

# safe-default/compose.yaml
services:
  app:
    image: nginx:1.27.2-alpine
    ports: ["${BIND:-127.0.0.1}:8080:80"]

# safe-nnp-equals/compose.yaml
services:
  app:
    image: nginx:1.27.2-alpine
    cap_drop: [ALL]
    read_only: true
    security_opt: ["no-new-privileges=true"]

# safe-dotenv/ is dotenv/ with .env holding
# PRIV=false, BIND=127.0.0.1 and SOCK=/srv/data
```

Each scenario directory was mounted read-only at `/src`. compose-lint runs
with `/src` as its working directory, so the scenario directory is the
boundary it reads within:

```bash
docker run --rm -w /src -v "$PWD:/src:ro" composelint/compose-lint:1.0.0@sha256:b6742a7ff80a1a75e824a8aa1c6579946fdd48c771f7085a046a18f95c3fe19d check --format json /src/compose.yaml
docker run --rm -v "$PWD:/src:ro" -v "$PWD/out:/out" checkmarx/kics:v2.1.20@sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602 scan -p /src -o /out --report-formats json -t DockerCompose --disable-secrets
docker run --rm -v "$PWD:/src:ro" -v "$PWD/out:/root/.docksec/results" owasp/docksec:2026.9.21@sha256:646e8250e2dc98ac4c8fd5f9a5d37f9aecae149a468271b5b1dc04092f927be4 --compose /src/compose.yaml --format json --scan-only
docker run --rm -v "$PWD:/src:ro" semgrep/semgrep:1.180.0@sha256:529ee8a277ec8adc5b534d7c74eea0a47e9de21d62852b6ba7ac6ba9566845c3 semgrep --metrics=off --config p/docker-compose --json /src
docker run --rm -v "$PWD:/src:ro" zavoloklom/dclint:3.1.0@sha256:dd6e0faa9fa8856a643a1e55476077d555b8e9c946cc481f8fbee203662c3e77 -f json -r /src
```

`docker compose config` in each directory is the ground truth for what
deploys. A finding counts for a row only when it comes from that tool's own
rule for the setting.

## Corrections

The counts in the summary table come from the linked documentation as read
on 2026-10-08. The runs are from 2026-10-09 and 2026-10-17 with the versions
listed above.
Tools change. If a row is out of date, [open an
issue](https://github.com/tmatens/compose-lint/issues) with the link or the
output that shows it and the row will be corrected.

Known changes that would move these results when they land:

- Semgrep's column goes from 0 to 6 of 21 when
  [semgrep-rules#4037](https://github.com/semgrep/semgrep-rules/pull/4037)
  merges, and gains `user: root` with
  [#4048](https://github.com/semgrep/semgrep-rules/pull/4048). The same fix
  moves its column in the run on a stack spread across files to the
  `version:` results in the † notes.
- KICS stops reporting the `no-new-privileges=true` spelling as missing when
  [#7077](https://github.com/Checkmarx/kics/issues/7077) is fixed.
- Trivy gets a column if
  [trivy#8729](https://github.com/aquasecurity/trivy/issues/8729) is taken up.
- DockSec moves to 14 of 21 if it starts flagging an explicit `user: root`.
