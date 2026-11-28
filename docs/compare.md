# compose-lint compared with DCLint, KICS, Checkov, Trivy, Semgrep, DockSec and Hadolint

Five of these eight tools read a Docker Compose file and check it for
security misconfigurations: compose-lint, DCLint, KICS, Semgrep's
`p/docker-compose` ruleset and OWASP DockSec. Checkov, Trivy and Hadolint
lint Dockerfiles or images and do not read a Compose file.

I maintain compose-lint, and I ran all eight on the same files. Two of the
five, Semgrep and KICS, only work fully on files that still carry the obsolete
top-level `version:` key. [The `version:` key](#the-version-key) below has the
detail. Writing a script of your own is a ninth option, and it has
[its own section](#when-a-script-of-your-own-is-enough).

Sources are linked under each heading. The versions and dates behind the
tables are under [Reproduce it](#reproduce-it).

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
which of them fired on which file. What compose-lint has no rule for, and
why, is listed at the end of the page. It does not replace the image scanner
or the Dockerfile linter you already run.

## Against the OWASP cheat-sheet rules

The table above comes from each tool's documentation, so I also ran every
tool on the same files to see what it reported. The first fixture is built
from the [OWASP Docker Security Cheat
Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html),
with one service per violation that can be expressed in a Compose file. That
covers Rules 1 to 8, 12 and 13. Rules 0, 9, 10 and 11 concern the host, the
CI pipeline and the daemon.

It has twenty-one services and no `version:` key. I ran each tool from its
published image on 2026-11-28. The fixture and the exact commands are in
[Reproduce it](#reproduce-it). This fixture shows where compose-lint has no
rule.

| OWASP rule — violation | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| 1 — Docker socket mounted | Yes | Yes | Yes | Missed † | No rule |
| 2 — `user: root` set explicitly | Yes | No rule | Missed | No rule | No rule |
| 2 — no `user:`, image default | No rule | No rule | Yes | No rule | No rule |
| 3 — `privileged: true` | Yes | Yes | Yes | Missed † | No rule |
| 3 — default capability set, nothing dropped | Yes | Yes | No rule | No rule | No rule |
| 3 — `cap_drop: [ALL]` then `cap_add: [SYS_ADMIN]` | Yes | Yes | Yes | No rule | No rule |
| 4 — `no-new-privileges` not set | Yes | Yes | Yes | Missed † | No rule |
| 5 — `network_mode: host` | Yes | Yes | Yes | No rule | No rule |
| 5 — no `networks:`, joins the shared default network | No rule | No rule | Yes | No rule | No rule |
| 5a — port published on `0.0.0.0` | Yes | Yes | Missed ‡ | No rule | Yes |
| 6 — `seccomp:unconfined` | Yes | Yes | Yes | Missed † | No rule |
| 6 — `apparmor:unconfined` | Yes | No rule | Yes | No rule | No rule |
| 6 — SELinux `label:disable` | Yes | No rule | Missed | Missed † | No rule |
| 7 — no memory or CPU limits | Yes | Missed \* | Yes | No rule | No rule |
| 7 — no `pids_limit` | No rule | Missed | No rule | No rule | No rule |
| 7 — `restart: always`, unbounded | No rule | No rule | No rule | No rule | No rule |
| 8 — root filesystem writable | Yes | No rule | Yes | Missed † | No rule |
| 8 — host directory mounted read-write | No rule | No rule | No rule | No rule | No rule |
| 12 — credential as a literal `environment:` value | Yes | Yes | Yes | No rule | No rule |
| 13 — mutable `:latest` tag | Yes | No rule | Yes | No rule | Yes |
| 13 — version tag without a digest | Yes | No rule | No rule | No rule | No rule |
| **Flagged, of 21** | **16** | **9** | **13** | **0** † | **2** |
| **No rule for it** | 5 | 10 | 5 | 15 | 19 |
| **Has a rule, missed it** | 0 | 2 | 3 | 6 † | 0 |

- Yes: flagged
- Missed: has a rule for it, did not flag it
- No rule: the tool has no rule for it
- \* KICS: fires with the obsolete `version: "3.9"` key present, which makes
  its total 10 of 21.
- † Semgrep: all six rules need that key. With it added they catch these 6.
- ‡ DockSec: only for a fixed list of sensitive ports.

Checkov, Trivy and Hadolint flagged 0 of 21, with or without the `version:`
key, and are left off the table.

compose-lint flagged 16 of the 21 and has no rule for the other five. They
are listed under
[What compose-lint does not do](#what-compose-lint-does-not-do). It missed
none of the rules it has. For the other four tools in the table:

- **DockSec** flagged 13 and is the only tool that models the shared default
  network. It misses an explicit `user: root`, because it checks for
  the absence of `user:`. Its port rule did not cover the port the fixture
  publishes. Its disabled-`security_opt` rule fired on `seccomp:unconfined`
  and `apparmor:unconfined` but not on `label:disable`.
- **KICS** flagged 9. It has queries for two of the three Rule 7 items and
  fired neither on a file without `version:`. With `version: "3.9"` it
  recovers memory and CPU, which makes 10. Its PID query only fires on the
  old version 2 format, and it has no query for `restart: always`.
- **None of the five** flags a read-write bind mount that could be `:ro`, and
  none flags `restart: always`. Of the five, only compose-lint flags a missing
  digest.

## The `version:` key

The Compose Specification that Docker Compose has followed since 2020 makes
the top-level `version:` key obsolete, and `docker compose` warns when it sees
one. Two tools still depend on it.

**Semgrep's six Compose rules all require it.** Each one is written as
`pattern-inside: version: … services: …`, so on a Compose Specification file
they report nothing. Semgrep's own summary for the
[same-file run](#run-on-the-same-file) was six rules,
one file, zero findings. With `version: "3.9"` added and nothing else changed,
the same rules produced 31 findings and caught 5 of the 16. The ruleset's own
test fixtures carry `version: "3.9"`.

This is known upstream as
[semgrep-rules#4035](https://github.com/semgrep/semgrep-rules/issues/4035)
(July 2026), with a fix in
[PR #4037](https://github.com/semgrep/semgrep-rules/pull/4037). The
requirement was added on purpose in 2021 so the rules would not match the
`services:` block of a GitHub Actions workflow, and the fix has to keep that
behaviour. When it merges, Semgrep's column changes.

**KICS's limit queries depend on it too.** The memory and CPU queries only
fire when `version` is 3 or later, and `Pids Limit Not Set` only fires when it
is below 3, which means the old version 2 format. On a current file none of
the three can fire. The maintainers' position, stated in 2023 on
[#6509](https://github.com/Checkmarx/kics/issues/6509), is that the key is
needed to avoid false positives.

One more KICS query has a precondition of its own. `No New Privileges Not Set`
only fires on a service that already has a `security_opt:` list. Services
without one get the broader `Security Opt Not Set` instead.

## Run on a stack spread across files

The other two fixtures are single files, and many stacks are spread across
several. A service inherits from a base with `extends:`, another file is pulled in with
`include:`, `compose.override.yml` is merged on top, and values come from
`.env`. Compose deploys the merged result. A tool that grades each file as
written can miss a setting that only exists after the merge, or report one
the merge has already undone.

This run tests that. Each scenario puts `privileged: true`, the Docker
socket mount and a port published on all interfaces behind one Compose
mechanism, and `docker compose config` confirmed that each one deploys them.
Four more scenarios look dangerous as written and deploy safely.

I ran every scenario once as written and once with `version: "3.9"`
prepended. I gave KICS, Semgrep and DCLint the whole directory, so a base,
included or override file was in front of them as a file of its own. I gave
compose-lint and DockSec `compose.yaml`, the file `docker compose` starts
from. The run is from 2026-11-28, with the same versions as the OWASP run. The
fixtures and commands are in [Reproduce it](#reproduce-it).

The results are one table per setting.

**`privileged: true`**

| Where the setting comes from | compose-lint | KICS | DockSec | Semgrep |
|---|---|---|---|---|
| Written inline (control) | Yes | Yes | Yes | Missed † |
| `extends:` a service in the same file | Yes | Base only | Base only | Missed † |
| `extends:` a service in another file | Yes | Base only | Missed | Missed † |
| `include:` of another file | Yes | Yes | Missed | Missed † |
| `compose.override.yml` | Yes | Missed | Missed | Missed † |
| YAML anchor and `<<:` merge key | Yes | Yes | Yes | Missed † |
| `${VAR:-default}` | Yes | Missed | Missed | Missed |
| A value from `.env` | Yes | Missed | Missed | Missed |

**The Docker socket mount**

| Where the setting comes from | compose-lint | KICS | DockSec | Semgrep |
|---|---|---|---|---|
| Written inline (control) | Yes | Yes | Yes | Missed † |
| `extends:` a service in the same file | Yes | Base only | Base only | Missed † |
| `extends:` a service in another file | Yes | Base only | Missed | Missed † |
| `include:` of another file | Yes | Yes | Missed | Missed † |
| `compose.override.yml` | Yes | Missed | Missed | Missed † |
| YAML anchor and `<<:` merge key | Yes | Yes | Yes | Missed † |
| `${VAR:-default}` | Yes | Missed | Yes | Missed |
| A value from `.env` | Yes | Missed | Missed | Missed |

**A port published on all interfaces**

| Where the setting comes from | compose-lint | KICS |
|---|---|---|
| Written inline (control) | Yes | Yes |
| `extends:` a service in the same file | Yes | Base only |
| `extends:` a service in another file | Yes | Base only |
| `include:` of another file | Yes | Yes |
| `compose.override.yml` | Yes | Missed |
| YAML anchor and `<<:` merge key | Yes | Yes |
| `${VAR:-default}` | Yes | Missed |
| A value from `.env` | Yes | Yes § |

DockSec and Semgrep have no rule for this port, so they are left off the
port table.

Four more scenarios carry one or two settings each:

| Scenario | compose-lint | KICS | DockSec | Semgrep |
|---|---|---|---|---|
| Socket in the long `volumes:` syntax | Yes | Missed | Yes | Missed † |
| Port in the long `ports:` syntax | Yes | Yes | No rule | No rule |
| Socket as `secrets:` with `file: /var/run/docker.sock` | Yes | Missed | Missed | Missed |
| `seccomp=unconfined` | Yes | Missed | Missed | Missed |
| `seccomp:unconfined` (control) | Yes | Yes | Yes | Missed † |

- Yes: flagged on the service Compose deploys
- Base only: flagged on the base service, not on the service that extends it
- Missed: has a rule for it, did not flag it
- No rule: the tool has no rule for it
- † Semgrep's rules require the `version:` key. With it added, Semgrep:
    - flags the inline, `include:` and override settings
    - flags the base for both `extends:` rows
    - flags the socket but not `privileged` behind the anchor
    - catches the long-syntax socket and `seccomp:unconfined`
- § KICS also flags the port when `.env` sets it to `127.0.0.1`, so the
  finding comes from an address it cannot read and not from the address
  Compose deploys.

DCLint is left off these tables because it has a rule for the port only. It
flagged a port set from a variable whether it resolved to `0.0.0.0` or
`127.0.0.1`, and it did not read a base or included file
([compose-lint vs DCLint](#compose-lint-vs-dclint)).

The last four scenarios look dangerous as written and deploy safely, so the
right result is no finding:

| Looks dangerous, deploys safely | compose-lint | KICS | DockSec | Semgrep |
|---|---|---|---|---|
| `privileged: true`, set back to `false` by `compose.override.yml` | Quiet | False alarm | False alarm | Quiet † |
| Port bound to `${BIND:-127.0.0.1}` | Quiet | Quiet | No rule | No rule |
| `no-new-privileges=true`, the `=` spelling | Quiet | False alarm | False alarm | Quiet † |
| Port, socket and `privileged` from a `.env` with safe values | Quiet | False alarm | Quiet | Quiet |

- Quiet: no finding
- False alarm: reported a setting Compose does not deploy
- † With the `version:` key added, Semgrep reports both.

What the run shows about the five tools I ran:

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

The run does not show that YAML anchors are a problem for the other tools.
KICS reports the anchored settings at the anchor's lines and DockSec on the
service. Compose profiles, several `-f` files and `COMPOSE_FILE` were not
tested.

## Run on the same file

This fixture was built from compose-lint's own rules, so a full score on it
only shows that those rules fire. It says nothing about coverage. It has
sixteen services, each with one deliberate misconfiguration, written to the
Compose Specification, so without the obsolete `version:` key. I ran each
tool from its published image on 2026-11-28. The fixture and the exact
commands are in [Reproduce it](#reproduce-it).

| Misconfiguration | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Docker socket mounted | Yes | Yes | Yes | Missed † | No rule |
| `privileged: true` | Yes | Yes | Yes | Missed † | No rule |
| `no-new-privileges` missing | Yes | Yes | Yes | Missed † | No rule |
| Unpinned `:latest` tag | Yes | No rule | Yes | No rule | Yes |
| Port published on `0.0.0.0` | Yes | Yes | Missed ‡ | No rule | Yes |
| No `cap_drop: [ALL]` | Yes | Yes | No rule | No rule | No rule |
| Writable root filesystem | Yes | No rule | Yes | Missed † | No rule |
| `network_mode: host` | Yes | Yes | Yes | No rule | No rule |
| `seccomp:unconfined` | Yes | Yes | Yes | Missed † | No rule |
| `pid: host` / `ipc: host` | Yes | Yes | Yes | No rule | No rule |
| Sensitive host path mounted | Yes | Yes | Yes | No rule | No rule |
| `logging: driver: none` | Yes | No rule | No rule | No rule | No rule |
| `user: root` | Yes | No rule | Missed | No rule | No rule |
| Tag without digest | Yes | No rule | No rule | No rule | No rule |
| Credential in `environment:` | Yes | Yes | Yes | No rule | No rule |
| No memory/CPU limits | Yes | Missed \* | Yes | No rule | No rule |
| **Caught, of 16** | **16** | **10** | **11** | **0** † | **2** |

- Yes: flagged
- Missed: has a rule for it, did not flag it
- No rule: the tool has no rule for it
- \* KICS: the memory and CPU queries need the `version:` key. With
  `version: "3.9"` added it catches 11.
- † Semgrep: all six rules need the `version:` key. With it added they
  produced 31 findings and caught these 5.
- ‡ DockSec: its all-interfaces rule covers a fixed list of admin, database
  and broker ports, and the fixture publishes 8080.

The run contradicted the documentation in three places. Two are about the
`version:` key and are under [The `version:` key](#the-version-key). The third is that DockSec's
Compose rules need only Trivy installed. Its default mode also scans each
service's image, which needs the Docker CLI, and runs an AI explanation pass,
which needs an AI provider key, OpenAI by default. Without either, it still
reports the Compose findings but exits with code 3. The run used
`--scan-only`, which skips the AI pass.

Checkov, Trivy and Hadolint were run on the same file too and, as their
documentation says, none of them read it as a Compose file. Their sections
below say what each one checks instead.

## Does Checkov scan docker-compose.yml?

No. Checkov's Docker coverage is its [Dockerfile policy
index](https://www.checkov.io/5.Policy%20Index/dockerfile.html): 28 policies
(`CKV_DOCKER_1` to `CKV_DOCKER_11` and `CKV2_DOCKER_1` to `CKV2_DOCKER_17`),
all typed `dockerfile`. There is no `docker_compose` framework, and a
`compose.yaml` passed to `checkov` is not inspected as a Compose file.

If you already run Checkov for Terraform or Kubernetes, keep running it and
add compose-lint for the Compose files it skips. As of 2026-11-28 there is no
open request for Compose support on Checkov's tracker.

## Does Trivy lint Docker Compose files?

Not the Compose file itself. Trivy's [misconfiguration
scanner](https://trivy.dev/latest/guide/scanner/misconfiguration/) handles
Dockerfile, Kubernetes, Terraform and Terraform plans, CloudFormation, Helm,
Azure ARM and Ansible. Docker Compose is not one of its configuration types.

What Trivy does cover is the images a Compose file references. compose-lint never pulls an image or
reports a CVE, so the two fit together: `trivy image` for what is inside the
image, compose-lint for how the Compose file runs it.

Compose support was requested in April 2025
([aquasecurity/trivy#8729](https://github.com/aquasecurity/trivy/issues/8729)).
A maintainer replied that it could be added but that "there are no checks for
it" to reuse. The most recent comment in the thread, from July 2026, is from
a user surprised that `trivy config` did not catch a port bound to all
interfaces. That is the Rule 5a case in the
[OWASP run](#against-the-owasp-cheat-sheet-rules).

## Does Hadolint lint Docker Compose files?

No. [Hadolint](https://github.com/hadolint/hadolint) lints Dockerfiles and
does not read Compose files. A request for Compose support from 2025
([hadolint#1091](https://github.com/hadolint/hadolint/issues/1091)) is
still open with no reply from the maintainers. The one answer, from another
user, was to parse the YAML with a script or `yq`. Nothing on
this page replaces it. Hardening the Compose file does not harden the image it
runs, so keep running Hadolint. The two tools do not overlap.

## compose-lint vs DCLint

They do different jobs and are often run together. DCLint
([zavoloklom/docker-compose-linter](https://github.com/zavoloklom/docker-compose-linter))
validates a Compose file against the schema and applies fifteen
best-practice rules. Most are about ordering and formatting (alphabetical
services, key order, quoted ports) or structure (no `version:` field, no
duplicate container names or exported ports, a project name). Two overlap
with security: `no-unbound-port-interfaces` and
`service-image-require-explicit-tag`. In both single-file runs it caught
exactly those two. Its `--fix` applies the formatting rules.

compose-lint does not validate the schema. An invalid file is a usage error,
not a finding. Its 28 rules are all security rules: capabilities,
`no-new-privileges`, `read_only`, the Docker socket, host namespaces,
resource limits, credentials in `environment:` and command lines, digest
pinning. Each rule ships with the fix, the error message you will see if the
fix breaks something, and the OWASP or CIS citation behind it.

Where both tools flag
the same thing, such as an image without a tag or a port bound to
`0.0.0.0`, compose-lint grades it as a security finding with a severity and
DCLint reports it as a lint error.

## compose-lint vs KICS

KICS ([docs.kics.io](https://docs.kics.io/latest/queries/dockercompose-queries/))
is the closest in coverage, with 21 Docker Compose queries: the Docker
socket mount, `no-new-privileges`, privileged containers, unrestricted
capabilities, the default seccomp profile, shared host namespaces, memory,
CPU and PID limits, and `security_opt`. In the
[same-file run](#run-on-the-same-file) it caught 10 of 16,
or 11 with the [`version:` key](#the-version-key) added. KICS is a broad IaC
scanner and Compose is one of many platforms it covers. Each query page
describes the pattern and shows a compliant and a non-compliant sample.

The queries compose-lint lacks are ones it retired or declined, with the
reason on the rule page: the PID limit and the missing healthcheck
([ADR-028](adr/028-pre-1.0-rule-id-sweep.md)), the host user namespace and
`cgroup_parent` ([CL-0010](rules/CL-0010.md)), the restart cap
([CL-0026](rules/CL-0026.md)) and privileged host ports
([CL-0005](rules/CL-0005.md)).

Two open issues on KICS's tracker matter if you rely on it for Compose:

- `No New Privileges Not Set` reports a service that uses the newer
  `no-new-privileges=true` spelling as missing it
  ([#7077](https://github.com/Checkmarx/kics/issues/7077), open since 2024).
  compose-lint accepts both spellings.
- An anonymous volume is reported as `Volume Has Sensitive Host Directory`
  ([#8047](https://github.com/Checkmarx/kics/issues/8047), open since May
  2026).

Its results on a stack spread across files are in
[the multi-file run](#run-on-a-stack-spread-across-files).

compose-lint is Compose-only. Each rule page
explains what the setting does at runtime, which error messages the hardened
configuration produces when an image was not built for it, and how to tell a
real breakage from a false alarm. Its claims about runtime behaviour are
re-tested against live containers in CI, by the `rule-premises` job in the
[CI reference](CI.md). KICS has a `remediate` command, but
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
has the obsolete [`version:` key](#the-version-key).

The person who reported the `version:` problem also reported that an explicit
`user: root` is not detected
([#4036](https://github.com/semgrep/semgrep-rules/issues/4036), still open).
A fix was proposed in
[PR #4048](https://github.com/semgrep/semgrep-rules/pull/4048), and its author
withdrew it on 2026-11-18. Until
[PR #4037](https://github.com/semgrep/semgrep-rules/pull/4037) merges, the
ruleset only reports on files that keep `version:`. On a file without it,
which is what Compose now recommends, the ruleset reports nothing.

Two narrower gaps showed up on a
[stack spread across files](#run-on-a-stack-spread-across-files), both with
`version:` present. The socket rule did not fire on
`/var/run/docker.sock:/sock`, the socket mounted at another path inside the
container. The seccomp rule fired on a `security_opt:` list holding only
`seccomp:unconfined`, and not on one that also held `apparmor:unconfined`.

compose-lint covers those six and the rest of its 28 rules: capability
tiers, resource limits, credentials in environment variables, connection
strings and command-line arguments, digest pinning, sensitive host paths,
mount propagation, logging disabled. Severities are set per rule from a
stated model, where Semgrep uses one level for all six, and each finding
carries fix guidance.

## compose-lint vs OWASP DockSec

DockSec ([OWASP/DockSec](https://github.com/OWASP/DockSec)) scans
Dockerfiles, images and, with `--compose`, Compose files, and uses an LLM to
explain and prioritise findings. Its 17 Compose rules are documented and
need only Trivy installed. The Docker CLI adds a scan of each service's image,
and an AI provider key adds the explanation pass.

In the [same-file run](#run-on-the-same-file) its Compose rules caught 11 of
16. It also reported two
cross-service "exploit chains", such as an internet-facing service sharing the
default network with a service that holds a committed credential, which no
other tool here attempts. Its `--fix` applies mechanical Dockerfile changes
only. Compose findings are listed as "needs review".

compose-lint is deterministic. The same file produces the same findings,
severities and diff on every run, with no network access and no external
service, and its auto-fix works on the Compose file. A suppression given an `expires:` date
is the one input that reads the date, and `--as-of` pins it. Which matters
more depends on whether the linter is a CI gate or an advisor.

The explicit `user: root` gap was not on DockSec's tracker as of 2026-11-28.

Its results on a stack spread across files are in
[the multi-file run](#run-on-a-stack-spread-across-files).

## When a script of your own is enough

Another option is to skip the tools and write the check yourself:
`yq '.services[] | select(.privileged == true)'`, a Conftest policy, a custom
Semgrep or KICS rule. For a single check in a pre-commit hook, such as "nothing in this repository may say
`privileged: true`", that is the right answer. No tool on this page does it
better.

What the script does not give you is the Compose semantics, and the runs
above show where KICS, DockSec and Semgrep miss them. Two depend on the obsolete
[`version:` key](#the-version-key), and KICS reports `no-new-privileges=true`
as missing over a `:` versus `=` difference. A script that grades what Compose
actually deploys has to:

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
[what a run reads](what-a-run-reads.md)), and several of them were added
because a real file slipped past a simpler version. The
[run on a stack spread across files](#run-on-a-stack-spread-across-files)
shows the tools above missing several of them too: `extends:`, overrides,
`.env`, the long volume syntax and the socket as a secret. A script also has to
be updated when Compose changes.

Custom rules for the tools above inherit the tool's parser, which makes them
a middle path, but only where the tool reads the file. A custom KICS query
(Rego) or Semgrep rule can check anything in a Compose file the tool parses.
A custom Checkov policy cannot help, because Checkov never loads the file.

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

The [OWASP run](#against-the-owasp-cheat-sheet-rules) also shows five things
the OWASP cheat sheet asks for that compose-lint has no rule for:

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

Everything needed to repeat the three runs is in
[`scripts/compare`](https://github.com/tmatens/compose-lint/tree/main/scripts/compare): the fixtures, `run.sh`, which runs every tool at the
versions listed below, and `score.py`, which prints these tables from what the
tools reported. The image digest each version resolved to is in
[`last-run/versions.txt`](https://github.com/tmatens/compose-lint/tree/main/scripts/compare/last-run/versions.txt).

```bash
scripts/compare/run.sh /tmp/compare-out
python scripts/compare/score.py /tmp/compare-out
```

All three runs are from 2026-11-28. Versions, as each tool reported them:
compose-lint 1.8.2, DCLint 3.1.0, KICS 2.2.1, DockSec 2026.8.19,
Semgrep 1.187.0, Checkov 3.4.11, Trivy 0.76.2, Hadolint 2.15.1. DockSec's image tag is 2026.9.21. The release declares that
version but the tool still reports the older string.

The same-file fixture is sixteen services with one deliberate misconfiguration each,
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
mounted read-only at `/src`. The commands below pull each tool's current
image, apart from DockSec. `run.sh` pins every tool to the versions listed
above, so use it to repeat the measurement:

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
misses on every service that lacks them.

The OWASP-framed fixture has the same shape, one service per row of its
table, named `rule<N>-<violation>`, with the same images. The multi-file
scenarios are one directory each, and every image in them is
`nginx:1.27.2-alpine`. Both are under
[`scripts/compare/fixtures`](https://github.com/tmatens/compose-lint/tree/main/scripts/compare/fixtures). None of them is meant to be
started.

Every fixture was run once as written and once with `version: "3.9"` added at
the top of each YAML file. What Compose renders for each multi-file scenario
is the ground truth for what deploys. A finding counts for a row only when it
comes from that tool's own rule for the setting and is reported on the service
the row is about.

## Corrections

The summary table was checked against each tool's documentation on
2026-10-08. The three runs were first made on 2026-10-09 and 2026-10-17, on
compose-lint 0.34.0 and 0.36.0. They were repeated on 2026-11-15 on
compose-lint 1.6.0, and again on 2026-11-28 at the versions listed under
[Reproduce it](#reproduce-it). Every cell came out the same both times.

Tools change, so if a row is out of date, [open an
issue](https://github.com/tmatens/compose-lint/issues) with the link or the
output that shows it and I'll correct the row.

Known changes that would move these results when they land:

- Semgrep's column goes from 0 to 6 of 21 when
  [semgrep-rules#4037](https://github.com/semgrep/semgrep-rules/pull/4037)
  merges. It gains `user: root` if
  [#4036](https://github.com/semgrep/semgrep-rules/issues/4036) is fixed.
  The fix first proposed for it,
  [PR #4048](https://github.com/semgrep/semgrep-rules/pull/4048), was
  withdrawn. The #4037 fix
  moves its column in the run on a stack spread across files to the
  `version:` results in the † notes.
- KICS stops reporting the `no-new-privileges=true` spelling as missing when
  [#7077](https://github.com/Checkmarx/kics/issues/7077) is fixed.
- Trivy gets a column if
  [trivy#8729](https://github.com/aquasecurity/trivy/issues/8729) is taken up.
- DockSec moves to 14 of 21 if it starts flagging an explicit `user: root`.
