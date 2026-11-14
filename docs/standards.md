# Standards mapping: CIS, OWASP and MITRE ATT&CK tags

Every rule cites the sources it is grounded in. In SARIF output the same
mapping is also published as tags on each rule, so findings can be filtered
by a CIS control, an OWASP rule or an ATT&CK technique.

| Source | Version | Tag shape | Rules tagged |
|---|---|---|---|
| [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) | v1.9.0 | `external/cis-docker/<control>` | 23 of 28 |
| [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) | unversioned | `external/owasp-docker/rule-<number>` | 23 of 28 |
| [MITRE ATT&CK](https://attack.mitre.org/) | v18 | `external/mitre-attack/<technique>` | 25 of 28 |

## What a tag claims

A tag says the rule **relates to** the named control or technique. It does
not say that a file with no findings complies with the benchmark.
compose-lint reads a Compose file, not a running daemon, so most of the CIS
Docker Benchmark is outside what it can see: host configuration, daemon
configuration, file permissions and image builds are not checked at all.

An ATT&CK tag is mitigation coverage. Fixing the finding helps against the
technique. compose-lint detects nothing at runtime.

Do not present a clean compose-lint run as benchmark compliance.

## Where the tags appear

The tags are in `properties.tags` on each rule in `--format sarif` output.
They are not in text or JSON output.

In GitHub Code Scanning, filter the alert list with `tag:`, for example
`tag:external/cis-docker/5.4` or `tag:external/mitre-attack/T1611`.

There is no `security` tag. GitHub already treats every compose-lint result
as a security result, because each rule carries a `security-severity`. Use
the severity filters to select them.

ATT&CK is also published as a SARIF taxonomy, with a relationship from each
rule to its techniques, for consumers that read that form. GitHub Code
Scanning does not.

## Stability

The tags are informational. They are not part of the
[machine-readable output contract](compatibility.md), so a tag can be
corrected, added or removed in any release. The changelog records each
change. The decision is recorded in
[ADR-043](adr/043-standards-mappings-are-sarif-tags.md).

A CIS tag does not carry the benchmark version. The numbers are the ones in
v1.9.0; CIS renumbers controls between versions, so check the version first
if a number looks wrong against your copy.

## Rule mapping

| Rule | CIS Docker Benchmark | OWASP Docker Security | MITRE ATT&CK |
|---|---|---|---|
| [CL-0001](rules/CL-0001.md) | `external/cis-docker/5.32` | `external/owasp-docker/rule-1` | `external/mitre-attack/T1610`<br>`external/mitre-attack/T1609`<br>`external/mitre-attack/T1611`<br>`external/mitre-attack/T1612`<br>`external/mitre-attack/T1552.007`<br>`external/mitre-attack/T1613` |
| [CL-0002](rules/CL-0002.md) | `external/cis-docker/5.5` | `external/owasp-docker/rule-3` | `external/mitre-attack/T1611`<br>`external/mitre-attack/T1685` |
| [CL-0003](rules/CL-0003.md) | `external/cis-docker/5.26` | `external/owasp-docker/rule-4` | `external/mitre-attack/T1548.001` |
| [CL-0004](rules/CL-0004.md) | `external/cis-docker/5.28` | `external/owasp-docker/rule-13` | `external/mitre-attack/T1204.003` |
| [CL-0005](rules/CL-0005.md) | `external/cis-docker/5.14` | `external/owasp-docker/rule-5a` | none |
| [CL-0006](rules/CL-0006.md) | `external/cis-docker/5.4` | `external/owasp-docker/rule-3` | `external/mitre-attack/T1040`<br>`external/mitre-attack/T1557`<br>`external/mitre-attack/T1548.001` |
| [CL-0007](rules/CL-0007.md) | `external/cis-docker/5.13` | `external/owasp-docker/rule-8` | none |
| [CL-0008](rules/CL-0008.md) | `external/cis-docker/5.10` | none | `external/mitre-attack/T1046` |
| [CL-0009](rules/CL-0009.md) | `external/cis-docker/5.22`<br>`external/cis-docker/5.2`<br>`external/cis-docker/5.3` | `external/owasp-docker/rule-6` | `external/mitre-attack/T1685` |
| [CL-0010](rules/CL-0010.md) | `external/cis-docker/5.16`<br>`external/cis-docker/5.17` | none | `external/mitre-attack/T1611` |
| [CL-0011](rules/CL-0011.md) | `external/cis-docker/5.4` | `external/owasp-docker/rule-3` | `external/mitre-attack/T1611`<br>`external/mitre-attack/T1557`<br>`external/mitre-attack/T1040`<br>`external/mitre-attack/T1529` |
| [CL-0013](rules/CL-0013.md) | `external/cis-docker/5.6` | `external/owasp-docker/rule-8` | `external/mitre-attack/T1552.001` |
| [CL-0014](rules/CL-0014.md) | `external/cis-docker/2.14` | none | `external/mitre-attack/T1070` |
| [CL-0016](rules/CL-0016.md) | `external/cis-docker/5.18` | none | `external/mitre-attack/T1611`<br>`external/mitre-attack/T1552.001` |
| [CL-0017](rules/CL-0017.md) | `external/cis-docker/5.20` | none | `external/mitre-attack/T1611` |
| [CL-0018](rules/CL-0018.md) | none | `external/owasp-docker/rule-2` | `external/mitre-attack/T1611`<br>`external/mitre-attack/T1078` |
| [CL-0019](rules/CL-0019.md) | none | `external/owasp-docker/rule-13` | `external/mitre-attack/T1204.003`<br>`external/mitre-attack/T1525` |
| [CL-0020](rules/CL-0020.md) | none | `external/owasp-docker/rule-12` | `external/mitre-attack/T1552.001` |
| [CL-0021](rules/CL-0021.md) | none | `external/owasp-docker/rule-12` | `external/mitre-attack/T1552.001` |
| [CL-0022](rules/CL-0022.md) | none | `external/owasp-docker/rule-8` | none |
| [CL-0024](rules/CL-0024.md) | `external/cis-docker/5.4` | `external/owasp-docker/rule-3` | `external/mitre-attack/T1611` |
| [CL-0025](rules/CL-0025.md) | `external/cis-docker/5.6` | `external/owasp-docker/rule-8` | `external/mitre-attack/T1611` |
| [CL-0026](rules/CL-0026.md) | `external/cis-docker/5.11`<br>`external/cis-docker/5.12` | `external/owasp-docker/rule-7` | `external/mitre-attack/T1496`<br>`external/mitre-attack/T1499` |
| [CL-0027](rules/CL-0027.md) | `external/cis-docker/5.4` | `external/owasp-docker/rule-3` | `external/mitre-attack/T1055`<br>`external/mitre-attack/T1003`<br>`external/mitre-attack/T1552.001`<br>`external/mitre-attack/T1611` |
| [CL-0028](rules/CL-0028.md) | `external/cis-docker/5.4` | `external/owasp-docker/rule-3` | `external/mitre-attack/T1070`<br>`external/mitre-attack/T1499`<br>`external/mitre-attack/T1003` |
| [CL-0029](rules/CL-0029.md) | `external/cis-docker/5.4` | `external/owasp-docker/rule-3` | `external/mitre-attack/T1499`<br>`external/mitre-attack/T1496` |
| [CL-0030](rules/CL-0030.md) | `external/cis-docker/5.4` | `external/owasp-docker/rule-3` | `external/mitre-attack/T1613` |
| [CL-0031](rules/CL-0031.md) | `external/cis-docker/5.32` | `external/owasp-docker/rule-1` | `external/mitre-attack/T1610`<br>`external/mitre-attack/T1609`<br>`external/mitre-attack/T1611`<br>`external/mitre-attack/T1612`<br>`external/mitre-attack/T1552.007`<br>`external/mitre-attack/T1552.001`<br>`external/mitre-attack/T1613` |

## Rules with no tag from a source

A rule is left untagged for a source only for a recorded reason.

**CIS Docker Benchmark**

- **CL-0018**: the nearest control, 4.1, asks that the image defines a user; it is an image-build control and does not cover a Compose `user:` key.
- **CL-0019**: no control asks for a digest; 5.28 is about stale cached images and is CL-0004's.
- **CL-0020**: the secrets controls cover Dockerfiles (4.9) and swarm (7.4), not a Compose `environment:` value.
- **CL-0021**: same as CL-0020.
- **CL-0022**: no control covers tmpfs mount options.

**OWASP Docker Security Cheat Sheet**

- **CL-0008**: Rule 5 is about traffic between containers and does not mention host networking; no rule on the sheet does.
- **CL-0010**: no rule on the sheet covers host PID or IPC namespaces.
- **CL-0014**: Rule 10 is about the daemon's log level; the rule cites the OWASP Logging Cheat Sheet, a different document.
- **CL-0016**: no rule on the sheet covers host devices.
- **CL-0017**: no rule on the sheet covers mount propagation.

**MITRE ATT&CK**

- **CL-0005**: published ports are attack surface that enables a technique; the rule has no technique of its own.
- **CL-0007** and **CL-0022**: defence in depth that denies an attacker a place to stage tools, which is too indirect to name a technique.
