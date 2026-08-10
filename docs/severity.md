# Severity Matrix

compose-lint uses four severity levels: **LOW**, **MEDIUM**, **HIGH**, and
**CRITICAL**. A rule's default severity is **derived** — it is the value a
two-axis matrix produces for the rule's cell, under a stated baseline, adjusted
by at most one qualifier and one modifier.

The derivation is never altered to reach a desired number. When the derived
severity is right about the risk but wrong for the product, the rule ships a
different value as a **declared override** (see
[Calibration overrides](#calibration-overrides)) — a reviewable decision, rather
than an invisibly re-chosen cell.

Severities are configurable via `.compose-lint.yml` if the defaults don't match
your environment.

## Baselines

A severity is unanswerable without a fixed attacker starting position. Mounting
`docker.sock` is not itself an exploit; it is a primitive used *after* a
foothold. Two baselines cover the rule set.

**Baseline A — post-foothold (default).**

> The attacker already has arbitrary code execution inside the affected
> container, as whatever uid the workload runs as, and can reach from the
> network any port the file publishes. **Given that, what does this line add?**

**Baseline B — pre-foothold reader.** Used by the disclosure and supply-chain
rules (CL-0004, CL-0019, CL-0020, CL-0021), whose story starts *before* any
foothold:

> The attacker can read the compose file, or can influence what the named image
> resolves to. They have no code execution anywhere yet.

**Score each rule in isolation, assuming every other key is at its secure
default.** Never worst-case a sibling key — that privilege is scored by the rule
that owns it. A rule whose honest score varies with its siblings is either two
rules (split it) or has a scoping assumption it must state.

### Grounded posture

*Adopted in [ADR-020](adr/020-severity-scoping-and-overrides.md).*

Every rule's premise and severity assume **rootful Docker Engine on Linux at
default configuration** — the most severe supported posture. Rules are not
scored against hardened or loosened daemons, and other runtimes that consume
compose files (Podman, nerdctl) are out of scope. Other Docker postures
(rootless, Docker Desktop's LinuxKit VM, Swarm) *reduce* these severities rather
than increase them.

A rule that departs from this baseline states the departure on its own page in a
`Daemon assumptions:` field. That field is an exception list, not something
every rule repeats.

**Analysis reads files only** — the compose file(s) named on the command line
plus `.compose-lint.yml`. compose-lint does not read the registry, the daemon,
or image contents. *Grounding* (premise validation, `scripts/validate_rule_premises.py`)
is the separate phase that measures live containers at the posture above.

If your daemon is **not** at defaults, some findings become unreliable:

| Non-default daemon setting | Consequence |
|---|---|
| `--no-new-privileges` on | CL-0003 becomes a false positive — the daemon already applies it |
| permissive `--seccomp-profile` | several CL-0011 capabilities are under-scored; their syscall gates are gone |
| `--icc=false` | CL-0006's cross-container reach is removed |
| `--userns-remap` | `userns_mode: host` becomes a real finding rather than a no-op |
| `--default-runtime` other than `runc` | any rule's premise may be rewritten before `runc` sees the spec |

## Axes

### Axis 1 — attacker precondition

What else has to be true for the attacker, standing at the baseline, to turn
this line into impact?

| Level | Decision test |
|-------|-----------|
| **Direct** | Supported API or CLI calls alone realise the impact. No published technique, no second defect. |
| **Technique** | A published technique against the primitive this line grants. The technique needs no software vulnerability in any victim. |
| **Second flaw** | Needs a defect or event *outside this file* — an application RCE, a setuid binary in the image, a compromised registry, an operator action. |
| **Removes a mitigation** | Grants no primitive at all. Deletes a control, or declines to add one. |

Two clarifications settle most disputes:

- **"Removes a mitigation" is not a synonym for "absence rule."** Use the
  **named-primitive test**: if the missing directive leaves the attacker a
  concrete, nameable primitive to use (a setuid-root binary, `NET_RAW`), the
  rule is **Second flaw** or **Technique**. If nothing can be named and the
  absence only widens the blast radius of some other failure, it is **Removes a
  mitigation**.
- **Reachability is not a level** — it is a modifier (below).

### Axis 2 — impact scope

What can the attacker reach once the precondition is met?

| Level | Definition |
|-------|-----------|
| **Host** | Full control of the Docker host, or equivalent reach into it. |
| **Cross-container** | Escape from the compromised container, or a pivot to other containers. |
| **Single container** | Impact is contained within the affected container. |

## Matrix

| | Host | Cross-container | Single container |
|---|---|---|---|
| **Direct** | CRITICAL | CRITICAL | HIGH |
| **Technique** | CRITICAL | HIGH | HIGH |
| **Second flaw** | HIGH | HIGH | MEDIUM |
| **Removes a mitigation** | HIGH | MEDIUM | LOW |

### Qualifiers and modifiers

Apply **at most one qualifier and at most one modifier**. They exist because the
impact axis has nowhere to put host *read* or host *denial of service*, which is
how a resource-exhaustion rule once ended up labelled Cross-container.

| Adjustment | Effect | When |
|---|---|---|
| `read-only` (qualifier) | one tier **down** | The realised impact is disclosure or observation, with no write and no execution. |
| `availability-only` (qualifier) | one tier **down** | The realised impact is denial of service, with no confidentiality or integrity loss. |
| `pre-foothold reach` (modifier) | one tier **up** | The impact is reachable by an attacker who has no foothold anywhere — scored on Baseline A because the rule's subject is a runtime primitive, not the file's contents. |

Tiers are clamped at CRITICAL and LOW.

## Tier definitions

| Tier | Meaning |
|---|---|
| **CRITICAL** | Under the grounded default posture, the configuration hands the host over **outright, with no further attacker technique** — verified by mechanism (socket → daemon API; `privileged`/`SYS_MODULE` → host code execution; raw block device → host disk; writable `/` or `/proc` → host root). Triage: fix these first. |
| **HIGH** | Strong compromise — host or cross-container — but it needs a published technique or a second flaw to land. |
| **MEDIUM** | Real but bounded: single-container compromise, a host-adjacent effect short of takeover, or a derived-HIGH rule calibrated down by a declared override. |
| **LOW** | Removes a defence-in-depth measure, or yields disclosure only. No primitive is granted. |

Mature scanners that grade Kubernetes manifests cap several of our CRITICAL
primitives at HIGH. That is a convention of *their* scales, not a disagreement
about the mechanism: the tier here is an internal triage distinction —
"game over" versus "serious" — and all severities are default-posture, so
hardened deployments read them down (see [Grounded posture](#grounded-posture)).
It is **not** a claim that Compose is more dangerous than Kubernetes. The full
argument, including the framing that was withdrawn, is in
[ADR-021](adr/021-critical-tier-posture.md).

The rule set is mapped to MITRE ATT&CK for Containers (pinned to v18) and the
scoring axes are crosswalked against CVSS 4.0 — see
[ADR-022](adr/022-threat-model-grounding.md).

## Calibration overrides

*Adopted in [ADR-020](adr/020-severity-scoping-and-overrides.md).*

A rule may ship a severity different from the one its cell derives, but only by
declaring it:

```
Derived: <precondition> × <impact> = <SEVERITY>
Shipped: <SEVERITY>   (override: <reason> — <one line>, <ADR or issue link>)
```

The reason must come from this closed list. Anything else needs an ADR
extending it.

| Reason | Use when |
|---|---|
| `detection-precision` | The matcher flags a superset of the dangerous case and cannot yet tell the two apart. The override **must name the case being over-covered**, so there is a concrete path off it. |
| `pending-split` | The rule holds members at different tiers; the row is priced at its most dangerous member until the split lands. |
| `pending-move` | **Transitional.** The derivation has been corrected and ratified, and the code relabel (or removal) lands in a later change of the same release train. Must be empty once that train completes. |

**There is deliberately no "this rule is too noisy" reason.** How often a rule
fires is a property of the world, not of the risk, and `--fail-on` already
exists to decide how much risk a given pipeline tolerates. Pricing a gate
threshold into a severity would make severity a function of corpus prevalence
and leave the override with no exit condition. Where a frequent rule genuinely
should ship lower, it is nearly always because the matcher over-covers —
`detection-precision`, which names something fixable.

Every override row carries a reason **and** a link, both enforced by
`tests/test_severity_matrix.py`. An override is a reviewable decision; a
re-chosen cell is not.

## Scoring procedure for a new rule

1. Complete the sentence: "Given the baseline foothold, this key lets the
   attacker ____."
2. Name the **furthest** thing reached, and cite evidence. Doc-derived claims
   are not evidence — add a premise check to `scripts/validate_rule_premises.py`
   *before* assigning a severity.
3. Apply at most one qualifier and one modifier.
4. Write all the derivation fields before looking at the number you wanted.
5. If the result disagrees with instinct, fix an **axis definition** or file an
   **override** — never try a different cell. Evaluating combinations until one
   produces your target number is the documented failure mode this model exists
   to prevent.
6. **Neighbour check.** List every rule in your cell. Find the closest rule that
   grants strictly more, and confirm it scores at least as high.
7. **Heterogeneity check.** Do your members land in different cells? Then it is
   two rules. Split now.

### Edge rules

- **One rule, one severity.** SARIF advertises `security-severity` on the rule
  descriptor, so a two-severity rule misreports one of them in GitHub no matter
  what the finding says. Split; never branch.
- **Heterogeneous members score at their most dangerous member** until the split
  lands, and the assignment row says so via `pending-split`.
- **No context sensitivity.** If the honest score varies with sibling keys,
  split the rule or state the excluded case as a scoping assumption.

### Per-rule derivation block

Every `docs/rules/CL-XXXX.md` carries these fields immediately after
`**Severity:**`: Baseline, Precondition, Impact, Qualifier/modifier, Derived,
Shipped (plus override, if any), Scoping assumptions, and **Evidence** — a
premise check or a captured observation that backs the impact claim. A rule that
cannot name evidence for its furthest-reach claim is not ready to be scored.
`Daemon assumptions:` appears only where a rule departs from the grounded
posture.

## CIS Docker Benchmark version

CIS reference numbers in rule docs are pinned to **CIS Docker Benchmark v1.7.0**
unless otherwise noted. Numbers shift between benchmark versions; if a citation
looks wrong against your benchmark copy, check the version first.

## Current rule assignments

Sorted by rule ID. `Derived` is the matrix result for the row's cell after any
qualifier or modifier; `Shipped` is the severity the rule actually emits. Where
they differ, the `Override` column carries a reason from the closed list and a
link. `tests/test_severity_matrix.py` enforces all four properties.

| Rule | Baseline | Precondition | Impact | Qualifier | Derived | Shipped | Override |
|------|----------|--------------|--------|-----------|---------|---------|----------|
| [CL-0001](rules/CL-0001.md) | A | Direct | Host | — | CRITICAL | CRITICAL | — |
| [CL-0002](rules/CL-0002.md) | A | Direct | Host | — | CRITICAL | CRITICAL | — |
| [CL-0003](rules/CL-0003.md) | A | Second flaw | Single container | — | MEDIUM | MEDIUM | — |
| [CL-0004](rules/CL-0004.md) | B | Second flaw | Single container | — | MEDIUM | MEDIUM | — |
| [CL-0005](rules/CL-0005.md) | A | Second flaw | Single container | pre-foothold reach | HIGH | HIGH | — |
| [CL-0006](rules/CL-0006.md) | A | Technique | Cross-container | — | HIGH | MEDIUM | `detection-precision` — fires on every service, not only those with a reachable neighbour ([ADR-020](adr/020-severity-scoping-and-overrides.md)) |
| [CL-0007](rules/CL-0007.md) | A | Removes a mitigation | Single container | — | LOW | MEDIUM | `pending-move` — relabel to LOW not yet landed ([CL-0007](rules/CL-0007.md)) |
| [CL-0008](rules/CL-0008.md) | A | Technique | Cross-container | — | HIGH | HIGH | — |
| [CL-0009](rules/CL-0009.md) | A | Second flaw | Cross-container | — | HIGH | HIGH | — |
| [CL-0010](rules/CL-0010.md) | A | Technique | Cross-container | — | HIGH | HIGH | — |
| [CL-0011](rules/CL-0011.md) | A | Direct | Host | — | CRITICAL | HIGH | `pending-split` — priced at `ALL`, its most dangerous member ([#503](https://github.com/tmatens/compose-lint/issues/503)) |
| [CL-0012](rules/CL-0012.md) | A | Second flaw | Single container | availability-only | LOW | MEDIUM | `pending-move` — premise refuted; removal not yet landed ([CL-0012](rules/CL-0012.md)) |
| [CL-0013](rules/CL-0013.md) | A | Direct | Host | — | CRITICAL | HIGH | `pending-split` — priced at a writable host root, its most dangerous member ([#503](https://github.com/tmatens/compose-lint/issues/503)) |
| [CL-0014](rules/CL-0014.md) | A | Removes a mitigation | Single container | — | LOW | MEDIUM | `pending-move` — relabel to LOW not yet landed ([CL-0014](rules/CL-0014.md)) |
| [CL-0015](rules/CL-0015.md) | A | Removes a mitigation | Single container | — | LOW | LOW | — |
| [CL-0016](rules/CL-0016.md) | A | Direct | Host | — | CRITICAL | HIGH | `pending-move` — relabel to CRITICAL not yet landed ([CL-0016](rules/CL-0016.md)) |
| [CL-0017](rules/CL-0017.md) | A | Second flaw | Single container | read-only | LOW | MEDIUM | `pending-move` — relabel to LOW not yet landed ([CL-0017](rules/CL-0017.md)) |
| [CL-0018](rules/CL-0018.md) | A | Second flaw | Single container | — | MEDIUM | MEDIUM | — |
| [CL-0019](rules/CL-0019.md) | B | Second flaw | Single container | — | MEDIUM | MEDIUM | — |
| [CL-0020](rules/CL-0020.md) | B | Direct | Single container | — | HIGH | HIGH | — |
| [CL-0021](rules/CL-0021.md) | B | Direct | Single container | — | HIGH | HIGH | — |
| [CL-0022](rules/CL-0022.md) | A | Removes a mitigation | Single container | — | LOW | LOW | — |

### Notes on individual derivations

- **CL-0003** — the named primitive is a setuid-root binary in the image, which
  the missing `no-new-privileges` stops blocking. Present in most base images,
  but still a defect outside this file, so: Second flaw.
- **CL-0004 / CL-0019** — scored on Baseline B. The earlier "supply chain"
  pseudo-level and its `Host` blast radius are withdrawn: they worst-cased the
  rest of the compose file, a licence no other rule has. A poisoned image runs
  code in *its own* container; anything further is scored by the rule that owns
  that privilege.
- **CL-0005** — the impact is a single container's exposed service, but it is
  reachable with no foothold at all, which is what the `pre-foothold reach`
  modifier prices. Docker's iptables manipulation bypasses UFW and firewalld, so
  a `0.0.0.0` bind is exposed even behind a host firewall.
- **CL-0006** — Technique is ARP cache poisoning against the `NET_RAW` primitive
  Docker grants by default; the impact ceiling with default capabilities is
  interception plus denial of service against an L2 neighbour on the *same*
  Docker network. Transparent MITM relay needs `NET_ADMIN`, which is not in the
  default set. The override is `detection-precision` because the derived impact
  needs a co-resident neighbour emitting interceptable traffic, and the matcher
  — which only asks whether `cap_drop: [ALL]` is present — cannot see whether
  one exists. Services and networks are both declared in the file, so this is a
  matcher that can be sharpened rather than a permanent limitation.
- **CL-0008 / CL-0010** — Technique rather than Direct: host networking and host
  PID/IPC hand over visibility immediately, but converting that visibility into
  impact (sniffing, ARP spoofing, abusing a loopback-trusted service, host
  `/dev/shm`) takes a published technique rather than a supported API call.
- **CL-0011 / CL-0013** — heterogeneous today; each is priced at its most
  dangerous member per the edge rule above, which is why the emitted finding can
  be CRITICAL while the rule descriptor says HIGH. That mismatch is the subject
  of [#503](https://github.com/tmatens/compose-lint/issues/503) and resolves
  when the rules split.
- **CL-0017** — the leg that works unaided is host → container: the container
  passively receives whatever the host later mounts under the shared path. It
  needs no capability, but it also needs a host operator action that no attacker
  controls (Second flaw), and it conveys visibility rather than write access
  (`read-only`). The container → host leg needs `CAP_SYS_ADMIN` *and*
  `apparmor=unconfined`, both flagged separately at HIGH.
- **CL-0018** — scored with no host bind mount present. With one, container root
  writes host-root-owned files and the impact is Host; that combination is
  scored by the mount rule.
- **CL-0020 / CL-0021** — Baseline B, and Direct: reading the file *is* the
  attack. Impact is Single container because the credential authenticates to the
  service it belongs to; a credential that unlocks a neighbour is that
  neighbour's finding.

## Rule categories

Rules fall into two categories with very different real-world hit rates. Both
are by design — neither is a bug.

### Absence rules — fire when a hardening directive is missing

These rules trigger when a service does not declare a recommended hardening
directive. The trigger condition is essentially
`if 'foo' not in service_config: yield finding`, so they fire on the vast
majority of unhardened services in the wild.

- **CL-0003** — `security_opt: [no-new-privileges:true]` not set
- **CL-0004** — `image:` not pinned to a tag
- **CL-0006** — `cap_drop: [ALL]` not declared
- **CL-0007** — `read_only: true` not set
- **CL-0019** — `image:` not pinned to a digest

CL-0001 (runtime socket) and CL-0002 (privileged) are technically presence-based,
but the underlying patterns (mounting the socket, running privileged) are common
enough that, in practice, they cluster with absence rules in frequency.

### Explicit-disable rules — fire only when a service opts into a dangerous configuration

These rules trigger only when a developer wrote something specifically dangerous
— a config value that explicitly turns off a protection or grants unusual
access. Real-world hit rates are very low (corpus testing on 1,554 real compose
files showed several of these never firing). That is the design: they trade
frequency for precision against deeply dangerous configurations, and a zero-hit
run does not mean the rule is broken.

- **CL-0012** — `pids_limit: 0` or `-1` (cgroup PID limit disabled)
- **CL-0014** — `logging.driver: none`
- **CL-0015** — `healthcheck.disable: true` or `test: ["NONE"]`
- **CL-0016** — `devices:` mapping a sensitive host device (e.g. `/dev/mem`, `/dev/kmem`)
- **CL-0017** — `volumes:` using `:rshared` (shared mount propagation)
- **CL-0022** — `tmpfs` mount passing `exec`, `suid`, or `dev` (re-enabling Docker's default `noexec,nosuid,nodev`)

Other rules (CL-0005, CL-0008, CL-0009, CL-0010, CL-0011, CL-0013, CL-0018) are
also presence-based but target patterns common enough in real compose files that
they do not need this caveat.

## Overriding defaults

```yaml
# .compose-lint.yml
rules:
  CL-0005:
    severity: medium    # downgrade if your ports are intentionally public
  CL-0006:
    severity: high      # upgrade if you require strict capability control
```
