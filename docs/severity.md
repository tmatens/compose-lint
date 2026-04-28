# Severity Matrix

compose-lint uses four severity levels: **LOW**, **MEDIUM**, **HIGH**, and **CRITICAL**. Each rule's default severity is determined by a two-axis matrix based on **exploitability** and **impact scope**.

Severities are configurable via `.compose-lint.yml` if the defaults don't match your environment.

## Axes

### Exploitability

How much else needs to go wrong for the misconfiguration to be exploited?

| Level | Definition |
|-------|-----------|
| **Direct** | The misconfiguration is itself the exploit. No attacker creativity or additional vulnerabilities needed. |
| **Exposed** | Creates an attack surface reachable under a standard threat model (attacker on network, untrusted input reaching the service). |
| **Requires chaining** | Exploitable only when combined with a separate vulnerability (RCE in the app, compromised dependency). |
| **Hardening gap** | Missing defense-in-depth measure. Not directly exploitable, but weakens the security posture. |

### Impact scope

What can the attacker reach if the misconfiguration is exploited?

| Level | Definition |
|-------|-----------|
| **Host** | Full control of the Docker host or equivalent. |
| **Cross-container** | Escape from the compromised container or pivot to other containers. |
| **Single container** | Impact is contained within the affected container. |

## Matrix

| | Host | Cross-container | Single container |
|---|---|---|---|
| **Direct** | CRITICAL | CRITICAL | HIGH |
| **Exposed** | CRITICAL | HIGH | HIGH |
| **Requires chaining** | HIGH | HIGH | MEDIUM |
| **Hardening gap** | HIGH | MEDIUM | LOW |

## CIS Docker Benchmark version

CIS reference numbers in rule docs are pinned to **CIS Docker Benchmark v1.6.0** unless otherwise noted. Numbers shift between benchmark versions; if a citation looks wrong against your benchmark copy, check the version first.

## Current rule assignments

| Rule | Exploitability | Impact | Severity |
|------|---------------|--------|----------|
| CL-0001 (Docker socket) | Direct | Host | CRITICAL |
| CL-0002 (Privileged mode) | Direct | Host | CRITICAL |
| CL-0005 (Unbound ports) | Exposed | Single container | HIGH |
| CL-0008 (Host network) | Exposed | Host | HIGH |
| CL-0009 (Security profile disabled) | Requires chaining | Cross-container | HIGH |
| CL-0010 (Host namespace) | Exposed | Cross-container | HIGH |
| CL-0011 (Dangerous capabilities added — `ALL`) | Direct | Host | CRITICAL |
| CL-0011 (Dangerous capabilities added — others) | Requires chaining | Host | HIGH |
| CL-0013 (Sensitive host path mounted — `/`) | Direct | Host | CRITICAL |
| CL-0013 (Sensitive host path mounted — others) | Exposed | Host | HIGH |
| CL-0016 (Dangerous host device exposed) | Exposed | Host | HIGH |
| CL-0003 (No-new-privileges) | Requires chaining | Single container | MEDIUM |
| CL-0004 (Image not pinned) | Supply chain* | Host | MEDIUM |
| CL-0006 (No capability restrictions) | Hardening gap | Single container | MEDIUM |
| CL-0007 (Read-only filesystem) | Hardening gap | Single container | MEDIUM |
| CL-0012 (PIDs cgroup limit disabled) | Requires chaining | Cross-container | MEDIUM |
| CL-0014 (Logging driver disabled) | Hardening gap | Cross-container | MEDIUM |
| CL-0017 (Shared mount propagation) | Requires chaining | Single container | MEDIUM |
| CL-0018 (Explicit root user) | Hardening gap | Single container | MEDIUM |
| CL-0019 (Image tag without digest) | Supply chain* | Host | MEDIUM |
| CL-0015 (Healthcheck disabled) | Hardening gap | Single container | LOW |

*CL-0004 and CL-0019 are supply chain risks that don't fit the runtime exploitation model cleanly. They are scored MEDIUM based on the combination of an unlikely-but-uncontrollable attack vector (upstream registry compromise) and a host-level blast radius. CL-0019 is the stronger guarantee of the two; CL-0004 catches the obvious mutable-tag cases.

## Rule categories

Rules fall into two categories with very different real-world hit rates. Both are by design — neither is a bug.

### Absence rules — fire when a hardening directive is missing

These rules trigger when a service does not declare a recommended hardening directive. The trigger condition is essentially `if 'foo' not in service_config: yield finding`, so they fire on the vast majority of unhardened services in the wild.

- **CL-0003** — `security_opt: [no-new-privileges:true]` not set
- **CL-0004** — `image:` not pinned to a tag
- **CL-0006** — `cap_drop: [ALL]` not declared
- **CL-0007** — `read_only: true` not set
- **CL-0019** — `image:` not pinned to a digest

CL-0001 (Docker socket) and CL-0002 (privileged) are technically presence-based, but the underlying patterns (mounting the socket, running privileged) are common enough that, in practice, they cluster with absence rules in frequency.

### Explicit-disable rules — fire only when a service opts into a dangerous configuration

These rules trigger only when a developer wrote something specifically dangerous — a config value that explicitly turns off a protection or grants unusual access. Real-world hit rates are very low (corpus testing on 1,554 real compose files showed several of these never firing). That is the design: they trade frequency for precision against deeply dangerous configurations, and a zero-hit run does not mean the rule is broken.

- **CL-0012** — `pids_limit: 0` or `-1` (cgroup PID limit disabled)
- **CL-0014** — `logging.driver: none`
- **CL-0015** — `healthcheck.disable: true` or `test: ["NONE"]`
- **CL-0016** — `devices:` mapping a sensitive host device (e.g. `/dev/mem`, `/dev/kmem`)
- **CL-0017** — `volumes:` using `:rshared` (shared mount propagation)

Other rules (CL-0005, CL-0008, CL-0009, CL-0010, CL-0011, CL-0013, CL-0018) are also presence-based but target patterns common enough in real compose files that they do not need this caveat.

## Overriding defaults

```yaml
# .compose-lint.yml
rules:
  CL-0005:
    severity: medium    # downgrade if your ports are intentionally public
  CL-0006:
    severity: high      # upgrade if you require strict capability control
```
