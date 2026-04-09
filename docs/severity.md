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

## Current rule assignments

| Rule | Exploitability | Impact | Severity |
|------|---------------|--------|----------|
| CL-0001 (Docker socket) | Direct | Host | CRITICAL |
| CL-0002 (Privileged mode) | Direct | Host | CRITICAL |
| CL-0005 (Unbound ports) | Exposed | Single container | HIGH |
| CL-0008 (Host network) | Exposed | Host | HIGH |
| CL-0009 (Security profile disabled) | Requires chaining | Cross-container | HIGH |
| CL-0010 (Host namespace) | Exposed | Cross-container | HIGH |
| CL-0003 (No-new-privileges) | Requires chaining | Single container | MEDIUM |
| CL-0004 (Image not pinned) | Supply chain* | Host | MEDIUM |
| CL-0006 (No capability restrictions) | Hardening gap | Single container | MEDIUM |
| CL-0007 (Read-only filesystem) | Hardening gap | Single container | MEDIUM |

*CL-0004 is a supply chain risk that doesn't fit the runtime exploitation model cleanly. It is scored MEDIUM based on the combination of an unlikely-but-uncontrollable attack vector (upstream registry compromise) and a host-level blast radius.

## Overriding defaults

```yaml
# .compose-lint.yml
rules:
  CL-0005:
    severity: medium    # downgrade if your ports are intentionally public
  CL-0006:
    severity: high      # upgrade if you require strict capability control
```
