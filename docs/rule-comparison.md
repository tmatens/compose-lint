# Rule Comparison: compose-lint vs KICS and Checkov

How compose-lint's rules map to checks in [KICS](https://kics.io/) and
[Checkov](https://www.checkov.io/), the two most widely used infrastructure-as-code
scanners that cover Docker Compose.

**Last updated**: 2026-04-07

## Key Findings

- **Checkov** does not have a Docker Compose scanning framework. It covers Dockerfiles
  (`CKV_DOCKER_*`) and Kubernetes (`CKV_K8S_*`), but not `docker-compose.yml` files.
  All comparisons below are compose-lint vs KICS only.
- **KICS** covers 4 of compose-lint's 5 rules. CL-0004 (image not pinned) has no KICS
  equivalent for Compose files.
- **Severity mapping**: KICS uses HIGH > MEDIUM > LOW > INFO (no CRITICAL level for
  Compose). compose-lint uses CRITICAL > ERROR > WARNING.

## Rule-by-Rule Comparison

### CL-0001: Docker Socket Mounted (CRITICAL)

| Tool | Check ID | Severity |
|------|----------|----------|
| compose-lint | CL-0001 | CRITICAL |
| KICS | `d6355c88` — Docker Socket Mounted In Container | HIGH |
| Checkov | No equivalent | — |

Same detection logic. Both flag `/var/run/docker.sock` in volume mounts. KICS HIGH maps
to compose-lint CRITICAL — both treat this as the most severe category available.

### CL-0002: Privileged Mode Enabled (CRITICAL)

| Tool | Check ID | Severity |
|------|----------|----------|
| compose-lint | CL-0002 | CRITICAL |
| KICS | `ae5b6871` — Privileged Containers Enabled | HIGH |
| Checkov | No equivalent | — |

Same detection. Both flag `privileged: true`.

### CL-0003: Privilege Escalation Not Blocked (WARNING)

| Tool | Check ID | Severity |
|------|----------|----------|
| compose-lint | CL-0003 | WARNING |
| KICS | `27fcc7d6` — No New Privileges Not Set | HIGH |
| Checkov | No equivalent | — |

**Severity gap**: KICS rates this HIGH; compose-lint rates it WARNING. compose-lint's
lower severity reflects that this is a defense-in-depth hardening measure — the absence
of `no-new-privileges` is not directly exploitable without a separate vulnerability in
the container. KICS does not distinguish between direct exploitability and missing
hardening.

KICS also has a broader check (`610e266e` — Security Opt Not Set, MEDIUM) that fires
when `security_opt` is entirely absent, not just when `no-new-privileges` is missing.

### CL-0004: Image Not Pinned to Version (WARNING)

| Tool | Check ID | Severity |
|------|----------|----------|
| compose-lint | CL-0004 | WARNING |
| KICS | No equivalent | — |
| Checkov | No equivalent | — |

**compose-lint exclusive**. Neither KICS nor Checkov check image tag pinning in Docker
Compose files. KICS has Dockerfile-level image checks but not Compose-level. This is a
supply chain security concern grounded in
[OWASP Rule #13](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-13---enhance-supply-chain-security).

### CL-0005: Ports Bound to All Interfaces (WARNING)

| Tool | Check ID | Severity |
|------|----------|----------|
| compose-lint | CL-0005 | WARNING |
| KICS | `451d79dc` — Container Traffic Not Bound To Host Interface | MEDIUM |
| Checkov | No equivalent | — |

Same detection. Both flag port mappings like `"8080:80"` that lack an explicit IP
binding. Severity is comparable (KICS MEDIUM ≈ compose-lint WARNING).

## Severity Mapping

| compose-lint | KICS |
|-------------|------|
| CRITICAL | HIGH |
| ERROR | — |
| WARNING | MEDIUM |

Notable exception: CL-0003 is WARNING in compose-lint but HIGH in KICS.

## KICS Checks Not in compose-lint

### Planned for v0.2

| KICS Query | Severity | compose-lint |
|-----------|----------|--------------|
| `ce76b7d0` — No Capabilities Dropped | HIGH | CL-0006 (cap_drop) |
| `071a71ff` — Container Host Network Enabled | HIGH | CL-0008 (network_mode: host) |
| `404fde2c` — Security Profile Not Set | MEDIUM | CL-0009 (seccomp/apparmor) |

CL-0007 (read_only filesystem) is planned for v0.2 but has no KICS equivalent.

### Not yet planned

| KICS Query | Severity | Description |
|-----------|----------|-------------|
| `1c1325ff` | HIGH | Sensitive host directories mounted (`/etc`, `/proc`, `/sys`) |
| `baa452f0` | HIGH | Same volume mounted in multiple containers |
| `698ed579` | MEDIUM | Healthcheck not set |
| `bb9ac4f7` | MEDIUM | Memory not limited |
| `221e0658` | MEDIUM | PID limit not set |
| `baa3890f` | MEDIUM | Shared host IPC namespace (`ipc: host`) |
| `8af7162d` | MEDIUM | Shared host user namespace (`userns_mode: host`) |
| `4f31dd9f` | MEDIUM | Shared host PID namespace (`pid: host`) |
| `bc2908f3` | MEDIUM | Privileged ports mapped (< 1024) |
| `4d9f44c6` | MEDIUM | Non-default cgroup setting |
| `2fc99041` | MEDIUM | Restart policy not capped |
| `6b610c50` | LOW | CPU not limited |

The most security-relevant candidates for future compose-lint rules:

1. **Sensitive host directory mounted** — natural extension of CL-0001, grounded in
   CIS Docker Benchmark 5.5
2. **Host namespace sharing** (PID/IPC/user) — three related isolation checks, grounded
   in CIS Docker Benchmark 5.8-5.10
3. **Resource limits** (memory/PID) — DoS prevention, grounded in CIS Docker
   Benchmark 5.14-5.15

## Sources

- KICS Docker Compose queries: [GitHub](https://github.com/Checkmarx/kics/tree/master/assets/queries/dockerCompose/) · [Docs](https://docs.kics.io/latest/queries/dockercompose-queries/)
- Checkov policy index: [Dockerfile checks](https://www.checkov.io/5.Policy%20Index/dockerfile.html) (no Compose framework)
- OWASP Docker Security Cheat Sheet: [Link](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- CIS Docker Benchmark: [Link](https://www.cisecurity.org/benchmark/docker)
