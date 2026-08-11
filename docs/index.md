# compose-lint

A security-focused linter for Docker Compose files. It tells you exactly what's
wrong with a Compose file and exactly how to fix it — every rule cites OWASP,
CIS, or Docker documentation, and runtime claims are re-proven against live
containers in CI.

```sh
pip install compose-lint
compose-lint check docker-compose.yml
```

Findings come with actionable fix guidance in the output; `compose-lint
--explain CL-XXXX` prints any rule's full documentation (the same page you are
reading here) in the terminal.

## Rules

| Rule | Checks for |
|---|---|
| [CL-0001](rules/CL-0001.md) | Container runtime socket mounted |
| [CL-0002](rules/CL-0002.md) | Privileged mode enabled |
| [CL-0003](rules/CL-0003.md) | Privilege escalation not blocked (`no-new-privileges` missing) |
| [CL-0004](rules/CL-0004.md) | Image not pinned to a version |
| [CL-0005](rules/CL-0005.md) | Ports bound to all interfaces |
| [CL-0006](rules/CL-0006.md) | No capability restrictions (`cap_drop: [ALL]` missing) |
| [CL-0007](rules/CL-0007.md) | Root filesystem not read-only |
| [CL-0008](rules/CL-0008.md) | Host network mode |
| [CL-0009](rules/CL-0009.md) | Seccomp/AppArmor profile disabled |
| [CL-0010](rules/CL-0010.md) | Host PID/IPC namespace sharing |
| [CL-0011](rules/CL-0011.md) | Strong host-adjacent capability added |
| [CL-0013](rules/CL-0013.md) | Sensitive host path exposed |
| [CL-0014](rules/CL-0014.md) | Logging driver disabled |
| [CL-0016](rules/CL-0016.md) | Dangerous host device exposed |
| [CL-0017](rules/CL-0017.md) | Shared mount propagation |
| [CL-0018](rules/CL-0018.md) | Explicit root user |
| [CL-0019](rules/CL-0019.md) | Image tag without digest |
| [CL-0020](rules/CL-0020.md) | Credential-shaped env key with literal value |
| [CL-0021](rules/CL-0021.md) | Credential embedded in a connection-string env value |
| [CL-0022](rules/CL-0022.md) | tmpfs mount re-enables exec/suid/dev |
| [CL-0024](rules/CL-0024.md) | Host-code-execution capability added |
| [CL-0025](rules/CL-0025.md) | Root-equivalent host path mounted writable |
| [CL-0026](rules/CL-0026.md) | No resource limits (memory/CPU) |
| [CL-0027](rules/CL-0027.md) | Bounded-grant capability added |
| [CL-0028](rules/CL-0028.md) | Host-reaching capability added |
| [CL-0029](rules/CL-0029.md) | Host-availability capability added |
| [CL-0030](rules/CL-0030.md) | Host-disclosure capability added |

## Where to start

- **[Configuration](configuration.md)** — `.compose-lint.yml`, suppressions
  with reasons, per-service overrides, severity threshold (`--fail-on`).
- **[Severity levels](severity.md)** — how CRITICAL/HIGH/MEDIUM/LOW are
  assigned, and why severities are deliberately not inflated.
- **[Hardening walkthrough](hardening.md)** — taking a real Compose file from
  default to hardened, finding by finding.
- **[CL-0006's capability guide](rules/CL-0006.md#determining-required-capabilities)**
  — how to determine the capabilities an image actually needs, with a verbatim
  error-message → capability table proven in CI.

Source, issues, and releases: [github.com/tmatens/compose-lint](https://github.com/tmatens/compose-lint)
