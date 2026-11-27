run 2026-11-15T16:08:54Z
docker 29.9.3
Docker Compose version v5.7.0
composelint/compose-lint:1.6.0 composelint/compose-lint@sha256:e02194511f211b7250fd043773acfa04b57d2732cf17fe36da8ca00f9da14585
zavoloklom/dclint:3.1.0 zavoloklom/dclint@sha256:dd6e0faa9fa8856a643a1e55476077d555b8e9c946cc481f8fbee203662c3e77
checkmarx/kics:v2.2.1 checkmarx/kics@sha256:49ccc54b6ae7f5d5fc95e96f8f95c18c57f3bba047ab611a03d80792bdff6757
owasp/docksec:2026.9.21 owasp/docksec@sha256:646e8250e2dc98ac4c8fd5f9a5d37f9aecae149a468271b5b1dc04092f927be4
semgrep/semgrep:1.185.0 semgrep/semgrep@sha256:67518c174185a2043fdbed16c70631b79209499b3671178e7194379b48295a0d
bridgecrew/checkov:3.4.5 bridgecrew/checkov@sha256:122602cf32cc72286155d39f1f234b7b594818f7b8d7fdf490701620e521368b
aquasec/trivy:0.76.2 aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb
hadolint/hadolint:v2.15.1 hadolint/hadolint@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d
compose-lint compose-lint 1.6.0
dclint 3.1.0
kics Keeping Infrastructure as Code Secure v2.2.1
docksec DockSec 2026.8.19
semgrep 1.185.0
checkov 3.4.5
trivy Version: 0.76.2
hadolint Haskell Dockerfile Linter 2.15.1


### same-file, as-written

| Row | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Docker socket mounted | Yes | Yes | Yes | Missed | No rule |
| `privileged: true` | Yes | Yes | Yes | Missed | No rule |
| `no-new-privileges` missing | Yes | Yes | Yes | Missed | No rule |
| Unpinned `:latest` tag | Yes | No rule | Yes | No rule | Yes |
| Port published on `0.0.0.0` | Yes | Yes | Missed | No rule | Yes |
| No `cap_drop: [ALL]` | Yes | Yes | No rule | No rule | No rule |
| Writable root filesystem | Yes | No rule | Yes | Missed | No rule |
| `network_mode: host` | Yes | Yes | Yes | No rule | No rule |
| `seccomp:unconfined` | Yes | Yes | Yes | Missed | No rule |
| `pid: host` / `ipc: host` | Yes | Yes | Yes | No rule | No rule |
| Sensitive host path mounted | Yes | Yes | Yes | No rule | No rule |
| `logging: driver: none` | Yes | No rule | No rule | No rule | No rule |
| `user: root` | Yes | No rule | Missed | No rule | No rule |
| Tag without digest | Yes | No rule | No rule | No rule | No rule |
| Credential in `environment:` | Yes | Yes | Yes | No rule | No rule |
| No memory/CPU limits | Yes | Missed | Yes | No rule | No rule |
| **Flagged, of 16** | 16 | 10 | 11 | 0 | 2 |
| **No rule for it** | 0 | 5 | 3 | 11 | 14 |
| **Has a rule, missed it** | 0 | 1 | 2 | 5 | 0 |

Distinct (service, rule) pairs reported: compose-lint 84, KICS 55, DockSec 84, Semgrep 0, DCLint 20
checkov: exit 0, 137 bytes of output
trivy: exit 0, 228 bytes of output
hadolint: exit 1, 317 bytes of output

### owasp, as-written

| Row | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| 1 — Docker socket mounted | Yes | Yes | Yes | Missed | No rule |
| 2 — `user: root` set explicitly | Yes | No rule | Missed | No rule | No rule |
| 2 — no `user:`, image default | No rule | No rule | Yes | No rule | No rule |
| 3 — `privileged: true` | Yes | Yes | Yes | Missed | No rule |
| 3 — default capability set, nothing dropped | Yes | Yes | No rule | No rule | No rule |
| 3 — `cap_drop: [ALL]` then `cap_add: [SYS_ADMIN]` | Yes | Yes | Yes | No rule | No rule |
| 4 — `no-new-privileges` not set | Yes | Yes | Yes | Missed | No rule |
| 5 — `network_mode: host` | Yes | Yes | Yes | No rule | No rule |
| 5 — no `networks:`, joins the shared default network | No rule | No rule | Yes | No rule | No rule |
| 5a — port published on `0.0.0.0` | Yes | Yes | Missed | No rule | Yes |
| 6 — `seccomp:unconfined` | Yes | Yes | Yes | Missed | No rule |
| 6 — `apparmor:unconfined` | Yes | No rule | Yes | No rule | No rule |
| 6 — SELinux `label:disable` | Yes | No rule | Missed | Missed | No rule |
| 7 — no memory or CPU limits | Yes | Missed | Yes | No rule | No rule |
| 7 — no `pids_limit` | No rule | Missed | No rule | No rule | No rule |
| 7 — `restart: always`, unbounded | No rule | No rule | No rule | No rule | No rule |
| 8 — root filesystem writable | Yes | No rule | Yes | Missed | No rule |
| 8 — host directory mounted read-write | No rule | No rule | No rule | No rule | No rule |
| 12 — credential as a literal `environment:` value | Yes | Yes | Yes | No rule | No rule |
| 13 — mutable `:latest` tag | Yes | No rule | Yes | No rule | Yes |
| 13 — version tag without a digest | Yes | No rule | No rule | No rule | No rule |
| **Flagged, of 21** | 16 | 9 | 13 | 0 | 2 |
| **No rule for it** | 5 | 10 | 5 | 15 | 19 |
| **Has a rule, missed it** | 0 | 2 | 3 | 6 | 0 |

Distinct (service, rule) pairs reported: compose-lint 108, KICS 68, DockSec 109, Semgrep 0, DCLint 13
checkov: exit 0, 137 bytes of output
trivy: exit 0, 227 bytes of output
hadolint: exit 1, 317 bytes of output

### multi, as-written


**`privileged: true`**

| Where the setting comes from | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Written inline (control) | Yes | Yes | Yes | Missed | No rule |
| `extends:` a service in the same file | Yes | Base only | Base only | Missed | No rule |
| `extends:` a service in another file | Yes | Base only | Missed | Missed | No rule |
| `include:` of another file | Yes | Yes | Missed | Missed | No rule |
| `compose.override.yml` | Yes | Missed | Missed | Missed | No rule |
| YAML anchor and `<<:` merge key | Yes | Yes | Yes | Missed | No rule |
| `${VAR:-default}` | Yes | Missed | Missed | Missed | No rule |
| A value from `.env` | Yes | Missed | Missed | Missed | No rule |

**The Docker socket mount**

| Where the setting comes from | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Written inline (control) | Yes | Yes | Yes | Missed | No rule |
| `extends:` a service in the same file | Yes | Base only | Base only | Missed | No rule |
| `extends:` a service in another file | Yes | Base only | Missed | Missed | No rule |
| `include:` of another file | Yes | Yes | Missed | Missed | No rule |
| `compose.override.yml` | Yes | Missed | Missed | Missed | No rule |
| YAML anchor and `<<:` merge key | Yes | Yes | Yes | Missed | No rule |
| `${VAR:-default}` | Yes | Missed | Yes | Missed | No rule |
| A value from `.env` | Yes | Missed | Missed | Missed | No rule |

**A port published on all interfaces**

| Where the setting comes from | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Written inline (control) | Yes | Yes | No rule | No rule | Yes |
| `extends:` a service in the same file | Yes | Base only | No rule | No rule | Base only |
| `extends:` a service in another file | Yes | Base only | No rule | No rule | Missed |
| `include:` of another file | Yes | Yes | No rule | No rule | Missed |
| `compose.override.yml` | Yes | Missed | No rule | No rule | Yes |
| YAML anchor and `<<:` merge key | Yes | Yes | No rule | No rule | Missed |
| `${VAR:-default}` | Yes | Missed | No rule | No rule | Yes |
| A value from `.env` | Yes | Yes | No rule | No rule | Yes |

**More scenarios**

| Scenario | compose-lint | KICS | DockSec | Semgrep |
|---|---|---|---|---|
| Socket in the long `volumes:` syntax | Yes | Missed | Yes | Missed |
| Port in the long `ports:` syntax | Yes | Yes | No rule | No rule |
| Socket as `secrets:` with `file: /var/run/docker.sock` | Yes | Missed | Missed | Missed |
| `seccomp=unconfined` | Yes | Missed | Missed | Missed |
| `seccomp:unconfined` (control) | Yes | Yes | Yes | Missed |
| Socket mounted at another path | Yes | Yes | Yes | Missed |
| `seccomp:unconfined` beside `apparmor:unconfined` | Yes | Yes | Yes | Missed |

**Looks dangerous, deploys safely**

| Scenario | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| `privileged: true`, set back to `false` by `compose.override.yml` | Quiet | False alarm | False alarm | Quiet | No rule |
| Port bound to `${BIND:-127.0.0.1}` | Quiet | Quiet | No rule | No rule | False alarm |
| `no-new-privileges=true`, the `=` spelling | Quiet | False alarm | False alarm | Quiet | No rule |
| Port, socket and `privileged` from a `.env` with safe values | Quiet | False alarm | Quiet | Quiet | False alarm |

### same-file, version-key

| Row | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Docker socket mounted | Yes | Yes | Yes | Yes | No rule |
| `privileged: true` | Yes | Yes | Yes | Yes | No rule |
| `no-new-privileges` missing | Yes | Yes | Yes | Yes | No rule |
| Unpinned `:latest` tag | Yes | No rule | Yes | No rule | Yes |
| Port published on `0.0.0.0` | Yes | Yes | Missed | No rule | Yes |
| No `cap_drop: [ALL]` | Yes | Yes | No rule | No rule | No rule |
| Writable root filesystem | Yes | No rule | Yes | Yes | No rule |
| `network_mode: host` | Yes | Yes | Yes | No rule | No rule |
| `seccomp:unconfined` | Yes | Yes | Yes | Yes | No rule |
| `pid: host` / `ipc: host` | Yes | Yes | Yes | No rule | No rule |
| Sensitive host path mounted | Yes | Yes | Yes | No rule | No rule |
| `logging: driver: none` | Yes | No rule | No rule | No rule | No rule |
| `user: root` | Yes | No rule | Missed | No rule | No rule |
| Tag without digest | Yes | No rule | No rule | No rule | No rule |
| Credential in `environment:` | Yes | Yes | Yes | No rule | No rule |
| No memory/CPU limits | Yes | Yes | Yes | No rule | No rule |
| **Flagged, of 16** | 16 | 11 | 11 | 5 | 2 |
| **No rule for it** | 0 | 5 | 3 | 11 | 14 |
| **Has a rule, missed it** | 0 | 0 | 2 | 0 | 0 |

Distinct (service, rule) pairs reported: compose-lint 84, KICS 87, DockSec 84, Semgrep 31, DCLint 21
checkov: exit 0, 137 bytes of output
trivy: exit 0, 228 bytes of output
hadolint: exit 1, 304 bytes of output

### owasp, version-key

| Row | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| 1 — Docker socket mounted | Yes | Yes | Yes | Yes | No rule |
| 2 — `user: root` set explicitly | Yes | No rule | Missed | No rule | No rule |
| 2 — no `user:`, image default | No rule | No rule | Yes | No rule | No rule |
| 3 — `privileged: true` | Yes | Yes | Yes | Yes | No rule |
| 3 — default capability set, nothing dropped | Yes | Yes | No rule | No rule | No rule |
| 3 — `cap_drop: [ALL]` then `cap_add: [SYS_ADMIN]` | Yes | Yes | Yes | No rule | No rule |
| 4 — `no-new-privileges` not set | Yes | Yes | Yes | Yes | No rule |
| 5 — `network_mode: host` | Yes | Yes | Yes | No rule | No rule |
| 5 — no `networks:`, joins the shared default network | No rule | No rule | Yes | No rule | No rule |
| 5a — port published on `0.0.0.0` | Yes | Yes | Missed | No rule | Yes |
| 6 — `seccomp:unconfined` | Yes | Yes | Yes | Yes | No rule |
| 6 — `apparmor:unconfined` | Yes | No rule | Yes | No rule | No rule |
| 6 — SELinux `label:disable` | Yes | No rule | Missed | Yes | No rule |
| 7 — no memory or CPU limits | Yes | Yes | Yes | No rule | No rule |
| 7 — no `pids_limit` | No rule | Missed | No rule | No rule | No rule |
| 7 — `restart: always`, unbounded | No rule | No rule | No rule | No rule | No rule |
| 8 — root filesystem writable | Yes | No rule | Yes | Yes | No rule |
| 8 — host directory mounted read-write | No rule | No rule | No rule | No rule | No rule |
| 12 — credential as a literal `environment:` value | Yes | Yes | Yes | No rule | No rule |
| 13 — mutable `:latest` tag | Yes | No rule | Yes | No rule | Yes |
| 13 — version tag without a digest | Yes | No rule | No rule | No rule | No rule |
| **Flagged, of 21** | 16 | 10 | 13 | 6 | 2 |
| **No rule for it** | 5 | 10 | 5 | 15 | 19 |
| **Has a rule, missed it** | 0 | 1 | 3 | 0 | 0 |

Distinct (service, rule) pairs reported: compose-lint 108, KICS 108, DockSec 109, Semgrep 43, DCLint 14
checkov: exit 0, 137 bytes of output
trivy: exit 0, 228 bytes of output
hadolint: exit 1, 304 bytes of output

### multi, version-key


**`privileged: true`**

| Where the setting comes from | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Written inline (control) | Yes | Yes | Yes | Yes | No rule |
| `extends:` a service in the same file | Yes | Base only | Base only | Base only | No rule |
| `extends:` a service in another file | Yes | Base only | Missed | Base only | No rule |
| `include:` of another file | Yes | Yes | Missed | Yes | No rule |
| `compose.override.yml` | Yes | Missed | Missed | Yes | No rule |
| YAML anchor and `<<:` merge key | Yes | Yes | Yes | Missed | No rule |
| `${VAR:-default}` | Yes | Missed | Missed | Missed | No rule |
| A value from `.env` | Yes | Missed | Missed | Missed | No rule |

**The Docker socket mount**

| Where the setting comes from | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Written inline (control) | Yes | Yes | Yes | Yes | No rule |
| `extends:` a service in the same file | Yes | Base only | Base only | Base only | No rule |
| `extends:` a service in another file | Yes | Base only | Missed | Base only | No rule |
| `include:` of another file | Yes | Yes | Missed | Yes | No rule |
| `compose.override.yml` | Yes | Missed | Missed | Yes | No rule |
| YAML anchor and `<<:` merge key | Yes | Yes | Yes | Yes | No rule |
| `${VAR:-default}` | Yes | Missed | Yes | Missed | No rule |
| A value from `.env` | Yes | Missed | Missed | Missed | No rule |

**A port published on all interfaces**

| Where the setting comes from | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Written inline (control) | Yes | Yes | No rule | No rule | Yes |
| `extends:` a service in the same file | Yes | Base only | No rule | No rule | Base only |
| `extends:` a service in another file | Yes | Base only | No rule | No rule | Missed |
| `include:` of another file | Yes | Yes | No rule | No rule | Missed |
| `compose.override.yml` | Yes | Missed | No rule | No rule | Yes |
| YAML anchor and `<<:` merge key | Yes | Yes | No rule | No rule | Missed |
| `${VAR:-default}` | Yes | Missed | No rule | No rule | Yes |
| A value from `.env` | Yes | Yes | No rule | No rule | Yes |

**More scenarios**

| Scenario | compose-lint | KICS | DockSec | Semgrep |
|---|---|---|---|---|
| Socket in the long `volumes:` syntax | Yes | Missed | Yes | Yes |
| Port in the long `ports:` syntax | Yes | Yes | No rule | No rule |
| Socket as `secrets:` with `file: /var/run/docker.sock` | Yes | Missed | Missed | Missed |
| `seccomp=unconfined` | Yes | Missed | Missed | Missed |
| `seccomp:unconfined` (control) | Yes | Yes | Yes | Yes |
| Socket mounted at another path | Yes | Yes | Yes | Missed |
| `seccomp:unconfined` beside `apparmor:unconfined` | Yes | Yes | Yes | Missed |

**Looks dangerous, deploys safely**

| Scenario | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| `privileged: true`, set back to `false` by `compose.override.yml` | Quiet | False alarm | False alarm | False alarm | No rule |
| Port bound to `${BIND:-127.0.0.1}` | Quiet | Quiet | No rule | No rule | False alarm |
| `no-new-privileges=true`, the `=` spelling | Quiet | False alarm | False alarm | False alarm | No rule |
| Port, socket and `privileged` from a `.env` with safe values | Quiet | False alarm | Quiet | Quiet | False alarm |
