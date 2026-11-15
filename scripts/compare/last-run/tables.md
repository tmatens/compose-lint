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
| Docker socket mounted | ✅ | ✅ | ✅ | ✗ | — |
| `privileged: true` | ✅ | ✅ | ✅ | ✗ | — |
| `no-new-privileges` missing | ✅ | ✅ | ✅ | ✗ | — |
| Unpinned `:latest` tag | ✅ | — | ✅ | — | ✅ |
| Port published on `0.0.0.0` | ✅ | ✅ | ✗ | — | ✅ |
| No `cap_drop: [ALL]` | ✅ | ✅ | — | — | — |
| Writable root filesystem | ✅ | — | ✅ | ✗ | — |
| `network_mode: host` | ✅ | ✅ | ✅ | — | — |
| `seccomp:unconfined` | ✅ | ✅ | ✅ | ✗ | — |
| `pid: host` / `ipc: host` | ✅ | ✅ | ✅ | — | — |
| Sensitive host path mounted | ✅ | ✅ | ✅ | — | — |
| `logging: driver: none` | ✅ | — | — | — | — |
| `user: root` | ✅ | — | ✗ | — | — |
| Tag without digest | ✅ | — | — | — | — |
| Credential in `environment:` | ✅ | ✅ | ✅ | — | — |
| No memory/CPU limits | ✅ | ✗ | ✅ | — | — |
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
| 1 — Docker socket mounted | ✅ | ✅ | ✅ | ✗ | — |
| 2 — `user: root` set explicitly | ✅ | — | ✗ | — | — |
| 2 — no `user:`, image default | — | — | ✅ | — | — |
| 3 — `privileged: true` | ✅ | ✅ | ✅ | ✗ | — |
| 3 — default capability set, nothing dropped | ✅ | ✅ | — | — | — |
| 3 — `cap_drop: [ALL]` then `cap_add: [SYS_ADMIN]` | ✅ | ✅ | ✅ | — | — |
| 4 — `no-new-privileges` not set | ✅ | ✅ | ✅ | ✗ | — |
| 5 — `network_mode: host` | ✅ | ✅ | ✅ | — | — |
| 5 — no `networks:`, joins the shared default network | — | — | ✅ | — | — |
| 5a — port published on `0.0.0.0` | ✅ | ✅ | ✗ | — | ✅ |
| 6 — `seccomp:unconfined` | ✅ | ✅ | ✅ | ✗ | — |
| 6 — `apparmor:unconfined` | ✅ | — | ✅ | — | — |
| 6 — SELinux `label:disable` | ✅ | — | ✗ | ✗ | — |
| 7 — no memory or CPU limits | ✅ | ✗ | ✅ | — | — |
| 7 — no `pids_limit` | — | ✗ | — | — | — |
| 7 — `restart: always`, unbounded | — | — | — | — | — |
| 8 — root filesystem writable | ✅ | — | ✅ | ✗ | — |
| 8 — host directory mounted read-write | — | — | — | — | — |
| 12 — credential as a literal `environment:` value | ✅ | ✅ | ✅ | — | — |
| 13 — mutable `:latest` tag | ✅ | — | ✅ | — | ✅ |
| 13 — version tag without a digest | ✅ | — | — | — | — |
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
| Written inline (control) | ✅ | ✅ | ✅ | ✗ | — |
| `extends:` a service in the same file | ✅ | ◐ | ◐ | ✗ | — |
| `extends:` a service in another file | ✅ | ◐ | ✗ | ✗ | — |
| `include:` of another file | ✅ | ✅ | ✗ | ✗ | — |
| `compose.override.yml` | ✅ | ✗ | ✗ | ✗ | — |
| YAML anchor and `<<:` merge key | ✅ | ✅ | ✅ | ✗ | — |
| `${VAR:-default}` | ✅ | ✗ | ✗ | ✗ | — |
| A value from `.env` | ✅ | ✗ | ✗ | ✗ | — |

**The Docker socket mount**

| Where the setting comes from | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Written inline (control) | ✅ | ✅ | ✅ | ✗ | — |
| `extends:` a service in the same file | ✅ | ◐ | ◐ | ✗ | — |
| `extends:` a service in another file | ✅ | ◐ | ✗ | ✗ | — |
| `include:` of another file | ✅ | ✅ | ✗ | ✗ | — |
| `compose.override.yml` | ✅ | ✗ | ✗ | ✗ | — |
| YAML anchor and `<<:` merge key | ✅ | ✅ | ✅ | ✗ | — |
| `${VAR:-default}` | ✅ | ✗ | ✅ | ✗ | — |
| A value from `.env` | ✅ | ✗ | ✗ | ✗ | — |

**A port published on all interfaces**

| Where the setting comes from | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Written inline (control) | ✅ | ✅ | — | — | ✅ |
| `extends:` a service in the same file | ✅ | ◐ | — | — | ◐ |
| `extends:` a service in another file | ✅ | ◐ | — | — | ✗ |
| `include:` of another file | ✅ | ✅ | — | — | ✗ |
| `compose.override.yml` | ✅ | ✗ | — | — | ✅ |
| YAML anchor and `<<:` merge key | ✅ | ✅ | — | — | ✗ |
| `${VAR:-default}` | ✅ | ✗ | — | — | ✅ |
| A value from `.env` | ✅ | ✅ | — | — | ✅ |

**More scenarios**

| Scenario | compose-lint | KICS | DockSec | Semgrep |
|---|---|---|---|---|
| Socket in the long `volumes:` syntax | ✅ | ✗ | ✅ | ✗ |
| Port in the long `ports:` syntax | ✅ | ✅ | — | — |
| Socket as `secrets:` with `file: /var/run/docker.sock` | ✅ | ✗ | ✗ | ✗ |
| `seccomp=unconfined` | ✅ | ✗ | ✗ | ✗ |
| `seccomp:unconfined` (control) | ✅ | ✅ | ✅ | ✗ |
| Socket mounted at another path | ✅ | ✅ | ✅ | ✗ |
| `seccomp:unconfined` beside `apparmor:unconfined` | ✅ | ✅ | ✅ | ✗ |

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
| Docker socket mounted | ✅ | ✅ | ✅ | ✅ | — |
| `privileged: true` | ✅ | ✅ | ✅ | ✅ | — |
| `no-new-privileges` missing | ✅ | ✅ | ✅ | ✅ | — |
| Unpinned `:latest` tag | ✅ | — | ✅ | — | ✅ |
| Port published on `0.0.0.0` | ✅ | ✅ | ✗ | — | ✅ |
| No `cap_drop: [ALL]` | ✅ | ✅ | — | — | — |
| Writable root filesystem | ✅ | — | ✅ | ✅ | — |
| `network_mode: host` | ✅ | ✅ | ✅ | — | — |
| `seccomp:unconfined` | ✅ | ✅ | ✅ | ✅ | — |
| `pid: host` / `ipc: host` | ✅ | ✅ | ✅ | — | — |
| Sensitive host path mounted | ✅ | ✅ | ✅ | — | — |
| `logging: driver: none` | ✅ | — | — | — | — |
| `user: root` | ✅ | — | ✗ | — | — |
| Tag without digest | ✅ | — | — | — | — |
| Credential in `environment:` | ✅ | ✅ | ✅ | — | — |
| No memory/CPU limits | ✅ | ✅ | ✅ | — | — |
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
| 1 — Docker socket mounted | ✅ | ✅ | ✅ | ✅ | — |
| 2 — `user: root` set explicitly | ✅ | — | ✗ | — | — |
| 2 — no `user:`, image default | — | — | ✅ | — | — |
| 3 — `privileged: true` | ✅ | ✅ | ✅ | ✅ | — |
| 3 — default capability set, nothing dropped | ✅ | ✅ | — | — | — |
| 3 — `cap_drop: [ALL]` then `cap_add: [SYS_ADMIN]` | ✅ | ✅ | ✅ | — | — |
| 4 — `no-new-privileges` not set | ✅ | ✅ | ✅ | ✅ | — |
| 5 — `network_mode: host` | ✅ | ✅ | ✅ | — | — |
| 5 — no `networks:`, joins the shared default network | — | — | ✅ | — | — |
| 5a — port published on `0.0.0.0` | ✅ | ✅ | ✗ | — | ✅ |
| 6 — `seccomp:unconfined` | ✅ | ✅ | ✅ | ✅ | — |
| 6 — `apparmor:unconfined` | ✅ | — | ✅ | — | — |
| 6 — SELinux `label:disable` | ✅ | — | ✗ | ✅ | — |
| 7 — no memory or CPU limits | ✅ | ✅ | ✅ | — | — |
| 7 — no `pids_limit` | — | ✗ | — | — | — |
| 7 — `restart: always`, unbounded | — | — | — | — | — |
| 8 — root filesystem writable | ✅ | — | ✅ | ✅ | — |
| 8 — host directory mounted read-write | — | — | — | — | — |
| 12 — credential as a literal `environment:` value | ✅ | ✅ | ✅ | — | — |
| 13 — mutable `:latest` tag | ✅ | — | ✅ | — | ✅ |
| 13 — version tag without a digest | ✅ | — | — | — | — |
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
| Written inline (control) | ✅ | ✅ | ✅ | ✅ | — |
| `extends:` a service in the same file | ✅ | ◐ | ◐ | ◐ | — |
| `extends:` a service in another file | ✅ | ◐ | ✗ | ◐ | — |
| `include:` of another file | ✅ | ✅ | ✗ | ✅ | — |
| `compose.override.yml` | ✅ | ✗ | ✗ | ✅ | — |
| YAML anchor and `<<:` merge key | ✅ | ✅ | ✅ | ✗ | — |
| `${VAR:-default}` | ✅ | ✗ | ✗ | ✗ | — |
| A value from `.env` | ✅ | ✗ | ✗ | ✗ | — |

**The Docker socket mount**

| Where the setting comes from | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Written inline (control) | ✅ | ✅ | ✅ | ✅ | — |
| `extends:` a service in the same file | ✅ | ◐ | ◐ | ◐ | — |
| `extends:` a service in another file | ✅ | ◐ | ✗ | ◐ | — |
| `include:` of another file | ✅ | ✅ | ✗ | ✅ | — |
| `compose.override.yml` | ✅ | ✗ | ✗ | ✅ | — |
| YAML anchor and `<<:` merge key | ✅ | ✅ | ✅ | ✅ | — |
| `${VAR:-default}` | ✅ | ✗ | ✅ | ✗ | — |
| A value from `.env` | ✅ | ✗ | ✗ | ✗ | — |

**A port published on all interfaces**

| Where the setting comes from | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| Written inline (control) | ✅ | ✅ | — | — | ✅ |
| `extends:` a service in the same file | ✅ | ◐ | — | — | ◐ |
| `extends:` a service in another file | ✅ | ◐ | — | — | ✗ |
| `include:` of another file | ✅ | ✅ | — | — | ✗ |
| `compose.override.yml` | ✅ | ✗ | — | — | ✅ |
| YAML anchor and `<<:` merge key | ✅ | ✅ | — | — | ✗ |
| `${VAR:-default}` | ✅ | ✗ | — | — | ✅ |
| A value from `.env` | ✅ | ✅ | — | — | ✅ |

**More scenarios**

| Scenario | compose-lint | KICS | DockSec | Semgrep |
|---|---|---|---|---|
| Socket in the long `volumes:` syntax | ✅ | ✗ | ✅ | ✅ |
| Port in the long `ports:` syntax | ✅ | ✅ | — | — |
| Socket as `secrets:` with `file: /var/run/docker.sock` | ✅ | ✗ | ✗ | ✗ |
| `seccomp=unconfined` | ✅ | ✗ | ✗ | ✗ |
| `seccomp:unconfined` (control) | ✅ | ✅ | ✅ | ✅ |
| Socket mounted at another path | ✅ | ✅ | ✅ | ✗ |
| `seccomp:unconfined` beside `apparmor:unconfined` | ✅ | ✅ | ✅ | ✗ |

**Looks dangerous, deploys safely**

| Scenario | compose-lint | KICS | DockSec | Semgrep | DCLint |
|---|---|---|---|---|---|
| `privileged: true`, set back to `false` by `compose.override.yml` | Quiet | False alarm | False alarm | False alarm | No rule |
| Port bound to `${BIND:-127.0.0.1}` | Quiet | Quiet | No rule | No rule | False alarm |
| `no-new-privileges=true`, the `=` spelling | Quiet | False alarm | False alarm | False alarm | No rule |
| Port, socket and `privileged` from a `.env` with safe values | Quiet | False alarm | Quiet | Quiet | False alarm |
