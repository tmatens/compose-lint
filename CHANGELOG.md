# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Upgrading

**A file compose-lint cannot fully see is now an error (exit 2), not a pass.**
`include:` and cross-file `extends: {file: ...}` reference services in other
files, and compose-lint reads single files without following them — so those
services were never linted. The gap was reported on stderr for `include:` and
not at all for `extends:`, while the verdict, exit code, JSON `errors` and SARIF
`executionSuccessful` all said the run was clean. A base carrying
`privileged: true` and `network_mode: host` could sit unlinted behind a green
check.

Measured over the 5,417-file corpus: **31 files (0.6%) change exit code — 20
from pass to error, 11 from fail to error.** Findings for the local services are
still reported; the file is graded on what could be seen *and* the gap is
recorded.

```bash
# Cover everything by linting the merged output (compose-lint reads files,
# not stdin, so write it out first):
docker compose config > merged.yml && compose-lint merged.yml

# Or accept the gap and grade only what is visible:
compose-lint --allow-partial-coverage docker-compose.yml
```

`fix` reports gaps but never fails on them — it is not the merge gate.

**Rules now grade `${VAR:-default}` as the value it deploys, so files that
passed may now fail.** With no `.env` and the variable unset, Compose ships the
default — `privileged: ${P:-true}` deploys `privileged: true` — but only bind
sources were being resolved, so every other rule compared its dangerous-value
set against the literal text `"${P:-true}"` and found no match. Writing a
dangerous value in interpolated form was a general-purpose bypass of twelve
rules.

Measured over the 5,417-file corpus: **286 files (5.3%) change findings, and
100 (1.8%) go from pass to fail at the default `--fail-on high`.** One file
goes the other way.

| Trigger | before | after |
|---|---|---|
| `POSTGRES_PASSWORD: ${PW:-hunter2}` | *none* | **CL-0020** high |
| `DATABASE_URL: postgres://${U:-u}:${P:-p}@db` | *none* | **CL-0021** high |
| `image: nginx:${TAG:-latest}` | CL-0019 medium | **CL-0004** medium |
| `ports: ["${BIND:-0.0.0.0}:80:80"]` | *none* | **CL-0005** medium |
| `user: "${UID:-0}:${GID:-0}"` | *none* | **CL-0018** medium |
| `mem_limit: "${MEM:-0}m"` | *none* | **CL-0026** medium |
| `privileged: ${P:-true}` | *none* | **CL-0002** critical |

The `image:` row is a reclassification, not a new failure: CL-0004 replaces
CL-0019 at the same location and severity, because the tag resolves to the
mutable `latest` rather than to an opaque `${TAG}`.

Two changes go the other way and **remove** findings, both fixing false
positives: a port whose default binds loopback (`"${PORT:-127.0.0.1:80}:80"`)
no longer trips CL-0005, and an empty placeholder in a list-form entry
(`- API_KEY=""`) no longer trips CL-0020 — the mapping form `API_KEY: ""` was
already exempt.

If a finding is genuinely parameterized in your deployment, that is what
`.compose-lint.yml` suppressions are for. Writing the reference without a
default (`${PW}` rather than `${PW:-hunter2}`) also stays exempt, because
Compose then ships nothing.

### Security

- **The shipped harnesses now terminate the option namespace with `--`.** A
  repository can contain a directory named `--config=cfgdir` holding a
  `compose.yml`; the resulting path `--config=cfgdir/compose.yml` matches the
  pre-commit hook's `files:` pattern and the Action's discovery, so a harness
  that globbed repo paths straight into argv handed argparse something it read
  as an option. The crafted file left the lint set *and* an attacker-authored
  policy disabling every rule was installed for the run — the gate went green
  over a `privileged` stack mounting `/var/run/docker.sock`. Confirmed
  end-to-end: the pre-commit hook reported `Passed` before this change and
  `Failed` after, on the same repository.

  The pre-commit hook ships `args: [--]` and the Action passes `--` before the
  file list in both invocations (the text run and the SARIF re-run). Setting
  `args:` in your `.pre-commit-config.yaml` replaces the default, so keep `--`
  last if you pass flags — see README.

  The separator is deliberately **not** inserted by the CLI's argv shim: it
  cannot tell a genuine `--config=x` from a file named that, and terminating
  before the first positional would break the documented
  `compose-lint init docker-compose.yml -o ci.yml` form.

### Changed

- **Coverage gaps are reported on every channel a consumer reads.** An
  unresolved `include:` or cross-file `extends: {file: ...}` now produces a JSON
  `errors[]` entry, a SARIF `toolExecutionNotifications` record with
  `executionSuccessful: false`, and exit 2 — previously a stderr warning for
  `include:` and complete silence for `extends:`. `parser.coverage_gaps(data)`
  exposes the same list to library callers. The text verdict counts them
  separately from parse failures, because those files parsed fine and saying
  otherwise would misdescribe the run. See **Upgrading** above.
- **New `--allow-partial-coverage` flag on `check`** to accept a coverage gap
  and grade what is visible. It waives the gap, not the findings: a local
  CRITICAL still fails the gate.
- **`${VAR:-default}` is resolved document-wide before rules run.** The parser
  normalizes every string leaf to the value Compose ships when the variable is
  unset, so a rule classifies the deployed configuration instead of the source
  text. Substitution had been wired into one call site (bind sources), leaving
  CL-0002, CL-0004, CL-0005, CL-0008, CL-0009, CL-0010, CL-0011, CL-0014,
  CL-0016, CL-0018, CL-0020, CL-0021, CL-0022, CL-0024, CL-0026 and the
  capability rules grading a string that is never deployed. Doing it once in the
  parser is what keeps it from being re-litigated per rule: a rule that adds a
  dangerous literal to its set gets the interpolated spellings for free. See
  **Upgrading** above for the measured impact. A reference with no default is
  still left as written — Compose ships nothing for it, so there is nothing to
  grade.
- **The credential rules' interpolation exemption is stated as what Compose
  does.** CL-0020 and CL-0021 previously skipped any value *containing* a
  reference, so appending one character to a literal (`hunter2$X`) silenced
  them, while Compose ships `hunter2`. The exemption is now "Compose resolves
  this value to nothing", which also correctly exempts a quoted reference in a
  list-form entry (`- SECRET_KEY="${KEY}"`, where the quotes are literal
  characters) that a stricter shape test would have flagged.
- **CL-0021's rule description** now says the password half is skipped when
  Compose resolves it to nothing, and that a defaulted password still fires.
  Visible in `--explain CL-0021`, the docs site and SARIF rule metadata.
- **CL-0026 no longer treats an unparseable dollar-bearing value as a limit.**
  `mem_limit: "${MEM:-0}m"` resolves to `0m`, which Docker reads as unlimited,
  and now fires; a bare `${MEM_LIMIT}` stays exempt as genuinely unknowable.
- Scalars longer than 8 KB are no longer scanned for interpolation. The two
  substitution regexes are quadratic (measured 80 KB → 0.49 s, 160 KB →
  1.94 s), and the pass above runs them over every string rather than bind
  sources alone; past the cap the conservative answer is returned unscanned.
- **A Compose file containing an ambiguous line break is now refused** (exit 2,
  reported per file, with a SARIF `toolExecutionNotifications` entry) instead of
  being linted with line numbers nothing else agrees with. A lone `\r`, U+0085,
  U+2028 or U+2029 is a line break to the YAML parser but not to editors, SARIF
  viewers or CI annotations, so on such a document *any* reported line number is
  wrong for one side or the other — and the fix engine would splice at a line
  the user is not looking at. There is no line numbering to fall back on, so the
  file is refused rather than mislabeled. None of the 5,417 files in the corpus
  contains one, and CRLF and LF are unaffected.
- **The parser now reads files without universal-newline translation**, so
  `check` and `fix` parse the same bytes for the same file. `fix` has always
  read with `newline=""` to preserve line endings, while the parser rewrote a
  lone `\r` to `\n` — a second, quieter version of the same disagreement.
  Verified no behavior change: LF and CRLF documents produce byte-identical
  findings and line numbers, and a full corpus run is unchanged.

### Fixed

- **`fix --apply` could edit the wrong line and silently delete config.** The
  fix engine's offset table counted only `\n`, while the line numbers it
  converted come from PyYAML, which also breaks on a lone `\r`, U+0085,
  U+2028 and U+2029. One such codepoint inside a quoted scalar shifted every
  later splice a line, so a fix could remove a line the user never selected —
  and because the result was still valid Compose, every safety net passed and
  the run exited 0. `compose_lint._lines` now owns a single definition of a
  line break, with `split_lines` and `line_starts` derived from one scan so
  they cannot disagree; the fixers, the fix engine and the text formatter's
  source excerpt all use it. A CI guard fails the build on a bare
  `str.splitlines()` in `src/`. Documents free of those four codepoints —
  effectively all real Compose files — are unaffected: a 5,417-file corpus run
  shows zero change in findings, exit codes or errors.
- **A file whose fixes could not be computed no longer destroys the batch.**
  The same desync could push a line number past the offset table and raise a
  bare `IndexError`, which aborted the whole run: `check --format sarif` then
  emitted a 0-byte document, discarding the findings of every other file
  scanned alongside it. Out-of-range positions now raise a
  `LineOutOfRangeError` that the CLI reports as a per-file failure (exit 2,
  the usage-error code) while the rest of the batch still lints and still
  ships its findings.

## [0.17.0] - 2026-08-12

### Upgrading from 0.16.x

**Four capabilities that passed on 0.16.0 now fail; nothing else moved.**
`SYS_NICE`, `IPC_LOCK` and `LEASE` are flagged by the new CL-0029, and
`SYSLOG` by the new CL-0030 — all four at HIGH, and all four ungraded on
0.16.0, where no rule covered them.

| Trigger | 0.16.0 | 0.17.0 |
|---|---|---|
| `cap_add: SYS_NICE` / `IPC_LOCK` / `LEASE` | *none* | **CL-0029** HIGH |
| `cap_add: SYSLOG` | *none* | **CL-0030** HIGH |

Unlike 0.15.x → 0.16.0, no existing finding changes rule or severity, so a
waiver written against 0.16.0 still covers what it named. The only new
suppressions you may need are for the four capabilities above.

### Added

- **CL-0029 — host-availability capability added** (HIGH): flags `cap_add`
  of `SYS_NICE`, `IPC_LOCK` or `LEASE`. Each reaches the host with nothing
  else in the file and costs availability alone — `SYS_NICE` puts the
  container's threads above every ordinary host process on a scheduler that
  is not namespaced, `IPC_LOCK` pins host RAM past `RLIMIT_MEMLOCK` that
  cannot be reclaimed or swapped, and `LEASE` stalls the host's own `open()`
  on any bind-mounted path for the kernel's lease-break timeout. Each member
  was measured on Docker 29.4.3 holding only that capability under
  `--cap-drop ALL`. The fix text points at `deploy.resources` and at bounding
  a workload that keeps the capability, since SPDK and DPDK ask for
  `SYS_NICE` and `IPC_LOCK` together.
- **CL-0030 — host-disclosure capability added** (HIGH): flags
  `cap_add: SYSLOG`, which reads the host kernel ring buffer — `dmesg` is not
  namespaced, so the container sees the host's boot, hardware and driver log,
  including kernel pointers where `kptr_restrict` allows them. Independence
  from the host's `kernel.dmesg_restrict` was measured rather than assumed:
  with that sysctl at 0, a capless container still read 0 lines against 2,028
  with the capability, because Docker's default seccomp profile admits
  `syslog(2)` only for `CAP_SYSLOG`. The gate is the capability, on any host.

  With SYSLOG graded, every Linux capability now carries a rule or a recorded
  reason it needs none — `test_rule_membership.py`'s ungraded set is empty.

### Changed

- CL-0013's remedy for `/dev/shm` and `/dev/hugepages` is now something the
  reader can actually follow. Both kept firing correctly — a host bind of
  either exposes segments belonging to the host and every other container —
  but the guidance said to drop the mount and "use a named volume", which
  provides neither facility. It now names the real alternatives, each
  verified against Docker 29.4.3 rather than taken from documentation:
  `shm_size:` for a larger segment, `ipc: shareable` plus `ipc: service:` for
  two services that must share one, and a `hugetlbfs` volume for huge pages
  (bounded with `deploy.resources.limits`, since the pool stays host-wide). A
  workload that genuinely needs the host's own huge-page files is told to
  suppress with a reason rather than pretend the mount is safe. Over the
  archived 5,417-file corpus this changed 39 fix texts and zero findings.
- CL-0024's doc now states what the `SYS_ADMIN` judgment call actually
  decides, rather than implying a broader choice than the rule makes.
- `docs/state-of-compose.md` and its four charts are regenerated on a 0.16.0
  baseline, so the published corpus figures reflect the current severity
  model rather than 0.15.x pricing.
- The examples library is refreshed against 0.16.0 — each worked example
  re-linted so its quoted findings, ids and severities match what the release
  actually emits.
- The demo GIFs are re-rendered on 0.16.0.
- Rule counts stated in prose are now held to the registry by
  `tests/test_rule_surfaces.py`. Four surfaces had gone on claiming 25 rules
  after CL-0029 and CL-0030 landed — the mkdocs `site_description` search
  engines index, the Docker Hub overview that syncs on every default-branch
  push, `SECURITY-EXPECTATIONS.md`, and the roadmap inventory — because such
  counts go stale when a rule lands, not when a version ships, so neither the
  release checklist nor CI's version-pin check reached them.

## [0.16.0] - 2026-08-11

### Upgrading from 0.15.x

**Your CI verdict may change in both directions, on files you have not
touched.** This release re-derived every severity and moved findings between
rules, so a gate that passed may fail and a gate that failed may pass. Nothing
here is a parser change: the same file is being read the same way and priced
differently.

**The hazard worth reading twice: a waiver can still parse and no longer
cover anything.** A retired rule id warns on load —
`config: unknown rule id 'CL-0012'; the override has no effect` — and
`--strict-config` turns that into an error. But a waiver naming a rule that
still *exists* is silent, even when the finding it was written for has moved:

```yaml
rules:
  CL-0011:
    reason: "we need SYS_ADMIN for the FUSE mount"   # no longer covers it
```

`SYS_ADMIN` is CL-0024 now. The config is valid, nothing warns, and the finding
comes back at CRITICAL. Check every waiver against the table below.

#### Where findings moved

Generated by linting one trigger per row under both versions.

| Trigger | 0.15.2 | 0.16.0 |
|---|---|---|
| `cap_add: ALL` | CL-0011 CRITICAL | **CL-0024** CRITICAL |
| `cap_add: SYS_ADMIN` / `SYS_MODULE` / `SYS_RAWIO` | CL-0011 HIGH | **CL-0024 CRITICAL** |
| `cap_add: PERFMON` / `SYS_TIME` | CL-0011 HIGH | **CL-0028** HIGH |
| `cap_add: SYS_PTRACE` / `DAC_READ_SEARCH` | CL-0011 HIGH | **CL-0027 MEDIUM** |
| `cap_add: NET_ADMIN` / `BPF` / `SYS_BOOT` | CL-0011 HIGH | CL-0011 HIGH *(unchanged)* |
| `cap_add: DAC_OVERRIDE` | CL-0011 HIGH | *none — Docker default* |
| whole-root mount `/`, either mode | CL-0013 CRITICAL | **CL-0001** CRITICAL |
| writable `/etc`, `/root`, `/boot`, `/proc` | CL-0013 HIGH | **CL-0025 CRITICAL** |
| read-only `/etc` and friends | CL-0013 HIGH | CL-0013 HIGH *(unchanged)* |
| `devices: /dev/sda` and other host disks | CL-0016 HIGH | CL-0016 **CRITICAL** |
| `devices: /dev/fuse` | CL-0016 HIGH | *none — needs `SYS_ADMIN`, which CL-0024 flags* |
| `userns_mode: host` | CL-0010 HIGH | *none — a no-op at Docker's default posture* |

#### Newly flagged — a passing file can now fail

| Trigger | 0.16.0 |
|---|---|
| writable `/var/lib` or `/var/lib/containerd` | CL-0025 CRITICAL |
| `/run` or `/var/run` mounted whole | CL-0001 CRITICAL |
| a path below them — `/run/udev`, `/var/run/libvirt/libvirt-sock` | CL-0013 HIGH |
| `~/.ssh`, `~/.aws`, `~/.docker`, `~/.kube`, `~/.gnupg` | CL-0013 HIGH |
| a relative source that climbs out — `../../../..` | CL-0001 CRITICAL |
| a bind-backed named volume (`driver_opts: {device: …, o: bind}`) | CL-0001 CRITICAL |
| `devices: /dev/md0`, `/dev/vd*`, `/dev/xvd*`, `/dev/mmcblk*` | CL-0016 CRITICAL |

#### No longer flagged — a failing file can now pass

`cap_add: DAC_OVERRIDE` · `userns_mode: host` · `devices: /dev/fuse` ·
`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom` ·
a project directory under a home dir (`/home/alice/proj/data`) ·
`/var/lib/mysql`, `/var/lib/postgresql/data` and other service state dirs ·
anything that was CL-0012, CL-0015 or CL-0023.

#### Check your own files rather than reasoning about this list

```bash
compose-lint check --format json . > before.json   # on 0.15.x
pip install --upgrade compose-lint
compose-lint check --strict-config .               # dead rule ids become errors
compose-lint check --format json . > after.json
diff <(jq -S '[.findings[]|{rule_id,line,service}]' before.json) \
     <(jq -S '[.findings[]|{rule_id,line,service}]' after.json)
```

The diff catches the moved-waiver case, which no warning can reach.

### Added

- **CL-0026 — no memory or CPU resource limits** (MEDIUM). Docker imposes
  neither by default: a container's `memory.max` is `max` and its `cpu.max` is
  `max 100000` unless a limit is set. Fires when a service declares no memory
  limit, no CPU limit, or neither, and names which is missing. Reservations
  (`mem_reservation`, `cpu_shares`) express priority under contention and do not
  satisfy it; `cpu_quota` does. Covers both halves of ATT&CK T1496 Resource
  Hijacking — the memory-exhaustion denial of service and the CPU-bound
  cryptomining that a memory limit does not bound at all.
- Every rule page carries a derivation block — baseline, precondition, impact,
  qualifier, derived, shipped, and an **Evidence** line naming a premise check
  or a captured observation. A test asserts the page and the severity table
  state the same derivation.
- `scripts/validate_rule_premises.py` asserts the daemon under test is at
  Docker's defaults before measuring anything, and aborts if it is not — a
  premise measured against a hardened or loosened daemon returns a confidently
  wrong answer. Five new premise checks: a `:ro` socket is still a working API
  endpoint, a raw host-disk read at default capabilities, the `/dev`-bind
  negative control for it, `core_pattern` writable through an rw `/proc` bind,
  and memory/CPU unbounded by default.
- CI smoke-tests `.pre-commit-hooks.yaml` with the real tool
  (`precommit-smoke`). `action.yml`, the image and the wheel each had an
  end-to-end smoke job; the pre-commit hook had none, which is how issue #465 —
  a `files` pattern that made the hook unable to pass — reached a user.
  `pre-commit try-repo` runs the manifest from the working tree, so `entry`,
  `language` and hook installation are exercised on the PR that changes them.
  `.pre-commit-hooks.yaml` was also missing from the `code` path filter, so a
  manifest-only edit previously skipped the jobs that check it.

### Changed

- **BREAKING — the severity model was rebuilt, and rule ids moved with it.**
  Severities are now *derived* from a documented two-axis matrix under a stated
  attacker baseline and a stated Docker posture, and any rule shipping a
  different value declares an override from a closed reason list. See
  `docs/severity.md`, [ADR-020](docs/adr/020-severity-scoping-and-overrides.md),
  [ADR-021](docs/adr/021-critical-tier-posture.md) and
  [ADR-022](docs/adr/022-threat-model-grounding.md).

  **Severity changes:** CL-0016 HIGH → CRITICAL; CL-0005 HIGH → MEDIUM;
  CL-0007, CL-0014 and CL-0017 MEDIUM → LOW. Only CL-0005 crosses the default
  `--fail-on high` gate: a file whose only finding at or above HIGH was an
  all-interfaces port bind now passes. That is deliberate — CI stops failing on
  intended-public exposure. Use `--fail-on medium`, or override CL-0005 back to
  HIGH in `.compose-lint.yml`, to keep the old behaviour.

  **Rules split.** `cap_add` is now four rules by what the capability grants:
  CL-0024 (CRITICAL: `ALL`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`), CL-0011
  (HIGH, unchanged id: `NET_ADMIN`, `BPF`, `SYS_BOOT`), **CL-0028** (HIGH:
  `PERFMON`, `SYS_TIME`) and CL-0027 (MEDIUM: `SYS_PTRACE`, `DAC_READ_SEARCH`).
  CL-0028 is new: both its members reach the host with no other key in the file
  and nothing from the image — `SYS_TIME` writes the host's wall clock, because
  Docker does not namespace `CLOCK_REALTIME`, and `PERFMON` opens a host-wide
  `perf_event_open` at the upstream kernel default. A service adding either now
  crosses the default gate where it previously reported MEDIUM. The severity
  model gains an `integrity-only` qualifier (one tier down) alongside
  `read-only` and `availability-only`, which is what the impact axis was missing
  for a host effect that corrupts without disclosing or granting control.

  Host paths are two rules: CL-0025 (CRITICAL) for writable mounts of `/etc`,
  `/root`, `/boot`, `/proc`, `/var/lib/docker`, `/var/lib/containerd` and
  `/var/lib`, and CL-0013 (HIGH, unchanged id) for `/sys`, `/dev`, the home tree
  and read-only mounts of CL-0025's paths. A whole-root mount (`/`) is CL-0001's
  in either mode, because it contains the daemon control socket. Neither rule
  branches severity any more, which fixes the SARIF descriptor/finding mismatch
  in #503.

  **Suppression migration.** A `CL-0011` waiver now covers only `NET_ADMIN`,
  `BPF` and `SYS_BOOT`; the other capabilities move to CL-0024, CL-0027 and
  CL-0028 and are no longer covered by it. A `CL-0027` waiver does not cover
  `PERFMON` or `SYS_TIME` — re-waive as CL-0028. A `CL-0013` waiver no longer
  covers a writable root-equivalent path (CL-0025) or a `/run`-family mount
  (CL-0001), and a waiver of a whole-root mount moves to CL-0001 (from CL-0025
  when writable, or from CL-0013 when read-only). Waivers for CL-0012, CL-0015
  and `/var/lib/kubelet` are dead and can be deleted.

- **CL-0013 matches the home tree by depth, not by subtree.** `/home` and a
  single user's home directory (`/home/alice`) are still flagged in either mode,
  and so are the credential directories `~/.ssh`, `~/.docker`, `~/.aws`,
  `~/.kube` and `~/.gnupg` together with everything below them. A deeper project
  path — `/home/alice/projects/app/data` — is the application's own directory
  and is no longer flagged. **Fewer findings** on absolute
  `/home/<user>/<project>/…` mounts, **new findings** on `~/.ssh`-style
  credential mounts. This pairs with relative-source resolution below: `./data`
  resolves to an absolute path under wherever the compose file sits, which for
  most projects is under `/home`, so a subtree match would have flagged the
  commonest bind idiom in Compose.

- CL-0016's device list is reconciled with what a device actually grants. It
  **gains** `/dev/vd*`, `/dev/xvd*`, `/dev/mmcblk*` and `/dev/md*` — the host
  root disks of KVM and Proxmox guests, EC2 instances, Raspberry Pis and mdraid
  arrays, which needed no capability and were not flagged at all. It **drops**
  `/dev/mem`, `/dev/port` and `/dev/fuse`, each live only alongside a capability
  CL-0024 or CL-0009 already flags, and `/dev/kmem` and `/dev/raw`, for which
  Docker refuses to create the container. Suppressions for the dropped devices
  are dead and can be deleted.

- CL-0001 flags any mount that exposes a host control socket, including a
  directory that merely contains one — `/run`, `/var/run`, `/run/containerd`,
  `/run/systemd`, or the whole root `/` — and is mode-independent, because `:ro`
  applies to the socket file rather than to the read-write API behind it. A
  read-only `/` used to be graded CL-0013 HIGH, a tier below the socket it
  exposes. It also matches a socket name on the **host** side of a mount only:
  `- /tmp/fake:/var/run/docker.sock` is no longer reported as a socket mount,
  since the container path is where a socket would land, not where it comes from.

- Host paths are normalised before the mount rules match them, so `.` and `..`
  segments no longer hide a mount. `- /.:/host`, `- /..:/host` and `- /./:/host`
  are whole-root mounts and now report CL-0001 CRITICAL instead of passing
  clean; `/run/.` is matched like `/run`, and `/etc/..` is treated as root
  rather than as CL-0013's HIGH.

- CL-0026 no longer accepts a non-positive value hidden in an interpolation
  default. `mem_limit: ${MEM:-0}` and `cpus: ${CPUS:-0}` describe an unbounded
  container and are now flagged; a bare `${MEM}` still counts as a limit,
  because its value is genuinely unknowable from the file.

- CL-0006 and the `cap_add` rules share one capability normaliser, so
  `cap_drop: [CAP_ALL]` and `cap_drop: ["  ALL  "]` are read the same way
  `cap_add` reads them. `cap_add: [CAP_ALL]` is no longer flagged at all:
  Docker rejects that spelling outright, so the file could never start.

### Removed

- **CL-0012 (PIDs cgroup limit disabled)** — the premise does not hold. On the
  grounded target, `pids_limit: -1`, `pids_limit: 0` and omitting the key all
  produce the same `pids.max` (systemd's `DefaultTasksMax`), so the explicit
  opt-out the rule flagged does not leave the process count unbounded.
- **CL-0015 (healthcheck disabled)** — no runtime delta, and its citations
  mandate the case it declines to flag.
- **`uts: host` and `userns_mode: host`** from CL-0010. Both are no-ops under
  the grounded posture: `sethostname()` needs `CAP_SYS_ADMIN`, which is not in
  Docker's default set, and `userns_mode` only means anything against a
  `--userns-remap` daemon.
- **`/var/lib/kubelet`** from CL-0013 — its danger is entirely conditional on
  Kubernetes being present, so it cannot be premise-checked on the grounded
  target.

  The ids CL-0012, CL-0015 and CL-0023 stay fallow and will not be reused.

### Fixed

- **The mount rules see host paths they were missing.** Each of these mounted a
  real host path and reported clean:
  - **A relative or `~` source.** Compose resolves a relative mount source
    against the compose file's directory and expands a leading `~`; the source
    was matched as written, so `- ../../../../../..:/host` mounted the host root
    filesystem and reported nothing. `./data:/data` and other in-project mounts
    are unaffected.
  - **An interpolated default.** With no `.env` and no exported variable,
    Compose substitutes the default, so `${DOCKER_SOCKET_PATH:-/var/run/docker.sock}`
    mounts the live control socket. A reference with **no** default (`${VAR}`,
    `${VAR:?err}`, `$VAR`) is still left alone — the host path is not knowable
    from the file, and guessing one would invent a finding.
  - **A bind-backed named volume.** `driver_opts: {type: none, device: <host
    path>, o: bind}` is the standard way to pin a bind mount's options, and the
    host path lives in the top-level `volumes:` block, which the mount rules
    never read. `external: true` volumes are left alone, since their host path
    is not in the file.
  - **A writable `/var/lib`** (CL-0025 CRITICAL; read-only, CL-0013 HIGH). It
    contains the container store, so a mount of it grants what `/var/lib/docker`
    does — verified on Docker 29.4.3, a container given only `-v /var/lib` read
    and modified a second container's files. It is matched **exactly**, because
    its grant comes from what it contains rather than from what lies below it:
    `-v /var/lib/mysql`, `/var/lib/postgresql/data` and other service data
    directories are *not* flagged. `/var/lib/containerd` is a member in its own
    right and is matched by descent.
  - **A path below `/run` or `/var/run`** (CL-0013 HIGH) — `/var/run/dbus`,
    which reaches systemd and PolicyKit; `/var/run/libvirt/libvirt-sock`, which
    is VM control; `/run/udev`, `/var/run/utmp`, `/run/systemd/journal`. CL-0001
    owns those directories and their ancestors, because those hold the control
    socket; what sits strictly below holds host service state instead. A
    descendant that *is* a socket stays CL-0001's at CRITICAL.
  - **`/dev/md/<name>`** (CL-0016). mdadm creates a named symlink per array
    alongside the numeric node, and `^/dev/md\d` cannot match it — the character
    after `md` is `/`, not a digit — so a named array passed clean while
    `/dev/md0` beside it was CRITICAL. Added as a second pattern rather than by
    loosening the first, which is what keeps `/dev/mdadm` out.

- **`/dev/null` and the other inert character devices are no longer flagged**
  (CL-0013). `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random` and
  `/dev/urandom` disclose no host state and grant no access — mounting
  `/dev/null` over a config file the image expects is a near-universal idiom,
  and the `/dev` descent match priced it HIGH. The rest of `/dev`, including
  `/dev/shm`, is unchanged.

- CL-0011 no longer flags `DAC_OVERRIDE`, which inverted the default gate
  (issue #492). `DAC_OVERRIDE` is one of Docker's 14 default capabilities, so a
  container holds it whether or not the file names it — flagging it on `cap_add`
  scored the declaration rather than the runtime state. The effect was that
  hardening a service made it fail: `cap_drop: [ALL]` plus
  `cap_add: [DAC_OVERRIDE]` — one capability — exited 1 at the default
  `--fail-on high`, while the same service with no `cap_drop` at all — fourteen
  capabilities, `DAC_OVERRIDE` among them — exited 0. The fastest way back to
  green was to delete the hardening. CL-0011 already excluded `MKNOD` and
  `SYS_CHROOT` for exactly this reason; `DAC_OVERRIDE` was the one default
  capability the list still carried. CL-0006 now names it among the retained
  defaults, so both rules describe the same capability the same way.

- CL-0020 and CL-0021 no longer skip credentials containing `$$`, Compose's
  escape for a literal dollar (issue #502). CL-0020's variable-reference regex
  read the second dollar of `pa$$w0rd` as starting a `$w0rd` substitution, and
  CL-0021 exempted any value containing `$` at all — so exactly the passwords a
  careful user escaped correctly went unchecked, and the two rules disagreed on
  values like `hunter2$`. Both now share one classifier that consumes `$$`
  escapes left-to-right, as Compose does, before testing for a reference.

- Handing compose-lint its own config file no longer fails the run (issue #499).
  `.compose-lint.yml` parses as YAML but has no `services:` key, and its shape
  matched neither of ADR-013's not-applicable buckets, so it fell through to
  `Not a valid Compose file` and exit 2. It is now recognised as a third
  not-applicable shape and skipped with exit 0, like fragments and Compose v1
  files. This is the root cause behind issue #465: `compose-lint init` followed
  by a pre-commit sweep could never pass. Genuinely malformed Compose files
  still exit 2; the check requires *every* non-meta top-level key to be a config
  key, so it cannot swallow a broken file.

- Fourteen false claims across the rule docs, each re-verified against a live
  daemon. The worst was CL-0006's documented `## Fix`, which crash-looped:
  `cap_drop: [ALL]` plus `cap_add: [NET_BIND_SERVICE]` exits with
  `chown("/var/cache/nginx/client_temp") failed (Operation not permitted)`. Also
  corrected: seccomp and AppArmor *do* survive `execve` of a setuid binary;
  `bpf` and `init_module` are capability-gated rather than blocked outright;
  `SYS_BOOT` does not load a kernel via kexec; `pid: host` does not expose
  `/proc/[pid]/environ` at default capabilities; `uts: host` cannot change the
  hostname; a `/dev` bind is not equivalent to `devices:`; `read_only` does not
  prevent persistence through a volume; and `user: root` does not undo a
  gosu/su-exec image's privilege drop.

- CL-0019 was ungrounded — its only citation contained no digest guidance at
  all. It now cites Docker's pull-by-digest documentation and CIS 5.28.

## [0.15.2] - 2026-08-08

### Changed

- Rule-doc headings are now phrased for the queries users actually search
  (issue #471): every `docs/rules/` H1 leads with the rule id then names the
  directive and the symptom it produces (e.g. "CL-0007: read_only — fixing
  'Read-only file system' errors"), and the docs-site nav labels — which set
  each page's `<title>` — are synced to match. Affects the site, the GitHub
  view, and `--explain` output; rule ids and content are unchanged.

### Fixed

- CL-0003's compatibility guidance claimed root-dropping entrypoints
  (`gosu`/`su-exec`: postgres, redis, mysql, …) crash-loop under
  `no-new-privileges` — **live-verified false**: nnp blocks privilege *gain*
  at `execve` (sudo, setuid bits, file capabilities), not a root process's
  downward `setuid()`, and a su-exec image (valkey) runs healthy under the
  flag. The doc and fix text are rewritten around the verified semantics,
  and a CI premise check now pins the drop-unaffected fact so the wrong
  claim cannot silently return.
- Fixed file matching in `.pre-commit-hooks.yaml` that was incorrectly including
  `.compose-lint.yml` if present in the commits. This generated errors
  meaning pre-commit will always fail (issue #465). The hook now matches only
  names beginning `compose` or `docker-compose`, and an `exclude` pattern skips
  compose-lint's own config in either spelling — `.compose-lint.yml` and the
  dotless `compose-lint.yml` that `init -o` can write — with either extension.
  **Note** environment specific files, e.g. `compose-dev.yml`, still match, but
  files with prefixes, e.g. `dev-compose.yml`, no longer do.

### Changed

- CL-0003 gains the "Reading the failure" treatment (the last rule from the
  symptom-table survey): sudo's explicit nnp message (captured live), the
  silent case — a setuid `execve` under nnp *succeeds* with privileges
  unchanged (CI-proven: exit 0, euid intact), so failures surface later as
  ordinary permission errors — the `NoNewPrivs` `/proc` confirmation step,
  and an explicit warning not to confuse the crash-looping `cap_drop`
  symptom (CL-0006's `SETUID` row) with this setting.

### Changed

- CL-0012, CL-0018, and CL-0022 get the symptom → remedy treatment
  (issue #479, same pattern as CL-0006/CL-0007): each rule doc gains a
  "Reading the failure" table quoting verbatim, live-captured error messages.
  CL-0012 maps the fork-failure wordings (chronically misattributed to
  `ulimit -u`) to the pids cgroup with a `pids.max`/`pids.current`
  confirmation step; CL-0018 maps non-root `Permission denied` writes by
  mount type, backed by two CI-proven facts — a tmpfs over an existing image
  directory inherits its root ownership (use `uid=`/`gid=`), and named-volume
  initial ownership follows Docker's copy-up rules; CL-0022 frames the
  `noexec` exec failure as relocate-first, `:exec`-with-documented-reason
  last, since the naive fix is the finding. Six new CI premise checks prove
  the busybox rows live. CL-0002's fix text now points at CL-0006's
  capability-determination guide instead of stopping at `<SPECIFIC_CAP>`.

## [0.15.1] - 2026-08-08

### Added

- Documentation site at <https://tmatens.github.io/compose-lint/> (issue
  #470) — the rule docs, configuration guide, severity model, hardening
  walkthrough, and State of Compose report, built by mkdocs from the same
  `docs/` markdown that `--explain` prints (single source, no duplicated
  pages) and deployed to GitHub Pages by the new `docs` workflow on every
  push to `main`. The docs toolchain is hash-pinned in
  `requirements-docs.lock` (new `docs` extra).

### Fixed

- The README's *State of Compose* report link was relative, so it 404'd in
  the PyPI rendering of the project description; it now points at the docs
  site, as do the rule-table and hardening-guide links (previously GitHub
  blob URLs).

### Changed

- CL-0007's guidance gets the same symptom → remedy treatment as CL-0006
  (issue #474): the rule doc gains a "Reading the failure" table mapping
  verbatim `Read-only file system` errors to remedies **by path type** —
  ephemeral paths to `tmpfs:`, persistent data to a named volume (never
  `tmpfs`, which silently erases it on restart), plus the masked
  `No such file or directory` symptom when the image lacks the directory.
  The finding's `fix` text carries the path-type rule and points at
  `--explain CL-0007`. Four new CI premise checks prove the busybox rows
  live, including that named volumes stay writable under `read_only`.

- The CL-0006 symptom → capability table now covers 11 mappings — added
  `NET_ADMIN`, `SYS_NICE`, `SYS_TIME`, `FOWNER`, `KILL`, and `IPC_LOCK` — and
  quotes the verbatim error messages real tools emit, captured from live
  container runs (issue #468). Every mapping is re-proven on each CI run by
  new checks in `scripts/validate_rule_premises.py` — the operation must fail
  under `cap_drop: [ALL]` (busybox wordings asserted verbatim; coreutils
  variants captured live but not CI-asserted) and succeed with only the
  mapped capability added — so an engine default change that invalidates a
  row (as Docker 20.10's `ip_unprivileged_port_start=0` did for the old
  "low ports need `NET_BIND_SERVICE`" folklore) fails CI instead of aging
  silently in the docs.

- CL-0006's fix guidance now teaches how to *determine* an image's required
  capability set instead of stopping at a `<SPECIFIC_CAP>` placeholder
  (issue #4). The finding's `fix` text gains the drop-and-observe method and
  the common `Operation not permitted` → capability mappings, and
  `docs/rules/CL-0006.md` (also served by `--explain CL-0006`) gains a full
  "Determining required capabilities" section covering the symptom→capability
  table, the `capable` BPF tool, `docker diff`, and entrypoint inspection.
  Both stress verifying *function*, not just startup: capability failures are
  often non-fatal, silently degrading a feature (e.g. DHCP device discovery
  under a dropped `NET_RAW`) while the container stays "healthy" — so review
  logs and exercise background behaviors after every change.
  Guidance-only per [ADR-019](docs/adr/019-withdraw-security-profile-catalog.md):
  no per-image capability data is bundled.

## [0.15.0] - 2026-08-07

### Removed

- **Profile enrichment has been withdrawn** ([ADR-019](docs/adr/019-withdraw-security-profile-catalog.md),
  superseding ADR-017 and ADR-018). The `compose_lint.profiles` package, the
  `scripts/validate_profiles.py` validator, the `profile-validate` CI gate, the
  `profiles` config block, and `run_rules`' `profile_lookup` parameter are all
  gone — roughly 2,200 lines across source, tests and docs.

  The feature matched a service's `image:` against a catalog of csd-derived
  security profiles and appended an image-specific hint to a finding's `fix`
  text. It shipped as an opt-in experimental preview, and the automation that
  ADR-017 §7 requires before any profile may be endorsed as `validated` (issue
  #360) was never built — it depends on csd emitting the catalog schema and on a
  BPF-capable runner. compose-lint was therefore carrying a complete consumer of
  a catalog that does not exist, behind a flag whose only honest setting was off.

  **Upgrade impact is limited to configuration.** A leftover `profiles:` block in
  `.compose-lint.yml` is now simply an unrecognized top-level key: it takes the
  standard warn-and-continue path, printing a stderr warning and leaving the exit
  code unchanged, so ordinary runs keep working. Under `--strict-config` it is a
  hard error (exit 2), as any unrecognized key is. No finding, severity, exit
  code, or output format changes — enrichment was additive-only, so nothing that
  was reported before is reported differently now.

  `CL-0009` ("Security profile disabled") is **unaffected**: it covers seccomp
  and AppArmor `security_opt` settings and is unrelated to this catalog.

### Fixed

- The GitHub Action snippet in `README.md` now pins the current release.
  `publish.yml`'s `bump-marketplace-smoke-pin` job rewrote the
  `tmatens/compose-lint@<sha> # vX.Y.Z` pin only in
  `.github/workflows/marketplace-smoke.yml`, so the copy-paste snippet users
  actually take from the README stayed a release behind every time — it was
  still on v0.14.0 after v0.14.1 shipped. The job now rewrites both files,
  and the stale pin is corrected.
- `release-prep.yml` now bumps the self-referencing version pins in
  `README.md` and `docs/` as part of the version-bump commit. The
  `version-consistency` job has required those pins to match
  `pyproject.toml` since #443, but release-prep only touched
  `pyproject.toml`, `__init__.py`, and `CHANGELOG.md` — so the release PR it
  opened failed its own required check on every release and needed a
  hand-pushed fixup commit.
- The sdist no longer ships whatever happens to sit in the maintainer's
  working tree. `[tool.hatch.build.targets.sdist]` was a denylist of nine
  known paths, but hatchling ships everything the *root* `.gitignore` does
  not exclude and does not read nested `.gitignore` files — so a local
  virtualenv, which writes its own `.gitignore: *` and is therefore
  invisible to `git status`, was swept in: 158 of 445 entries, 35% of a
  3.5 MB archive, including `bin/python` as an absolute symlink into the
  build machine's filesystem. Such an archive is not merely untidy but
  unusable — uv rejects it as an invalid tar — and nothing caught it:
  `twine check` validates metadata, not contents, and `publish.yml`'s
  content guard inspects the wheel alone. The sdist target is now a
  root-anchored allowlist, and `publish.yml` gates the sdist on symlinks
  and virtualenv markers. Published artifacts were never affected: release
  builds run from a clean checkout, and the wheel packages `src/` only.

### Changed

- Documentation no longer describes auto-fixable findings as "safe". `README.md`,
  `docs/dockerhub-overview.md`, and `docs/SECURITY-EXPECTATIONS.md` said `fix`
  applies "safe, mechanical edits", which invites the reading that applying them
  is harmless. Per ADR-014 the guarantee is a property of the *edit* — one
  unambiguous value, no collateral change, still-valid YAML — not of the
  outcome: `read_only: true` and the `127.0.0.1` port rebind both change runtime
  behavior by design, and are surfaced with a `⚠ behavior-changing` caveat
  rather than withheld. The docs now say "mechanically unambiguous", state the
  edit/outcome distinction explicitly, and show the caveat line a user will see.

## [0.14.1] - 2026-07-31

### Fixed

- `fix --apply` now prints the `⚠ behavior-changing` caveats for the fixes it
  applied, in the same form the dry-run diff uses. Previously the caveats were
  rendered only on the dry-run path, so a one-shot `compose-lint fix --apply`
  (the CI and script-pipeline case) wrote behavior-changing edits and printed
  only `applied N fix(es)` — the warning never reached the user at the moment
  it mattered. Runs whose edits all carry no caveat print no banner; stdout
  stays data-clean. Reported from the r/selfhosted feedback thread (#425,
  #428).

## [0.14.0] - 2026-07-29

### Added

- **Profile schema 1.6: optional per-dimension `derivation.features` — the
  feature ledger.** A drop-test proves the minimum only for what its correctness
  check exercises; the ledger records, as structured data instead of criteria-doc
  prose, which of the image's *privilege-relevant* features the workload did
  (`driven: true` + evidence) and did not (`driven: false` + the honest reason)
  drive. Human-authored, bounded by asking "what is each requested privilege
  FOR?" (1–3 entries per image in practice). Opt-in evidence, not a tax: with no
  ledger a profile's workload-coverage claim simply stays `partial` (ADR-018).
  Optional and additive — all 1.0–1.5 documents remain valid. See ADR-017 §13.
- **Profile schema 1.5: optional top-level `reference_url`.** An HTTPS link to the
  profile's rendered, human-readable page — the full derivation context (evidence
  table, invocation, criteria prose, provenance) that a one-line enrichment hint
  cannot carry. When present, enrichment surfaces it on the enriched finding's
  `references` (first, so the text formatter's `ref:` line shows the image-specific
  page rather than the rule's generic citation; JSON carries all references). The
  reference catalog publishes these pages at
  [tmatens.github.io/container-security-profiles](https://tmatens.github.io/container-security-profiles/).
  Optional and additive — all 1.0–1.4 documents remain valid. See ADR-017 §12.

- **Profile schema 1.4: optional `derivation.run_config.sysctls`.** Records the
  kernel sysctl posture a *posture-dependent* capability minimum was derived under.
  The canonical case is `net.ipv4.ip_unprivileged_port_start`: Docker defaults it
  to 0 (all ports unprivileged, so a low-port bind needs no cap and NET_BIND_SERVICE
  reads falsely-removable), while the kernel default of 1024 makes the cap required —
  the "works on my Docker, breaks in k8s" divergence. csd already pins the hardened
  posture and emits the `sysctls` list; this field lets the published profile state
  which posture its minimum assumes, so a consumer can reconcile against their own
  runtime instead of guessing. Optional and additive — all 1.0–1.3 documents remain
  valid; absent/empty means no sysctl was pinned. See ADR-017 §11.
- **`check --strict-config` / `fix --strict-config`.** Opt-in strict mode that
  turns config diagnostics that are normally stderr warnings — an unknown or
  typo'd rule id (`CL-001` vs `CL-0001`), an unknown top-level or per-rule key,
  an unknown `profiles` key — into hard errors (exit 2). Without it, a malformed
  config's warning can be lost in a redirect and silently disable the wrong rule;
  strict mode fails the run loudly instead. Default behavior is unchanged.

### Fixed

- **`check --format sarif` and `fix` no longer abort a batch when a file becomes
  unreadable mid-run.** Both re-read the source after parsing (for SARIF fix
  edits / to apply fixes); if the file was deleted, unmounted, or had its
  permissions changed between the parse and that second read, the `OSError` is
  now recorded per-file and the scan continues to the remaining files instead of
  crashing the whole run.

## [0.13.0] - 2026-07-05

### Added

- **Validated profiles must declare immutable version tags.** The profile ci-smoke
  gate (`scripts/validate_profiles.py`) now rejects a `status: validated` profile
  whose `applies_to.tags` includes a mutable rolling tag (`latest`, `stable`,
  `edge`, `main`, `nightly`, …): such a tag points to a different image over time,
  so a derivation done against it cannot be trusted to still apply to the image a
  consumer later pulls. Exploratory profiles are unaffected, and no existing catalog
  profile uses a mutable tag, so this guards against a future mistake without
  changing current data.
- **Profile schema 1.3: `app_tier_verified`.** An optional top-level block on a
  profile recording that the whole hardening was verified at the **service** level
  — the multi-container stack brought up with every dimension applied and a real
  service-level check passed — a stronger signal than the per-dimension workload,
  which exercises only one container. Fields: `service`, `service_version`,
  `method`, `check`, `verified_date`, `result`, and an optional `over_hardening`
  (`applied` + `result`) that proves the check catches a too-tight config (not a
  rubber stamp). Requires `status: validated` (schema) and `result: pass`
  (ci-smoke gate). Optional and additive — all 1.0–1.2 documents remain valid, and
  it never substitutes for the per-dimension `validated_via` evidence. ADR-017 §10.

### Fixed

- **Profile-enrichment hints no longer collapse across services in text output.**
  The fix-block dedup keyed on `rule_id` alone, so when two services were flagged
  by the same rule but enrichment gave them **different** image-specific guidance
  (e.g. postgres → `cap_add: [CHOWN, DAC_OVERRIDE, SETGID, SETUID]`, caddy →
  `cap_add: [NET_BIND_SERVICE]`), the second service was rendered
  `(see fix above)` — pointing at the *first* service's wrong-image recommendation.
  The dedup now keys on `(rule_id, fix, references)`, so distinct hints each print
  in full while identical fixes still collapse.

### Changed

- **Profile enrichment is now labeled experimental.** The feature is already
  opt-in and off by default (`profiles.enabled`); this makes its provisional
  status explicit. When enrichment is active, compose-lint prints a one-line
  stderr reminder that fix recommendations are advisory, derived for a specific
  invocation, and not validated against your runtime — and the config docs mark
  the section experimental. No behavior change to the findings themselves.
- **Clearer profile-enrichment caveat.** The provenance tail `not independently
  verified here` is replaced with `compose-lint can't see your runtime, confirm
  it fits your setup` — it names the actual limit (a static linter reads the
  compose text, not the running container, and can't confirm the recommendation
  matches your invocation) rather than a vague disclaimer.

### Added

- Profile schema **1.2** (ADR-017 §9): an optional `derivation.run_config` block
  recording the invocation a minimum was derived under — `user`, `command`,
  `entrypoint`, `network`, `pid`, `devices`, `security_opt`, `mounts`, and `env`
  (keys only, never values). A derived minimum is only valid for its invocation
  (postgres run with `user:` set skips the root→user drop and needs none of the
  startup caps a default-invocation profile lists), so a consumer can diff a
  target service against it and downgrade to a hint on divergence. Emitted by
  csd's drop-test producer, not hand-authored. Additive — all 1.0/1.1 documents
  remain valid.
- Opt-in profile enrichment (ADR-017). Set `profiles.enabled: true` and point
  `profiles.path` at a catalog of container-sec-derive (csd) profiles you trust;
  findings from CL-0006/0007/0002/0011/0016 then gain image-specific fix guidance
  — e.g. the observed minimum `cap_add` for that image. Enrichment is advisory
  and additive only (it never creates, drops, or reclassifies a finding) and the
  hint is attributed and marked unverified. Off by default. Per ADR-017 §7,
  compose-lint ships **no catalog of its own** — the catalog is a user-configured
  external source, so the linter neither grows nor endorses profile data.
- Profile contribution path (ADR-017): `scripts/validate_profiles.py` (the
  ci-smoke gate — schema, validated/exploratory invariants, and workload-hash
  verification), a `profile-validate` CI job that runs it on catalog changes, and
  a contributor guide (`docs/profiles.md`).

## [0.12.2] - 2026-06-13

### Security

- CL-0021 no longer exhibits quadratic (ReDoS) behavior on crafted env values.
  A value shaped like `scheme://<many chars>:<many chars>` with no terminating
  `@` made the connection-string regex rescan the tail from every offset —
  O(n^2) on attacker-controlled input, a cheap DoS when sweeping untrusted
  Compose files. The rule now bails before scanning when the value contains no
  `@` (the pattern requires one, so this changes no findings).
- The text formatter now escapes terminal-unsafe code points — C0/C1 controls
  (ANSI/escape-sequence injection), DEL, and bidirectional/zero-width formatting
  characters — in every string derived from an untrusted Compose file (finding
  messages, fix text, service names, paths, and the on-disk source excerpt). A
  crafted image or service name could previously smuggle a U+202E override (to
  make a malicious tag render as a benign one) or, via the source excerpt that
  is read straight off disk and bypasses the parser's printable-character check,
  a raw ANSI escape into a terminal or CI log. They now render as visible
  `\uXXXX` escapes. JSON and SARIF output were already safe (`ensure_ascii`).
- The corpus fetcher (`scripts/corpus/`, development tooling) now pins the
  download host and refuses redirects. It rewrites `github.com` blob URLs to
  `raw.githubusercontent.com`, but a candidate whose prefix didn't match was
  left intact and fetched verbatim, and `urlopen` follows redirects by default —
  so a malformed or hostile candidate URL could have turned a download into a
  request against an internal or attacker-chosen host (SSRF). The fetcher now
  rejects any non-`https://raw.githubusercontent.com/` URL before opening it and
  uses an opener that does not follow redirects. Candidate URLs come from the
  GitHub API, so this is defense-in-depth.

### Added

- ADR-016 records the runtime rule-premise validation bar — the second,
  `docker run`-based arm of rule grounding that `scripts/validate_rule_premises.py`
  and the `rule-premises` CI job already enforce. It captures *why* the policy
  exists (the CL-0022 rework and CL-0023 removal), which previously lived only in
  the CHANGELOG and the script's docstring, and extends ADR-002.
- A registry-wide consistency test (`tests/test_rule_consistency.py`) that fails
  if any rule's emitted `Finding.rule_id`/`severity` drift from its
  `metadata.id`/`severity`. Each rule states these twice and nothing else tied
  them together, so a typo could desynchronise the SARIF rule descriptor's
  `security-severity` from a result's `level`. Deliberate per-finding escalation
  (CL-0011, CL-0013) is declared in an allow-list; adding it elsewhere is a test
  failure by design.

## [0.12.1] - 2026-05-25

### Changed

- CL-0022 is reworked. As shipped in 0.12.0 it flagged tmpfs entries *missing*
  `noexec`/`nosuid`/`nodev` — but Docker mounts every tmpfs with all three by
  default (verified across the short, list, and long forms, and with `size=`
  set), so the old rule fired on already-secure configs and missed the real
  weakening. It now flags the *presence* of `exec`, `suid`, or `dev`, which
  explicitly remove those defaults, at LOW (was MEDIUM). A plain `tmpfs: [/tmp]`
  is no longer flagged; `tmpfs: [/tmp:exec]` is. The auto-fix is dropped — the
  option is set deliberately, so reverting is left to manual review.

- CL-0012's message no longer asserts a container can "create unlimited
  processes" and fork-bomb the host. A container's `pids.max` is bounded by the
  cgroup hierarchy (often a high parent cap, occasionally unbounded), so the
  finding now says the limit is left to whatever that hierarchy allows. The rule
  is unchanged — it still flags an explicit `pids_limit` of 0 or negative.

### Removed

- CL-0023 (dangerous network sysctls), shipped in 0.12.0, is removed. Verified
  against real Docker, its premise did not hold: `net.ipv4.ip_forward` and
  `net.ipv4.conf.all.send_redirects` are already `1` by default in every
  container (so flagging them flagged the platform default), and Docker rejects
  `net.*` sysctls under host networking — so the rule's "acute under host
  networking" case is a configuration Docker refuses to start. Hit rate was 0%
  across the corpus. Pre-1.0, the `CL-0023` id is freed and may be reassigned to
  a future rule. The remaining net.* deviations (`accept_source_route`,
  `accept_redirects`, IPv6 forwarding) are too niche and weakly grounded to
  carry a rule on their own.

## [0.12.0] - 2026-05-25

### Added

- The `init` subcommand generates a starter `.compose-lint.yml` from a Compose
  file's findings (ADR-011). Each finding becomes a per-service
  `exclude_services` entry with a placeholder reason for triage — never a global
  `enabled: false`, so a service added later still trips the rule. All
  severities are emitted and annotated; it writes `.compose-lint.yml` in the
  current directory by default (`-o PATH` to override), refuses to overwrite an
  existing config without `--force`, writes nothing for a clean file, and sends
  status to stderr. Takes a single `FILE`. Bare `compose-lint <file>` and
  `compose-lint check` are unaffected.

- CL-0022 flags `tmpfs:` mounts that omit `noexec`, `nosuid`, or `nodev`
  (MEDIUM). A writable, executable in-memory mount is a payload-staging surface,
  especially under `read_only: true` where tmpfs is often the only writable
  path. Covers the short string/list `tmpfs:` form (the long `volumes:` form
  can't express these flags through Compose); the message names the missing
  flags. `compose-lint fix` appends them in place, preserving existing options
  like `size=`, with a caveat that `noexec` is behavior-changing.

- CL-0023 flags services that enable an escape-adjacent `net.*` sysctl —
  `ip_forward`, IPv6 `forwarding`, `accept_source_route`, and ICMP
  `accept_redirects`/`send_redirects` (MEDIUM). Enabling these turns the
  container into a network pivot, most acutely with host networking (CL-0008)
  or multiple networks. Handles the map and list `sysctls:` forms; a value of
  `0` and unlisted sysctls are not flagged. No auto-fix — the parameter is set
  deliberately when present, so removal is left to manual review.

### Changed

- CL-0011 now flags the `PERFMON` capability (HIGH), completing the pair split
  out of `SYS_ADMIN` in Linux 5.8 (`BPF` shipped in 0.10.0). A service with
  `cap_add: [PERFMON]` that previously passed will now report a finding.

## [0.11.0] - 2026-05-25

### Added

- The `fix` subcommand is promoted out of experimental and onto the documented,
  SemVer-covered surface (ADR-014, Phase 3). It now lists in `compose-lint
  --help` and has a README section. Behavior is unchanged: dry-run by default
  (prints a unified diff, writes nothing), `--apply` writes fixes in place via
  an atomic swap, `--only CL-XXXX` scopes to named rules, suppressed findings
  are never touched, and every apply is guarded by a re-parse plus a
  verify-apply pass that refuses to write anything that wouldn't re-lint clean.
  Promotion follows a full-corpus soak over ~6.4k real Compose files with zero
  re-parse failures, zero non-idempotent fixes, and zero new findings
  introduced.

### Changed

- Structured SARIF `fixes[]` (machine-applicable `artifactChanges`, which GitHub
  Code Scanning renders as suggested changes) now ship unconditionally in
  `check --format sarif`. They were previously gated behind
  `COMPOSE_LINT_EXPERIMENTAL=1`; that environment variable is now a no-op.
- `fix` no longer prints a per-invocation "experimental" warning to stderr — it
  is part of the stability contract from this release.

## [0.10.0] - 2026-05-25

### Added

- SARIF results now carry a stable `partialFingerprints` value
  (`composeLintFinding/v1`). GitHub Code Scanning uses it to deduplicate
  uploads and track an alert across commits; without it, direct SARIF uploads
  produced duplicate alerts and lost continuity when code moved. The digest is
  derived from the finding's logical identity (file, rule, service, message) and
  deliberately excludes the line number, so an alert survives unrelated line
  shifts. Additive to the SARIF contract (ADR-015). (#278)

### Security

- ClusterFuzzLite hygiene (issue #279). The `cflite-pr` and `cflite-batch`
  workflow checkouts now set `persist-credentials: false` like every other
  workflow, so the `GITHUB_TOKEN` is not left in `.git/config` while PR-author
  code runs during fuzzing. The fuzz image's `COPY .` no longer ingests
  `CLAUDE.md` / `AGENTS.md` — they are added to `.dockerignore`. (#279)

### Fixed

- Parser line-map robustness (issue #279 E2/E3). A service (or any key) named
  `__lines__` is no longer silently dropped: the loader's line map now hangs off
  a private non-string sentinel key instead of the literal string `"__lines__"`,
  so it can't collide with user data — a security linter must not skip a service.
  And a service that both defines a YAML anchor and is aliased elsewhere now
  resolves its own line: previously the alias and the anchor-definer shared one
  dict, and only whichever the traversal reached first got its keys recorded, so
  the other (often the definer — the most obvious location) reported `line=None`.
  Line numbers are now recorded per reachable path while the subtree is still
  walked once, so the chained-alias DoS guard (issue #154) is preserved. (#279)

- Documentation and grounding drift corrected (issue #279 D1–D6). OWASP
  renumbered the Docker Security Cheat Sheet and switched its anchors to a
  single-dash slug, so every citation was either pointing at the wrong rule or
  landing at page top. All OWASP deep links (rule docs, the README table, and
  the embedded `references=` URLs in code) now use the live single-dash anchors,
  and four drifted citations are corrected: CL-0002 and CL-0011 → Rule #3 (Limit
  capabilities, where `--privileged` is discussed), CL-0003 → Rule #4 (Prevent
  in-container privilege escalation), CL-0018 → Rule #2 (Set a user), CL-0020 and
  CL-0021 → Rule #12 (Utilize Docker Secrets). CL-0002's finding message no
  longer overclaims "functionally equivalent to host root" — it now matches the
  doc's "trivially escapable to host root." The CL-0018 doc now reflects that
  the rule fires on any root *user portion* regardless of group (`root:1000`),
  and the CL-0015 doc now documents the `test: ["NONE"]` branch the code already
  implements. (#279)

- Rule coverage gaps closed (issue #279 R3/R4/R5). CL-0001 now flags any
  container-runtime control socket — `containerd.sock`, `crio.sock`, and
  `podman.sock` in addition to `docker.sock` (podman/crio were caught by no
  rule before); the rule is retitled "Container runtime socket mounted" and its
  message names the runtime. CL-0020 adds `PASSPHRASE` and `ENCRYPTION_KEY` to
  the credential-key list (a generic `_KEY` suffix is deliberately not matched
  — it false-positives on `LICENSE_KEY` etc.). CL-0011 adds the `SYS_BOOT`,
  `DAC_OVERRIDE`, and `BPF` capabilities; CL-0016 adds the `/dev/fuse` and
  `/dev/kmsg` devices. (#279)

- SARIF rule descriptors are now correct in three ways. `helpUri` is set only
  to a reference that is actually a URI — rules grounded in a CIS benchmark
  (CL-0012, CL-0015, CL-0016, CL-0017) emitted the benchmark *prose* as
  `helpUri`, which SARIF 2.1.0 declares `"format": "uri"` and strict validators
  / GitHub Code Scanning reject; the prose still appears in `help.text`. A
  config `severity:` override now reaches `defaultConfiguration.level` and
  `properties.security-severity` on the rule descriptor, not just the per-result
  `level` — GitHub derives an alert's severity column from the rule, so an
  override to e.g. `critical` no longer showed Medium while JSON and SARIF
  disagreed. And a finding's structured `fixes[]` are matched to the finding by
  logical identity (rule, line, service, message) rather than `id()`, so a
  future refactor that copies findings can't silently drop every fix. (#279)

- A rule that raises no longer aborts the entire run. Previously an uncaught
  exception from any rule escaped as a traceback and exited 1 —
  indistinguishable from a normal "findings at/above threshold" result, and in a
  directory sweep every remaining file was lost. The engine now isolates each
  rule per service: a failure is reported to stderr and the run continues, and
  the CLI maps it to exit 2 ("compose-lint itself couldn't run", ADR-006) so a
  crash is never mistaken for a clean lint failure. (#279)

- CL-0005 now flags a bare short-syntax port with no colon (`"3000"`, `3001`, a
  `"3000-3005"` range). Docker still publishes it — `docker compose up` assigns a
  random (ephemeral) host port bound to all interfaces (`0.0.0.0` and `[::]`) —
  so it is the same exposure class the rule targets, and it is the most common
  port form in real homelab files. The finding notes the host port is ephemeral
  and the guidance binds it to localhost with `127.0.0.1::<port>`. The in-scalar
  autofixer refuses this form (it can't synthesize the empty-host-port syntax).
  (#279)

- CL-0021 now flags a password-only userinfo (`scheme://:password@host`). The
  regex required a non-empty username, but RFC 3986 §3.2.1 permits an empty one
  and `redis://:password@host` is the standard Redis URL form. The
  password-is-a-`$VAR` skip is unchanged. (#279)

- `.compose-lint.yml` no longer silently ignores misconfiguration that would
  leave a security control at its default. An unknown rule id (a typo'd
  `CL-001` or a retired `CL-9999`), an unrecognized top-level key (a misplaced
  `fail_on:`), or an unknown per-rule key (`severty:`) now prints a stderr
  warning instead of being dropped — mirroring the existing unknown-service
  warning. And `enabled` must be a real boolean: a quoted `'false'` or a `0` is
  now a hard error (exit 2) rather than a silent no-op that left the rule
  running while the user believed it off. (YAML's bare `false`/`no`/`off` still
  parse to a real boolean and work.) (#279)

- Text output: the `SUPPRESSED` marker no longer pushes a suppressed finding's
  rule and message columns out of alignment — the severity column is padded to
  fit the marker so every row lines up. CL-0020 and CL-0021 (credential-shaped
  env keys and inline connection-string credentials) now render the source
  excerpt and underline like the other value-naming rules; they had been left
  out of the presence-rule set. `FORCE_COLOR=0`/`false` (case-insensitive) now
  disables color and any other set value — including the empty string — enables
  it, matching the chalk/supports-color convention (previously `FORCE_COLOR=false`
  turned color *on*). The excerpt underline now matches the value at a token
  boundary and measures display width (East-Asian wide and combining characters),
  so it no longer mis-points on a value that is a substring of a longer token or
  contains CJK/accented characters. (#278)

- SARIF no longer emits a misleading `ruleIndex` for an unregistered rule.
  `ruleIndex` defaulted to `0`, so a result whose rule was absent from the
  registry pointed at the first rule (CL-0001) while `ruleId` named the real one
  — a SARIF §3.52.5 contradiction. It is now emitted only when the rule is in
  the registry. A result with an unknown or non-positive line likewise omits its
  `region` instead of fabricating `startLine: 1`, which had mislocated the alert
  at the top of the file. (#278)
- SARIF `$schema` now points at the canonical, immutable OASIS errata01 URL
  (`docs.oasis-open.org/.../sarif-schema-2.1.0.json`) instead of a
  `raw.githubusercontent.com` `main`-branch link — the schema's own `$id`, and
  no longer a mutable ref. (#278)

- SARIF `artifactLocation.uri` is now a conformant, GitHub-resolvable URI
  reference. Paths were emitted verbatim, so an absolute path would not resolve
  on GitHub Code Scanning and a space or non-ASCII byte
  (`/tmp/my dir/café.yml`) was not a legal RFC-3986 URI reference at all. Files
  under the working directory are now emitted as percent-encoded repo-relative
  paths tagged with a `SRCROOT` `uriBaseId`, declared once per run in
  `originalUriBaseIds` alongside `invocations[].workingDirectory`; out-of-tree
  paths fall back to an absolute, percent-encoded `file:` URI. (#278)

- JSON output now emits `service` as a string and never emits bare `NaN`/
  `Infinity`. A service name is a YAML mapping key, so a key like `true`, a bare
  number, or `.nan` resolved to a non-string scalar: `.nan` produced invalid
  JSON (`"service": NaN`, which RFC 8259 forbids) while `true`/`123` produced a
  wrongly-typed `service` field (ADR-015 contracts it as a string). The formatter
  now coerces `service` to `str`, and both the JSON and SARIF dumps use
  `allow_nan=False` so a stray non-finite float raises instead of writing invalid
  JSON. (#278)

- Duplicate mapping keys are now rejected with a parse error, matching Docker
  (which refuses them). Previously PyYAML silently let the last value win, so a
  service with `privileged: true` followed by `privileged: false` — a file
  Docker will not load — reported clean, and the line map pointed at the wrong
  occurrence. Detection runs before merge-key (`<<`) flattening, so an
  `extends`/anchor merge that overrides an inherited key is not misreported as a
  duplicate. (#277)

- CL-0011 now flags `CAP_`-prefixed capabilities (`CAP_SYS_ADMIN`, `CAP_ALL`,
  ...). Docker treats the `CAP_` prefix as optional, but the rule keyed on the
  bare name and missed the prefixed form entirely. (#277)
- CL-0017 now flags `rshared` mount propagation in both short and long syntax,
  not just `shared`. `rshared` is the recursive — and more common — form that
  still propagates container mounts to the host. (#277)
- CL-0005 now evaluates the bind-address slot when the host port is a `${VAR}`
  substitution (`${HOSTPORT}:80`). Previously a var-valued host port failed the
  port pattern and the whole entry was skipped, hiding a wildcard publish. (#277)
- CL-0021 now flags an inline connection-string credential when the username is
  a `${VAR}` but the password is a literal (`postgres://${DB_USER}:secret@db`).
  Only a var-valued *password* means the secret is parameterized. (#277)
- CL-0020 now flags an unquoted numeric credential value (`DB_PASSWORD:
  12345678`). The value decodes to an int and was skipped; it is coerced to its
  string form before the checks, while YAML boolean toggles stay exempt. (#277)

- `security_opt` directives are now matched with their `=` separator treated as
  equivalent to `:`, the way Docker accepts them. CL-0009 was missing an
  `=`-form profile disable (`seccomp=unconfined`, `label=disable`) and CL-0003
  was firing on a service already hardened with `no-new-privileges=true`. A
  shared `normalize_security_opt` helper canonicalizes the separator (and case)
  before every membership/prefix check across the rules and the fix engine.
  (#277)
- CL-0005 no longer misses short-syntax ports whose host and container sides are
  both `<= 59` (`22:22`, `25:25`, `53:53`, ...). PyYAML's YAML 1.1 resolvers
  parsed these as a single base-60 integer (`22:22` → `1342`), so the rule's
  `str(port)` saw no colon and reported the file clean. `LineLoader` now drops
  the sexagesimal `int`/`float` resolver alternatives and the `timestamp`
  resolver (a bare date like `2024-01-01` was becoming a non-JSON-serializable
  `datetime.date`), while keeping YAML 1.1 booleans — Docker coerces
  `yes`/`no`/`on`/`off` to booleans for boolean-typed fields, so keeping them
  preserves CL-0002/CL-0007 parity with `docker compose config`. (#277)
- Compose override-file tags `!reset` and `!override` no longer make a valid
  file fail to parse (exit 2). `LineLoader` (a `SafeLoader` subclass) had no
  constructor for them, so it raised a `ConstructorError`; it now constructs the
  underlying value and ignores the merge directive, which is all the linter
  needs. (#277)
- A non-UTF-8 (e.g. latin-1) file now raises a per-file `ComposeError` instead
  of an uncaught `UnicodeDecodeError`. Previously one bad-encoding file aborted
  an entire directory sweep. (#277)
- The `fix` engine no longer adds `no-new-privileges:true` to either side of an
  `extends` relationship. Docker concatenates list fields like `security_opt`
  across an `extends` merge, so adding the entry to a service that `extends:`
  another — or to a base another service extends — could produce a duplicated
  item that `docker compose config` rejects. The duplicate only exists after
  Docker's merge (our parser does not resolve `extends`), so the post-apply
  reparse guard could not catch it. Both the per-finding CL-0003 fixer and the
  CL-0003/CL-0009 coordination pass now refuse both sides and leave the chain
  for manual review. (#276, #277)

## [0.9.0] - 2026-05-24

### Added

- **Experimental `fix` subcommand** (ADR-014) that auto-remediates the
  mechanically-safe findings — CL-0003, CL-0005, CL-0007, CL-0009,
  CL-0014, and CL-0015. Dry-run by default (prints a unified diff and
  flags behavior-changing edits); `--apply` writes fixes in place;
  `--only` restricts to named rules; `.compose-lint.yml` suppressions are
  honored; and SARIF output can carry the edits as `fixes[]`. It is
  reachable without `COMPOSE_LINT_EXPERIMENTAL` but stays hidden from
  `--help`, prints an experimental warning on every run, and is excluded
  from the SemVer contract until promoted.
  (#246, #247, #250, #251, #253, #255, #260, #263, #264, #265, #266,
  #267, #268, #269, #270)
- `check` as an explicit subcommand, with the CLI routed through argparse
  subcommands; bare `compose-lint <file>` still works as an implicit
  `check`, and `--explain CL-XXXX` prints a rule's documentation
  (ADR-011). (#248)
- `skip-suppressed`, `quiet`, and `verbose` inputs on the GitHub Action,
  mirroring the CLI flags. (#258)
- A published compatibility and stability policy
  (`docs/compatibility.md`) documenting what SemVer does and does not
  cover, including the JSON `version` field. (#254)

### Changed

- **Breaking (JSON consumers):** `--format json` is now a versioned
  envelope — an object with `version`, `tool`, `findings`, and `errors`
  — instead of a bare findings array. Read findings from `.findings`, and
  `.version` for the schema (ADR-015). (#252)
- `--explain` is rejected when combined with `--format json` or
  `--format sarif`, which produced meaningless output. (#257)
- CIS Docker Benchmark rule citations re-grounded to v1.7.0 and
  corrected — e.g. CL-0015 now cites 5.26 (was 5.27) and CL-0019 drops a
  miscited 5.27. (#249, #256)

## [0.8.0] - 2026-05-23

### Added

- Full *State of Docker Compose Security* report content in
  `docs/state-of-compose.md` — an empirical study of security
  misconfigurations across a 6,444-file corpus of public Compose files,
  with per-tier SVG charts in `docs/assets/` generated by
  `scripts/corpus/charts.py` (new maintainer-only `[corpus]` extra). The
  README hero stat now cites the corpus headline and links to the report.
- A recorded terminal demo (GIF) in the README hero, regenerated
  deterministically from `scripts/demo/`. (#235)
- `-q` / `--quiet` text mode: one line per finding, dropping the fix
  block, reference URL, source excerpt, and suppression reason. The
  inverse of `-v`, and mutually exclusive with it. (#239)
- `NO_COLOR` and `FORCE_COLOR` are honored: `NO_COLOR` disables color
  even on a terminal, `FORCE_COLOR` forces it through a pipe (e.g. into a
  pager or an ANSI-rendering CI log). (#239)
- `--help` now lists the valid `--fail-on` values
  (`{low,medium,high,critical}`) instead of a bare `FAIL_ON`. (#239)

### Changed

- Text output readability (no change to JSON or SARIF): findings now
  render highest-severity first within each service; a column header
  labels the `line / severity / rule / message` columns; the offending
  value is marked with a severity-colored box-drawing underline instead
  of a red caret; parse failures (exit 2) show a distinct `⚠ ERROR`
  verdict rather than the `✗ FAIL` used for threshold breaches (exit 1);
  and a passing run names its sub-threshold findings
  (`✓ PASS · threshold: critical · below: 1 high, 15 medium`). (#239)

### Fixed

- Text-mode stdout is flushed so the header and findings can no longer
  appear after stderr when both streams are captured together (`2>&1`),
  which scrambled combined CI logs. (#239)
- The aggregate summary pluralizes correctly: `1 file scanned`, not
  `1 files scanned`. (#239)

## [0.7.1] - 2026-05-21

### Added

- `GOVERNANCE.md`, `MAINTAINERS.md`, `docs/ASSURANCE.md`,
  `docs/SECURITY-EXPECTATIONS.md`, and `docs/CONTINUITY.md` documenting
  the project's governance model, single-page assurance case (threat
  model, trust boundaries, mitigations), user-facing security promises,
  and continuity-of-access plan. Closes the OpenSSF Silver
  `governance`, `roles_responsibilities`, `documentation_security`,
  `assurance_case`, and `access_continuity` criteria. (#202)
- Statement coverage gate at >=80% (new `coverage` CI job; thresholds
  configured in `pyproject.toml [tool.coverage.report]` and duplicated
  at the workflow level). Closes the OpenSSF Silver
  `test_statement_coverage80` criterion. (#202)
- `docs/state-of-compose.md` canonical landing page for the forthcoming
  State of Compose security report. README and corpus tooling already
  reference this path. (#210)

### Changed

- Corpus pipeline scripts (`fetch`, `retier`, `enrich`, `run`, and the
  per-tier fetchers) now live in-repo under `scripts/corpus/` so the
  State of Compose numbers are reproducible from a clean checkout. The
  corpus cache stays at `~/.cache/compose-lint-corpus/` and remains
  outside git — the repo never accumulates third-party Compose files.
  (#206)
- Corpus pipeline now classifies parse-error stderr into stable buckets
  (`missing-services-key`, `services-not-mapping`, `service-not-mapping`,
  `top-level-not-mapping`, `empty-file`, `invalid-yaml`, `other`) and
  emits a per-tier × class matrix alongside the existing rule tables.
  `scripts/corpus/README.md` documents the longtail sampling design and
  its four known biases (GH-search ranking, single-source, filename-
  pinned, public-only). (#209)

### Security

- Release tags must now cryptographically verify against
  `.github/allowed_signers` before any publish step runs. The new third
  check in `publish.yml`'s `verify-tag` job runs `git verify-tag` with
  the maintainer's authorized SSH signing key; an attacker who pushed
  a tag from a stolen GitHub credential can no longer trigger a
  release. Closes the OpenSSF Silver `version_tags_signed` criterion.
  (#202)
- Dropped `--ignore-vuln CVE-2026-3219` from CI `pip-audit`. pip 26.1.1
  fixes both CVE-2026-3219 and CVE-2026-6357; `pip-audit --skip-editable`
  against the regenerated `requirements-dev.lock` reports no known
  vulnerabilities. pip is dev-only here (transitive of `pip-audit`) and
  is stripped from the runtime container image; the OpenVEX statements
  for the published image are unaffected. (#208)
- Dockerfile build stage now upgrades the venv-seeded pip to the latest
  release before stripping pip's code from the runtime image. The
  retained `.dist-info` metadata now reports a patched version, so
  Docker Scout reports genuine remediation (not just `not_affected`)
  for CVE-2025-8869, CVE-2026-1703, and CVE-2026-6357. CVE-2026-3219
  has no upstream fix and stays VEX-covered. (#217)
- OpenVEX document (v4) adds a fourth `not_affected` statement covering
  CVE-2026-6357 with the same `vulnerable_code_not_present`
  justification used for the other pip CVEs, and drops the `@25.1.1`
  pin from every pip subcomponent PURL. The mitigation is
  version-independent — pip's executable code is removed at build time
  regardless of which pip the build seeds — so the statements continue
  matching after the bundled-pip upgrade in #217. (#216)
- urllib3 bumped to 2.7.0 in `requirements-dev.lock` for CVE-2026-44431
  and CVE-2026-44432. urllib3 is a transitive dev/publish dependency
  only (via `id`, `requests`, `tuf`, `twine`); the runtime package
  depends only on PyYAML, so published-package users are unaffected.
  (#214)
- idna bumped to 3.15 in `requirements-dev.lock` for CVE-2026-45409,
  and `pip-audit` now ignores the disputed `PYSEC-2025-183` advisory
  against pyjwt 2.12.1 (the pyjwt maintainers dispute it because JWT
  signing key length is chosen by the consuming application, not the
  library; no fix version exists). Both packages are dev/publish
  transitives; the runtime image is unaffected. (#224)

## [0.7.0] - 2026-05-01

### Added

- New rule **CL-0020** — credential-shaped env keys with literal values.
  Flags `environment:` entries whose key matches a credential convention
  (`PASSWORD`, `TOKEN`, `SECRET`, `API_KEY`, `ACCESS_KEY`, `PRIVATE_KEY`,
  `CREDENTIAL`, plus suffix-anchored `_PASS`, `_PWD`, `PASSWD`, `_SALT`,
  `_DSN`) and whose value is a non-empty literal string. Exempts the
  `*_FILE` secrets-mount convention, `ALLOW_EMPTY_*` / `RANDOM_*`
  boolean toggles, and bool/numeric values. Skips `${VAR}` substitutions.
  Severity HIGH. Fires on 17.9% of real-world Compose files in the
  corpus. See [docs/rules/CL-0020.md](docs/rules/CL-0020.md). (#190)
- New rule **CL-0021** — credentials embedded in connection-string env
  values. Flags `environment:` values containing a literal
  `scheme://user:password@host` userinfo regardless of the key name.
  Skips when either userinfo half is a `${VAR}` substitution. Catches
  inline credentials in `DATABASE_URL`, `MONGO_URL`,
  `AIRFLOW__DATABASE__SQL_ALCHEMY_CONN`, etc. — the largest detection
  class CL-0020's key-pattern matching misses. Severity HIGH. See
  [docs/rules/CL-0021.md](docs/rules/CL-0021.md). (#193)
- Mutation testing via `mutmut` configured in `pyproject.toml` against
  `src/compose_lint/rules/` and `src/compose_lint/_image.py`. Baseline
  documented in `docs/mutation-testing.md`. New `tests/test_rule_loader.py`
  exercises rule auto-discovery so loader-logic mutants are caught. (#172)
- Corpus regression snapshot at `tests/corpus_snapshot.json.gz` plus
  `scripts/snapshot.py` (`generate` / `diff` / `verify` subcommands) that
  digests compose-lint output across a real-world Compose corpus into a
  `(rule_id, service, line)` fingerprint per file. A CI-gated schema test
  prevents the digest from accidentally carrying third-party content; an
  opt-in pytest entry (`COMPOSE_LINT_CORPUS=<cache-root>`) verifies the
  snapshot against the latest local run. See `LICENSE-corpus.md` for the
  licensing posture and `CONTRIBUTING.md` for the regen workflow. (#173)
- Negative-coverage fixtures (`tests/compose_files/safe_*.yml`) asserting that
  hardened-but-unusual Compose patterns do not trigger false positives:
  `cap_drop: [ALL]` + targeted `cap_add` for CL-0006/CL-0011, the short-form
  `no-new-privileges` security option for CL-0003, `CMD-SHELL` healthchecks
  for CL-0015, and named-volume mounts for CL-0017. (#174)

### Changed

- `CL-0005 _is_wildcard_ip` no longer carries an unreachable defensive
  branch for `[0.0.0.0]` / `[*]` — Docker doesn't accept those forms and
  no test exercised them. `[::]` continues to match via the wildcard set.
  (#172)
- Release docker-smoke jobs (`publish.yml`, `publish-channel.yml`) now
  exercise the image with the full hardening flag set documented in the
  README (`--read-only`, `--cap-drop ALL`, `--security-opt
  no-new-privileges:true`, `--network none`, `--user 65532:65532`,
  `--pids-limit 256`, plus `:ro` on bind mounts). A copy-paste regression
  in the documented recipe will now fail the release gate. (#196)
- README "Running with full hardening" snippet now uses
  `composelint/compose-lint:0.6.0` instead of the
  `composelint/compose-lint@sha256:<digest>` placeholder, so the recipe
  is copy-paste runnable. A new note points users at Docker Hub or
  `docker buildx imagetools inspect` if they want to substitute a digest
  pin for full CL-0004 / CL-0019 satisfaction. The new tag form is
  tracked as a fourth version sync point in `docs/RELEASING.md`.

## [0.6.0] - 2026-04-26

### Added

- `-v` / `--verbose` flag for the text formatter. Default text output now
  prints the fix block and reference URL only on the first occurrence of
  each rule id within a file; subsequent occurrences carry
  `(see fix above)` instead. `-v` restores today's per-finding fix
  repetition for IDE tooling or local fix-it-now workflows. JSON and
  SARIF output are unaffected. (#156)

### Changed

- Text formatter groups findings by service under a per-file header.
  Presence rules (e.g. CL-0001, CL-0002, CL-0005, CL-0019) render a
  one-line source excerpt under the finding so the offending value is
  visible inline. Pure-absence rules (CL-0003/4/6/7) skip the excerpt —
  the violation is the absence — and rely on the fix block to show the
  remediation. (#156)
- `docs/severity.md` now distinguishes "absence" rules (fire when a
  hardening directive is missing — high real-world hit rate) from
  "explicit-disable" rules (fire only when a service opts into a
  dangerous configuration — deliberately low hit rate by design). A
  zero-hit run on an explicit-disable rule is expected, not a bug. (#159)
- Multi-file invocations no longer fail-fast on the first parse error.
  The CLI now records the failure, continues scanning the remaining
  files, and exits 2 only after every input has been attempted. Per-file
  error messages include the filepath; the text-mode aggregate footer
  and verdict report how many files were skipped; SARIF output surfaces
  parse failures via `runs[].invocations[].toolExecutionNotifications`
  and sets `executionSuccessful: false`. A single-file invocation that
  fails to parse still exits 2 with the same `Error:` line. (#158)
- Compose v1 files (services declared at the top level) and structural
  fragments (files with only `volumes:` / `networks:` / `configs:` /
  `secrets:` / `x-*` keys) are now skipped with exit 0 and a per-file
  stderr note rather than hard-failing the whole invocation. The v1
  format was retired by Docker in 2023; fragments are typically merged
  with `-f overlay.yml` and not meaningful to lint in isolation.
  Genuinely unrecognised shapes still exit 2. Combined with the
  multi-file change above, `compose-lint **/*.yml` over a monorepo no
  longer dies on the first v1 file or overlay it encounters. See
  [ADR-013](docs/adr/013-missing-services-key.md). (#163)
- SARIF `result.fixes[]` removed in favor of `result.properties.fix`.
  SARIF 2.1.0 § 3.55 requires `artifactChanges` on every fix object,
  and compose-lint's `Finding.fix` is human-readable prose, not a
  machine-applicable patch — emitting `fixes[]` without `artifactChanges`
  produced documents that strict validators (`check-jsonschema`
  against the canonical OASIS schema) rejected. Lenient consumers
  reading `result.fixes[0].description.text` should switch to
  `result.properties.fix`. GitHub Code Scanning, Sonar, and other
  major consumers tolerated the missing field but the document was
  schema-invalid. (#168, fixes #166)

### Fixed

- Findings on YAML sequence items (e.g. one entry in `ports:`,
  `volumes:`, `cap_add:`, `devices:`, `security_opt:`) now report the
  line of the offending item, not the line of the parent mapping key.
  Previously every finding on a sequence item attributed to the parent
  key — three unbound ports all showed the `ports:` line, sensitive
  mounts pointed at `volumes:` instead of the mount itself. The parser
  now records per-item line numbers in `LineLoader` (sidecar keyed on
  `id(list)` on the loader instance, kept off the list itself to avoid
  changing list semantics), and `_collect_lines` emits `...[N]`
  entries. CL-0009, CL-0011, CL-0013, CL-0016, and CL-0017 were
  updated to consult the per-item entry with parent-key fallback;
  CL-0001 and CL-0005 already used this pattern and now resolve
  correctly. Fixes #157.
- `_collect_lines` no longer fans out `O(branching^depth)` across YAML
  alias graphs. Chained anchors (`b: {p: *a, q: *a, ...}; c: {p: *b,
  ...}; ...`) previously revisited the same container along every alias
  path; ClusterFuzzLite hit this with a sub-4KB input that grew RSS
  past 3 GB and OOMed the linter. Mirrors the `id()`-keyed visited-set
  pattern already in `_strip_lines`. The same input now completes in
  &lt;1 ms / 13 MB. (#161, fixes #154)

## [0.5.2] - 2026-04-25

### Fixed

- **CL-0009** now detects SELinux disabled via `security_opt:
  [label:disable]`. The rule's description and references promised
  SELinux coverage but the implementation only checked seccomp and
  AppArmor — `label:disable` turns off SELinux type enforcement for
  the container and was silently ignored. Description updated to
  reflect actual coverage; messages now read "SELinux" rather than
  "label profile". `label:user:...`, `label:type:...`, `label:role:...`
  and `label:level:...` overrides remain unflagged since they
  reconfigure rather than disable confinement.
- **CL-0004** and **CL-0019** now parse OCI image references via a
  shared `split_image_ref` helper that recognizes `registry:port/name`
  prefixes. The previous naive `image.rsplit(":", 1)` mistook the
  registry port for a tag separator, causing two related bugs:
  (a) `localhost:5000/foo` was treated as tag-pinned by CL-0004, so
  the "no tag, defaults to :latest" finding never fired; and
  (b) CL-0019 fired on the same input with a misleading message
  ("pinned to a tag but not a digest") for an image that had no tag at
  all. Verified for `localhost:5000/foo`, `localhost:5000/foo:latest`,
  `localhost:5000/foo:v1`, and digest variants of each.
- **CL-0005** now detects IPv6 wildcard binds in short syntax
  (`"[::]:8080:80"`) — the previous regex's IP capture group rejected
  any colon-containing prefix, causing the rule to silently skip the
  port. Bracketed IPv6 prefixes are now stripped before the main pattern
  runs.
- **CL-0005** now detects explicit wildcard `host_ip` values in long
  syntax (`host_ip: "0.0.0.0"`, `host_ip: "::"`). The previous
  implementation treated *any* non-empty `host_ip` as a real bind, so
  operators who explicitly wildcarded their long-syntax bind got no
  warning. Loopback (`127.0.0.1`, `::1`) and specific addresses still
  suppress the finding.
- **CL-0005** also detects IPv4 wildcard short syntax (`"0.0.0.0:8080:80"`)
  — incidental fix; the previous `_is_ip_address` helper accepted
  `0.0.0.0` as a "real" IP and suppressed the finding.
- **CL-0013** now detects mounting the entire host root filesystem
  (`"/:/host"`, `"/:/host:ro"`) at CRITICAL severity — previously the
  short-syntax regex required at least one non-colon character after `/`
  and silently skipped the most dangerous bind possible.
- **CL-0013** now detects long-syntax binds where `source:` is an absolute
  path even when `type: bind` is omitted. Compose infers bind mounts from
  absolute-path sources, but the rule previously gated on `type` and missed
  this realistic configuration.
- **CL-0013** sensitive-paths list extended with `/var/lib/docker`,
  `/var/run`, and `/home`. The existing `/root` entry already covered
  `/root/.ssh` and `/root/.aws` via subpath matching.
- **CL-0011** now flags `cap_add: [ALL]` (and lowercase `[all]`) at
  CRITICAL severity. Granting all Linux capabilities is functionally
  equivalent to `--privileged` for capability isolation, but the rule
  previously only knew the seven named caps and silently ignored the
  catch-all. Named caps (`SYS_ADMIN`, `NET_ADMIN`, etc.) continue to
  fire at HIGH; the rule now emits per-finding severity so `--fail-on`
  thresholds against the named caps are unchanged.
- **CL-0015** now flags `test: ["NONE"]` and the string form
  `test: NONE`, the idiomatic way to disable a healthcheck inherited
  from a base image. Lowercase `["none"]` deliberately does not fire
  — Docker's runtime treats only uppercase `NONE` as the disable
  sentinel; lowercase is executed as a command and is a different
  problem (a broken healthcheck, not a disabled one). Severity stays
  at LOW.
- **CL-0018** now detects the cross-spec root forms `root:0`, `0:root`,
  `root:1000`, and `0:1000` by parsing `user:` rather than matching a
  fixed allowlist. The previous `{"root", "0", "root:root", "0:0"}`
  set silently passed any value where a non-root group was paired with
  a root user, even though the container still runs as UID 0. The
  inverse (`user: "1000:0"` — non-root UID with root group) correctly
  does not fire.
- OpenVEX product identifier in `.vex/compose-lint.openvex.json` now uses
  `repository_url=index.docker.io/composelint/compose-lint`. The previous
  `docker.io/...` form loaded successfully but matched zero scanned
  images: Trivy, Grype (per anchore/grype#2818), and Scout all canonicalise
  Docker Hub to `index.docker.io` for VEX product matching. Confirmed
  locally with Trivy 0.70.0 against the published image.
- Every VEX statement now ships two `products[]` entries —
  `pkg:oci/compose-lint?repository_url=index.docker.io/composelint/compose-lint`
  for Trivy and Grype, plus a bare `pkg:docker/composelint/compose-lint`
  for Docker Scout, whose own "Create exceptions" docs example uses the
  `pkg:docker/` form. Trivy honoured the single-PURL form from PR #143
  but Scout did not — verified empirically on commit `5abd036`'s
  `scout-scan.yml` dispatch where `Loaded 1 VEX document` was followed
  by all three pip CVEs still flagged. OpenVEX explicitly invites
  multi-identifier products for exactly this scanner-disagreement case.
- Every `docker/scout-action` step that passes `vex-location` now passes
  `vex-author: .*`. Scout's default `--vex-author` allowlist is
  `<.*@docker.com>` and silently drops statements signed outside that
  pattern. PR #143's first override (`<.*@gmail\.com>`) was also
  silently dropped — Scout appears to use full-string regex match on
  the author field rather than substring, so the bracket-anchored shape
  did not match the full author string `Todd Matens <tmatens@gmail.com>`.
  `.*` accepts any author and is safe because the document is also
  cosign-attested to the image manifest. Applied to both `scout-scan.yml`
  steps and the `docker-smoke` Scout step in `publish.yml`.

### Added

- VEX statement covering CVE-2026-3219 (pip 25.1.1 — incorrect file
  installation due to improper archive handling). Same
  `vulnerable_code_not_present` mitigation as the existing pip CVEs:
  pip's runtime code is removed from the container image during build,
  only `.dist-info` metadata remains for SCA scanner identification.

### Changed

- VEX document `version` bumped to 3 and `timestamp` refreshed. See
  ADR-012 (`docs/adr/012-vex-product-identifier.md`) for the full
  rationale on the product-identifier and author-allowlist decisions,
  including the empirical evidence from PR #143's first attempt.

### Security

- CI `pip-audit` step ignores `CVE-2026-3219` (pip 26.0.1) until pip
  26.0.2+ ships on PyPI and the dev lockfile is regenerated. pip is a
  dev-only transitive of `pip-audit` here — it is not in
  `requirements.lock` and is stripped from the runtime container image
  (only `.dist-info` metadata is kept for SCA attribution). The same
  CVE is declared `not_affected` against the published image via the
  OpenVEX document on the same `vulnerable_code_not_present` grounds
  as the existing pip CVEs.

## [0.5.1] - 2026-04-24

### Changed

- Container image strips the `pip` package code and `pip` CLI binaries
  from the runtime venv but keeps pip's `.dist-info` metadata. 0.4.1
  stripped all of it to silence Docker Scout alerts on unreachable pip
  CVEs, but deleting the `.dist-info` also removed the signal SCA
  scanners use to identify pip — making the image appear vuln-free by
  metadata deletion rather than by code removal. Keeping the metadata
  while dropping the code gives honest reporting: scanners still see
  pip and flag CVE-2025-8869 / CVE-2026-1703, and the code that would
  host those CVEs is gone from the runtime layer. The CVEs also remain
  unreachable by execution path — distroless base, no shell, entrypoint
  is `/venv/bin/compose-lint`. The `activate*` shell-script stripping
  from 0.4.1 stays.

### Added

- OpenVEX document (`.vex/compose-lint.openvex.json`) published as a
  release asset alongside the SBOM, Sigstore bundles, and SLSA
  provenance, **and** attached to the container image manifest as a
  cosign in-toto attestation (predicate type `openvex`). Declares the
  known pip CVEs (CVE-2025-8869, CVE-2026-1703) as `not_affected`
  against the container image with justification
  `vulnerable_code_not_present`. Scanners invoked with `--vex` on the
  release asset, or attestation-aware scanners (Docker Scout; Trivy /
  Grype in attestation-discovery modes), render those CVEs as
  non-exploitable rather than either hiding pip or flagging reachable
  risk. New pip CVEs get added to the VEX when verified as covered by
  the same mitigation; CVEs in any actually-reachable code path do
  not.

## [0.5.0] - 2026-04-23

### Added

- `--explain CL-XXXX` prints the per-rule prose documentation
  (`docs/rules/CL-XXXX.md`) to stdout so reviewers can read the full
  rationale, references, and fix guidance without context-switching to
  the browser. Accepts any case, exits 2 on unknown or malformed rule
  ids, and refuses to run alongside FILE arguments. The rule-doc
  markdown ships inside the wheel under `compose_lint/rule_docs/`.

## [0.4.1] - 2026-04-23

### Security

- Container image no longer ships `pip` or its `dist-info`. `pip` was
  only used at build time against `--require-hashes` lockfiles and was
  unreachable at runtime (distroless, no shell, nonroot entrypoint),
  but its presence in the runtime layer surfaced ongoing Docker Scout
  alerts (CVE-2025-8869, CVE-2026-1703 against pip 25.1.1) and would
  have generated more on every future pip CVE. The runtime venv now
  contains only PyYAML, compose_lint, and the Python interpreter
  symlinks; image drops ~17 MB. (#116)

### Fixed

- `parser.load_compose` now wraps `RecursionError` as `ComposeError`.
  PyYAML's composer is recursive; deeply-nested flow input like
  `[[[[...]]]]` exhausted the interpreter stack from inside `yaml.load`
  and raised `RecursionError` — a `RuntimeError`, not a `YAMLError` —
  bypassing the existing wrapper and crashing the CLI with an unhandled
  exception instead of returning exit code 2. Surfaced by ClusterFuzzLite
  (#114). (#115)

### Added

- SLSA build provenance attestations on PyPI sdist + wheel and the
  Docker image, providing verifiable supply-chain proof that release
  artifacts were built from this repository's tagged source. (#107)

## [0.4.0] - 2026-04-19

### Added

- Per-service rule exclusions in `.compose-lint.yml`. A rule's
  `exclude_services` key accepts either a mapping (service name →
  reason) or a list of service names. Excluded services still produce
  findings marked suppressed, with the per-service reason flowing to
  `suppression_reason` (JSON), SARIF `justification`, and the text
  formatter's `SUPPRESSED` trailer. Global `enabled: false` takes
  precedence over per-service exclusions. Unknown service names in
  `exclude_services` warn on stderr rather than erroring. Closes #5.
  See [ADR-010](docs/adr/010-per-service-rule-overrides.md).

### Changed

- v0.4 roadmap repointed from Linux package distribution to
  configuration depth and a Homebrew tap. ADR-008 deferred: no
  demand signal, and GitHub-Releases-hosted `.deb`/`.rpm` have
  strictly worse upgrade UX than pip/Docker without hosted-repo
  infrastructure.

## [0.3.7] - 2026-04-18

### Changed

- CL-0003 fix guidance now warns that `no-new-privileges` breaks
  images whose entrypoint switches users via `gosu`/`su-exec` (e.g.
  official `postgres`, `redis`, `minecraft-server`). The finding's
  `fix` field gains a one-line caveat; full compatibility notes and
  a testing workflow live in `docs/rules/CL-0003.md`. Closes #2.
- CL-0007 fix guidance now describes the writable-path discovery
  workflow (`docker diff`) and the chown-on-startup pitfall seen on
  `netdata` and `valkey`. The finding's `fix` field gains a one-line
  caveat; details live in `docs/rules/CL-0007.md`. Closes #3.

No rule logic, severity, or finding-shape changes. A compose file
that passed on 0.3.6 passes identically on this revision; only the
`fix` field text and rule docs changed.

## [0.3.6] - 2026-04-18

### Fixed

- Dockerfile `FROM` lines now pin the multi-arch OCI image index
  (manifest list) digest instead of the per-arch amd64 manifest
  digest. The 0.3.5 per-arch pins resolved correctly during the
  single-arch `docker-smoke` but failed in `docker-publish`'s arm64
  leg because the pinned digest referenced an amd64-only manifest.

### Changed

- `docker-smoke` in `publish.yml` now runs as a native-runner matrix
  across `linux/amd64` (`ubuntu-latest`) and `linux/arm64`
  (`ubuntu-24.04-arm`). Each leg builds the image without QEMU
  emulation and runs the full fixture battery (version check, clean,
  insecure, SARIF). Multi-arch regressions — per-arch digest pins,
  native-wheel mismatches, future base-image surprises — now fail
  the release-gate instead of surfacing mid-release during the
  production Docker Hub push.
- New `ci.yml` job `dockerfile-digests` runs
  `scripts/verify-dockerfile-digests.sh` on every PR. The script
  HEADs each `FROM ...@sha256:` in the Dockerfile and fails if the
  `Content-Type` is not an OCI image index or Docker manifest list
  — catching the per-arch-pin mistake at review time rather than
  release time. No image pulls; ~1s total.

No CLI, config, or finding-shape changes. Exit codes (0/1/2) are
preserved. A Compose file that passed on 0.3.5 passes identically on
0.3.6.

## [0.3.5] - 2026-04-17

### Changed

- Runtime Docker image switched from `python:3.13-alpine` to
  `gcr.io/distroless/python3-debian13:nonroot`. The image no longer
  ships `/bin/sh`, `apk`, or busybox — only the Python interpreter,
  stdlib, libc, and the project venv. Attack surface in the event of
  a container escape is significantly reduced. See
  [ADR-009](docs/adr/009-runtime-base-image.md) for the rationale.
- `docker run` examples in the README now show `--read-only --cap-drop
  ALL --security-opt no-new-privileges --network none` with a
  read-only mount, modelling the least-privilege posture the linter
  itself recommends. The simpler form still works.

### Fixed

- Parser post-YAML traversals (`_collect_lines`, `_strip_lines`) no
  longer recurse one Python frame per nesting level, so pathologically-
  deep input raises `ComposeError` (or lints cleanly) instead of
  crashing with an uncaught `RecursionError`. Found by ClusterFuzzLite.

### Security

- Dockerfile sets `USER 65532:65532` explicitly at the runtime stage.
  Distroless `:nonroot` already enforces this; the redundancy survives
  a future base-image swap that might not default to nonroot.

No CLI, config, or finding-shape changes. Exit codes (0/1/2) are
preserved. A Compose file that passed on 0.3.4 passes identically on
0.3.5.

## [0.3.4] - 2026-04-13

### Changed

- Text output now opens with a branded one-line header showing the tool
  version and active parameters (`files`, `config`, `fail-on`) so runs are
  self-describing in CI logs.
- Severity labels in findings are padded to 8 chars so rule IDs line up
  across `MEDIUM`, `HIGH`, `CRITICAL`, and `LOW` rows.
- "No issues found" message is now green instead of dim gray.
- Multi-file text runs end with an aggregate `N files scanned · N issues
  (...)` line.
- Every text run ends with an explicit verdict relative to `--fail-on`:
  `✓ PASS · threshold: high` or `✗ FAIL · N findings at or above high`.
- Suppressed counts are separated from the severity breakdown and labeled
  `(not counted)` so the severity totals reconcile at a glance.

JSON and SARIF output shapes are unchanged. Exit codes (0/1/2) are
preserved.

## [0.3.3] - 2026-04-12

### Added

- Docker Hub image (`composelint/compose-lint`) — multi-stage build on
  `python:3.13-alpine`, multi-arch (`linux/amd64`, `linux/arm64`), runs as
  non-root, signed with cosign (Sigstore keyless).
- Docker usage section in README.
- README rules table now lists all 19 rules (CL-0011–CL-0019 were missing).
- Automated TestPyPI smoke test in publish workflow — installs from TestPyPI,
  verifies `--version`, runs fixture tests. Real PyPI publish is gated on it.
- Automated post-push verification in Docker publish workflow — pulls by
  digest, verifies cosign signature, checks version output.

## [0.3.0] - 2026-04-12

### Added

- 9 new security rules, bringing the total to 19:
  - **CL-0011**: Dangerous capabilities added — `cap_add` with SYS_ADMIN,
    SYS_PTRACE, NET_ADMIN, SYS_MODULE, SYS_RAWIO, SYS_TIME, or
    DAC_READ_SEARCH (HIGH)
  - **CL-0012**: PIDs cgroup limit disabled — `pids_limit: 0` or `-1` (MEDIUM)
  - **CL-0013**: Sensitive host paths mounted — bind mounts of `/etc`, `/proc`,
    `/sys`, `/boot`, or `/root` in short or long syntax (HIGH)
  - **CL-0014**: Logging driver disabled — `logging.driver: none` (MEDIUM)
  - **CL-0015**: Healthcheck disabled — `healthcheck.disable: true` (LOW)
  - **CL-0016**: Dangerous host devices exposed — `/dev/mem`, `/dev/kmem`,
    `/dev/port`, `/dev/sd*`, `/dev/nvme*`, `/dev/disk/*` (HIGH)
  - **CL-0017**: Shared mount propagation — `:shared` suffix or
    `bind.propagation: shared` (MEDIUM)
  - **CL-0018**: Explicit root user — `user: root` or `user: "0"` overrides
    image USER instruction (MEDIUM)
  - **CL-0019**: Image tag without digest — version tag present but no
    `@sha256:` pin; non-overlapping with CL-0004 (MEDIUM)

### Changed

- **CL-0010** now also detects `uts: host` (CIS 5.21 — sharing the host's UTS
  namespace lets a container change the host's hostname).

## [0.2.0] - 2026-04-10

First public release.

### Added

- 10 security rules grounded in OWASP Docker Security Cheat Sheet and the CIS
  Docker Benchmark:
  - **CL-0001**: Docker socket mounted (CRITICAL)
  - **CL-0002**: Privileged mode enabled (CRITICAL)
  - **CL-0003**: Privilege escalation not blocked (MEDIUM)
  - **CL-0004**: Image not pinned to version (MEDIUM)
  - **CL-0005**: Ports bound to all interfaces (HIGH)
  - **CL-0006**: No capability restrictions (MEDIUM)
  - **CL-0007**: Filesystem not read-only (MEDIUM)
  - **CL-0008**: Host network mode (HIGH)
  - **CL-0009**: Security profile disabled (HIGH)
  - **CL-0010**: Host namespace sharing (HIGH)
- CVSS-aligned severity model with a documented scoring matrix (`docs/severity.md`).
- Output formatters: `text` (colored, with fix guidance and references), `json`
  (for CI integration), and `sarif` (SARIF 2.1.0, for GitHub Code Scanning).
- GitHub Action (`tmatens/compose-lint@v0.2.0`) with optional SARIF upload to the
  Code Scanning tab.
- Auto-discovery of `compose.yml` / `docker-compose.yml` (and their `.yaml` /
  `.override.*` variants) when no file arguments are given.
- Configuration via `.compose-lint.yml`: disable rules, override severity, record
  an exception `reason` that flows through to all output formats.
- Suppressed-finding reporting with `--skip-suppressed` to hide them from output.
- Documented exit code contract (0 = clean, 1 = findings at/above threshold,
  2 = usage error) and `--fail-on` flag to set the threshold.
- Pre-commit hook support via `.pre-commit-hooks.yaml`.
- Python 3.10–3.13 support.

### Security

- PyPI releases use Trusted Publishing (OIDC) with Sigstore build attestations.
  No long-lived API tokens.
- TestPyPI publish gates the real PyPI publish — a TestPyPI failure aborts the
  release before a version number is burned on the real index.
- Supply chain hardening: CodeQL (python + actions), OpenSSF Scorecard, Bandit,
  pip-audit, and Dependabot all run on every push and weekly.
- GitHub Actions workflows are pinned, scoped to least-privilege permissions, and
  use `persist-credentials: false` on checkout. The composite action passes user
  inputs through `env:` rather than direct `${{ }}` interpolation to prevent
  shell injection.

[Unreleased]: https://github.com/tmatens/compose-lint/compare/v0.17.0...HEAD
[0.17.0]: https://github.com/tmatens/compose-lint/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/tmatens/compose-lint/compare/v0.15.2...v0.16.0
[0.15.2]: https://github.com/tmatens/compose-lint/compare/v0.15.1...v0.15.2
[0.15.1]: https://github.com/tmatens/compose-lint/compare/v0.15.0...v0.15.1
[0.15.0]: https://github.com/tmatens/compose-lint/compare/v0.14.1...v0.15.0
[0.14.1]: https://github.com/tmatens/compose-lint/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/tmatens/compose-lint/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/tmatens/compose-lint/compare/v0.12.2...v0.13.0
[0.12.2]: https://github.com/tmatens/compose-lint/compare/v0.12.1...v0.12.2
[0.12.1]: https://github.com/tmatens/compose-lint/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/tmatens/compose-lint/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/tmatens/compose-lint/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/tmatens/compose-lint/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/tmatens/compose-lint/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/tmatens/compose-lint/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/tmatens/compose-lint/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/tmatens/compose-lint/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/tmatens/compose-lint/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/tmatens/compose-lint/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/tmatens/compose-lint/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/tmatens/compose-lint/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/tmatens/compose-lint/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/tmatens/compose-lint/compare/v0.3.7...v0.4.0
[0.3.7]: https://github.com/tmatens/compose-lint/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/tmatens/compose-lint/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/tmatens/compose-lint/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/tmatens/compose-lint/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/tmatens/compose-lint/compare/v0.3.0...v0.3.3
[0.3.0]: https://github.com/tmatens/compose-lint/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tmatens/compose-lint/releases/tag/v0.2.0
