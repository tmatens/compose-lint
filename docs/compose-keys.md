# Compose keys and what compose-lint does with each

Every key the [Compose Specification](https://github.com/compose-spec/compose-spec)
defines at the top level, on a service or on a job, and what compose-lint does
with it. `tests/test_spec_round_trip.py` holds this table to the vendored copy
of the spec's schema (`tests/data/compose-spec/`), so a key the spec adds
fails a test until this page says what compose-lint does with it. The copy is
refreshed by `compose-spec-bump.yml`; the upstream commit is in
`tests/data/compose-spec/SOURCE`.

The third column starts with one of five words:

- **graded**: one or more rules read the key; they are listed.
- **engine**: the engine acts on the key before rules run (merging, reading,
  refusing); no rule sees it.
- **traversed**: the key holds containers the engine grades as units.
  **not traversed** names the issue that will make it so.
- **parse-only**: accepted and kept, nothing acts on it. These keys carry no
  grant and describe nothing a rule derives a severity from.
- **not graded**: the key has a security meaning but no rule, with the reason
  and the issue that records it for a recount.

A key appearing on both a service and a job is graded the same way on each
once jobs are traversed.

| Key | Where | What compose-lint does |
| --- | --- | --- |
| `configs` | top-level | parse-only |
| `include` | top-level | engine: followed when it stays inside the repository (ADR-036, ADR-038) |
| `jobs` | top-level | not traversed (#1185) |
| `models` | top-level | not graded: model runner declarations, parse-only today (#1189) |
| `name` | top-level | parse-only |
| `networks` | top-level | parse-only |
| `secrets` | top-level | parse-only |
| `services` | top-level | traversed |
| `version` | top-level | engine: a Compose v1 file is refused (ADR-013) |
| `volumes` | top-level | parse-only |
| `annotations` | service, job | parse-only |
| `attach` | service | parse-only |
| `blkio_config` | service, job | parse-only |
| `build` | service, job | not graded: build-time `privileged` and `entitlements` recorded (#1189); a build-only service skips the image rules |
| `cap_add` | service, job | graded: CL-0011, CL-0024, CL-0027, CL-0028, CL-0029, CL-0030 |
| `cap_drop` | service, job | graded: CL-0006, CL-0016 |
| `cgroup` | service, job | not graded: `cgroup: host` proposed for CL-0010 (#1188) |
| `cgroup_parent` | service, job | parse-only |
| `command` | service, job | graded: CL-0020 |
| `configs` | service, job | parse-only |
| `container_name` | service | parse-only |
| `cpu_count` | service, job | parse-only |
| `cpu_percent` | service, job | parse-only |
| `cpu_period` | service, job | parse-only |
| `cpu_quota` | service, job | graded: CL-0026 |
| `cpu_rt_period` | service, job | parse-only |
| `cpu_rt_runtime` | service, job | parse-only |
| `cpu_shares` | service, job | parse-only |
| `cpus` | service, job | graded: CL-0026 |
| `cpuset` | service, job | parse-only |
| `credential_spec` | service, job | parse-only |
| `depends_on` | service, job | parse-only |
| `deploy` | service | graded: CL-0026 |
| `develop` | service | parse-only |
| `device_cgroup_rules` | service, job | graded: CL-0016 |
| `devices` | service, job | graded: CL-0016 |
| `dns` | service, job | parse-only |
| `dns_opt` | service, job | parse-only |
| `dns_search` | service, job | parse-only |
| `domainname` | service, job | parse-only |
| `entrypoint` | service, job | graded: CL-0020 |
| `env_file` | service, job | engine: keys read for CL-0020 and CL-0021 (ADR-027) |
| `environment` | service, job | graded: CL-0020, CL-0021 |
| `expose` | service, job | parse-only |
| `extends` | service, job | engine: merged before grading (ADR-036) |
| `external_links` | service | parse-only |
| `extra_hosts` | service, job | parse-only |
| `gpus` | service, job | not graded: device shorthand; CL-0016 grades dangerous device paths and a GPU is not one (#1189) |
| `group_add` | service, job | not graded: supplementary groups are not a grant on their own (#1189) |
| `healthcheck` | service, job | graded: CL-0020 |
| `hostname` | service, job | parse-only |
| `image` | service, job | graded: CL-0004, CL-0019 |
| `init` | service, job | parse-only |
| `ipc` | service, job | graded: CL-0010 |
| `isolation` | service, job | parse-only |
| `label_file` | service, job | not graded: zero incidence; labels themselves are #1079 (#1189) |
| `labels` | service, job | not graded: credential-shaped label values are an open proposal (#1079) |
| `links` | service | parse-only |
| `logging` | service, job | graded: CL-0014 |
| `mac_address` | service, job | parse-only |
| `mem_limit` | service, job | graded: CL-0026 |
| `mem_reservation` | service, job | parse-only |
| `mem_swappiness` | service, job | parse-only |
| `memswap_limit` | service, job | parse-only |
| `models` | service, job | not graded: model runner bindings (#1189) |
| `network_mode` | service, job | graded: CL-0008 (`host`); the `service:` form is a transitive grant (#1076) |
| `networks` | service, job | parse-only |
| `oom_kill_disable` | service, job | not graded: zero incidence (#1189) |
| `oom_score_adj` | service, job | parse-only |
| `pid` | service, job | graded: CL-0010 |
| `pids_limit` | service, job | not graded: a near-universal absence finding, decision recorded in the roadmap (#1189) |
| `platform` | service, job | parse-only |
| `ports` | service, job | graded: CL-0005 |
| `post_start` | service | not traversed (#1185) |
| `pre_start` | service | not traversed (#1185) |
| `pre_stop` | service | not traversed (#1185) |
| `privileged` | service, job | graded: CL-0002 |
| `profiles` | service, job | parse-only |
| `provider` | service | engine: not a container, no rule runs on it (#1186) |
| `pull_policy` | service, job | parse-only |
| `pull_refresh_after` | service, job | parse-only |
| `read_only` | service, job | graded: CL-0007 |
| `restart` | service | parse-only |
| `runtime` | service, job | not graded: runtime selection, not a grant (#1189) |
| `scale` | service | parse-only |
| `secrets` | service, job | parse-only |
| `security_opt` | service, job | graded: CL-0003, CL-0009 |
| `shm_size` | service, job | parse-only |
| `stdin_open` | service, job | parse-only |
| `stop_grace_period` | service, job | parse-only |
| `stop_signal` | service, job | parse-only |
| `storage_opt` | service, job | parse-only |
| `sysctls` | service, job | not graded: Docker permits namespaced sysctls only (#1189) |
| `tmpfs` | service, job | graded: CL-0022 |
| `triggers` | job | parse-only |
| `tty` | service, job | parse-only |
| `ulimits` | service, job | parse-only |
| `umask` | service, job | parse-only |
| `use_api_socket` | service, job | graded: CL-0031 |
| `user` | service, job | graded: CL-0018 |
| `userns_mode` | service, job | not graded: only changes behaviour under user-namespace remapping, not the grounded default (ADR-020, #1189) |
| `uts` | service, job | graded: CL-0010 |
| `volumes` | service, job | graded: CL-0001, CL-0013, CL-0017, CL-0025 |
| `volumes_from` | service, job | not graded: inherits a graded mount without a finding (#1076) |
| `working_dir` | service, job | parse-only |
