# Rung 3 — Constrain it when the need is real

**Verified against:** compose-lint 0.15.1, 2026-08-08

A host-metrics agent needs the Docker API. Not log data, not "container state" in the abstract — it calls `/containers/json` to enumerate containers and `/containers/<id>/json` to map a cgroup back to a container name. There is no journal file that answers those, so [rung 2](../logging-without-the-socket/index.md) does not apply.

The requirement is real and the remediation is still not "suppress it". It is to make the socket the agent can reach a strictly smaller thing than the socket.

## `:ro` on a socket does not do what it looks like

The starting file mounted the socket read-only, which reads as a mitigation and is not one:

```yaml
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

`:ro` applies to the socket *file*. It makes the inode non-writable. The Docker API is a request/response protocol over an open connection, and the daemon accepts `POST` regardless of the mount flag — `POST /containers/create` with a host bind mount and `POST /containers/<id>/start` is a two-call path to root on the host, and neither call writes to the socket file. This is covered in [CL-0001](../../rules/CL-0001.md); it is repeated here because it is the single most common misreading of this finding.

## The architecture

A filtering proxy holds the real socket and publishes a restricted one:

```yaml
  docker-socket-proxy:
    user: "65534:${DOCKER_GID}"      # nobody, plus the docker group to open the socket
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./sockets:/sock
    command:
      - -proxysocketendpoint=/sock/docker.sock
      - -proxysocketendpointfilemode=432   # 0660; the 0600 default leaves the consumer unable to connect
      - -allowGET=^(/v[0-9]+\.[0-9]+)?/(_ping|version|info|images/json(\?.*)?|containers/json(\?.*)?|containers/[a-zA-Z0-9_.-]+/json(\?.*)?)$$
```

and the agent consumes it by pointing `DOCKER_HOST` at the published socket instead of mounting the real one.

### Why a unix socket rather than a loopback TCP port

A TCP proxy would be simpler to wire up, and it is the wrong choice here. The agent runs with host networking, so a proxy on a bridge network would have to publish a host port — and `GET /containers/<id>/json`, which is on the allow-list because the agent genuinely needs it, returns `.Config.Env`: every container's environment variables, which is where secrets live.

A `127.0.0.1:2375` listener would therefore expose every container's secrets to any local uid and any host-network container. The real socket is `root:docker` mode `0660`; a loopback port is a strictly wider audience than that. The unix socket keeps the audience identical to what it was.

This is also the honest limit of this rung: the filtering converts "can take over the host" into "can read container names and environments". That is a large reduction and it is not zero.

### The filter, verified

Probed against the running proxy — status codes only, since some of these responses carry environment variables:

```
ALLOWED (what the agent actually calls):
  GET    /_ping                                -> 200
  GET    /version                              -> 200
  GET    /info                                 -> 200
  GET    /containers/json                      -> 200
  GET    /images/json                          -> 200

BLOCKED paths:
  GET    /volumes                              -> 403
  GET    /networks                             -> 403
  GET    /secrets                              -> 403
  GET    /containers/json/../../secrets        -> 403

BLOCKED methods:
  POST   /_ping                                -> 405
  DELETE /_ping                                -> 405
```

The proxy logs each rejection, so attempts show up in the same log pipeline as everything else rather than failing silently.

## The finding count did not go down

Before: 14 findings. After: 14 findings.

The critical one moved from the metrics agent — host network, host PID namespace, unconfined AppArmor, several sensitive host mounts — to a scratch-image container that is read-only, has no capabilities, runs as `nobody` and answers `403` to everything it does not need. Same number, different blast radius.

If you are tracking a finding count as a security metric, this refactor is invisible to you. That is a problem with the metric.

## Capabilities, and a failure the healthcheck did not catch

The capability set was reduced by drop-testing: remove one, restart, see what breaks. Two results are worth writing down because in both cases *the container stayed healthy while being wrong*.

**`SYS_PTRACE`.** An earlier, more aggressive reduction dropped it. Per-process metrics then failed for privileged processes — reading `/proc/<pid>/io` for a setuid or non-dumpable process requires the capability even as root — and the agent logged a flood of permission errors while its healthcheck continued to report healthy. The drop-test that approved the change had only verified reading the agent's *own* processes, which are dumpable and need no capability. The test was passing on an unrepresentative case.

**`SETUID` / `SETGID`.** These are used exactly once, at startup, to drop from root to the agent's user. Drop them and the agent silently continues as root — still healthy, still collecting metrics, no longer dropping privileges. A hardening change that quietly *removes* the privilege drop is the worst possible outcome, and nothing in the container's own status reports it.

The signature to alert on is not the message, it is the errno. Over the last 30 days of logs from the current configuration:

```
     0  Cannot process /host/proc/<pid>/... + errno 13 (Permission denied)   <- the regression
  2549  Cannot process /host/proc/<pid>/... + errno  3 (No such process)     <- benign race
```

Same message text. The benign one fires thousands of times a month because processes exit between enumeration and read. Anyone grepping for the message string rather than the errno would drown in false positives and conclude the alert was useless.

`SYS_ADMIN` was also dropped and deliberately stays absent: the image ships no eBPF plugin, so the config option that appears to require it is a no-op and the capability gated nothing.

## The suppressions

Every entry is scoped with `exclude_services` rather than globally disabled — including CL-0001, which is suppressed **only** for the proxy:

```yaml
rules:
  CL-0001:
    exclude_services:
      docker-socket-proxy: >-
        This service exists to hold the socket. It is the mitigation, not the
        risk: scratch image, read_only, cap_drop ALL, no-new-privileges, runs
        as nobody, and exposes only a GET-filtered subset of the API. Netdata
        itself no longer mounts the socket, so CL-0001 stays enabled for it.
```

A global `enabled: false` would have been shorter and would have quietly re-permitted the exact thing this architecture exists to prevent: a later edit re-adding a direct socket mount to the agent would lint clean. The scoped form keeps the rule live for every other service in the file. See [ADR-010](../../adr/010-per-service-rule-overrides.md).

The remaining suppressions cover what a host-metrics agent inherently needs — host networking for interface metrics, host PID for process attribution, read-only `/proc`, `/sys`, `/etc/passwd` and `/etc/group` to attribute metrics to real users, and an unconfined AppArmor profile for that access. Each is scoped to the agent, so the proxy is still held to the default standard, which it meets.

## Scope note

Files are sanitized: hostnames, paths and the docker group id are replaced. The finding set of the sanitized file was compared against the deployed original and is identical — 14 findings, same rules, same services. Capability and mount claims were verified against the running containers.
