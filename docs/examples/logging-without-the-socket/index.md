# Rung 2 — Re-architect so the socket isn't needed

**Verified against:** compose-lint 0.16.0, 2026-08-11

The management UI in [rung 1](../portainer-removed/index.md) was mounting the Docker socket, but almost all of what it was used for was reading container logs and checking whether services were up. That is a data problem, not a control problem — and the data is available without the Docker API.

This stack does the same job with no socket anywhere in it.

## How

Container logs reach this stack because the Docker daemon is configured to use the `journald` log driver, so every container's stdout is already in the systemd journal, tagged with the container name and its Compose project and service. A collector reads the journal off disk, read-only, and ships it to a log database that a dashboard queries.

The Docker API is never involved. Nothing here needs to ask the daemon anything, because the daemon already wrote the data down.

```yaml
    # The read-only systemd journal. This is what replaces the Docker socket.
    volumes:
      - /var/log/journal:/var/log/journal:ro
      - /etc/machine-id:/etc/machine-id:ro
```

The access requirement collapses to something very small. Journal files are `root:systemd-journal` mode `0640`, so *group read* is the entire permission needed to collect every container's logs. The collector therefore runs as the image's own unprivileged user with the host's `systemd-journal` group added:

```yaml
    user: "473:473"
    group_add:
      - "999"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true
```

No capability, no root, no socket — to do the job that a moment ago justified root-equivalent access to the host.

## What the linter says

```
docker-compose.yml: 3 medium  ·  1 suppressed (not counted)
✓ PASS  ·  threshold: high  ·  below: 3 medium
```

Nothing at or above the gate. The three mediums are [CL-0026](../../rules/CL-0026.md), one per service, none of which has a memory or CPU limit — the same finding this library reports on almost every stack in it, and a fair one: an unbounded collector on a busy host is a denial of service waiting for a log storm.

One suppression, on the collector, for a host mount:

```yaml
rules:
  CL-0013:
    exclude_services:
      alloy: >-
        The two host mounts are the log source itself and are both read-only:
        /var/log/journal is the systemd journal this collector exists to read,
        and /etc/machine-id is the single file journal entries need in order to
        resolve which host they came from. No writable host path is exposed.
```

The reason names both host mounts, and as of 0.16.0 only one of them still reports: `/etc/machine-id` is under `/etc`, and a read-only mount of a CL-0025 path is [CL-0013](../../rules/CL-0013.md) at HIGH. `/var/log/journal` is not on the sensitive-path list at all. The waiver is left as written rather than narrowed to the one path, because it documents a decision about the collector's whole mount set, and a reason that only survives as long as the rule's path list does is a worse artifact than one that says what was actually decided.

Note what this suppression does *not* have to say. There is no residual risk paragraph, because there is no residual risk to state: the mount is read-only, it contains log data, and a compromise of this container yields the logs it was already reading. Compare that with the suppression in [rung 4](../ci-runner-suppression/index.md), which has to be explicit that the risk is accepted rather than mitigated. The difference in how those two reasons read is a decent smell test for which rung you are actually on.

## Two details that are easy to get wrong

**The port bind is doing real work.** The collector publishes a syslog listener for network devices, bound to one specific host address rather than `0.0.0.0`:

```yaml
    ports:
      - "10.10.20.5:1514:1514/udp"
```

This is not cosmetic. Docker's port publishing inserts DNAT rules that are evaluated before host firewall rules, so a host firewall will not save a `0.0.0.0` publish. The bind address is the control that actually holds. See [CL-0005](../../rules/CL-0005.md).

**The log database is on its own network.** It is reachable only by its actual clients, not by every co-tenant on the default network — an unauthenticated internal API is still an API.

## When this rung applies

Ask what the socket is being used to *learn*, and whether that information exists anywhere else. Logs, resource usage and container state are all published by the runtime through channels that are not the control API. If the answer is that the service needs to *do* something — create, start, stop, exec — no amount of re-architecting removes the requirement, and you are on [rung 3](../netdata-socket-proxy/index.md) or [rung 4](../ci-runner-suppression/index.md).

## Scope note

This file is excerpted from a larger deployed stack; services unrelated to the logging path have been left out, and identifiers are sanitized. The claim that nothing here mounts the socket was verified against the running containers, not just the file.
