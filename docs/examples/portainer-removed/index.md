# Rung 1 — Delete the service

**Verified against:** compose-lint 0.16.0, 2026-08-11

The cheapest fix for a critical finding is the one nobody proposes: stop running the thing.

This example is a container-management UI that mounted the Docker socket. It was hardened in every way its own documentation suggests — `cap_drop: ALL`, `no-new-privileges`, `read_only: true`, a tmpfs for `/tmp`, an image pinned by digest — and every one of those controls is irrelevant to the finding, because none of them constrain what a process can ask the Docker daemon to do once it can reach the socket.

## What the linter says

```
  service: portainer  (line 11)
    line  severity    rule     message
      24  CRITICAL    CL-0001  Docker runtime socket mounted via
                               '/var/run/docker.sock:/var/run/docker.sock'. This gives the
                               container full control over the Docker runtime — equivalent
                               to root on the host.
      11  MEDIUM      CL-0026  Service declares no memory limit and no CPU limit. Docker
                               imposes neither by default, so the container can consume
                               the host's memory or CPU until other workloads are starved.
```

One finding, one rung. The socket line is the whole example, and CL-0026 is the ambient one every service in this library reports until someone sizes it.

Two findings this file used to report are worth naming, because both left in 0.16.0 and neither left because the file changed. A second HIGH used to fire on the socket path itself, from the sensitive-host-path rule — the same mount counted twice, once as the daemon API and once as a file under `/var/run`. That path is [CL-0001](../../rules/CL-0001.md)'s alone now. And a static `curl` binary is bind-mounted at line 26 from `/home/deploy/.local/bin`, put there so the healthcheck had something to run against an image that ships no shell; that used to report as a sensitive home-directory mount. [CL-0013](../../rules/CL-0013.md) now matches the home tree by depth — `/home`, a user's home directory, and the credential directories below it — so an application's own path further down is no longer flagged. It is still the kind of thing that accumulates around a service you are keeping alive; it is no longer something the linter will point at.

## The suppression that was there

```yaml
rules:
  CL-0001:
    enabled: false
    reason: "Portainer requires Docker socket to manage containers — socket proxy migration planned"
```

This is not a lazy suppression. It is accurate — the tool genuinely does require the socket — and it commits to a fix. It is still the failure mode to learn from, for three reasons:

- **It is global.** `enabled: false` disables CL-0001 for the entire file, not just this service.
- **It has no date and no owner.** "Planned" is not a state anything can transition out of.
- **Nothing ever reopened it.** The migration it promised was never done. What actually resolved the finding was noticing, much later, that the service had not been used to manage anything in months.

A suppression with an indefinite promise in it is indistinguishable from a permanent one after a few months, because that is what it has become.

## The fix

The service was removed. The log- and status-viewing that it was genuinely still used for moved to a stack that does not need the Docker API at all — that is [rung 2](../logging-without-the-socket/index.md).

There is no hardened file in this directory, because the hardened version of this service is its absence.

## The question to ask first

Before asking how to constrain a socket mount, it is worth asking what the service is still doing for you. Management UIs, one-off debugging tools and "we set this up to try it" containers are heavily represented among socket mounts, and they are the population where the answer is most often "nothing, any more".

Rungs 2 through 4 are for when the answer is not "nothing".
