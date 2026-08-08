# The clean one

**Verified against:** compose-lint 0.15.1, 2026-08-08

Every other example in this library is a story about a finding. This one is here because a library made only of those teaches the wrong lesson — that real infrastructure inevitably needs a pile of waivers, and that a suppression file with six entries is just how it goes.

It isn't. This is the public entry point for every service in the deployment, and its entire suppression file covers **one rule on one service**:

```
docker-compose.yml: 0 issues  ·  2 suppressed (not counted)
```

The two suppressed findings are ports 80 and 443 on the proxy. The forward-auth service alongside it produces **no findings at all** and appears nowhere in the config.

## What a zero-finding service looks like

```yaml
  auth:
    entrypoint: ['authelia', '--config', '/config/configuration.yml']
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    networks:
      - auth-net        # reachable only by the proxy; publishes nothing
```

No capabilities at all — not `cap_drop: ALL` with add-backs, but `cap_drop: ALL` full stop. Read-only root, no published ports, one internal network, secrets by environment reference, image pinned by digest.

## The trick worth stealing

That `entrypoint:` line is doing the work, and it is the most transferable thing on this page.

The stock image entrypoint chowns `/config` and drops privileges using `su-exec`. That sequence needs `CHOWN`, `SETUID` and `SETGID`. With those dropped, the container crash-loops before the application starts — and the obvious response is to add the three capabilities back, which is what most hardening guides end up doing.

The alternative is to skip the entrypoint and exec the binary directly. The process then runs as root **with no capabilities**, under a read-only root filesystem, and never needs to drop privileges because it never gains any.

That trade is worth being precise about, because "runs as root" sounds worse than "drops to an unprivileged user":

| | stock entrypoint | direct exec |
|---|---|---|
| final user | unprivileged | root |
| capabilities held | whatever was granted to enable the drop | **none** |
| `CHOWN`/`SETUID`/`SETGID` | required | not granted |
| root filesystem | writable for the chown | read-only |

Root without capabilities is a much weaker position than the name suggests. Nearly everything root can normally do — bind low ports, override file permissions, change ownership, signal other processes, load modules — *is* a capability, and this process has none of them. Meanwhile the privilege-dropping path requires handing the container three capabilities during the window when it is still root, one of which (`SETUID`) is exactly what an attacker wants.

This only works when the image's setup step is unnecessary in your deployment. Here it is: the config files are read-only bind mounts owned correctly on the host, so nothing needs chowning. Check that before copying — if the entrypoint is doing real initialisation, skipping it will fail in a less obvious way than a crash loop.

## The one waiver, and why it stays

Ports 80 and 443 bind all interfaces. The original reason said they "must" — which is imprecise, since they could bind a single address. The right question is whether narrowing would close anything.

Probed from containers, rather than assumed:

```
container -> host address:443       unreachable
container -> bridge gateway:443     unreachable      already blocked at the firewall
isolated container -> gateway:443   unreachable
container -> bridge gateway:80      HTTP 308         the HTTPS redirect, nothing else
```

The host has exactly one routable interface, so `0.0.0.0` adds only loopback and the docker bridge gateways over a specific bind — and 443 is already unreachable by every container path tested, while 80 serves only a redirect.

So narrowing the bind would **remove the finding without closing a reachable path**, while putting ingress for every service behind this proxy at risk. The waiver stays, and now says that instead of asserting necessity.

This is the mirror of a problem described in the [multi-service example](../read-only-multi-service/index.md#when-the-number-and-the-posture-disagree): there, hardening made the linter's output worse. Here, improving the linter's output would not harden anything. Both are cases where the count and the posture point different directions, and the count is the one that deserves less trust.

Also recorded in the suppression: certificates are issued over the DNS-01 challenge, so port 80 is not needed for issuance. It exists purely for the HTTP-to-HTTPS redirect. That is the lever if this finding ever has to be closed outright — drop the port, lose the redirect.

## What made this one easy

Nothing here was hard-won. The proxy needs one capability because it binds low ports, and it needs open ports because it is the front door. Everything else — read-only roots, no extra capabilities, no host mounts, digest pins, an internal-only network for the auth service — was available from the start.

The contrast with the rest of this library is the point. The stacks that needed waivers needed them because of what the software does: an agent that reads host processes, a runner that creates containers, an init system that writes to its own directory. Where the software has no such requirement, the hardened configuration is not a compromise and the suppression file stays nearly empty.

If your edge proxy has six waivers, that is worth a look. This one manages with one, and the one is a deliberate decision with the evidence written down.

## Scope note

Sanitized: hostnames, domains, addresses and credential names are replaced, and the proxy's per-backend network list is trimmed to two entries for readability. Capabilities, `read_only`, the entrypoint override and the port configuration are as deployed; both containers were running in that configuration and healthy when the reachability probes above were taken.
