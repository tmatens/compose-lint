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

## A granted capability is not a held capability

The stack ran for a month with a permission error at every startup that everyone had filed as harmless:

```
Runtime directory '/run/netdata' is not writable, falling back to '/tmp'
```

It looks self-resolving, it says so itself, and collection genuinely does keep working. The reading was that the agent had lost a capability somewhere and found another path.

That is half right. Here is what the running processes actually showed:

| | Uid | CapEff | CapBnd |
|---|---|---|---|
| the agent daemon | `201` | `0000000000000000` | `00000000000800c2` |
| `apps.plugin` | `201 0 0 0` | `00000000000800c2` | `00000000000800c2` |

`0x800c2` decodes to exactly `DAC_OVERRIDE + SETGID + SETUID + SYS_PTRACE` — the four capabilities in the Compose file above.

**The daemon holds none of them.** `setuid()` from root to an unprivileged uid clears the permitted and effective capability sets unless the process opts out with `PR_SET_KEEPCAPS`, and this one doesn't. So `DAC_OVERRIDE` — granted, visible in the file, sitting right there in `cap_add` — is not in effect at the moment the daemon meets its own root-owned `0755` runtime directory.

`apps.plugin` is the other half. It runs `Uid: 201 0 0 0`: real uid 201, *effective uid 0*, because it is setuid-root. On exec it re-acquires the full set bounded by `CapBnd`. That is the actual function of `cap_add` here — it is not configuring what the daemon holds, it is setting the ceiling that setuid-root plugin processes can climb back to. It is also exactly why `no-new-privileges` is genuinely incompatible with this service rather than merely inconvenient: `no_new_privs` blocks that escalation, so the suppression above is load-bearing.

### Why the fallback was not harmless

The `/tmp` fallback rescues the runtime directory. It does not rescue the control socket:

```
uv_pipe_bind(): permission denied
Failed to initialize command server. The netdata cli tool will be unable to send commands.
```

Thirty days of logs: 32 runtime-directory fallbacks, 36 command-server failures. The agent's CLI had been non-functional on every restart for at least a month, on a host where it was working fine by every other measure.

### The fix is not a capability

The instinct is to add one. That would be wrong twice: it would not help the daemon, which drops whatever it is given, and it would widen the ceiling the plugins can reach. The defect is a directory-ownership mismatch, so the fix is a directory owned by the right uid:

```yaml
    tmpfs:
      - /run/netdata:uid=201,gid=201,mode=0770
```

`0770` rather than the tmpfs default `1777`, since exactly one uid needs it. Afterwards: `netdatacli ping` → `pong`, and zero command-server failures across restarts.

## The requirements are a property of your configuration, not of the image

Everything above is specific to how *this* deployment uses this image. That is not a disclaimer, it is the most transferable thing on the page.

This agent's config turns two features off:

```
network-viewer = no                                    # would setns() into other containers' namespaces
script to get cgroup network interfaces = /bin/true    # per-container network charts, also via setns()
```

Both features work by entering other containers' network namespaces. With them off, the privilege they would have required is not needed — which is a large part of why the capability set here is four and not more, and why `SYS_ADMIN` could be dropped. Turn either back on and the minimum changes, and a hardened file copied from this page would be wrong for that deployment.

The same holds in the other direction. Two of the suppressions on this page were tested and turned out to say the wrong thing:

- **Host networking was justified as "required to monitor all network interfaces".** It isn't — and the correct answer took three attempts to find. That story is [below](#a-reason-that-was-wrong-twice), because it is the most useful thing on this page.
- **`apparmor:unconfined` was justified as needed for `/proc` and `/sys` access.** It is needed, but not for the stated reason, and the way it fails is covered below.

Neither error was detectable from the Compose file, and neither was detectable from the image. They were properties of one deployment's configuration, and they only surfaced when someone re-derived them against that deployment.

This is also why a "security profile for image X" is a harder artifact than it sounds, and why [ADR-019](../../adr/019-withdraw-security-profile-catalog.md) withdrew the attempt to publish one. The minimum privilege for an image is not a function of the image. It is a function of the image *plus the features you turned on*, and the second half does not fit in a catalog.

## A reason that was wrong twice

The host-networking suppression on this stack carried this justification for a long time:

> Host network required to monitor all network interfaces

Testing it produced a correction. Testing the correction produced another correction. It is worth walking through all three, because the failure was not carelessness — each answer was reached by measuring something real, and the first two were still wrong.

**Attempt 1 — "it's needed for interface metrics."** False. A bridged container with the same configuration collects the host's physical interfaces with real data. The agent reads `/host/proc/1/net/dev` — PID 1's network namespace — which resolves to the host's only because `pid: host` is set. Bind-mounting `/proc` does not help on its own: `/proc/net` is namespace-relative, so `/host/proc/net/dev` shows the container's own `lo` and `eth0`. `pid: host` had been supplying the network metrics all along.

**Attempt 2 — "then it's for the dashboard's bind address."** True, and not why it is needed. This one was checked carefully: every network chart family was compared between host-network and bridge — bandwidth, operstate, carrier, speed, MTU, sockstat, conntrack — and all of them collected identically. A prediction that interface *state* would break, on the grounds that `/sys/class/net` is per-netns, turned out to be wrong too. The conclusion looked solid, and it was recorded as a decision.

**Attempt 3 — what it is actually for.** The agent discovers application containers through the socket proxy and then connects to each at its own docker-network address. Host networking is what lets it route to every docker bridge. On a single bridge network, discovery still succeeds and *every scrape times out*:

```
service discovery:   works — finds postgres, redis, mysql across projects
scrape result:       7 timeouts
redis contexts:      21 with host networking  ->  0 on bridge
```

Twenty-one contexts of application monitoring, silently gone, while the container stays healthy and every host-level chart keeps working perfectly.

### Why attempt 2 was so convincing

The probe used to reach it was faithful in every way that seemed to matter — real config file, `pid: host`, the same mounts, a four-minute settle so no chart was judged before its first collection cycle. It omitted one thing: the socket-proxy mount. Without it, service discovery never ran, so the missing application contexts looked like an artifact of the probe rather than a finding.

The posture you test in has to match production in the dimension that matters, and *which dimension matters is not knowable in advance*. Namespace sharing mattered for the AppArmor test. Configuration completeness mattered here. A probe that is faithful in four respects and incomplete in the fifth returns a clean, confident, wrong answer.

### What this costs a reader

Nothing about this deployment ever looked wrong. The dashboards were populated, the container was healthy, and CI was green — throughout the entire period the suppression carried a false justification. Nothing surfaces a wrong reason except deciding to test it.

## A second false green, from a different cause

Dropping `SYS_PTRACE` breaks per-process metrics while the healthcheck stays green. So does running under Docker's default AppArmor profile — and that one is stranger, because the capability is present and effective:

```
container health:  healthy
apps.plugin:       "Cannot process /host/proc/1/io (command 'systemd')"   errno 13
                   259 permission-denied lines
apps.cpu:          "No metrics where matched to query"
apps.plugin caps:  Uid: 201 0 0 0    CapEff: 00000000000800c2   <- SYS_PTRACE present
```

`SYS_PTRACE` is granted, the plugin is setuid-root and holds it effectively, and the read is refused anyway, because mandatory access control is evaluated independently of capabilities. Two different mechanisms, one indistinguishable symptom: a healthy container with missing data.

### The posture you test in decides the answer you get

The same AppArmor test run without `pid: host` reports **zero denials** and a perfectly healthy agent. Nothing is wrong, because with no host processes visible there is nothing to be refused access to.

A drop-test run in that posture returns "`apparmor:unconfined` is removable" — confidently, reproducibly, and wrongly. The capability minimum you derive is only valid for the posture you derived it in, and the posture includes the namespace sharing, the mounts, and the enabled feature set. A derived minimum also inherits any bug present at derivation time: `DAC_OVERRIDE` here was re-tested on the suspicion that it was only masking the runtime-directory problem described above, and survived — removing it fails startup on a different directory entirely — but that suspicion was reasonable, and the way to settle it was to run it again rather than to reason about it.

### What this means for the linter

compose-lint cannot find this one. Every fact that matters — that the daemon drops its capabilities, that a directory inside the image is root-owned, that a plugin is setuid-root — is a property of the running container, not of the Compose file. The file was, and still is, clean.

That is worth stating plainly rather than leaving implied. A Compose linter checks the configuration you declare. It does not check that the process you launched can use what you declared, and a green run is not evidence that your capability grants are reaching the code that needs them. This example exists partly to mark that boundary.

The same limit applies to the suppression reasons. compose-lint will faithfully carry a justification that is completely false — as the host-networking one on this page was, twice — because a reason is prose, and nothing checks prose against reality. Every version of that file linted clean: the one with the false reason, the one with the better-but-still-wrong reason, and the correct one. The linter can tell you a waiver exists. Only re-testing tells you whether it is true.

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
