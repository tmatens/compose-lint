# Docker Compose security: a hardening guide

This page takes an ordinary Compose file from Docker's defaults to a hardened
configuration, one setting at a time. Each step shows the change, says why it
matters, gives the share of real-world files that skip it, and links the rule
page that holds the details, the failure signatures, and the exceptions. The
complete hardened file is at the end, with a checklist.

The prevalence figures come from [the State of Docker Compose Security
study](state-of-compose.md): 11,111 public Compose files from GitHub, of which
99.2% of the files that parsed carried at least one security finding.
Mostly, they're defaults nobody changed.

## The starting file

A two-service stack, written the way most are:

```yaml
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
    volumes:
      - ./site:/usr/share/nginx/html
    depends_on:
      - db

  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: hunter2
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

Nothing in it is unusual, and `compose-lint check --fail-on low` reports twelve
findings on it: one HIGH, nine MEDIUM, two LOW. The steps below clear them in
the order that matters most.

## 1. Get credentials out of `environment:`

**Share of real files affected: 28.1%** carry a credential-shaped key with a
literal value, and 5.1% embed one in a connection string. This is the
most common acute finding in the study.

A value in `environment:` is returned by `docker inspect` to anyone with
access to the Docker API, is readable from `/proc/<pid>/environ` by processes
in the container running as the same user, and is in git for whoever reads the
file. Compose's `secrets:` element mounts the value as a file at
`/run/secrets/<name>` instead, absent from the environment, the daemon's
metadata and process listings. Images
that follow the `*_FILE` convention (Postgres, MySQL, MariaDB, the Bitnami
images, many others) make it a one-line change:

```yaml
# ❌ Before
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: hunter2

# ✅ After
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password

secrets:
  db_password:
    file: ./secrets/db_password.txt   # add to .gitignore
```

The secret file is an ordinary file you create on the host, next to the
Compose file. It holds the value alone, with no `KEY=` prefix, no quotes and
no trailing newline:

```bash
mkdir -p secrets
openssl rand -base64 32 | tr -d '\n' > secrets/db_password.txt
chmod 600 secrets/db_password.txt
echo 'secrets/' >> .gitignore
```

If the same password also goes into a connection URL, generate it with
`openssl rand -hex 32` instead: base64 output can contain `/`, which ends a
URL's host part.

A new random value only works on a database that has not started yet. The
postgres image reads the password once, when it initialises an empty data
directory, so on the starting file's existing `pgdata` volume it keeps the old
password and refuses the new one. For a database that already holds data, put
its current password in the file instead, as the CL-0020 page's section on
moving an existing database's password shows.

A file-sourced secret is mounted byte for byte and keeps the host file's owner
and mode, so an env-file-style line would become the password, and the
process that reads it in the container must be able to open it. The
CL-0020 page covers both. The same fix applies when the credential lives in an
`env_file:`; that file's values land in the process environment exactly as
`environment:` values do, and keeping it out of git does not change that.

Connection strings with a password inside (`postgresql://app:hunter2@db/app`)
have the same exposure. The CL-0021 page gives three ways
to take the password out, in order of preference.

Rules: [CL-0020](rules/CL-0020.md), [CL-0021](rules/CL-0021.md).

### Secrets vs environment variables

An environment variable is the right place for configuration that is not sensitive: hostnames, feature
flags, log levels. It is the wrong place for anything that would matter if it
leaked, because anyone with Docker API access can read it with `docker inspect`. Compose's
`secrets:` exists for exactly that distinction, and it works outside Swarm: on
a single host, a file-sourced secret is a read-only bind mount of that file.

## 2. Pin the image

**Share of real files affected: 50.2%** use a mutable tag or no tag, and 50.2%
pin a tag but not a digest.

`nginx:latest` means a different image every time the registry's tag moves. You
can't reproduce it or roll it back, and a compromised upstream push deploys
itself. A version tag fixes the first two
problems. A digest fixes the third, because Docker resolves a digest to
content and ignores the tag.

```yaml
# ❌ Before
image: nginx:latest

# ✅ Better
image: nginx:1.27-alpine

# ✅ Best
image: nginx:1.27-alpine@sha256:…
```

Get the digest without pulling the whole image. `crane` runs from its own
container, so nothing needs installing:

```bash
docker run --rm gcr.io/go-containerregistry/crane digest nginx:1.27-alpine
```

Pin the index digest that command returns, not a per-architecture digest; a
per-architecture pin breaks every user on the other architecture. Then let
Renovate or Dependabot bump the digest when the tag moves. Projects that
publish only a `latest` tag can still be digest-pinned:
`image: excalidraw/excalidraw:latest@sha256:<digest>` pulls exactly the image
you pinned until you change the pin.

Rules: [CL-0004](rules/CL-0004.md), [CL-0019](rules/CL-0019.md).

## 3. Bind published ports to an address

**Share of real files affected: 72.0%** publish at least one port on all
interfaces. Steps 4 to 7 score higher, but they count settings a file leaves
out; this is the most common thing a file writes in that it should not.

`"8080:80"` binds to every interface, IPv4 and IPv6 (`0.0.0.0` and `[::]`). Docker publishes a port by writing its own
iptables rules, so the binding is reachable from the network even where UFW or
firewalld would normally block it.

```yaml
# ❌ Before
ports:
  - "8080:80"

# ✅ After
ports:
  - "127.0.0.1:8080:80"
```

A service that has to be reachable from outside goes behind a reverse proxy
that terminates TLS, and only the proxy publishes a port. For a host-wide
answer, Docker's `DOCKER-USER` iptables chain is where firewall rules that
survive Docker's own rules belong; the rule page links Docker's documentation
for it.

Rules: [CL-0005](rules/CL-0005.md).

## 4. Block privilege escalation with `security_opt`

**Share of real files affected: 97.3%** do not set it.

`no-new-privileges` stops a process in the container from gaining privileges
through setuid binaries like `sudo` and `su`. It is one line, and most
services run unchanged with it.

```yaml
# ✅ After
security_opt:
  - no-new-privileges:true
```

Most of what it blocks fails quietly: a setuid helper runs, without the
privilege, and later fails with an ordinary `Permission denied`; the rule
page lists what it breaks and the one message that names the flag. A
container that needs `sudo` in its entrypoint is a container that should be fixed at the image, not by
leaving escalation open; the rule page covers the cases.

While you are in `security_opt`, do not disable the kernel profiles. Docker
applies a seccomp profile and, where available, an AppArmor profile or SELinux
labelling by default. `seccomp:unconfined`, `apparmor:unconfined` and
`label:disable` turn them off, and a workload
that needs a syscall the default profile blocks should get a custom profile
rather than none:

```yaml
# ❌ Never
security_opt:
  - seccomp:unconfined

# ✅ If the default profile is in the way
security_opt:
  - seccomp:./seccomp.json   # the CL-0009 page shows how to build it
```

Rules: [CL-0003](rules/CL-0003.md), [CL-0009](rules/CL-0009.md).

## 5. Drop every capability, then add back the ones the image needs

**Share of real files affected: 98.6%** keep Docker's default capability set.

A container starts with Docker's fixed set of fourteen Linux capabilities. Most workloads use
none of them once running. Dropping them all and only adding back the ones
required removes privileges the service never uses but an attacker could.

```yaml
# ✅ After, for nginx:1.27-alpine
cap_drop:
  - ALL
cap_add:
  - CHOWN      # entrypoint chowns /var/cache/nginx at startup
  - SETUID     # then drops the workers to the nginx user
  - SETGID
```

The list is image-specific. That one is verified for `nginx:1.27-alpine`
against a live daemon; another image needs a different set, and the rule page
has the method for finding it. Two things worth knowing before you start:

- Do not begin from `cap_add: [NET_BIND_SERVICE]`. Under Docker's
  per-container network namespaces a low port needs no capability (since
  Docker 20.10), so it is inert, and on its own it leaves the entrypoint's
  `chown` failing.
- When a container crash-loops after the change, the log line names the
  operation that failed, and the rule page maps each message to the
  capability that clears it.

### Two measured examples

The sets below were determined through testing, not read off documentation. Each was run under
`read_only: true` with the image's own entrypoint and no `user:` override;
one capability was removed at a time, the service restarted, and its real
function exercised. What remains is the set whose removal broke it.

| Image | `cap_add` | `tmpfs` needed under `read_only` | Why |
|---|---|---|---|
| `nginx:1.27-alpine` | `CHOWN, SETUID, SETGID` | `/run`, `/var/cache/nginx` | the entrypoint chowns the cache directory, then drops the workers to the `nginx` user |
| `postgres:16` | `CHOWN, DAC_OVERRIDE, SETGID, SETUID` | `/run/postgresql` | the entrypoint chowns the data and socket directories and switches to the `postgres` user; on every later start it reads the `0700` data directory as root, and it reads the secret file, which Compose mounts with the host file's owner and mode (`0600` after step 1) |

Both follow the most common pattern: an entrypoint that starts as root, fixes
ownership of something, and drops to a service user needs `SETUID` and
`SETGID`, plus `CHOWN` or `DAC_OVERRIDE` for the ownership fix. `FOWNER`,
which entrypoints of this kind often need, was not required for `postgres:16`
under the drop test.

What the postgres measurement shows applies to any image. First,
a capability can be needed by more than one step, so test a restart, not only
the first start. Without `DAC_OVERRIDE` and with the step 1 secret, postgres
fails its first start, unable to read the `0600` file. With a world-readable
secret it initialises and serves, then fails every later start, unable to read
its own `0700` data directory. Second, not every
logged failure is a missing capability: even with the full set, the first
start logs an `Operation not permitted` from a `chmod` of the data
directory, which the entrypoint tolerates because `initdb` sets the mode
itself.

An image that
starts directly as its service user, or that is a single static binary, often
needs nothing at all. Measured for the tags shown in October 2026 on Docker
29.7.2, on a host without AppArmor; the nginx set is also verified on the rule page. A different `user:`, a volume that already
holds data, an overridden entrypoint or a new major version can change a set
in either direction, so measure again for what you run.

### How to find the minimum for any image

There is no trustworthy registry of images to capability sets, because the set
depends on your configuration as much as on the image. The method on the
rule page is short:

1. **Start from nothing.** `cap_drop: [ALL]` with no `cap_add`, then
   `docker compose up`. Many services run this way unchanged.
2. **Exercise the real function, not just startup.** Applications routinely
   catch a capability failure and carry on with that feature silently off.
3. **Read the failure.** A missing capability almost always surfaces as
   `Operation not permitted` in the logs, naming the operation, and
   occasionally as `Permission denied`. The rule page maps the
   common messages to the capability each one needs.
4. **Add back only the capability implicated, one at a time, and repeat.**

For a new service, put `cap_drop: [ALL]`, `read_only: true` and
`no-new-privileges` in its first definition. Adding back what fails is quicker
than proving each default unnecessary later.

### Tools that shorten the search

Reading failures out of logs works, but it is slow when an application
swallows the error. Before you start, check:

- **The entrypoint script.** Most official images publish theirs. A `gosu`,
  `su-exec` or `chown` call in it tells you the capability set before the
  container starts.
- **`docker diff <container>`.** Run against the service before hardening,
  it lists every path written in the writable layer, which is the list
  `read_only: true` will refuse. Volumes do not appear in it, because they
  stay writable.

Tracers (Inspektor Gadget, BCC `capable`) and Mint are on the rule page, with
the caveats that decide whether their output can be trusted. None of these
replace the loop above. They tell you faster what the loop would have told
you.

Rules: [CL-0006](rules/CL-0006.md). The capabilities you add back are graded
too, by what each one reaches: [CL-0024](rules/CL-0024.md) (`ALL`,
`SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`), [CL-0011](rules/CL-0011.md)
(`NET_ADMIN`, `BPF`, `SYS_BOOT`), [CL-0027](rules/CL-0027.md) (`SYS_PTRACE`,
`DAC_READ_SEARCH`), [CL-0028](rules/CL-0028.md) (`PERFMON`, `SYS_TIME`),
[CL-0029](rules/CL-0029.md) (`SYS_NICE`, `IPC_LOCK`, `LEASE`) and
[CL-0030](rules/CL-0030.md) (`SYSLOG`).

## 6. Make the root filesystem read-only

**Share of real files affected: 98.7%** leave it writable.

With `read_only: true`, a process that gets code execution cannot modify the
container's binaries, drop tools, or persist. The paths an application
genuinely writes to become `tmpfs` entries (ephemeral) or volumes (persistent).
Named volumes and bind mounts stay writable under `read_only`; that is what
declaring them means, so persistence through a volume is out of this
setting's reach and is handled by the mount steps below.

```yaml
# ✅ After
read_only: true
tmpfs:
  - /tmp
  - /run
  - /var/cache/nginx
```

Finding the paths: run the service once without `read_only`, exercise it, and
read `docker diff <container>`. It lists the writable-layer writes, which is
exactly what `read_only` will block. Leave `tmpfs` entries without `:exec`
or `:suid` unless the image needs them; Docker mounts every tmpfs `noexec`
and `nosuid` by default, and `:exec` re-enables the download-to-`/tmp`-and-run
playbook. A few images do need it. When yours does, keep the entry and
suppress CL-0022 for that service with the reason recorded, so the exception
is visible instead of silent.

Rules: [CL-0007](rules/CL-0007.md), [CL-0022](rules/CL-0022.md).

## 7. Set memory and CPU limits

**Share of real files affected: 97.4%** lack a memory limit, a CPU limit or
both.

Docker imposes no limit by default, so one runaway or malicious process can
take the host down with it. Set both, sized from what the workload uses at
steady state.

```yaml
# ✅ After
deploy:
  resources:
    limits:
      memory: 512M
      cpus: '0.50'
```

Compose honours `deploy.resources.limits` outside Swarm, so this works for a
plain `docker compose up`. Size memory with more headroom than CPU: a memory
limit kills, a CPU limit only throttles. The rule page has the sizing
procedure and how to read each failure.

Rules: [CL-0026](rules/CL-0026.md).

## 8. Do not run as root when the image does not need to

An explicit `user: root` overrides whatever user the image was built to run
as. Remove it and let the image decide, or set a specific non-root user. When
the image needs root at startup to fix volume ownership and then drops
privileges, that is what the capabilities in step 5 are for.

```yaml
# ❌ Before
user: root

# ✅ After — let the image decide, or:
user: "1000:1000"
```

A non-root user cannot write a bind mount the host owns as root, and Compose
creates a missing bind source as root. The rule page walks through fixing the
ownership rather than reverting to root.

Rules: [CL-0018](rules/CL-0018.md).

## 9. Keep the Docker socket out of containers

**Share of real files affected: 7.8%** mount the host's control socket.

A container that can reach `/var/run/docker.sock` can start a privileged
container with the host's root filesystem mounted. It is host root with one
extra step, and `:ro` does not change that; the API accepts writes over a
read-only socket mount. compose-lint rates it CRITICAL, and in the study it is
the most common CRITICAL finding.

The right fix depends on why the socket is there, and there are four correct
answers, in order of preference: delete the service that wanted it, re-design
so it is not needed, put a filtering proxy in front of it that exposes only
the API endpoints required, or suppress the finding with the risk written
down and a review date. [The examples library](examples/index.md) shows a
deployed stack for each of the four. The proxy pattern, from the
[netdata example](examples/netdata-socket-proxy/index.md), looks like this:

```yaml
services:
  docker-socket-proxy:
    image: wollomatic/socket-proxy:1@sha256:…
    user: "65534:${DOCKER_GID}"   # nobody, plus the host docker group
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./sockets:/sock
    command:
      - -proxysocketendpoint=/sock/docker.sock
      - -proxysocketendpointfilemode=432   # 0660, so a consumer in the docker group can connect
      # Only the GET endpoints the consumer calls; every write answers 405.
      - -allowGET=^(/v[0-9]+\.[0-9]+)?/(_ping|version|info|images/json(\?.*)?|containers/json(\?.*)?|containers/[a-zA-Z0-9_.-]+/json(\?.*)?)$$

  netdata:
    # image and the rest as in the netdata example; it runs as root
    environment:
      DOCKER_HOST: unix:///sock/docker.sock
    volumes:
      - ./sockets:/sock               # the filtered socket, not the real one
```

The proxy runs as `nobody`, so create its socket directory for the docker
group, and give Compose the group id, before the first start:

```bash
install -d -m 0770 -g docker sockets
echo "DOCKER_GID=$(getent group docker | cut -d: -f3)" >> .env
```

Without the first line the proxy cannot create its socket and exits. A
consumer that runs as root, as netdata does, connects to the `0660` socket as
it is; a non-root consumer needs the docker group, as the CL-0001 page's
example shows.

The proxy still holds the socket, so it has to be at least as hardened as
anything else would be, and its CL-0001 finding is suppressed for that one
service with the reason written down, so the rule stays live for the rest of
the stack.

One key grants the socket without a `volumes:` line. `use_api_socket: true`
(Compose 2.37.1 and later) bind-mounts the socket read-write and copies the
registry logins of whoever runs `docker compose up` into the container as
well, so the service can push and pull as that person. Engine-management
tools such as Docker's MCP gateway ask for it. The same four answers apply,
with one more consideration for the credential half: it can only be narrowed
on the host, by running the stack from a deploy identity whose Docker config
holds no logins the stack does not need.

Rules: [CL-0001](rules/CL-0001.md), [CL-0031](rules/CL-0031.md).

## 10. Never `privileged: true`

**Share of real files affected: 2.4%.**

`privileged: true` grants every capability, disables the seccomp and AppArmor
profiles, and exposes every host device. It is often added to get a stuck
container running. Use the narrower setting instead:

| Need | Instead of `privileged: true` |
|---|---|
| Access to one device | `devices: [/dev/foo]` |
| Network configuration | `cap_add: [NET_ADMIN, NET_RAW]` |
| A debugger sidecar | `cap_add: [SYS_PTRACE]` with `pid: "service:<name>"`, so it sees only that service's processes (`SYS_PTRACE` also reads their memory) |
| Docker-in-Docker | the `sysbox-runc` runtime. Rootless DinD is not a way out: it still needs `privileged`, or seccomp unconfined plus more (see the rule page) |

Narrower is not free: `NET_ADMIN` is itself a HIGH finding and `SYS_PTRACE`
is graded too. If you do not know which capability a workload needs, remove
`privileged: true`, run it, and add back only what the failure names.

Rules: [CL-0002](rules/CL-0002.md), [CL-0011](rules/CL-0011.md),
[CL-0027](rules/CL-0027.md).

## 11. Keep host namespaces and host networking off

**Share of real files affected: 2.8%** use `network_mode: host`.

`network_mode: host` puts the container on the host's interfaces directly.
Port-publish rules do not apply, so the firewall bypass from step 3 becomes
total, and the container sees every host interface. Bridge networking with an
explicit port mapping restores the isolation. `pid: host` and `ipc: host` share the host's process
and shared-memory namespaces; a sidecar that needs to see another container's
processes can use `pid: "service:<name>"` instead.

```yaml
# ❌ Before
network_mode: host
pid: host

# ✅ After
ports:
  - "127.0.0.1:8080:8080"
networks:
  - app-network
```

Rules: [CL-0008](rules/CL-0008.md), [CL-0010](rules/CL-0010.md).

## 12. Look hard at every host path you mount

**Share of real files affected: 2.5%** bind-mount a sensitive host path
that CL-0013 flags. Writable mounts of root-equivalent paths, CL-0025's
subject, are under 2%.

A bind mount of `/etc`, `/proc`, `/root`, `/var/lib/docker` or a home
directory hands the container the host's secrets even when read-only. Writable,
`/etc`, `/root`, `/proc` and `/var/lib/docker` hand it the host itself;
`/var/lib/docker` writable is every other container's filesystem. Device nodes under `devices:` and `shared` mount propagation open
further routes. The questions to ask of each `volumes:` entry:

- Does the container need this path at all, or a copy of some of it? A named
  volume or a `COPY` at build time usually replaces a host bind.
- If it needs the host path, does it need to write? Add `:ro`.
- Is it `/dev/shm`? The container already has its own; if the bind is there
  because 64 MiB is too small, set `shm_size:` instead of sharing the host's.

```yaml
# ❌ Before
volumes:
  - /etc:/host-etc
  - ./site:/usr/share/nginx/html

# ✅ After
volumes:
  - ./site:/usr/share/nginx/html:ro
```

Rules: [CL-0013](rules/CL-0013.md), [CL-0025](rules/CL-0025.md),
[CL-0016](rules/CL-0016.md), [CL-0017](rules/CL-0017.md).

## 13. Keep logs on

`logging: driver: none` discards the container's output at the daemon.
`docker logs` returns an error, nothing reaches a log shipper, and an incident
in that container leaves no record. Rotate instead of disabling:

```yaml
# ✅ After
logging:
  driver: json-file
  options:
    max-size: 10m
    max-file: '3'
```

Rules: [CL-0014](rules/CL-0014.md).

## The hardened file

The starting file with every step applied. With real digests in place of the
shortened ones, `compose-lint check --fail-on low` reports no findings on it:
the twelve findings at the top of the page become none.

```yaml
services:
  web:
    image: nginx:1.27-alpine@sha256:…               # step 2
    ports:
      - "127.0.0.1:8080:80"                          # step 3
    volumes:
      - ./site:/usr/share/nginx/html:ro              # step 12
    read_only: true                                  # step 6
    tmpfs:
      - /tmp
      - /run
      - /var/cache/nginx
    cap_drop:                                        # step 5
      - ALL
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
    security_opt:                                    # step 4
      - no-new-privileges:true
    deploy:                                          # step 7
      resources:
        limits:
          memory: 128M
          cpus: '0.50'
    logging:                                         # step 13
      driver: json-file
      options:
        max-size: 10m
        max-file: '3'
    depends_on:
      - db

  db:
    image: postgres:16@sha256:…                      # step 2
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password   # step 1
    secrets:
      - db_password
    volumes:
      - pgdata:/var/lib/postgresql/data
    read_only: true                                  # step 6
    tmpfs:
      - /run/postgresql
    cap_drop:                                        # step 5
      - ALL
    cap_add:                                         # measured minimum
      - CHOWN                                        # for postgres:16,
      - DAC_OVERRIDE                                 # see step 5
      - SETGID
      - SETUID
    security_opt:                                    # step 4
      - no-new-privileges:true
    deploy:                                          # step 7
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
    logging:                                         # step 13
      driver: json-file
      options:
        max-size: 10m
        max-file: '3'

volumes:
  pgdata:

secrets:
  db_password:
    file: ./secrets/db_password.txt
```

Both capability lists are measured ones: `web` is the set the
[CL-0006](rules/CL-0006.md) page verifies for `nginx:1.27-alpine`, and `db`
is the `postgres:16` example in step 5. Without the `/run/postgresql`
tmpfs, postgres cannot create its lock file and exits under `read_only`;
step 6's `docker diff` pass is there to predict paths like that one. Measure again for the
versions you run.

## Checklist

| Setting | Rule | Real files skipping it |
|---|---|---|
| Credentials in `secrets:`, not `environment:` or `env_file:` | [CL-0020](rules/CL-0020.md), [CL-0021](rules/CL-0021.md) | 28.1% / 5.1% |
| Image pinned to a tag | [CL-0004](rules/CL-0004.md) | 50.2% |
| Image pinned to a digest | [CL-0019](rules/CL-0019.md) | 50.2% |
| Published ports bound to an address | [CL-0005](rules/CL-0005.md) | 72.0% |
| `no-new-privileges:true` | [CL-0003](rules/CL-0003.md) | 97.3% |
| Seccomp, AppArmor and SELinux labelling left on | [CL-0009](rules/CL-0009.md) | — |
| `cap_drop: [ALL]`, image-specific `cap_add` | [CL-0006](rules/CL-0006.md) | 98.6% |
| Added capabilities limited to what the image needs | [CL-0011](rules/CL-0011.md), [CL-0024](rules/CL-0024.md), [CL-0027](rules/CL-0027.md) to [CL-0030](rules/CL-0030.md) | 3.5% / under 2% |
| `read_only: true` with `tmpfs` for writable paths | [CL-0007](rules/CL-0007.md) | 98.7% |
| No `:exec` or `:suid` on `tmpfs` | [CL-0022](rules/CL-0022.md) | — |
| Memory and CPU limits | [CL-0026](rules/CL-0026.md) | 97.4% |
| No explicit `user: root` | [CL-0018](rules/CL-0018.md) | — |
| No Docker socket mount | [CL-0001](rules/CL-0001.md) | 7.8% |
| No `privileged: true` | [CL-0002](rules/CL-0002.md) | 2.4% |
| No `network_mode: host`, `pid: host`, `ipc: host` | [CL-0008](rules/CL-0008.md), [CL-0010](rules/CL-0010.md) | 2.8% / under 2% |
| Host paths mounted only when needed, `:ro` where possible | [CL-0013](rules/CL-0013.md), [CL-0025](rules/CL-0025.md) | 2.5% / under 2% |
| No host devices, no `shared` mount propagation | [CL-0016](rules/CL-0016.md), [CL-0017](rules/CL-0017.md) | — |
| Logging driver not `none` | [CL-0014](rules/CL-0014.md) | — |

Run `compose-lint check --fail-on low compose.yaml` to check the file against
all of it at once; `compose-lint fix` applies the steps that can be applied
mechanically and shows the diff before writing anything.

## Questions that come up

**Does binding to 127.0.0.1 fix the firewall problem?** For that port, yes:
nothing off the host can reach it. For the host as a whole, no; any other
service that publishes on `0.0.0.0` still bypasses UFW or firewalld. The `DOCKER-USER`
chain is the host-wide answer. See [CL-0005](rules/CL-0005.md).

**My container crash-loops after `cap_drop: ALL`. Which capability is it?**
The log line names the operation that failed. The
[CL-0006](rules/CL-0006.md) page maps each message to the capability it
needs and explains how to find the full set for an image.

**My `.env` is gitignored. Do I still need `secrets:`?** Yes. Gitignoring
keeps the value out of git, but it still lands in the container's environment,
where `docker inspect` shows it to anyone with Docker API access. See [CL-0020](rules/CL-0020.md).

**The image only publishes `latest`. How do I pin it?** By digest:
`image: name:latest@sha256:<digest>`. Docker resolves by digest and ignores
the tag for content, so you keep pulling the image you pinned until you change
the pin. See [CL-0004](rules/CL-0004.md).

**Does a hardened Compose file mean I can drop my image scanner?** No. This
page and compose-lint cover the Compose file: how the container is run. What
is inside the image, and how the image was built, are the image scanner's and
the Dockerfile linter's jobs. [The comparison page](compare.md) sets out what
each tool reads.

**Where do I start if I can only do one thing?** Step 1 if any credential is in
`environment:`; otherwise step 4, `no-new-privileges`, because it is one line
and rarely changes what a service does (step 4 says what it quietly breaks
when it does), and then step 5.

## Running compose-lint itself hardened

The linter's own container follows this page. The fully hardened `docker run`
for it, with each flag mapped to the rule it satisfies, is on
[Running compose-lint hardened](running-hardened.md).
