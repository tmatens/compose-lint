# Docker Compose security: a hardening guide

This page takes an ordinary Compose file from Docker's defaults to a hardened
configuration, one setting at a time. Each step shows the change, says why it
matters, gives the share of real-world files that skip it, and links the rule
page that holds the details, the failure signatures, and the exceptions. The
complete hardened file is at the end, with a checklist.

The prevalence figures come from [the State of Docker Compose Security
study](state-of-compose.md): 11,111 public Compose files from GitHub, of which
99.2% of the files that parsed carried at least one security finding. The
pattern behind that number is the point of this page. The findings are mostly
not exotic mistakes. They are hardening settings that Docker leaves off by
default and almost nobody turns on.

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
that follow the `*_FILE` convention (Postgres, MySQL, MariaDB, MinIO, the
Bitnami images, many others) make it a one-line change:

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

A file-sourced secret is mounted byte for byte and keeps the host file's owner
and mode, so an env-file-style line would become the password, and the
process that reads it in the container must be able to open it. The
[CL-0020](rules/CL-0020.md) page covers both. The same fix applies when the credential lives in an
`env_file:`; that file's values land in the process environment exactly as
`environment:` values do, and keeping it out of git does not change that.

Connection strings with a password inside (`postgresql://app:hunter2@db/app`)
have the same exposure. The [CL-0021](rules/CL-0021.md) page gives three ways
to take the password out, in order of preference.

Rules: [CL-0020](rules/CL-0020.md), [CL-0021](rules/CL-0021.md).

### Secrets vs environment variables

The question comes up often enough to answer directly. An environment variable
is the right place for configuration that is not sensitive: hostnames, feature
flags, log levels. It is the wrong place for anything that would matter if it
leaked, because the container's environment is not a private place. Compose's
`secrets:` exists for exactly that distinction, and it works outside Swarm: on
a single host, a file-sourced secret is a read-only bind mount of that file.

## 2. Pin the image

**Share of real files affected: 50.2%** use a mutable tag or no tag, and 50.2%
pin a tag but not a digest.

`nginx:latest` means a different image every time the registry's tag moves. It
breaks reproducibility, makes a rollback impossible, and turns a compromised
upstream push into an automatic deployment. A version tag fixes the first two
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

Get the digest without pulling the whole image:

```bash
crane digest nginx:1.27-alpine
# or
docker buildx imagetools inspect nginx:1.27-alpine --format '{{ .Manifest.Digest }}'
```

Pin the index digest those commands return, not a per-architecture digest; a
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

`"8080:80"` binds to `0.0.0.0`. Docker publishes a port by writing its own
iptables rules, so the binding is reachable from the network even where UFW or
firewalld would normally block it. That is the mechanism behind the
long-running "Docker bypasses my firewall" surprise.

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
through setuid binaries like `sudo` and `su`. It is one line, it costs nothing
for almost every workload, and it closes a whole class of escalation.

```yaml
# ✅ After
security_opt:
  - no-new-privileges:true
```

Most of what it blocks fails quietly: a setuid helper runs, without the
privilege, and later fails with an ordinary `Permission denied`. The one
failure that names the flag is `sudo`: `sudo: The "no new privileges" flag is
set, which prevents sudo from running as root.` A container that needs `sudo` in
its entrypoint is a container that should be fixed at the image, not by
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
  - seccomp:custom-seccomp.json
```

Rules: [CL-0003](rules/CL-0003.md), [CL-0009](rules/CL-0009.md).

## 5. Drop every capability, then add back the ones the image needs

**Share of real files affected: 98.6%** keep Docker's default capability set.

A container starts with Docker's fixed set of fourteen Linux capabilities. Most workloads use
none of them once running. Dropping them all and adding back the specific ones
an image's entrypoint needs is the single biggest reduction in what a
compromised process can do.

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
  missing capability. `chown(...) failed (1: Operation not permitted)` is
  `CHOWN`. The rule page maps the common "Operation not permitted" messages
  to the capability that clears each one.

### Two measured examples

The sets below were measured, not read off documentation. Each was run under
`read_only: true` with the image's own entrypoint and no `user:` override;
one capability was removed at a time, the service restarted, and its real
function exercised. What remains is the set whose removal broke it.

| Image | `cap_add` | `tmpfs` needed under `read_only` | Why |
|---|---|---|---|
| `nginx:1.27-alpine` | `CHOWN, SETUID, SETGID` | `/tmp`, `/run`, `/var/cache/nginx` | the entrypoint chowns the cache directory, then drops the workers to the `nginx` user |
| `postgres:16` | `CHOWN, DAC_OVERRIDE, SETGID, SETUID` | `/run/postgresql` | the entrypoint chowns the data and socket directories and switches to the `postgres` user; on every later start it reads the `0700` data directory as root, and it reads the secret file, which Compose mounts `0600` and owned by the host user |

Both follow the most common pattern: an entrypoint that starts as root, fixes
ownership of something, and drops to a service user needs `SETUID` and
`SETGID`, plus `CHOWN` or `DAC_OVERRIDE` for the ownership fix. `FOWNER`,
which entrypoints of this kind often need, was not required for `postgres:16`
under the drop test.

Two things the postgres measurement shows that apply to any image. First,
test a restart, not only the first start: without `DAC_OVERRIDE` postgres
initialises and serves, then fails every later start with
`find: '/var/lib/postgresql/data': Permission denied`. Second, not every
logged failure is a missing capability: even with the full set, the first
start logs `chmod: changing permissions of '/var/lib/postgresql/data':
Operation not permitted`, which the entrypoint tolerates because `initdb`
sets the mode itself.

An image that
starts directly as its service user, or that is a single static binary, often
needs nothing at all. Measured for the tags shown in October 2026 on Docker
29; the nginx set is also verified on the rule page. A different `user:`, a volume that already
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

### Tools that shorten the search

Reading failures out of logs works, but it is slow when an application
swallows the error, and it says nothing about what the service would have
written to a read-only root. These narrow the loop. All of them run on the
host and need root there.

- **The entrypoint script.** Most official images publish theirs. A `gosu`,
  `su-exec` or `chown` call in it tells you the capability set before the
  container starts.
- **`docker diff <container>`.** Run against the service before hardening,
  it lists every path written in the writable layer, which is the list
  `read_only: true` will refuse. Volumes do not appear in it, because they
  stay writable.
- **Inspektor Gadget** (`ig`). `ig run trace_capabilities --containername
  <name>` prints each capability check a container's processes trigger, with
  a `CAPABLE` column that reads `false` when the check failed. Run the real
  workload with `cap_drop: [ALL]` in place and the failed rows are the set to
  add back. `ig run trace_open --containername <name> --failed` does the same
  for file opens, with the path and the error, which is the quickest way to
  see what a read-only root refused.
- **BCC `capable`** (bpftrace ships `capable.bt`). A capability trace across
  the whole host rather than one container; useful where `ig` is not
  available. It lists the checks, not whether they failed, so treat its
  output as candidates and confirm each one with a drop-and-observe run.
- **Mint** (formerly DockerSlim). Its `slim` command runs the image in a
  temporary container, observes it, and generates seccomp and AppArmor
  profiles from what it saw. The result is only as complete as the workload
  it watched, so the same rule applies: exercise the real function, not just
  startup, before trusting the profile.

None of these replace the loop above. They tell you faster what the loop
would have told you.

### Start new services from nothing

The method above is for a service that is already running with Docker's
defaults and has to be hardened in place, where every removed privilege is a
possible regression and nobody remembers which ones are load-bearing. A new
service has none of that history. Write `cap_drop: [ALL]`, `read_only: true`
and `no-new-privileges` into its first definition, bring it up, and add back
only what the first failure names. Starting from nothing and adding one
capability is a few minutes of work. Starting from everything and proving
each capability unnecessary is an afternoon, which is why it rarely happens
and why the study's numbers look the way they do.

Rules: [CL-0006](rules/CL-0006.md). The capabilities you add back are graded
too, by what each one reaches: [CL-0011](rules/CL-0011.md),
[CL-0024](rules/CL-0024.md), [CL-0027](rules/CL-0027.md),
[CL-0028](rules/CL-0028.md), [CL-0029](rules/CL-0029.md),
[CL-0030](rules/CL-0030.md).

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

**Share of real files affected: 97.4%** set neither.

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
limit kills (exit code 137, `OOMKilled: true`, no log line), a CPU limit only
throttles. The rule page has the sizing procedure and the failure table.

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

Non-root on a bind mount the host owns as root fails with `Permission denied`.
The rule page walks through fixing the ownership rather than reverting to
root.

Rules: [CL-0018](rules/CL-0018.md).

## 9. Keep the Docker socket out of containers

**Share of real files affected: 7.8%** mount the host's control socket.

A container that can reach `/var/run/docker.sock` can start a privileged
container with the host's root filesystem mounted. It is host root with one
extra step, and `:ro` does not change that; the API accepts writes over a
read-only socket mount. The study rates it CRITICAL and it is the most common
CRITICAL finding.

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
      - -proxysocketendpointfilemode=432   # 0660, so the consumer can connect
      # Only the GET endpoints the consumer calls; every write answers 405.
      - -allowGET=^(/v[0-9]+\.[0-9]+)?/(_ping|version|info|images/json(\?.*)?|containers/json(\?.*)?|containers/[a-zA-Z0-9_.-]+/json(\?.*)?)$$

  netdata:
    environment:
      DOCKER_HOST: unix:///sock/docker.sock
    volumes:
      - ./sockets:/sock               # the filtered socket, not the real one
```

The proxy still holds the socket, so it has to be at least as hardened as
anything else would be, and its CL-0001 finding is suppressed for that one
service with the reason written down, so the rule stays live for the rest of
the stack.

Rules: [CL-0001](rules/CL-0001.md).

## 10. Never `privileged: true`

**Share of real files affected: 2.4%.**

`privileged: true` grants every capability, disables the seccomp and AppArmor
profiles, and exposes every host device. It usually arrives as a fix for a
container that would not start, and then stays in the file long after anyone
remembers what it fixed. Each of the reasons people reach for it has a narrower setting:

| Need | Instead of `privileged: true` |
|---|---|
| Access to one device | `devices: [/dev/foo]` |
| Network configuration | `cap_add: [NET_ADMIN, NET_RAW]` |
| A debugger sidecar | `cap_add: [SYS_PTRACE]` (which also reads other processes' memory) |
| Docker-in-Docker | `sysbox-runc` or rootless DinD |

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
explicit port mapping buys the isolation back. `pid: host` and `ipc: host` share the host's process
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

**Share of real files affected: 2.5%** bind-mount a sensitive host path.

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
tmpfs, postgres fails under `read_only` with `FATAL:  could not create lock
file "/var/run/postgresql/.s.PGSQL.5432.lock": Read-only file system`, which is the kind of line
step 6's `docker diff` pass is there to predict. Measure again for the
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
| `read_only: true` with `tmpfs` for writable paths | [CL-0007](rules/CL-0007.md) | 98.7% |
| No `:exec` or `:suid` on `tmpfs` | [CL-0022](rules/CL-0022.md) | — |
| Memory and CPU limits | [CL-0026](rules/CL-0026.md) | 97.4% |
| No explicit `user: root` | [CL-0018](rules/CL-0018.md) | — |
| No Docker socket mount | [CL-0001](rules/CL-0001.md) | 7.8% |
| No `privileged: true` | [CL-0002](rules/CL-0002.md) | 2.4% |
| No `network_mode: host`, `pid: host`, `ipc: host` | [CL-0008](rules/CL-0008.md), [CL-0010](rules/CL-0010.md) | 2.8% |
| Host paths mounted only when needed, `:ro` where possible | [CL-0013](rules/CL-0013.md), [CL-0025](rules/CL-0025.md) | 2.5% |
| No host devices, no `shared` mount propagation | [CL-0016](rules/CL-0016.md), [CL-0017](rules/CL-0017.md) | — |
| Logging driver not `none` | [CL-0014](rules/CL-0014.md) | — |

Run `compose-lint check --fail-on low compose.yaml` to check the file against
all of it at once; `compose-lint fix` applies the steps that can be applied
mechanically and shows the diff before writing anything.

## Questions that come up

**Does binding to 127.0.0.1 fix the firewall problem?** For that port, yes:
nothing off the host can reach it. For the host as a whole, no; any other
service that publishes on `0.0.0.0` still bypasses UFW. The `DOCKER-USER`
chain is the host-wide answer. See [CL-0005](rules/CL-0005.md).

**My container crash-loops after `cap_drop: ALL`. Which capability is it?**
The log line says. `Operation not permitted` on a `chown` is `CHOWN`; on a
`setuid` or `setgid` call it is `SETUID` and `SETGID` together. The
[CL-0006](rules/CL-0006.md) page maps the messages to the capabilities and
explains how to find the full set for an image.

**My `.env` is gitignored. Do I still need `secrets:`?** Yes. The gain is not
that the value leaves git, which it may already have. It is that the value
leaves the container's process environment, which `docker inspect` returns
to anyone with Docker API access. See [CL-0020](rules/CL-0020.md).

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
with no workload cost, and then step 5.

## Running compose-lint itself hardened

The linter's own container follows this page. The fully hardened `docker run`
for it, with each flag mapped to the rule it satisfies, is on
[Running compose-lint hardened](running-hardened.md).
