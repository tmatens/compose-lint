---
title: "Docker Compose security: hardening one file, from 12 findings to none"
published: false
description: An ordinary two-service Compose file, hardened one setting at a time, with the share of public files that skip each step.
tags: docker, security, devops, selfhosted
canonical_url:
---

> **Source for the dev.to article.** A shorter, first-person version of the
> guide at [docs/hardening.md](../hardening.md). The article is
> [on dev.to](https://dev.to/tmatens/docker-compose-security-hardening-one-file-from-12-findings-to-none-4hl7),
> scheduled for 2026-11-17, and the link works from then. Everything below
> this note is the article body, starting at "Earlier this year". See
> [README.md](README.md) for how the article is updated.

Earlier this year I ran [compose-lint](https://tmatens.github.io/compose-lint/), a security linter for Docker Compose files that I maintain, against 11,111 public Compose files from GitHub. Of the ones that parsed, 99.2% had at least one security finding. I don't think that says much about the people who wrote them. Docker gives a container some protection by default, but most of the optional hardening is left for you to turn on, and most of the examples people copy from don't.

[The study](https://tmatens.github.io/compose-lint/state-of-compose/) shows how common each gap is, but it doesn't show how to close them. That's what this post is for. I took an ordinary two-service file, nginx in front of Postgres, and hardened it one setting at a time. For each step I show the change, explain why it matters, and give the share of files in the study that skip it. Every percentage is a share of the 5,907 files that parsed. The finished file is at the end, with a checklist.

Some of these settings will break a service the first time you turn them on, and I've tried to say where. The capability lists and tmpfs paths in this post come from testing against running containers.

None of these findings is a vulnerability on its own. Most of the steps limit what someone can do after they already have code running in one of your containers. A few, like credentials and published ports, are about what's exposed before that.

Each step links to a rule page that has the details, the error messages you'll see when something breaks, and the exceptions.

## The starting file

Here's a two-service stack, written the way most of them are:

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

Nothing in it is unusual. When I run `compose-lint check --fail-on low` on it, I get twelve findings: one HIGH, nine MEDIUM and two LOW. The first seven steps below clear all twelve. The rest cover things this file doesn't do but plenty of others do.

## 1. Get credentials out of `environment:`

In the study, 28.2% of files have a credential-shaped key with a literal value, and 5.1% have a password inside a connection string.

A value in `environment:` has three problems. Anything that can read container metadata through the Docker API gets it from `docker inspect`, and that includes monitoring agents that were only given read access. Processes in the container running as the same user can read it from `/proc/<pid>/environ`. And it's in git for whoever reads the file.

Compose's `secrets:` element mounts the value as a file at `/run/secrets/<name>`, so it stays out of the environment, the daemon's metadata and process listings. Images that follow the `*_FILE` convention (Postgres, MySQL, MariaDB, the Bitnami images and many others) make it a small change. It works outside Swarm. On a single host, a file-sourced secret is a read-only bind mount of that file.

This doesn't protect the value from someone who has full control of Docker on the host. They can read the file as easily as the variable, and the file is plain text on disk. What it does is keep the value out of the places that leak more often: inspect output, the environment every child process inherits, and anything that writes its environment to a log.

```yaml
# Before
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: hunter2

# After
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

The secret file is an ordinary file you create on the host, next to the Compose file. It holds only the value, with no `KEY=` prefix, no quotes and no trailing newline:

```bash
mkdir -p secrets
openssl rand -base64 32 | tr -d '\n' > secrets/db_password.txt
chmod 600 secrets/db_password.txt
echo 'secrets/' >> .gitignore
```

If the same password also goes into a connection URL, generate it with `openssl rand -hex 32`. Base64 output can contain `/`, which ends the host part of a URL.

Before you rely on it, check these:

- **An existing database keeps its old password.** The postgres image reads the password once, when it initializes an empty data directory. For a database that already holds data, put its current password in the file. The [CL-0020](https://tmatens.github.io/compose-lint/rules/CL-0020/) page has a section on this.
- **The file is mounted byte for byte, with the host file's owner and mode.** A line like `KEY=value` would become the whole password, and the process in the container has to be able to open the file.
- **`env_file:` has the same exposure.** Its values land in the process environment the same way `environment:` values do, and keeping the file out of git doesn't change that.
- **So does a connection string with a password inside,** like `postgresql://app:hunter2@db/app`. The [CL-0021](https://tmatens.github.io/compose-lint/rules/CL-0021/) page gives three ways to take the password out.

Rules: [CL-0020](https://tmatens.github.io/compose-lint/rules/CL-0020/), [CL-0021](https://tmatens.github.io/compose-lint/rules/CL-0021/).

## 2. Pin the image

In the study, 50.2% of files have at least one image on a mutable tag or no tag at all, and 50.2% have at least one image with a tag but no digest. The two numbers match by coincidence. They're 2,963 and 2,967 files.

`nginx:latest` means a different image every time the registry's tag moves. You can't reproduce it or roll it back, and a compromised upstream push deploys itself. A version tag mostly fixes the first two, although a tag like `1.30-alpine` still gets rebuilt and re-pushed when its base image is patched. A digest fixes all three, because Docker resolves a digest to content and ignores the tag.

```yaml
# Before
image: nginx:latest

# Better
image: nginx:1.30-alpine

# Best
image: nginx:1.30-alpine@sha256:…
```

You can get the digest without pulling the whole image. `crane` runs from its own container, so there's nothing to install:

```bash
docker run --rm gcr.io/go-containerregistry/crane digest nginx:1.30-alpine
```

Pin the index digest that command returns. A per-architecture digest breaks everyone on the other architecture. Then let Renovate or Dependabot bump the digest when the tag moves.

Projects that only publish a `latest` tag can still be pinned by digest. `image: excalidraw/excalidraw:latest@sha256:<digest>` pulls the image you pinned until you change the pin.

Rules: [CL-0004](https://tmatens.github.io/compose-lint/rules/CL-0004/), [CL-0019](https://tmatens.github.io/compose-lint/rules/CL-0019/).

## 3. Bind published ports to an address

In the study, 72.1% of files publish at least one port on all interfaces. Steps 4 to 7 have higher numbers, but those count settings a file leaves out. This is the most common thing a file writes that it shouldn't.

`"8080:80"` binds to every interface, IPv4 and IPv6. Docker publishes a port by writing its own iptables rules, so the port is reachable from the network even where UFW or firewalld would normally block it.

```yaml
# Before
ports:
  - "8080:80"

# After
ports:
  - "127.0.0.1:8080:80"
```

A service that has to be reachable from outside should go behind a reverse proxy that terminates TLS, so that only the proxy publishes a port. If you want a host-wide answer, Docker's `DOCKER-USER` iptables chain is where firewall rules go if they need to survive Docker's own rules. The rule page links Docker's documentation for it. Docker's newer nftables backend, which is still experimental, doesn't have that chain.

On Docker 28 and later, nothing off the host can reach a port bound to `127.0.0.1`. Before 28.0, a machine on the same network segment could.

Rule: [CL-0005](https://tmatens.github.io/compose-lint/rules/CL-0005/).

## 4. Block privilege escalation with `security_opt`

In the study, 97.3% of files don't set this.

`no-new-privileges` stops a process in the container from gaining privileges through setuid binaries like `sudo` and `su`. It's one line, and most services run unchanged with it.

```yaml
security_opt:
  - no-new-privileges:true
```

When it does break something, it usually breaks quietly. A setuid helper runs without the privilege and fails later with an ordinary `Permission denied`. The rule page lists what it breaks and the one message that names the flag. If a container needs `sudo` in its entrypoint, I'd fix that in the image before I'd leave escalation open.

While you're in `security_opt`, leave the kernel profiles on. Docker applies a seccomp profile by default and, where available, an AppArmor profile or SELinux labelling. `seccomp:unconfined`, `apparmor:unconfined` and `label:disable` turn them off. If a workload needs a syscall the default profile blocks, give it a custom profile:

```yaml
# Don't do this
security_opt:
  - seccomp:unconfined

# If the default profile is in the way
security_opt:
  - seccomp:./seccomp.json   # the CL-0009 page shows how to build it
```

Rules: [CL-0003](https://tmatens.github.io/compose-lint/rules/CL-0003/), [CL-0009](https://tmatens.github.io/compose-lint/rules/CL-0009/).

## 5. Drop every capability, then add back the ones the image needs

In the study, 98.6% of files keep Docker's default capability set.

A container starts with a fixed set of fourteen Linux capabilities. Most workloads use none of them once they're running. If you drop them all and add back only what's required, you remove privileges the service never uses but an attacker could.

```yaml
# For nginx:1.30-alpine
cap_drop:
  - ALL
cap_add:
  - CHOWN      # entrypoint chowns /var/cache/nginx at startup
  - SETUID     # then drops the workers to the nginx user
  - SETGID
```

The list depends on the image. That one is verified for `nginx:1.30-alpine` against a live daemon, and another image will need a different set.

Don't begin from `cap_add: [NET_BIND_SERVICE]`. Since Docker 20.10 a low port needs no capability inside a container's own network namespace, so it does nothing, and on its own it leaves the entrypoint's `chown` failing.

When a container crash-loops after the change, the log line names the operation that failed. The [CL-0006](https://tmatens.github.io/compose-lint/rules/CL-0006/) page maps each message to the capability that clears it.

### Two measured examples

I got the sets below by testing. Each image ran under `read_only: true` with its own entrypoint and no `user:` override. I removed one capability at a time, restarted the service, and exercised what it's actually for. What's left is the set where removing any one of them broke something.

| Image | `cap_add` | `tmpfs` needed under `read_only` | Why |
|---|---|---|---|
| `nginx:1.30-alpine` | `CHOWN, SETUID, SETGID` | `/run`, `/var/cache/nginx` | The entrypoint chowns the cache directory, then drops the workers to the `nginx` user. |
| `postgres:16` | `CHOWN, DAC_OVERRIDE, SETGID, SETUID` | `/run/postgresql` | The entrypoint chowns the data and socket directories and switches to the `postgres` user. As root it also has to read the `0700` data directory and the `0600` secret file. |

The postgres result showed me that a capability can be needed by more than one step, so test a restart and not only the first start. Without `DAC_OVERRIDE` and with the secret from step 1, postgres fails its first start because it can't read the `0600` file. With a world-readable secret it initializes and serves, then fails every later start because it can't read its own `0700` data directory.

I measured both sets on Docker 29, in October and November 2026. A different `user:`, a volume that already holds data, an overridden entrypoint or a new major version can change a set in either direction, so measure again for what you run.

### How to find the minimum for any image

I haven't found a registry of capability sets per image that I'd trust, and I don't think one can exist, because the set depends on your configuration as much as on the image. The method is short:

1. Start from nothing. Use `cap_drop: [ALL]` with no `cap_add`, then `docker compose up`. Many services run this way unchanged.
2. Exercise the real function and not only startup. Applications often catch a capability failure and carry on with that feature silently turned off.
3. Read the failure. A missing capability almost always shows up as `Operation not permitted` in the logs, naming the operation. Occasionally it's `Permission denied`.
4. Add back only the capability that failure points to, one at a time, and repeat.

For a new service, I'd put `cap_drop: [ALL]`, `read_only: true` and `no-new-privileges` in its first definition. Adding back what fails is quicker than proving later that each default was unnecessary.

The capabilities you add back are graded too, by what each one can reach. `SYS_ADMIN` and `NET_ADMIN` are findings in their own right. The rule page lists which rule covers which capability.

Rule: [CL-0006](https://tmatens.github.io/compose-lint/rules/CL-0006/).

## 6. Make the root filesystem read-only

In the study, 98.7% of files leave it writable.

With `read_only: true`, a process that gets code execution can't modify the container's binaries or add new ones to its filesystem. That makes persistence and bringing in tools harder. It doesn't make them impossible, because tmpfs paths and volumes are still writable. The paths an application needs to write to become `tmpfs` entries if they're ephemeral, or volumes if they need to persist. Named volumes and bind mounts stay writable under `read_only`, so persistence through a volume is something the mount step further down has to handle.

```yaml
read_only: true
tmpfs:
  - /tmp
  - /run
  - /var/cache/nginx
```

To find the paths, run the service once without `read_only`, exercise it, and read `docker diff <container>`. It lists the writes to the writable layer, which are the ones `read_only` will block.

Leave `tmpfs` entries without `:exec` or `:suid` unless the image needs them. Docker mounts every tmpfs `noexec` and `nosuid` by default, and `:exec` lets a downloaded binary run straight from `/tmp`. `noexec` doesn't stop an interpreter from running a script stored there, so I treat it as one more obstacle. A few images do need it. When yours does, keep the entry and suppress CL-0022 for that service with the reason written down, so the exception is visible.

Rules: [CL-0007](https://tmatens.github.io/compose-lint/rules/CL-0007/), [CL-0022](https://tmatens.github.io/compose-lint/rules/CL-0022/).

## 7. Set memory and CPU limits

In the study, 97.4% of files are missing a memory limit, a CPU limit, or both.

Docker sets no limit by default, so one runaway or malicious process can take the host down with it. Set both, sized from what the workload uses at steady state.

```yaml
deploy:
  resources:
    limits:
      memory: 512M
      cpus: '0.50'
```

Compose honors `deploy.resources.limits` outside Swarm, so this works with a plain `docker compose up`. Give memory more headroom than CPU, because a memory limit kills the process and a CPU limit only slows it down. The rule page has a sizing procedure.

These limits are per container, and nothing makes them add up to what the host has. Check that the total fits the machine, with room left for the host. Several services at their limits together can exhaust it while each one stays inside its own.

These two limits don't cap the number of processes. That's a separate limit, and it's in the section after step 13.

Rule: [CL-0026](https://tmatens.github.io/compose-lint/rules/CL-0026/).

That's all twelve findings on the starting file. The remaining steps are about settings it doesn't use.

## 8. Don't run as root when the image doesn't need to

In the study, 1.9% of files set an explicit root user.

An explicit `user: root` overrides whatever user the image was built to run as. Remove it and let the image decide, or set a specific non-root user. If the image needs root at startup to fix volume ownership and then drops privileges, that's what the capabilities in step 5 are for.

```yaml
# Before
user: root

# After: remove the line and let the image decide, or
user: "1000:1000"
```

A non-root user can't write to a bind mount the host owns as root, and Compose creates a missing bind source as root. The rule page walks through fixing the ownership so you don't have to go back to root.

Rule: [CL-0018](https://tmatens.github.io/compose-lint/rules/CL-0018/).

## 9. Keep the Docker socket out of containers

In the study, 7.8% of files mount the host's Docker socket.

A container that can reach `/var/run/docker.sock` can start a privileged container with the host's root filesystem mounted. That's root on the host with one extra step. Adding `:ro` doesn't help, because the API accepts writes over a read-only socket mount. compose-lint rates this CRITICAL, and it's the most common CRITICAL finding in the study.

The right fix depends on why the socket is there. In order of preference:

1. Delete the service that wanted it.
2. Redesign so it isn't needed.
3. Put a filtering proxy in front of it that exposes only the API endpoints required.
4. Suppress the finding, with the risk written down and a review date.

[The examples library](https://tmatens.github.io/compose-lint/examples/) has a deployed stack for each of the four, and the [netdata example](https://tmatens.github.io/compose-lint/examples/netdata-socket-proxy/) has the full proxy configuration.

A proxy still holds the real socket, so it has to be at least as hardened as anything else in the stack. Its own CL-0001 finding is suppressed for that one service with the reason written down, which keeps the rule active for everything else. If its allowlist includes the inspect endpoint, `containers/<id>/json`, the consumer can read each container's environment, and that is the case step 1 is about.

There's also a newer key that grants the socket without a `volumes:` line. `use_api_socket: true` (Compose 2.37.1 and later) bind-mounts the socket read-write and also copies the registry logins of whoever runs `docker compose up` into the container. The same four answers apply. The [CL-0031](https://tmatens.github.io/compose-lint/rules/CL-0031/) page covers the credential half.

Rules: [CL-0001](https://tmatens.github.io/compose-lint/rules/CL-0001/), [CL-0031](https://tmatens.github.io/compose-lint/rules/CL-0031/).

## 10. Avoid `privileged: true`

In the study, 2.4% of files set it.

`privileged: true` grants every capability, disables the seccomp and AppArmor profiles, and exposes every host device. It often gets added to make a stuck container run. There's usually a narrower setting that does the job:

| Need | Use this |
|---|---|
| Access to one device | `devices: [/dev/foo]` |
| Network configuration | `cap_add: [NET_ADMIN, NET_RAW]` |
| A debugger sidecar | `cap_add: [SYS_PTRACE]` with `pid: "service:<name>"`, so it sees only that service's processes. `SYS_PTRACE` can also read their memory. |
| Docker-in-Docker | The `sysbox-runc` runtime. Rootless DinD doesn't get you out of this. It still needs `privileged`, or seccomp unconfined plus more. |

The narrower settings aren't free. `NET_ADMIN` is a HIGH finding by itself, and `SYS_PTRACE` is graded too. If you don't know which capability a workload needs, remove `privileged: true`, run it, and add back only what the failure names.

Rules: [CL-0002](https://tmatens.github.io/compose-lint/rules/CL-0002/), [CL-0011](https://tmatens.github.io/compose-lint/rules/CL-0011/), [CL-0027](https://tmatens.github.io/compose-lint/rules/CL-0027/).

## 11. Keep host namespaces and host networking off

In the study, 2.8% of files use `network_mode: host`.

`network_mode: host` puts the container directly on the host's network stack. The `ports:` key is ignored, so you can't limit a service to `127.0.0.1` the way step 3 does. Whatever address the application binds is the address it's on, and most bind every interface by default. The container also sees every host interface and can reach services the host only listens for on `127.0.0.1`.

The firewall works the other way around from step 3. A host-network service is an ordinary listener on the host, so UFW and firewalld rules do apply to it. What you lose is the separation between the container and the host's own network. Bridge networking with an explicit port mapping gets that back.

`pid: host` and `ipc: host` share the host's process and shared-memory namespaces. A sidecar that needs to see another container's processes can use `pid: "service:<name>"`.

```yaml
# Before
network_mode: host
pid: host

# After
ports:
  - "127.0.0.1:8080:8080"
networks:
  - app-network
```

Rules: [CL-0008](https://tmatens.github.io/compose-lint/rules/CL-0008/), [CL-0010](https://tmatens.github.io/compose-lint/rules/CL-0010/).

## 12. Look hard at every host path you mount

In the study, 2.5% of files bind-mount a sensitive host path. Writable mounts of root-equivalent paths are under 2%.

A bind mount of `/etc`, `/proc`, `/root`, `/var/lib/docker` or a home directory hands the container the host's secrets even when it's read-only. When it's writable, `/etc`, `/root`, `/proc` and `/var/lib/docker` hand it the host. A writable `/var/lib/docker` is every other container's filesystem. Device nodes under `devices:` and `shared` mount propagation open more routes.

I ask three questions of each `volumes:` entry:

- Does the container need this path at all, or only a copy of part of it? A named volume or a `COPY` at build time usually replaces a host bind.
- If it needs the host path, does it need to write to it? If it doesn't, add `:ro`.
- Is it `/dev/shm`? The container already has its own. If the bind is there because 64 MiB is too small, set `shm_size:`.

```yaml
# Before
volumes:
  - /etc:/host-etc
  - ./site:/usr/share/nginx/html

# After
volumes:
  - ./site:/usr/share/nginx/html:ro
```

Rules: [CL-0013](https://tmatens.github.io/compose-lint/rules/CL-0013/), [CL-0025](https://tmatens.github.io/compose-lint/rules/CL-0025/), [CL-0016](https://tmatens.github.io/compose-lint/rules/CL-0016/), [CL-0017](https://tmatens.github.io/compose-lint/rules/CL-0017/).

## 13. Keep logs on

In the study, 15 of the 5,907 files turn logging off.

`logging: driver: none` discards the container's output at the daemon. `docker logs` returns an error, nothing reaches a log shipper, and an incident in that container leaves no record. If the concern is disk space, rotate the logs:

```yaml
logging:
  driver: json-file
  options:
    max-size: 10m
    max-file: '3'
```

Rule: [CL-0014](https://tmatens.github.io/compose-lint/rules/CL-0014/).

## Hardening that compose-lint doesn't grade

Every step so far maps to a compose-lint rule. The settings in this section don't, and in each case that was a decision. I've said why for each one. They can still be worth setting. The first two are in the final file below, and I ran it with them: both services started, served, and came back after a restart.

### Cap the number of processes

This one is optional if you've set the memory limit from step 7. The memory limit is what protects the host from a fork bomb. A process limit changes how the failure ends. I ran a fork bomb in a container held to 128M and half a CPU, with and without one:

| Process limit | Processes reached | What happened |
|---|---|---|
| None | About 1,200 in five seconds | Hit the memory limit and was killed |
| 100 | 100 | Further forks refused, container stayed up |

The host stayed responsive both times. Neither ending is healthy. A killed container with a restart policy comes back to the same attack, and a service at its process ceiling can't start new work. If you haven't set a memory limit, don't skip this one.

CIS and OWASP both ask for a process limit, so set it if you're audited against either. The [CL-0026](https://tmatens.github.io/compose-lint/rules/CL-0026/#what-it-detects) page has the rest of the measurement.

```yaml
deploy:
  resources:
    limits:
      memory: 512M
      cpus: '1.0'
      pids: 200
```

Put it next to the limits from step 7. I first tried the service-level `pids_limit:` key beside a `deploy.resources.limits` block, and Compose 5.6.1 refused the file with `can't set distinct values on 'pids_limit' and 'deploy.resources.limits.pids'`.

Size it from what the service runs. `docker stats --no-stream` has a PIDS column. Postgres forks one backend per client connection, so its limit has to clear `max_connections`.

Why there's no rule: compose-lint used to have one and I retired it. Memory is the bigger risk, and a file that leaves it unbounded is already flagged by [CL-0026](https://tmatens.github.io/compose-lint/rules/CL-0026/).

### Separate the networks

Compose puts every service in a project on one network, so `web` and `db` can reach each other and both can reach the internet. Two networks, with the database's marked `internal`, narrow that:

```yaml
services:
  web:
    networks:
      - frontend
      - backend
  db:
    networks:
      - backend

networks:
  frontend:
  backend:
    internal: true
```

On the final file, `web` still served its published port and reached `db:5432`, and a client on `backend` logged in with the secret from step 1. A container attached only to an `internal` network had no default route and couldn't resolve or reach an outside host. Attached to both networks, it could.

Why there's no rule: which services in a project should be able to reach each other is a design decision, and the file doesn't say what you intended.

### Start without root

Both services in the final file start as root, and the capabilities from step 5 are the cost of that. The nginx master process stays root for its lifetime, and postgres starts as root before it switches user. I measured two alternatives, each with `cap_drop: [ALL]`, no `cap_add`, `read_only: true` and `no-new-privileges`.

`nginxinc/nginx-unprivileged:1.30-alpine` ran as uid 101 and served, with one `tmpfs` at `/tmp`. It listens on 8080, so the port mapping becomes `"127.0.0.1:8080:8080"`.

`postgres:16` with `user: "999:999"`, which is the image's `postgres` user, ran through a first start and a restart on a fresh volume. The cost moves to the secret. Without `DAC_OVERRIDE`, uid 999 has to be able to read the file by its mode. At `0600` and owned by another user the entrypoint stopped with `Permission denied`, and at `0644` it started. Giving the file to uid 999 on the host would keep it at `0600`, but I didn't run that.

Why there's no rule: the image's default user isn't in the Compose file, so compose-lint can't tell a root default from a non-root one, and I didn't want it to guess. It flags `user: root` when you write it.

## The hardened file

This is the starting file with every step applied, plus the process limits and networks from the last section. With real digests in place of the shortened ones, `compose-lint check --fail-on low` reports no findings on it.

```yaml
services:
  web:
    image: nginx:1.30-alpine@sha256:…               # step 2
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
          pids: 100                                  # optional, not graded
    logging:                                         # step 13
      driver: json-file
      options:
        max-size: 10m
        max-file: '3'
    networks:                                        # not graded
      - frontend
      - backend
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
          pids: 200                                  # optional, not graded
    logging:                                         # step 13
      driver: json-file
      options:
        max-size: 10m
        max-file: '3'
    networks:                                        # not graded
      - backend

volumes:
  pgdata:

networks:
  frontend:
  backend:
    internal: true

secrets:
  db_password:
    file: ./secrets/db_password.txt
```

Both capability lists are the measured ones from step 5. Without the `/run/postgresql` tmpfs, postgres can't create its lock file and exits under `read_only`. The `docker diff` pass in step 6 is how you find paths like that one ahead of time. Measure again for the versions you run.

No findings doesn't mean there's nothing left to do. Both services here still start as root, and the linter stays quiet about that on purpose, for the reason in the last section. If that matters for your stack, the unprivileged variants there are the next step.

## Checklist

| Setting | Rule | Files in the study that skip it |
|---|---|---|
| Credentials in `secrets:`, not `environment:` or `env_file:` | [CL-0020](https://tmatens.github.io/compose-lint/rules/CL-0020/), [CL-0021](https://tmatens.github.io/compose-lint/rules/CL-0021/) | 28.2% / 5.1% |
| Image pinned to a tag | [CL-0004](https://tmatens.github.io/compose-lint/rules/CL-0004/) | 50.2% |
| Image pinned to a digest | [CL-0019](https://tmatens.github.io/compose-lint/rules/CL-0019/) | 50.2% |
| Published ports bound to an address | [CL-0005](https://tmatens.github.io/compose-lint/rules/CL-0005/) | 72.1% |
| `no-new-privileges:true` | [CL-0003](https://tmatens.github.io/compose-lint/rules/CL-0003/) | 97.3% |
| Seccomp, AppArmor and SELinux labelling left on | [CL-0009](https://tmatens.github.io/compose-lint/rules/CL-0009/) | under 2% |
| `cap_drop: [ALL]`, image-specific `cap_add` | [CL-0006](https://tmatens.github.io/compose-lint/rules/CL-0006/) | 98.6% |
| Added capabilities limited to what the image needs | [CL-0011](https://tmatens.github.io/compose-lint/rules/CL-0011/), [CL-0024](https://tmatens.github.io/compose-lint/rules/CL-0024/), [CL-0027](https://tmatens.github.io/compose-lint/rules/CL-0027/) to [CL-0030](https://tmatens.github.io/compose-lint/rules/CL-0030/) | 3.5% / under 2% |
| `read_only: true` with `tmpfs` for writable paths | [CL-0007](https://tmatens.github.io/compose-lint/rules/CL-0007/) | 98.7% |
| No `:exec` or `:suid` on `tmpfs` | [CL-0022](https://tmatens.github.io/compose-lint/rules/CL-0022/) | under 2% |
| Memory and CPU limits | [CL-0026](https://tmatens.github.io/compose-lint/rules/CL-0026/) | 97.4% |
| No explicit `user: root` | [CL-0018](https://tmatens.github.io/compose-lint/rules/CL-0018/) | under 2% |
| No Docker socket mount | [CL-0001](https://tmatens.github.io/compose-lint/rules/CL-0001/) | 7.8% |
| No `privileged: true` | [CL-0002](https://tmatens.github.io/compose-lint/rules/CL-0002/) | 2.4% |
| No `network_mode: host`, `pid: host`, `ipc: host` | [CL-0008](https://tmatens.github.io/compose-lint/rules/CL-0008/), [CL-0010](https://tmatens.github.io/compose-lint/rules/CL-0010/) | 2.8% / under 2% |
| Host paths mounted only when needed, `:ro` where possible | [CL-0013](https://tmatens.github.io/compose-lint/rules/CL-0013/), [CL-0025](https://tmatens.github.io/compose-lint/rules/CL-0025/) | 2.5% / under 2% |
| No host devices, no `shared` mount propagation | [CL-0016](https://tmatens.github.io/compose-lint/rules/CL-0016/), [CL-0017](https://tmatens.github.io/compose-lint/rules/CL-0017/) | under 2% |
| Logging driver not `none` | [CL-0014](https://tmatens.github.io/compose-lint/rules/CL-0014/) | under 2% |
| Process limit, optional with a memory limit | not graded | n/a |
| Database on an `internal` network | not graded | n/a |
| No root at start, where the image allows it | not graded | n/a |

To check a file against all of it at once, run `compose-lint check --fail-on low compose.yaml`. `compose-lint fix` applies the steps that can be applied mechanically and shows the diff before it writes anything.

## Where to start if you can only do one thing

If any credential is in `environment:`, start with step 1. Otherwise I'd start with step 4, `no-new-privileges`, because it's one line and rarely changes what a service does. Step 5 would be next.

## What this doesn't cover

- **What's inside the images.** This post and compose-lint cover the Compose file, which is how the container is run. What's inside the image and how it was built are jobs for an image scanner and a Dockerfile linter. I wrote up what each tool reads on [the comparison page](https://tmatens.github.io/compose-lint/compare/).
- **Daemon-level options.** Rootless Docker and user namespace remapping change what root in a container means, and they're worth looking at separately.

## If you want to run it on your own files

compose-lint is on PyPI and Docker Hub, and there's a GitHub Action if you want it in CI. The [docs](https://tmatens.github.io/compose-lint/) cover all three, and the source is on [GitHub](https://github.com/tmatens/compose-lint). I keep a copy of this guide [in the docs](https://tmatens.github.io/compose-lint/hardening/) too, and update it there as the rules change. If a rule page is wrong about an image you run, I'd like to hear about it.

*compose-lint is a personal project and is not affiliated with my employer. The views here are my own.*
