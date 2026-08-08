# Rung 4 — Suppress it, with the risk written down

**Verified against:** compose-lint 0.15.1, 2026-08-08

A CI runner starts a container per job. Starting containers means calling `POST /containers/create` and `POST /containers/<id>/start`. There is no filtered subset of the Docker API that permits creating containers while withholding host compromise — the two are the same capability. `POST /containers/create` with a bind mount of `/` is the whole exploit, and it is also just how the runner does its job.

So the [rung 3](../netdata-socket-proxy/index.md) proxy does not help here. This is the case where the finding is correct, unfixable in place, and gets suppressed. What separates a defensible suppression from the one in [rung 1](../portainer-removed/index.md) is entirely in how it is written.

## The suppression

```yaml
rules:
  CL-0001:
    exclude_services:
      forge-runner: >-
        The runner creates a container per CI job, which requires the Docker
        API; there is no filtered subset that permits container creation while
        withholding host compromise, so a GET-only proxy cannot help here.
        RESIDUAL RISK, ACCEPTED, NOT MITIGATED: anyone who can run CI on this
        instance can reach the daemon and is effectively root on the host. This
        is contained by restricting who can push to it, not by anything in this
        file. Review 2027-02-08.
```

Three properties, against the rung-1 version:

- **Scoped, not global.** CL-0001 stays enabled for the forge itself. If a socket mount ever appears there it is a finding, not a silence inherited from this entry.
- **States the residual risk in the same breath.** Not "this is required, therefore fine" but "this is required, and here is what remains true afterwards". A reader who only reads the reason still learns that CI access equals host root here.
- **Carries a review date.** Not a promise to migrate — rung 1 shows what those are worth — but a date on which someone is obliged to look again. The question on that date is whether a rootless runner has become viable for this workload, not whether the requirement still exists. It will.

Note also that the control that actually bounds this risk is named, and it is not in the Compose file. It is who can push to the repository. A suppression that implies the risk is handled by configuration, when it is really handled by access policy somewhere else, is worse than no suppression at all.

## The dependent finding

```yaml
  CL-0018:
    exclude_services:
      forge-runner: >-
        Runs as root plus the host docker group in order to open the socket.
        Note that this is a consequence of the CL-0001 suppression above, not
        an independent decision: fixing that one removes this one.
```

Worth flagging as dependent rather than justifying separately. `user: "0:${DOCKER_GID}"` looks like its own decision and is not — it is downstream of the socket requirement. Suppressions that each look locally reasonable are how a file ends up with six of them and no one able to say which is load-bearing.

The same goes for `no-new-privileges: true` on that service: it is set, it is not useless, and it does not contain a process that can ask the daemon to start a privileged container on its behalf. Controls that do not apply to the actual threat are worth being explicit about, or someone will read the file and conclude the runner is contained.

## Four findings are left open on purpose

```
docker-compose.yml: 4 medium  ·  6 suppressed (not counted)
```

The open ones are CL-0006 (`cap_drop`) and CL-0007 (`read_only`), on both services. They are not suppressed, and the reason is written in the config:

> The honest reason is that neither fix has been tested against the forge's first-boot behaviour or its backup path, and a suppression saying "pending live-test" would be the same expiry-free waiver the portainer example in this ladder exists to criticise. An open finding that is visible in every CI run is a more accurate record of the state than a waiver that says the same thing while turning the output green.

This is the part most easily lost: **not every finding needs a suppression.** A waiver is a claim that you have considered the finding and decided. If you have not decided yet, an open medium finding is the truthful output, and it costs nothing as long as the failure threshold is set where you want it — here the gate is `--fail-on high`, so these four are visible without blocking.

The failure mode a suppression file drifts into is one entry per finding, each individually defensible, collectively meaning the tool reports nothing. Leaving things open is the pressure valve against that.

## Reading the ladder backwards

If you arrived here because you have a socket mount and want to know what to write in your config, the honest advice is to check the three rungs above first:

1. Is anything still using this service? ([rung 1](../portainer-removed/index.md))
2. Does it need the API, or does it need *data* the runtime already publishes elsewhere? ([rung 2](../logging-without-the-socket/index.md))
3. Does it need to read, or does it need to write? Read-only needs can be filtered down to a fraction of the API. ([rung 3](../netdata-socket-proxy/index.md))

Rung 4 is for when all three answers are the wrong ones. It is a legitimate place to end up, and it should be the smallest category in your infrastructure rather than the default.

## Scope note

This example is de-identified: it is a representative self-hosted forge and runner pairing, with domains, addresses, network topology and identifiers replaced, and services unrelated to the CI path removed. The socket requirement, the root-plus-docker-group user and the suppression structure are as deployed.
