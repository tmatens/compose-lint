# Real-world examples

Four Compose files that all trip the same rule — [CL-0001](../rules/CL-0001.md), the Docker socket mount — and four different correct answers.

The rule text can tell you that mounting `/var/run/docker.sock` is root-equivalent. What it cannot tell you is which of these you are allowed to do about it, because that depends on what the service is for. These examples are drawn from stacks that are actually deployed and continuously linted, so the hardened files are what runs, not what a documentation author wished were running.

## The ladder

| | Example | Remediation | Result |
|---|---|---|---|
| 1 | [Delete the service](portainer-removed/index.md) | The socket was mounted for a management UI nobody was managing anything with | Finding gone, no suppression |
| 2 | [Re-architect so the socket isn't needed](logging-without-the-socket/index.md) | Same job — reading container logs — done from the systemd journal instead of the Docker API | Finding gone, no suppression |
| 3 | [Constrain it when the need is real](netdata-socket-proxy/index.md) | Container metrics genuinely require the Docker API, so a GET-only filtering proxy holds the socket | Suppressed for the proxy, still enforced everywhere else |
| 4 | [Suppress it, with the risk written down](ci-runner-suppression/index.md) | A CI runner creates job containers; nothing removes that requirement | Suppressed with a review date and a stated residual risk |

Read in order, they answer a question the rule docs cannot: the first question is never "how do I silence this", it is "which rung am I on".

## What the linter says about each

Every example ships the Compose file and the `.compose-lint.yml` that goes with it, so you can reproduce these numbers:

```
portainer-removed            exit=1   2 high            1 suppressed
logging-without-the-socket   exit=0   0 issues          1 suppressed
netdata-socket-proxy         exit=0   0 issues         14 suppressed
ci-runner-suppression        exit=0   4 medium          6 suppressed
```

Two of these deserve comment, because they are the opposite of what a "findings went down" summary would suggest.

**The socket-proxy example did not reduce its finding count.** Before hardening it reported 14 findings; after hardening it reports 14 findings. What changed is that the critical one moved from a container with host networking, the host PID namespace and an unconfined AppArmor profile, onto a scratch-image container that is read-only, capability-less and answers `403` to every API path it does not need. The number is identical and the blast radius is not. Counting findings is a bad proxy for security, and this is the clearest example of it we have.

**The CI-runner example still has four open medium findings.** They are not suppressed, on purpose — see [that page](ci-runner-suppression/index.md). Leaving a finding open is a valid state, and often a more honest one than a waiver that says "pending investigation" and then does not expire.

## How suppressions are written here

Every suppression in these examples uses per-service `exclude_services` ([ADR-010](../adr/010-per-service-rule-overrides.md)) rather than a global `enabled: false`, including the cases where only one service exists today.

A global disable switches the rule off for the whole file. In the socket-proxy example that would mean a later edit re-adding a direct socket mount to the metrics agent would lint clean — the exact regression the architecture was built to prevent, made invisible by the config that documents it. Scoping the suppression to the service that is supposed to hold the socket keeps the rule live for everything else.

Suppressed findings still appear in the output, marked `SUPPRESSED` and carrying their reason, so what was waived stays auditable rather than disappearing.

## On staleness

Each page carries a "verified against" stamp naming the compose-lint version and the date its output was captured. The files come from deployed stacks, so they are re-linted whenever those stacks change, but the narrative around them is maintained by hand — if a stamp is old, treat the prose as older than the rule.

Identifiers have been sanitized: hostnames, domains, addresses and paths are replaced. Sanitizing is done carefully, because it can change findings — replacing a `/home/...` bind mount with `/opt/...` silently removes a CL-0013 finding, which happened once while these examples were being written and was caught by re-linting the scrubbed file against the original.
