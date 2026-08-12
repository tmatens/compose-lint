# Real-world examples

Compose files from stacks that are actually deployed and continuously linted, so the hardened versions are what runs rather than what a documentation author wished were running.

The library is in two parts. **The ladder** is four files that all trip the same rule — [CL-0001](../rules/CL-0001.md), the Docker socket mount — and four different correct answers to it, because the rule text can tell you a socket mount is root-equivalent but not which remediation your service is allowed. **Beyond the ladder** is three stacks chosen for lessons the ladder doesn't reach: two rules that cannot both be satisfied, a waiver whose premise was true and whose conclusion wasn't, and one stack that needed almost nothing waived at all.

## The ladder

| | Example | Remediation | Result |
|---|---|---|---|
| 1 | [Delete the service](portainer-removed/index.md) | The socket was mounted for a management UI nobody was managing anything with | Finding gone, no suppression |
| 2 | [Re-architect so the socket isn't needed](logging-without-the-socket/index.md) | Same job — reading container logs — done from the systemd journal instead of the Docker API | Finding gone, no suppression |
| 3 | [Constrain it when the need is real](netdata-socket-proxy/index.md) | Container metrics genuinely require the Docker API, so a GET-only filtering proxy holds the socket | Suppressed for the proxy, still enforced everywhere else |
| 4 | [Suppress it, with the risk written down](ci-runner-suppression/index.md) | A CI runner creates job containers; nothing removes that requirement | Suppressed with a review date and a stated residual risk |

Read in order, they answer a question the rule docs cannot: the first question is never "how do I silence this", it is "which rung am I on".

## Beyond the ladder

Three more stacks, each carrying a lesson the ladder doesn't.

| Example | The lesson |
|---|---|
| [Two rules in tension](read-only-in-tension/index.md) | Satisfying one rule means violating another. Buying a read-only root by accepting a CL-0022 — one low traded for another, so the output says nothing about which posture is better. |
| [A true premise and a false conclusion](read-only-multi-service/index.md) | A four-service stack whose waiver said read-only was impossible because the services write to volumes. True, and it doesn't follow: volumes stay writable. |
| [The clean one](clean-edge-proxy/index.md) | The public entry point, with one waiver for the whole stack and a forward-auth service that holds *no capabilities at all*. |

## What the linter says about each

Every example ships the Compose file and the `.compose-lint.yml` that goes with it, so you can reproduce these numbers:

```
portainer-removed                                   exit=0   1 medium                1 suppressed
logging-without-the-socket                          exit=0   3 medium                1 suppressed
netdata-socket-proxy  docker-compose.yml            exit=1   1 critical, 2 medium   10 suppressed
netdata-socket-proxy  docker-compose.hardened.yml   exit=0   3 medium               11 suppressed
ci-runner-suppression                               exit=0   4 medium, 2 low         3 suppressed
read-only-in-tension                                exit=0   0 issues                1 suppressed
read-only-multi-service                             exit=0   3 medium                2 suppressed
clean-edge-proxy                                    exit=0   2 medium                2 suppressed
```

Most of those mediums are the same finding. [CL-0026](../rules/CL-0026.md) — no memory or CPU limit — landed in 0.16.0 and fires on nearly every service here, because these stacks were deployed before the rule existed and nobody has sized the limits yet. They are left open rather than waived, which is the state [rung 4](ci-runner-suppression/index.md) argues for: a finding you have not decided about is more truthful open than behind a waiver that says "pending".

Two rows deserve comment, because they are the opposite of what a "findings went down" summary would suggest.

**The socket-proxy example increased its finding count.** Before hardening it reported 13 findings; after hardening, 14. The critical one moved from a container with host networking, the host PID namespace and an unconfined AppArmor profile onto a scratch-image container that is read-only, capability-less and answers `403` to every API path it does not need — and the proxy, being a service, brought its own resource-limit finding with it. The number went the wrong way and the blast radius collapsed. Counting findings is a bad proxy for security, and this is the clearest example of it we have.

**The CI-runner example has six findings open on purpose.** They are not suppressed — see [that page](ci-runner-suppression/index.md). Leaving a finding open is a valid state, and often a more honest one than a waiver that says "pending investigation" and then does not expire.

## How suppressions are written here

Every suppression in these examples uses per-service `exclude_services` ([ADR-010](../adr/010-per-service-rule-overrides.md)) rather than a global `enabled: false`, including the cases where only one service exists today.

A global disable switches the rule off for the whole file. In the socket-proxy example that would mean a later edit re-adding a direct socket mount to the metrics agent would lint clean — the exact regression the architecture was built to prevent, made invisible by the config that documents it. Scoping the suppression to the service that is supposed to hold the socket keeps the rule live for everything else.

Suppressed findings still appear in the output, marked `SUPPRESSED` and carrying their reason, so what was waived stays auditable rather than disappearing.

## On staleness

Each page carries a "verified against" stamp naming the compose-lint version and the date its output was captured. The files come from deployed stacks, so they are re-linted whenever those stacks change, but the narrative around them is maintained by hand — if a stamp is old, treat the prose as older than the rule.

Identifiers have been sanitized: hostnames, domains, addresses and paths are replaced. Sanitizing is done carefully, because it can change findings — replacing a `/home/...` bind mount with `/opt/...` silently removes a CL-0013 finding, which happened once while these examples were being written and was caught by re-linting the scrubbed file against the original.
