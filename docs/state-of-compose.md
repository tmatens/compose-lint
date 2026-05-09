# State of Docker Compose Security

> **Status: draft in progress.** This is the canonical doc for the State of Docker Compose Security report. The methodology and limitations sections below are stable; the data tables, charts, and prose are landing in follow-up commits. Tracking issue: [#186](https://github.com/tmatens/compose-lint/issues/186).

The first published empirical study of security misconfigurations in real-world Docker Compose files at corpus scale.

## What this study does NOT claim

Read this section before citing any number from the report. The corpus is a descriptive sample, not a randomized population study, and the framing matters for what the findings can and cannot support.

### Out of scope by design

- **Exploit rate.** Findings count *misconfigurations that violate hardening guidance*. The report does not measure how often each misconfiguration is exploited in the wild, which exploits are reachable from the public internet, or which exploits have been observed in incident data. A finding is a code smell with a citation, not an attestation that the file has been compromised.
- **Runtime behavior.** compose-lint reads YAML; it does not run containers. The corpus tells us what people *write* in Compose files, not what their containers actually do once started (network policy, AppArmor profiles, kernel features, secret-injection sidecars, runtime admission controllers).
- **Production usage.** Public GitHub repos are a mix of demos, tutorials, archived projects, app-store templates, and production code. The corpus cannot distinguish them. A `docker-compose.yml` in a public repo is *evidence that someone wrote that compose file*, not evidence that anything is running it.
- **Private-repo prevalence.** The corpus is public-only. Enterprise and internal Compose files are out of scope; their misconfiguration distribution may differ.

### Sampling caveats

- **GitHub-only.** No GitLab, Codeberg, Gitea, Bitbucket, Docker Hub README snippets, package-manager fragments, blog-post YAML blocks, or Stack Overflow answers. The longtail tier is a stratified sweep of GitHub's code search; see [`scripts/corpus/README.md`](../scripts/corpus/README.md#longtail-sampling-methodology) for the exact query design and the four biases it inherits.
- **Filename-pinned.** Files saved under non-standard names (`stack.yml`, `web.compose.yml`, etc.) are missed. The four canonical filenames cover the documented Compose Specification names but not every project's conventions.
- **No statistical inference.** This is descriptive sampling for prevalence estimation. There are no hypothesis tests, no confidence intervals, no population estimates, and no claims about the "average" Compose file outside the four named tiers (`canonical`, `popular`, `selfhosted`, `longtail`). Tier counts are reported as observed; treat them as descriptive of the corpus, not extrapolated to all of GitHub.
- **Snapshot in time.** Each report version pins to a single corpus run and a single compose-lint version. The published numbers do not move when a new rule lands; the next quarterly refresh ships a new version with a delta callout.

### Tool caveats

- **Rules are based on hardening guidance, not on incident response data.** Each rule cites OWASP, CIS, or Docker docs. A rule firing means the file diverges from authoritative hardening guidance, not that an attacker would necessarily exploit the divergence on a given deployment.
- **compose-lint does not validate the full Compose schema.** Files that fail to parse as v2/v3 Compose are bucketed by error class and reported as a separate population, not silently dropped. The parser does not resolve `${VAR}` interpolation or merge external `extends:` files; rules see what is written in the file, not the runtime resolution.

The framing is: *here is what people put in their Compose files at corpus scale, scored against published hardening guidance, with the sampling design and tool boundaries spelled out so you can re-rank, re-bucket, or re-run against your own corpus*. It is not a runtime risk assessment, a CVE database, or a population estimate.
