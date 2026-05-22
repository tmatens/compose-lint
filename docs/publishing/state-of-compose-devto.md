---
title: "I scanned 6,444 public Docker Compose files. 91% had a security finding."
published: false
description: An empirical look at how real-world docker-compose.yml files are configured — and why even vendor copy-paste examples ship insecure defaults.
tags: docker, security, devops, opensource
canonical_url:
---

> **Draft / teaser.** Derived from the canonical report at
> [github.com/tmatens/compose-lint/blob/main/docs/state-of-compose.md](https://github.com/tmatens/compose-lint/blob/main/docs/state-of-compose.md).
> Before publishing: set `published: true`, leave `canonical_url` blank so dev.to is
> the SEO-original, and (optionally) add a cover image. See `docs/publishing/README.md`.

I built [compose-lint](https://github.com/tmatens/compose-lint), a security linter for Docker Compose files, and then pointed it at the wild: **6,444 public `docker-compose.yml` and `compose.yaml` files from GitHub**.

The headline:

- **91%** of the files that parse have at least one security finding.
- **68%** have at least one **HIGH or CRITICAL** finding.
- The same three issues sit at the top of *every* category of file — including the official, copy-paste-me vendor examples.

This isn't a "gotcha" about careless developers. It's a story about **defaults**: Docker Compose ships with none of the hardening flags on, almost nobody turns them on, and the examples people learn from don't either.

Here's what the corpus says.

## How the corpus is built

I split the files into four tiers, because "X% of compose files do Y" is misleading when a Bitnami reference example and someone's half-finished homelab get averaged together:

- **`canonical`** (327 files) — official upstream examples: awesome-compose, Bitnami, Grafana, Vaultwarden. *The stuff READMEs tell you to copy-paste.*
- **`popular`** (3,977) — repos with ≥50 stars and a recent Compose file. *Production-adjacent code.*
- **`selfhosted`** (588) — app-store / template registries: CasaOS, runtipi, Dockge. *Home-LAN threat model.*
- **`longtail`** (1,552) — a stratified sweep of GitHub code search. *The median file in the wild.*

Every file is linted with the same rule set (compose-lint 0.7.0), each rule grounded in the [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) or the CIS Docker Benchmark. The full methodology — including what this study deliberately does **not** claim — is in the [canonical report](https://github.com/tmatens/compose-lint/blob/main/docs/state-of-compose.md).

## Finding 1: nobody flips the hardening flags

Three findings fire on roughly **90% of every file in the corpus**:

![Most common findings across the corpus, by share of parsed files affected, coloured by severity](https://raw.githubusercontent.com/tmatens/compose-lint/main/docs/publishing/assets/top-findings.png)

- **Filesystem not read-only** (`read_only: true` missing) — 91%
- **No capability restrictions** (`cap_drop: [ALL]` missing) — 91%
- **Privilege escalation not blocked** (`no-new-privileges` missing) — 90%

These are MEDIUM, not CRITICAL, because each is a *missing* defense-in-depth control rather than an active misuse. But that's exactly why they're interesting: the Compose hardening triple is essentially **never set**.

The fix takes about 30 seconds per service:

```yaml
services:
  app:
    image: nginx:1.27@sha256:...   # pin a digest, not just a tag
    read_only: true                # CL-0007
    cap_drop: [ALL]                # CL-0006
    security_opt:
      - no-new-privileges:true     # CL-0003
```

Add a `tmpfs:` for the paths your app actually writes to, and you've closed the three most common findings on the internet.

## Finding 2: even copy-paste vendor examples aren't clean

You'd expect the official examples — the ones whose entire job is to be copied — to be the hardened ones. They're the *cleanest* tier, and they're still at **83%**:

![Share of files with at least one finding by tier: canonical 82.8%, popular 95.2%, selfhosted 100%, longtail 78.3%](https://raw.githubusercontent.com/tmatens/compose-lint/main/docs/publishing/assets/findings-by-tier.png)

A few things jump out:

- **Self-hosted app-store templates: 100%.** Every single one trips at least one rule. They optimize for "works on your LAN in one click," which means exposed ports, root users, and big host mounts.
- **Popular repos aren't better than the long tail.** Stars don't buy hardening discipline.
- **Canonical examples are config *demos*, not hardening *exemplars*** — and people copy them verbatim into production.

That last point is the whole reason this gap exists. The examples teach the unhardened shape, and the unhardened shape propagates.

## Finding 3: ~10% of ordinary files don't even parse

Here's the one I didn't expect. In the long-tail tier, **9.6%** of files don't parse as a valid Compose file at all — versus well under 1% everywhere else:

![Parse-error rate by tier: canonical 0.6%, popular 0.7%, selfhosted 0.0%, longtail 9.6%](https://raw.githubusercontent.com/tmatens/compose-lint/main/docs/publishing/assets/parse-error-rate.png)

And it's almost never broken YAML. It's **shape errors** — people writing `services` as a dictionary of strings:

```yaml
# What a lot of people write (does not parse):
services:
  nginx: nginx:1.27

# What Compose actually wants:
services:
  nginx:
    image: nginx:1.27
```

A file that doesn't parse with a real Compose engine was never deployed by one. So these are documentation snippets, tutorial follow-alongs, and first attempts — none of which are getting linted before they ship. The parse-error rate is itself a signal about where unreviewed config lives.

(If you're wondering: "long tail" here means the low-visibility mass of ordinary repos, not a statistical distribution tail.)

## Why it's all MEDIUM-heavy

One more chart, because the severity mix surprises people:

![Findings by severity: MEDIUM 78.5%, HIGH 20.3%, CRITICAL 1.1%, LOW 0.0%](https://raw.githubusercontent.com/tmatens/compose-lint/main/docs/publishing/assets/severity-distribution.png)

Nearly four out of five findings are MEDIUM — because the hardening-triple misses from Finding 1 fire on almost every file and they're MEDIUM by design. CRITICAL findings (a mounted Docker socket, `cap_add: ALL`, a bind-mounted `/`) are rare but real: a mounted Docker socket — full host takeover — shows up on **6.4%** of parsed files, and **8%** in the popular tier.

## So why are all the flags off by default?

Because Docker optimizes for "it runs on the first try." A writable filesystem, a full
capability set, and unrestricted privilege escalation are the path of least surprise — your
container starts and your app works. Every hardening control is **opt-in**, and opting in
means knowing it exists, knowing your app still works without the capability or the write
access, and adding three or four lines per service.

That's a real cost, and it compounds: the examples never opt in, so the next person copies
the unhardened shape, ships it, and becomes the next example. The corpus is what that loop
looks like at scale. Nothing here is exotic — it's the accumulated weight of a sensible
default that nobody revisits.

## What this is *not*

I want to be precise about the framing, because it's easy to over-claim:

- It measures **misconfiguration prevalence**, not exploitation. A finding is divergence from hardening guidance, not proof anything was breached.
- It's **descriptive sampling**, not statistical inference — no p-values, no population estimates.
- It's **GitHub-only and public-only.** Private and enterprise Compose may look different.

The full ["what this study does not claim"](https://github.com/tmatens/compose-lint/blob/main/docs/state-of-compose.md#what-this-study-does-not-claim) section spells out every boundary.

## Try it on your own files

compose-lint is MIT-licensed, zero-config, and has PyYAML as its only runtime dependency:

```bash
pipx install compose-lint
compose-lint docker-compose.yml
```

Or via Docker:

```bash
docker run --rm -v "$(pwd):/src" composelint/compose-lint
```

It emits SARIF for GitHub Code Scanning, so you can gate PRs on it. A minimal CI gate:

```yaml
# .github/workflows/compose-lint.yml
name: compose-lint
on: [pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pipx install compose-lint
      - run: compose-lint --fail-on high docker-compose.yml
```

`--fail-on high` fails the build only on HIGH/CRITICAL, so you can adopt it without
drowning in the MEDIUM hardening backlog on day one, then tighten the threshold over time.

📊 **Read the full report** — every table, the complete methodology, per-rule breakdowns, and reproducibility steps: **[State of Docker Compose Security](https://github.com/tmatens/compose-lint/blob/main/docs/state-of-compose.md)**

If you maintain a popular Compose example, I'd genuinely love a PR or an issue — hardening the examples people copy is the highest-leverage fix there is.
