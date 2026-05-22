---
title: "I scanned 6,444 public Docker Compose files. 91% of the ones that parse had a security finding."
published: false
description: What real-world docker-compose.yml files actually look like, and why even the examples people copy ship insecure defaults.
tags: docker, security, devops, opensource
canonical_url:
---

> **Draft / teaser.** Derived from the canonical report at
> [github.com/tmatens/compose-lint/blob/main/docs/state-of-compose.md](https://github.com/tmatens/compose-lint/blob/main/docs/state-of-compose.md).
> Before publishing: set `published: true`, leave `canonical_url` blank so dev.to is
> the SEO-original, and (optionally) add a cover image. See `docs/publishing/README.md`.

I pointed [compose-lint](https://github.com/tmatens/compose-lint), a security linter for Docker Compose files, at **6,444 public `docker-compose.yml` and `compose.yaml` files from GitHub**. (More on why I built it below.)

Three numbers stood out:

- **91%** of the files that parse have at least one security finding.
- **68%** have at least one **HIGH or CRITICAL** finding.
- The same three issues top *every* category I looked at, including the official vendor examples people are told to copy.

I don't read this as developers being careless. It's about defaults. Docker Compose ships with the hardening switched off, almost nobody turns it on, and the examples people learn from don't either.

## Why this exists

By day I lead a team of security engineers at a large financial institution, where Compose barely comes up. Production runs on Kubernetes and ECS, both with mature security tooling around them. At home in my lab, though, Compose is the right tool: quick, low-ceremony, enough to stand up a stack on a Saturday.

What bugged me was the asymmetry. Kubernetes and Terraform have a deep bench of scanners: Checkov, Trivy, kube-bench, Kubescape. Compose is an afterthought in most of them. The Compose-specific tools I found solved adjacent problems instead. [Hadolint](https://github.com/hadolint/hadolint) lints Dockerfiles, not Compose files. [dclint](https://github.com/zavoloklom/docker-compose-linter) checks Compose structure and style, not security.

What I wanted was simple: a zero-config, OWASP/CIS-grounded linter I could drop into CI and run against my own stacks. So I wrote one. Then I got curious whether the stuff I kept fixing in my own files showed up everywhere else.

It does. That's what this writeup is about, and I'm putting the tool out there in case it's useful to anyone who builds the way I do.

> *Personal project; the views here are my own, not my employer's.*

Here's what I found.

## How the corpus is built

I split the files into four tiers. A single "X% of Compose files do Y" number is misleading when it averages a polished Bitnami example against someone's half-finished homelab:

- **`canonical`** (327 files) — official upstream examples: awesome-compose, Bitnami, Grafana, Vaultwarden. *The stuff READMEs tell you to copy-paste.*
- **`popular`** (3,977) — repos with ≥50 stars and a recent Compose file. *Production-adjacent code.*
- **`selfhosted`** (588) — app-store / template registries: CasaOS, runtipi, Dockge. *Home-LAN threat model.*
- **`longtail`** (1,552) — a stratified sweep of GitHub code search. *The median file in the wild.*

Every file goes through the same rule set (compose-lint 0.7.0), and every rule is grounded in the [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) or the CIS Docker Benchmark. The full methodology, including what the study deliberately doesn't claim, is in the [canonical report](https://github.com/tmatens/compose-lint/blob/main/docs/state-of-compose.md).

## Finding 1: nobody flips the hardening flags

Three findings fire on roughly **90% of every file in the corpus**:

![Most common findings across the corpus, by share of parsed files affected, coloured by severity](https://raw.githubusercontent.com/tmatens/compose-lint/main/docs/publishing/assets/top-findings.png)

- **Filesystem not read-only** (`read_only: true` missing) — 91%
- **No capability restrictions** (`cap_drop: [ALL]` missing) — 91%
- **Privilege escalation not blocked** (`no-new-privileges` missing) — 90%

They're rated MEDIUM, not CRITICAL, because each one is a missing control rather than active misuse. That's also what makes them interesting. The Compose hardening triple is almost never set.

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

Add a `tmpfs:` for whatever paths your app writes to and you've cleared the three most common findings in the corpus.

**"Aren't these just optional flags, not real vulnerabilities?"** Mostly, yeah. The bulk of that 91% is missing defense-in-depth, not an active breach, and I'd rather say that up front than bury it. But these aren't my personal preferences about tidy YAML. `read_only`, `cap_drop: [ALL]`, and `no-new-privileges` are all named controls in the [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) and the OWASP Docker Security Cheat Sheet. A finding means the file diverges from that published baseline.

## Finding 2: even copy-paste vendor examples aren't clean

You'd expect the official examples to be the hardened ones. Being copied is their entire job. They're the cleanest tier in the corpus, and they still come in at **83%**:

![Share of files with at least one finding by tier: canonical 82.8%, popular 95.2%, selfhosted 100%, longtail 78.3%](https://raw.githubusercontent.com/tmatens/compose-lint/main/docs/publishing/assets/findings-by-tier.png)

A few things jump out:

- **Self-hosted app-store templates: 100%.** Every single one trips at least one rule. They're built for "works on your LAN in one click," which in practice means exposed ports, root users, and big host mounts.
- **Popular repos aren't better than the long tail.** Stars don't buy hardening discipline.
- **Canonical examples are config demos, not hardening exemplars.** People copy them into production anyway.

That last point is most of the story. The examples teach the unhardened shape, and the shape propagates.

A fair caveat here, especially if you're running a homelab: threat model matters. A single-user box behind a firewall and Tailscale is a different risk calculus than something exposed to the internet, and a finding is usually something to decide about rather than an emergency. Start with what actually bites. A mounted Docker socket is full host takeover whether or not you meant to expose it, so fix those first and treat the MEDIUM pile as gradual cleanup. It's why the CI gate defaults to `fail-on: high`.

## Finding 3: ~10% of ordinary files don't even parse

This is the one I didn't expect. In the long-tail tier, **9.6%** of files don't parse as a valid Compose file at all, against well under 1% everywhere else:

![Parse-error rate by tier: canonical 0.6%, popular 0.7%, selfhosted 0.0%, longtail 9.6%](https://raw.githubusercontent.com/tmatens/compose-lint/main/docs/publishing/assets/parse-error-rate.png)

And it's almost never broken YAML. It's shape errors: people writing `services` as a dictionary of strings.

```yaml
# What a lot of people write (does not parse):
services:
  nginx: nginx:1.27

# What Compose actually wants:
services:
  nginx:
    image: nginx:1.27
```

A file that doesn't parse with a real Compose engine was never deployed by one. So these are docs snippets, tutorial follow-alongs, half-finished first drafts. None of them are getting linted before they ship, and the parse-error rate is really a map of where unreviewed config piles up.

(If you're wondering: "long tail" here means the low-visibility mass of ordinary repos, not a statistical distribution tail.)

## Why it's all MEDIUM-heavy

One more chart, because the severity mix surprises people:

![Findings by severity: MEDIUM 78.5%, HIGH 20.3%, CRITICAL 1.1%, LOW 0.0%](https://raw.githubusercontent.com/tmatens/compose-lint/main/docs/publishing/assets/severity-distribution.png)

Nearly four out of five findings are MEDIUM. That's the hardening-triple misses from Finding 1, which hit almost every file and are MEDIUM by design. CRITICAL findings are rarer but real: a mounted Docker socket, `cap_add: ALL`, a bind-mounted `/`. The Docker socket one alone, which is full host takeover, shows up on **6.4%** of parsed files and **8%** in the popular tier.

LOW is almost empty, and that's by construction. Only one of compose-lint's 21 rules is LOW (a healthcheck someone explicitly turned off), because the tool's whole scope is security misconfiguration, where the floor is MEDIUM. So read "0.0% LOW" as a fact about the tool, not as the small stuff being fine.

## So why are all the flags off by default?

Because Docker optimizes for "it runs the first time." A writable filesystem, the full capability set, privilege escalation left on: that's the path of least surprise. Your container starts, your app works. Hardening is opt-in, and opting in means knowing the control exists, confirming your app still works without that capability or that write access, and adding a few lines per service.

And "knowing it exists" is the hard part. There's no single secure-Compose baseline to copy from. The controls are scattered across the Compose spec, the Docker run reference, the [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html), and the CIS benchmark. You'd have to already know that `no-new-privileges` is a thing, that `cap_drop: [ALL]` goes before a targeted `cap_add`, that `read_only: true` usually needs a `tmpfs` for whatever your app writes. Most people writing a Compose file aren't container-security specialists. They want their stack up. Expecting everyone to carry that whole surface in their head is how you end up with a 91% finding rate. A linter flips it around: you don't memorize anything, you fix the line it points at and read why.

And it compounds. The examples never opt in, so the next person copies the unhardened shape, ships it, and becomes the next example someone copies. The corpus is that loop at scale. None of it is exotic. It's the accumulated weight of a sensible default that nobody goes back to revisit.

## What this is *not*

A few things I'm explicitly not claiming, because it's easy to over-read this:

- It measures how common misconfigurations are, not whether they were exploited. A finding is divergence from guidance, not evidence of a breach.
- It's descriptive sampling, not statistical inference. No p-values, no population estimates.
- It's **GitHub-only and public-only.** Private and enterprise Compose may look different.

The [full "what this study does not claim"](https://github.com/tmatens/compose-lint/blob/main/docs/state-of-compose.md#what-this-study-does-not-claim) section in the report lays out every boundary.

## Try it on your own files

compose-lint is MIT-licensed, zero-config, and depends only on PyYAML. A few ways to run it:

```bash
# one-off, locally
pipx install compose-lint && compose-lint docker-compose.yml

# or the published image (distroless, nonroot)
docker run --rm -v "$(pwd):/src" composelint/compose-lint
```

In CI, there's a GitHub Action:

```yaml
# .github/workflows/compose-lint.yml
name: compose-lint
on: [pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tmatens/compose-lint@v0.7.0
        with:
          pattern: "**/*compose*.y*ml"   # docker-compose.yml, compose.yaml, …
          fail-on: high
```

`fail-on: high` (the default) fails only on HIGH/CRITICAL, so you can adopt it without drowning in the MEDIUM backlog on day one, then tighten later. There's also a pre-commit hook, JSON and SARIF output (SARIF feeds GitHub Code Scanning), and `compose-lint --explain CL-0007` to print any rule's rationale and fix.

For what it's worth on a tool you'd wire into CI: every rule cites OWASP, CIS, or Docker docs, the image is distroless and nonroot, and releases ship SLSA provenance and Sigstore attestations. Details are in the [repo](https://github.com/tmatens/compose-lint).

📊 **The full report** has every table, the complete methodology, the per-rule breakdowns, and steps to reproduce it: **[State of Docker Compose Security](https://github.com/tmatens/compose-lint/blob/main/docs/state-of-compose.md)**

If you maintain a popular Compose example, I'd genuinely love a PR or an issue. Hardening the examples people copy is the highest-leverage fix there is.
