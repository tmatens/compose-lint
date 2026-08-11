# State of Docker Compose Security

> This is the canonical, citable version of the State of Docker Compose Security report. Tracking issue: [#186](https://github.com/tmatens/compose-lint/issues/186).
>
> Pinned to **compose-lint 0.16.0** and corpus run **`20260811T044906Z`** (5,417 files, 2026-08-11).
>
> **This edition is a new baseline, not a refresh of the previous one.** The 6,444-file corpus the 0.7.0 edition was pinned to no longer exists, and it cannot be rebuilt: its `longtail` tier was a stratified GitHub code-search sweep, and GitHub does not reproduce that sweep. The rule set changed underneath it as well. Two variables moved at once, so **no delta across the two editions is measurable, and none is presented here** — figures from the 0.7.0 edition are not repeated as like-for-like comparisons, because they were not measured the same way. The snapshot behind this edition is archived rather than left in a cache directory, so the discontinuity does not happen twice, and refreshes measured against it can carry a delta callout.

The first published empirical study of security misconfigurations in real-world Docker Compose files at corpus scale.

## TL;DR

- **91% of public Docker Compose files** that successfully parse ship with at least one security finding (4,816 of 5,279 parsed files, from a 5,417-file corpus).
- **Even canonical vendor examples are not clean.** The canonical tier — the awesome-compose / bitnami / grafana / vaultwarden examples people copy-paste — averages 9.95 findings per file, and 83.7% of those files carry at least one.
- **The same four rules lead every tier:** filesystem not read-only, no capability restrictions, no resource limits, privilege escalation not blocked. Each fires on 89–91% of parsed files, and their order barely changes between vendor examples and the longtail.
- **9.1% of longtail files fail to parse as a v2/v3 Compose file at all** — almost entirely shape errors (someone wrote `services` as a string-valued mapping instead of a service-mapping), not malformed YAML. We treat the parse-error population as a finding, not a discard.
- **Every one of the 25 rules fires on real files.** None is dead, and there were zero crashes and zero timeouts across 5,279 linted files.

The framing is descriptive, not inferential. Read [§ What this study does NOT claim](#what-this-study-does-not-claim) before citing any number from this report.

## Methodology

### Corpus

The corpus lives outside the repo at `~/.cache/compose-lint-corpus/`. Each unique compose file is stored by content hash; an index file maps content hash → source repo, path, blob SHA, and tier. The fetch + lint pipeline is in [`scripts/corpus/`](https://github.com/tmatens/compose-lint/tree/main/scripts/corpus). All numbers in this report come from corpus run `20260811T044906Z` (2026-08-11).

The corpus is divided into four tiers, each with a distinct threat-model framing:

| Tier | Files | What it represents |
| --- | ---: | --- |
| `canonical` | 345 | Official upstream examples (awesome-compose, bitnami, docker/compose, grafana, vaultwarden, …). *Do the examples people copy-paste ship insecure defaults?* |
| `popular` | 3,351 | High-star (≥50) GitHub repos with a Compose file pushed in the last two years. *What does production-adjacent code look like?* |
| `selfhosted` | 596 | Curated app-store / template-registry repos (CasaOS-AppStore, runtipi-appstore, Compose-Examples, dockge, …). Distinct threat model from `popular`: home-LAN deployments, not cloud. |
| `longtail` | 1,125 | Stratified GitHub-code-search sweep across anchor terms × filenames × size buckets — the low-visibility mass of ordinary repos (a homelab, a tutorial follow-along, a half-finished side project), as opposed to the curated, high-attention head the other three tiers represent. The name is the "long tail" of GitHub *by repo attention*, not a distribution tail in the statistical sense. *What does the median compose file in the wild look like?* |

Tier sizes are a property of the sweep that built this snapshot, not a designed allocation, and they differ from the previous edition's. The `longtail` tier in particular is whatever the code-search sweep returned on the day it ran — which is exactly why it does not reproduce.

The longtail sweep is **not random sampling.** GitHub's code-search API has no random-document primitive, so `fetch.py` runs 6 anchors × 4 filenames × 5 size buckets = 120 stratified queries × up to 200 hits each, deduped on `(repo, path, sha)` then on content hash. The exact query design and inherited biases are documented in [`scripts/corpus/README.md`](https://github.com/tmatens/compose-lint/blob/main/scripts/corpus/README.md#longtail-sampling-methodology).

### Tool

All findings come from [compose-lint 0.16.0](https://github.com/tmatens/compose-lint/releases/tag/v0.16.0) — **25 rules** — running with `--fail-on low` (so every severity is reported, not gated). Each rule cites OWASP, CIS, or Docker docs; rule definitions are in [`docs/rules/`](rules/). The version pin matters: when a new rule lands or an existing rule's severity changes, the headline percentages move.

Severities in this edition come from the derived two-axis model in [`docs/severity.md`](severity.md): a rule's tier is what the matrix produces for its cell under a stated attacker baseline and the grounded Docker posture, not a number chosen per rule. Any severity read off this page describes that model. It is the reason the tier shares here cannot be compared against an edition built on an earlier model, even setting the corpus change aside.

### Severity weights

For ranking rules by overall impact within a tier we use a doubled weighting: **CRITICAL = 8, HIGH = 4, MEDIUM = 2, LOW = 1**. Doubling per step keeps a single CRITICAL finding visible against a flood of MEDIUMs while still letting very common HIGHs surface. The per-rule tables in this report show raw hit counts and files-affected as well, so a reader who prefers a different curve can re-rank.

## Findings overview

Across the 5,279 successfully-parsed files:

| Metric | Value |
| --- | ---: |
| Files with ≥1 finding | 4,816 (91.2%) |
| Files clean | 463 (8.8%) |
| Total findings | 61,735 |
| Findings per file (mean) | 11.7 |
| Findings per file (median) | 7 |
| Findings per file (max) | 323 |

Severity distribution across the 61,735 findings:

| Severity | Count | Share |
| --- | ---: | ---: |
| CRITICAL | 780 | 1.3% |
| HIGH | 3,465 | 5.6% |
| MEDIUM | 47,062 | 76.2% |
| LOW | 10,428 | 16.9% |

![Stacked bar of findings by severity across all 61,735 findings: MEDIUM 76.2% (47,062), LOW 16.9% (10,428), HIGH 5.6% (3,465), CRITICAL 1.3% (780).](assets/severity-distribution.svg)

The MEDIUM-heavy distribution is a property of compose-lint's rule design, not of the corpus: the hardening misses that fire on nearly every file — capability restrictions, no-new-privileges, resource limits — sit at MEDIUM, so a near-universal rule contributes tens of thousands of findings to one tier. CRITICAL findings are rarer, because they require something acutely dangerous like a mounted control socket, but they are not marginal: **10.5% of parsed files (554 of 5,279) carry at least one CRITICAL finding**, and 7.6% carry a mounted host control socket specifically.

Broadening to HIGH-or-above, **32.4% of parsed files (1,710) carry at least one finding rated HIGH or CRITICAL.** Roughly a third of public Compose files contain something the model rates as an active dangerous grant rather than a missing flag.

If you remember a much larger HIGH-or-above share from the previous edition, that is a rule-model difference, not a change in what people write — the derived model moved several near-universal rules off HIGH, most consequentially the published-port rule. It cannot be quantified as a delta, because the corpus changed at the same time.

**LOW is one rule.** The 10,428 LOW findings (16.9%) look like a substantial tier and are almost entirely a single rule: [CL-0007](rules/CL-0007.md) (filesystem not read-only) accounts for 10,405 of them, or 99.8%. The remaining 23 come from [CL-0014](rules/CL-0014.md) (logging driver disabled, 15), [CL-0022](rules/CL-0022.md) (tmpfs re-enables exec/suid/dev, 5), and [CL-0017](rules/CL-0017.md) (shared mount propagation, 3) — rules that fire only when a file *explicitly* opts out of a default, a deliberate and uncommon act rather than an omission. Read the LOW tier as "almost every file omits `read_only: true`", not as a broad population of small problems.

## Per-tier breakdown

Tier-level rates differ enough that aggregate "X% of compose files have finding Y" numbers can mislead. A vendor example, a self-hosted app-store template, and a random GitHub file have different authorship, different intent, and different review pressure.

### Files with at least one finding

| Tier | Total | Parsed | With findings | Clean | Rate (of parsed) | Findings per parsed file |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `canonical` | 345 | 343 | 287 | 56 | 83.7% | 9.95 |
| `popular` | 3,351 | 3,317 | 3,150 | 167 | 95.0% | 13.29 |
| `selfhosted` | 596 | 596 | 596 | 0 | **100.0%** | 9.32 |
| `longtail` | 1,125 | 1,023 | 783 | 240 | 76.5% | 8.50 |

![Bar chart of the share of parsed files with at least one finding, by tier: canonical 83.7%, popular 95.0%, selfhosted 100.0%, longtail 76.5%.](assets/findings-by-tier.svg)

Notable observations:

- **Every `selfhosted` file has at least one finding.** The app-store templates ship with optimistic defaults — they target a home-LAN audience and frequently expose ports on `0.0.0.0`, run as root, mount large host paths, and skip the hardening flags. The fact that 100% of these files trigger compose-lint is the central finding of this tier.
- **Popular repos are not noticeably better than the longtail.** With ≥50 stars and recent activity as the inclusion criteria, the `popular` tier averages *more* findings per file than the longtail — 13.29 against 8.50. Higher visibility doesn't translate to hardening discipline.
- **Canonical is the cleanest tier and still 84% with findings.** The vendor examples that READMEs tell users to copy-paste are not hardening exemplars — they're configuration demos. That's the gap this report is documenting.

### Severity distribution per tier

| Tier | CRITICAL | HIGH | MEDIUM | LOW |
| --- | ---: | ---: | ---: | ---: |
| `canonical` | 23 | 212 | 2,591 | 587 |
| `popular` | 624 | 2,499 | 33,550 | 7,396 |
| `selfhosted` | 67 | 318 | 4,287 | 885 |
| `longtail` | 66 | 436 | 6,634 | 1,560 |

CRITICAL findings are concentrated in `popular` (624 of 780, 80% of all CRITICAL findings in the corpus) — though `popular` is also the largest tier, so the concentration partly tracks tier size. Normalising to the share of each tier's parsed files carrying a mounted host control socket ([CL-0001](rules/CL-0001.md), the dominant CRITICAL rule) separates the two: `popular` 9.9%, `selfhosted` 5.2%, `canonical` 4.4%, `longtail` 2.3%. The production-adjacent tier really does mount the control socket most often, roughly four times as often as the longtail.

## Top findings

Ten rules account for 98% of all findings. They cluster into three groups: hardening defaults that nobody flips, supply-chain shortcuts, and acute privilege grants.

![Horizontal bar chart of the ten most common rules by share of parsed files affected, coloured by severity: CL-0007 read_only 91% (LOW), CL-0006 cap_drop ALL 91% (MEDIUM), CL-0026 No resource limits 90% (MEDIUM), CL-0003 no-new-privileges 89% (MEDIUM), CL-0005 Ports published on 0.0.0.0 64% (MEDIUM), CL-0019 Image tags without digest pins 49% (MEDIUM), CL-0004 Unpinned image tags 46% (MEDIUM), CL-0020 Credential-shaped environment keys 20% (HIGH), CL-0001 Host control socket exposed 8% (CRITICAL), CL-0011 Strong host-adjacent capabilities 4% (HIGH).](assets/top-findings.svg)

### Hardening defaults (the bulk of the findings)

These four rules fire on roughly 90% of every parsed file in the corpus:

| Rule | Severity | Files affected | Share of parsed |
| --- | --- | ---: | ---: |
| [CL-0007](rules/CL-0007.md) Filesystem not read-only | LOW | 4,791 | 90.8% |
| [CL-0006](rules/CL-0006.md) No capability restrictions | MEDIUM | 4,788 | 90.7% |
| [CL-0026](rules/CL-0026.md) No resource limits | MEDIUM | 4,728 | 89.6% |
| [CL-0003](rules/CL-0003.md) Privilege escalation not blocked | MEDIUM | 4,722 | 89.4% |

Each is a *missing hardening flag* rather than an active misuse — the file isn't doing something dangerous, it's failing to opt into a defense-in-depth control, which is why the derived model rates them MEDIUM or LOW rather than HIGH. The fact that each fires on ~90% of files is the central observation of the report: the Compose hardening set (`read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, and a `deploy.resources.limits` block) is essentially never set.

The four move together. They are not four independent habits but one: a service definition written without a hardening pass at all.

### Network and supply-chain shortcuts

| Rule | Severity | Files affected | Share of parsed |
| --- | --- | ---: | ---: |
| [CL-0005](rules/CL-0005.md) Ports bound to all interfaces | MEDIUM | 3,396 | 64.3% |
| [CL-0019](rules/CL-0019.md) Image tag without digest | MEDIUM | 2,595 | 49.2% |
| [CL-0004](rules/CL-0004.md) Image not pinned to version | MEDIUM | 2,421 | 45.9% |

Nearly two thirds of all parsed files publish at least one port to `0.0.0.0`. The image-pinning pair (CL-0019 + CL-0004) shows that ~49% of files don't pin a digest and ~46% don't even pin a tag — `latest` is still the de facto default in published examples.

### Acute privilege grants

| Rule | Severity | Files affected | Share of parsed |
| --- | --- | ---: | ---: |
| [CL-0020](rules/CL-0020.md) Credential-shaped env key with literal value | HIGH | 1,042 | 19.7% |
| [CL-0001](rules/CL-0001.md) Host control socket exposed | CRITICAL | 399 | 7.6% |
| [CL-0011](rules/CL-0011.md) Strong host-adjacent capability added | HIGH | 194 | 3.7% |
| [CL-0021](rules/CL-0021.md) Credential embedded in connection-string env value | HIGH | 152 | 2.9% |
| [CL-0008](rules/CL-0008.md) Host network mode | HIGH | 137 | 2.6% |
| [CL-0013](rules/CL-0013.md) Sensitive host path exposed | HIGH | 126 | 2.4% |
| [CL-0002](rules/CL-0002.md) Privileged mode enabled | CRITICAL | 121 | 2.3% |
| [CL-0024](rules/CL-0024.md) Host-code-execution capability added | CRITICAL | 66 | 1.3% |
| [CL-0025](rules/CL-0025.md) Root-equivalent host path mounted writable | CRITICAL | 30 | 0.6% |

These are the rules where a finding indicates an *active* dangerous configuration, not a missing flag. Two observations:

- **Plaintext credentials are the most common acute finding by a wide margin.** CL-0020 fires on 19.7% of parsed files — roughly one in five commits a literal value to an environment variable that looks like a credential (e.g. `DB_PASSWORD: hunter2`). Adding CL-0021's connection-string variant, better than one in five public Compose files carries a credential in cleartext.
- **The container-escape rules are rare but not negligible.** A mounted host control socket (CL-0001, 7.6%) and `privileged: true` (CL-0002, 2.3%) each grant root-equivalent host access. Together with the capability and host-path rules, they are what lifts the CRITICAL-carrying share to 10.5% of parsed files.

The remaining rules each fire on under 1.5% of files: [CL-0018](rules/CL-0018.md) explicit root user (1.3%), [CL-0009](rules/CL-0009.md) security profile disabled (1.1%), [CL-0010](rules/CL-0010.md) host namespace sharing (0.5%), [CL-0027](rules/CL-0027.md) bounded-grant capability (0.2%), [CL-0014](rules/CL-0014.md) logging driver disabled (0.2%), [CL-0016](rules/CL-0016.md) dangerous host device (0.1%), [CL-0022](rules/CL-0022.md) tmpfs re-enables exec/suid/dev (0.1%), [CL-0017](rules/CL-0017.md) shared mount propagation (0.1%), and [CL-0028](rules/CL-0028.md) host-reaching capability (one file). A rule at this rate is not dead — it is specific, and the corpus is large enough to find its handful of real instances.

## Parse errors as a finding

138 of 5,417 files (2.5%) did not lint as a v2 or v3 Compose file. The dominant class is shape errors — files that don't match the Compose schema's expected structure — not malformed YAML.

| Class | Count | Description |
| --- | ---: | --- |
| `services-not-mapping` | 55 | The top-level `services` key is something other than a mapping (commonly a list or a scalar) |
| `service-not-mapping` | 32 | A specific service is a scalar instead of a mapping (e.g., `db: "postgres:14"`) |
| `invalid-yaml` | 24 | YAML scanner / parser error |
| `empty-file` | 8 | File parsed to nothing |
| `top-level-not-mapping` | 7 | Root document is a list or scalar |
| `other` | 7 | Not a parse failure — all seven are files using `include:`, which compose-lint declines to lint because it does not resolve included files (see below) |
| `missing-services-key` | 5 | No `services:` at the top level (likely an `extends:`-only fragment or an old v1 file) |

**Seven of the 138 are not errors.** They are `include:` files, which compose-lint deliberately refuses rather than lints: the services live in other files it does not resolve, so linting what is written would report a misleading clean result. They land in the same exit-2 population as genuine parse failures and are counted here for completeness; the real parse-failure count is 131 (2.4%).

The per-tier rate is the load-bearing number:

| Tier | Parse-error rate | Dominant class |
| --- | ---: | --- |
| `canonical` | 0.6% | invalid-yaml |
| `popular` | 1.0% | invalid-yaml |
| `selfhosted` | 0.0% | — |
| `longtail` | **9.1%** | shape errors (53% + 30%) |

![Bar chart of parse-error rate by tier: canonical 0.6%, popular 1.0%, selfhosted 0.0%, longtail 9.1%.](assets/parse-error-rate.svg)

Longtail's parse-error tail isn't malformed YAML. It's people writing `services` as a string-valued mapping, the way a `package.json` `dependencies` block works. A reader skimming a Compose tutorial sees `nginx: image: nginx:1.25` and writes `nginx: nginx:1.25` instead. The parse error here is itself a security-relevant finding: a Compose file that doesn't parse with a real Compose engine isn't deployed by that engine, so these files are documentation, copy-paste fragments, or first-attempts — none of which are getting linted before they ship.

## Related work

Two pieces of prior work are the closest neighbors to this report. Neither publishes a Compose-specific corpus security study, which is why the framing here is "first published empirical study" — but the framing is only credible if they are acknowledged.

- **Ibrahim, Truong, Wadia, Zhang & Wahsheh (EMSE 27(1), 2021).** *A study of how Docker Compose is used to compose multi-component systems.* [Springer link.](https://link.springer.com/article/10.1007/s10664-021-10025-1) The closest existing corpus study of Docker Compose. Examines composition patterns and architectural shape, not security misconfigurations. This report's tier model is partly informed by their findings on heterogeneity between hobbyist and production Compose usage.
- **Liu, Wang, Tao & Lu (ESORICS 2020).** *A large-scale empirical study of Docker container security.* [Paper PDF.](https://www-users.cse.umn.edu/~kjlu/papers/docker.pdf) A Docker Hub image corpus security study. They flag `docker-compose.yml` as an underexplored attack surface. This report is a direct response to that gap.

## What this study does NOT claim

Read this section before citing any number from the report. The corpus is a descriptive sample, not a randomized population study, and the framing matters for what the findings can and cannot support.

### Out of scope by design

- **Exploit rate.** Findings count *misconfigurations that violate hardening guidance*. The report does not measure how often each misconfiguration is exploited in the wild, which exploits are reachable from the public internet, or which exploits have been observed in incident data. A finding is a code smell with a citation, not an attestation that the file has been compromised.
- **Runtime behavior.** compose-lint reads YAML; it does not run containers. The corpus tells us what people *write* in Compose files, not what their containers actually do once started (network policy, AppArmor profiles, kernel features, secret-injection sidecars, runtime admission controllers).
- **Production usage.** Public GitHub repos are a mix of demos, tutorials, archived projects, app-store templates, and production code. The corpus cannot distinguish them. A `docker-compose.yml` in a public repo is *evidence that someone wrote that compose file*, not evidence that anything is running it.
- **Private-repo prevalence.** The corpus is public-only. Enterprise and internal Compose files are out of scope; their misconfiguration distribution may differ.

### Sampling caveats

- **GitHub-only.** No GitLab, Codeberg, Gitea, Bitbucket, Docker Hub README snippets, package-manager fragments, blog-post YAML blocks, or Stack Overflow answers. The longtail tier is a stratified sweep of GitHub's code search; see [`scripts/corpus/README.md`](https://github.com/tmatens/compose-lint/blob/main/scripts/corpus/README.md#longtail-sampling-methodology) for the exact query design and the four biases it inherits.
- **Filename-pinned.** Files saved under non-standard names (`stack.yml`, `web.compose.yml`, etc.) are missed. The four canonical filenames cover the documented Compose Specification names but not every project's conventions.
- **No statistical inference.** This is descriptive sampling for prevalence estimation. There are no hypothesis tests, no confidence intervals, no population estimates, and no claims about the "average" Compose file outside the four named tiers (`canonical`, `popular`, `selfhosted`, `longtail`). Tier counts are reported as observed; treat them as descriptive of the corpus, not extrapolated to all of GitHub.
- **Snapshot in time.** Each report version pins to a single corpus run and a single compose-lint version. The published numbers do not move when a new rule lands; a refresh ships a new version with its own run.
- **Editions are not a time series.** This edition is a new baseline: the corpus behind the previous one is gone and unrebuildable, and the rule set changed at the same time, so the two cannot be differenced. Do not read successive editions of this report as a trend unless the edition explicitly states that it was measured against the same archived snapshot as its predecessor.

### Tool caveats

- **Rules are based on hardening guidance, not on incident response data.** Each rule cites OWASP, CIS, or Docker docs. A rule firing means the file diverges from authoritative hardening guidance, not that an attacker would necessarily exploit the divergence on a given deployment.
- **compose-lint does not validate the full Compose schema.** Files that fail to parse as v2/v3 Compose are bucketed by error class and reported as a separate population, not silently dropped. The parser does not resolve `${VAR}` interpolation or merge external `extends:` files; rules see what is written in the file, not the runtime resolution.

The framing is: *here is what people put in their Compose files at corpus scale, scored against published hardening guidance, with the sampling design and tool boundaries spelled out so you can re-rank, re-bucket, or re-run against your own corpus*. It is not a runtime risk assessment, a CVE database, or a population estimate.

## Reproducibility

The corpus is not committed to the repo (third-party content), but the pipeline that builds it is. **Re-fetching does not reproduce this corpus** — see the note below — so the reproducible path is to lint the archived snapshot:

```bash
git clone https://github.com/tmatens/compose-lint
cd compose-lint
git checkout v0.16.0    # the tool version this report is pinned to
python -m venv .venv && .venv/bin/pip install -e .

# Restore the archived snapshot this edition is measured on.
# sha256 d9be6bbc7a0971a37d0715b5d8ef8b9ef08b64ddd375fc6aebe4e708ffa5e0f5
mkdir -p ~/.cache/compose-lint-corpus
tar -xzf compose-lint-corpus-5417-20260811.tar.gz -C ~/.cache/compose-lint-corpus

# Lint the corpus and write summary.md + tier_summary.md.
# COMPOSE_LINT_BIN defaults to <repo>/.venv/bin/compose-lint; set it
# explicitly if your interpreter lives anywhere else.
COMPOSE_LINT_BIN=$PWD/.venv/bin/compose-lint python scripts/corpus/run.py

# Re-render the charts in this report (matplotlib is a maintainer-only extra)
pip install -e '.[corpus]'
python scripts/corpus/charts.py latest
```

The snapshot archive is not committed to the repo — it is 5,417 third-party files, the same reason the corpus itself isn't committed. It is held by the maintainers and identified by the sha256 above; open an issue on the tracker if you want a copy to verify a number in this report against.

To build a *new* corpus from public GitHub instead — a different sample, not this one — run the four fetchers plus `retier.py` and `enrich_metadata.py` first (`fetch.py`, `fetch_popular.py`, `fetch_canonical.py`, `fetch_selfhosted.py`); they are idempotent and re-running adds new files without re-downloading.

The output lands in `~/.cache/compose-lint-corpus/runs/<UTC-timestamp>/`. The `summary.md` and `tier_summary.md` files there are the source artifacts every table in this report is built from; `charts.py` reads the same per-tier aggregation, so the figures in `docs/assets/` can never disagree with the tables. A run that reports thousands of *crashes* is almost always a `COMPOSE_LINT_BIN` that does not exist — the harness buckets a missing binary as a per-file crash rather than a startup failure. Check the first few results before letting a full run proceed.

**Why re-fetching does not reproduce this corpus.** Three of the four tiers are enumerable from fixed sources and re-fetch closely. The `longtail` tier is not: it is a stratified GitHub code-search sweep, and GitHub's code search neither offers a random-document primitive nor returns a stable result set for the same queries over time. A re-fetch produces *a* longtail tier, not *this* one. That is why the 6,444-file corpus behind the 0.7.0 edition could not be rebuilt once its cache was lost, and why this edition's 5,417-file snapshot is archived as a file rather than trusted to a cache directory. Refreshes measured against the archived snapshot isolate rule-set changes from corpus drift and can legitimately carry a delta; a refresh against a fresh sweep cannot.
