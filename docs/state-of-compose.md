# State of Docker Compose Security

> **Status: draft in progress.** This is the canonical doc for the State of Docker Compose Security report. Tracking issue: [#186](https://github.com/tmatens/compose-lint/issues/186).
>
> Pinned to **compose-lint 0.7.0** and corpus run **`20260503T034026Z`** (6,444 files, 2026-05-03). Quarterly refreshes will bump both with a one-line delta callout.

The first published empirical study of security misconfigurations in real-world Docker Compose files at corpus scale.

## TL;DR

- **91% of public Docker Compose files** that successfully parse ship with at least one security finding (5,716 of 6,266 files in a 6,444-file corpus).
- **Even canonical vendor examples are not clean.** The canonical tier — the awesome-compose / bitnami / grafana / vaultwarden examples people copy-paste — averages 8.0 findings per file.
- **The top three findings are the same across every tier:** filesystem not read-only, no capability restrictions, privilege escalation not blocked. They fire on roughly 90% of every parsed file.
- **9.6% of longtail files fail to parse as a v2/v3 Compose file at all** — almost entirely shape errors (someone wrote `services` as a string-valued mapping instead of a service-mapping), not malformed YAML. We treat the parse-error population as a finding, not a discard.

The framing is descriptive, not inferential. Read [§ What this study does NOT claim](#what-this-study-does-not-claim) before citing any number from this report.

## Methodology

### Corpus

The corpus lives outside the repo at `~/.cache/compose-lint-corpus/`. Each unique compose file is stored by content hash; an index file maps content hash → source repo, path, blob SHA, and tier. The fetch + lint pipeline is in [`scripts/corpus/`](../scripts/corpus/). All numbers in this report come from corpus run `20260503T034026Z` (2026-05-03).

The corpus is divided into four tiers, each with a distinct threat-model framing:

| Tier | Files | What it represents |
| --- | ---: | --- |
| `canonical` | 327 | Official upstream examples (awesome-compose, bitnami, docker/compose, grafana, vaultwarden, …). *Do the examples people copy-paste ship insecure defaults?* |
| `popular` | 3,977 | High-star (≥50) GitHub repos with a Compose file pushed in the last two years. *What does production-adjacent code look like?* |
| `selfhosted` | 588 | Curated app-store / template-registry repos (CasaOS-AppStore, runtipi-appstore, Compose-Examples, dockge, …). Distinct threat model from `popular`: home-LAN deployments, not cloud. |
| `longtail` | 1,552 | Stratified GitHub-code-search sweep across anchor terms × filenames × size buckets. *What does the median compose file in the wild look like?* |

The longtail sweep is **not random sampling.** GitHub's code-search API has no random-document primitive, so `fetch.py` runs 6 anchors × 4 filenames × 5 size buckets = 120 stratified queries × up to 200 hits each, deduped on `(repo, path, sha)` then on content hash. The exact query design and inherited biases are documented in [`scripts/corpus/README.md`](../scripts/corpus/README.md#longtail-sampling-methodology).

### Tool

All findings come from [compose-lint 0.7.0](https://github.com/tmatens/compose-lint/releases/tag/v0.7.0) running with `--fail-on low` (so every severity is reported, not gated). Each rule cites OWASP, CIS, or Docker docs; rule definitions are in [`docs/rules/`](rules/). The version pin matters: when a new rule lands or an existing rule's severity changes, the headline percentages move. Quarterly refreshes will explicitly call out compose-lint version deltas.

### Severity weights

For ranking rules by overall impact within a tier we use a doubled weighting: **CRITICAL = 8, HIGH = 4, MEDIUM = 2, LOW = 1**. Doubling per step keeps a single CRITICAL finding visible against a flood of MEDIUMs while still letting very common HIGHs surface. The per-rule tables in this report show raw hit counts and files-affected as well, so a reader who prefers a different curve can re-rank.

## Findings overview

Across the 6,266 successfully-parsed files:

| Metric | Value |
| --- | ---: |
| Files with ≥1 finding | 5,716 (91.2%) |
| Files clean | 550 (8.8%) |
| Total findings | 64,767 |
| Findings per file (mean) | 10.3 |
| Findings per file (median) | 6 |
| Findings per file (max) | 627 |

Severity distribution across the 64,767 findings:

| Severity | Count | Share |
| --- | ---: | ---: |
| CRITICAL | 730 | 1.1% |
| HIGH | 13,147 | 20.3% |
| MEDIUM | 50,867 | 78.5% |
| LOW | 23 | 0.0% |

The MEDIUM-heavy distribution is a property of compose-lint's rule design: the three most common hardening misses (read-only root FS, capability restrictions, no-new-privileges) are MEDIUM and they fire on nearly every file in the corpus. CRITICAL findings are rarer — they require something acutely dangerous like a Docker socket mount — but they appear on 6.4% of parsed files (399 of 6,266).

## Per-tier breakdown

Tier-level rates differ enough that aggregate "X% of compose files have finding Y" numbers can mislead. A vendor example, a self-hosted app-store template, and a random GitHub file have different authorship, different intent, and different review pressure.

### Files with at least one finding

| Tier | Total | Parsed | With findings | Clean | Rate (of parsed) | Findings per parsed file |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `canonical` | 327 | 325 | 269 | 56 | 82.8% | 8.05 |
| `popular` | 3,977 | 3,950 | 3,760 | 190 | 95.2% | 11.33 |
| `selfhosted` | 588 | 588 | 588 | 0 | **100.0%** | 7.53 |
| `longtail` | 1,552 | 1,403 | 1,099 | 304 | 78.3% | 9.25 |

Notable observations:

- **Every `selfhosted` file has at least one finding.** The app-store templates ship with optimistic defaults — they target a home-LAN audience and frequently expose ports on `0.0.0.0`, run as root, mount large host paths, and skip the hardening flags. The fact that 100% of these files trigger compose-lint is the central finding of this tier.
- **Popular repos are not noticeably better than the longtail.** With ≥50 stars and recent activity as the inclusion criteria, the `popular` tier averages *more* findings per file than the longtail. Higher visibility doesn't translate to hardening discipline.
- **Canonical is the cleanest tier and still 83% with findings.** The vendor examples that READMEs tell users to copy-paste are not hardening exemplars — they're configuration demos. That's the gap this report is documenting.

### Severity distribution per tier

| Tier | CRITICAL | HIGH | MEDIUM | LOW |
| --- | ---: | ---: | ---: | ---: |
| `canonical` | 19 | 470 | 2,128 | 0 |
| `popular` | 586 | 9,163 | 34,971 | 22 |
| `selfhosted` | 49 | 870 | 3,506 | 0 |
| `longtail` | 76 | 2,644 | 10,262 | 1 |

CRITICAL findings are concentrated in `popular` (586 of 730, 80% of all CRITICAL findings in the corpus). The dominant CRITICAL rule is **CL-0001 (Docker socket mounted)** — see § Top findings.

## Top findings

Ten rules account for >95% of all findings. They cluster into three groups: hardening defaults that nobody flips, supply-chain shortcuts, and acute privilege grants.

### Hardening defaults (the long tail of MEDIUM findings)

These three rules fire on roughly 90% of every parsed file in the corpus:

| Rule | Severity | Files affected | Share of parsed |
| --- | --- | ---: | ---: |
| [CL-0007](rules/CL-0007.md) Filesystem not read-only | MEDIUM | 5,690 | 90.8% |
| [CL-0006](rules/CL-0006.md) No capability restrictions | MEDIUM | 5,691 | 90.8% |
| [CL-0003](rules/CL-0003.md) Privilege escalation not blocked | MEDIUM | 5,633 | 89.9% |

These are MEDIUMs because each one is a *missing hardening flag* rather than an active misuse — the file isn't doing something dangerous, it's failing to opt into a defense-in-depth control. The fact that each one fires on ~90% of files is the central observation of the report: the Compose hardening triple (`read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`) is essentially never set.

### Network and supply-chain shortcuts

| Rule | Severity | Files affected | Share of parsed |
| --- | --- | ---: | ---: |
| [CL-0005](rules/CL-0005.md) Ports bound to all interfaces | HIGH | 3,619 | 57.8% |
| [CL-0019](rules/CL-0019.md) Image tag without digest | MEDIUM | 3,244 | 51.8% |
| [CL-0004](rules/CL-0004.md) Image not pinned to version | MEDIUM | 2,858 | 45.6% |

Over half of all parsed files publish at least one port to `0.0.0.0`. The image-pinning pair (CL-0019 + CL-0004) shows that ~50% of files don't pin a digest and ~46% don't even pin a tag — `latest` is still the de facto default in published examples.

### Acute privilege grants

| Rule | Severity | Files affected | Share of parsed |
| --- | --- | ---: | ---: |
| [CL-0020](rules/CL-0020.md) Credential-shaped env key with literal value | HIGH | 1,230 | 19.6% |
| [CL-0013](rules/CL-0013.md) Sensitive host path mounted | HIGH (CRITICAL when `/`) | 649 | 10.4% |
| [CL-0001](rules/CL-0001.md) Docker socket mounted | CRITICAL | 399 | 6.4% |
| [CL-0011](rules/CL-0011.md) Dangerous capabilities added | HIGH (CRITICAL when `cap_add: ALL`) | 258 | 4.1% |

These are the rules where a finding indicates an *active* dangerous configuration, not a missing flag. CL-0020 is by far the most common: ~20% of files commit a literal value to an environment variable that looks like a credential (e.g., `DB_PASSWORD: hunter2`). CL-0001 (Docker socket mounted) is the canonical container-escape vector and appears on 6.4% of parsed files; in the `popular` tier specifically it appears on 8.1%.

## Parse errors as a finding

178 of 6,444 files (2.8%) failed to parse as a v2 or v3 Compose file at all. The dominant class is shape errors — files that don't match the Compose schema's expected structure — not malformed YAML.

| Class | Count | Description |
| --- | ---: | --- |
| `services-not-mapping` | 74 | The top-level `services` key is something other than a mapping (commonly a list or a scalar) |
| `service-not-mapping` | 49 | A specific service is a scalar instead of a mapping (e.g., `db: "postgres:14"`) |
| `invalid-yaml` | 28 | YAML scanner / parser error |
| `empty-file` | 13 | File parsed to nothing |
| `top-level-not-mapping` | 8 | Root document is a list or scalar |
| `missing-services-key` | 6 | No `services:` at the top level (likely an `extends:`-only fragment or an old v1 file) |

The per-tier rate is the load-bearing number:

| Tier | Parse-error rate | Dominant class |
| --- | ---: | --- |
| `canonical` | 0.6% | invalid-yaml |
| `popular` | 0.7% | top-level-not-mapping |
| `selfhosted` | 0.0% | — |
| `longtail` | **9.6%** | shape errors (49% + 32%) |

Longtail's parse-error tail isn't malformed YAML. It's people writing `services` as a string-valued mapping, the way a `package.json` `dependencies` block works. A reader skimming a Compose tutorial sees `nginx: image: nginx:1.25` and writes `nginx: nginx:1.25` instead. The parse error here is itself a security-relevant finding: a Compose file that doesn't parse with a real Compose engine isn't deployed by that engine, so these files are documentation, copy-paste fragments, or first-attempts — none of which are getting linted before they ship.

## Related work

Three pieces of prior work are the closest neighbors to this report. None of them publish a Compose-specific corpus security study, which is why the framing here is "first published empirical study" — but the framing is only credible if these are acknowledged.

- **Ibrahim, Truong, Wadia, Zhang & Wahsheh (EMSE 27(1), 2021).** *A study of how Docker Compose is used to compose multi-component systems.* [Springer link.](https://link.springer.com/article/10.1007/s10664-021-10025-1) The closest existing corpus study of Docker Compose. Examines composition patterns and architectural shape, not security misconfigurations. This report's tier model is partly informed by their findings on heterogeneity between hobbyist and production Compose usage.
- **Liu, Wang, Tao & Lu (ESORICS 2020).** *A large-scale empirical study of Docker container security.* [Paper PDF.](https://www-users.cse.umn.edu/~kjlu/papers/docker.pdf) A Docker Hub image corpus security study. They flag `docker-compose.yml` as an underexplored attack surface. This report is a direct response to that gap.
- **ComposeAudit** ([github.com/kriskimmerle/composeaudit](https://github.com/kriskimmerle/composeaudit)). The closest peer tool — also focused on Compose security misconfigurations. No published corpus findings; this report is the first published empirical study using either compose-lint or ComposeAudit's rule sets.

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

## Reproducibility

The corpus is not committed to the repo (third-party content), but the pipeline that builds it is. To reproduce these numbers from scratch:

```bash
git clone https://github.com/tmatens/compose-lint
cd compose-lint
git checkout v0.7.0    # the tool version this report is pinned to
python -m venv .venv && .venv/bin/pip install -e .

# Build the corpus from public GitHub. The four fetchers + retier + enrich
# steps are idempotent; re-running adds new files without re-downloading.
python scripts/corpus/fetch.py
python scripts/corpus/fetch_popular.py
python scripts/corpus/fetch_canonical.py
python scripts/corpus/fetch_selfhosted.py
python scripts/corpus/retier.py
python scripts/corpus/enrich_metadata.py

# Lint the corpus and write summary.md + tier_summary.md
python scripts/corpus/run.py
```

The output lands in `~/.cache/compose-lint-corpus/runs/<UTC-timestamp>/`. The `summary.md` and `tier_summary.md` files there are the source artifacts every table in this report is built from.

GitHub's code-search ranking is stochastic enough that a second run will not produce a byte-identical corpus, but the headline rates (per-tier finding rate, top-rule ranking, parse-error class distribution) are stable across runs at this corpus size. Quarterly refresh PRs will land both the new run's numbers and a delta callout against the previous version.
