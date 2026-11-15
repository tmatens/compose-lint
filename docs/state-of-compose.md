# State of Docker Compose Security

> **Fourth edition.** compose-lint 1.6.0, 11,111 public Compose files, run on 2026-11-15 UTC. Cite this version. Tracking issue: [#186](https://github.com/tmatens/compose-lint/issues/186). The [third edition](https://github.com/tmatens/compose-lint/blob/878a18bae9ed671c65fe4cea057e1dc06cbd5523/docs/state-of-compose.md) stays available at its commit.

A study of security misconfigurations in public Docker Compose files, measured on a corpus of 11,111 files from GitHub.

## Summary

- **99.2% of the files that lint have at least one security finding** (5,860 of 5,907).
- **96.2% set none of the four basic hardening flags:** a read-only filesystem, dropped capabilities, resource limits and blocked privilege escalation.
- **Hardening is not improving over time.** Files written in the last year have 5.99 findings per service and files three or more years old have 5.82.
- **Popular projects' files have the most findings because they are bigger.** Every group of files has about 6 findings per service, and popular projects write 3.3 services per file.
- **Local and dev overlay files hardcode more credentials** than main files do, at 37% and 35% against 28%.
- **Nothing moved since the third edition.** Across 23 releases of the tool, no file changed between "has findings" and "clean".

The numbers describe this sample. They are not estimates for all Compose files. Read [What this study does NOT claim](#what-this-study-does-not-claim) before citing any number from this report.

### Terms

- **Finding:** one rule firing on one service. It means the file diverges from published hardening guidance. It does not mean anything was exploited.
- **Tier:** a group of files from the same kind of source. The five compared tiers are `canonical` (vendor examples), `selfhosted` (app-store templates), `collections` (template collections), `popular` (projects with 50 or more stars) and `longtail` (everything else).
- **Prevalence tiers:** those five. Rates in this report are over them unless a section says otherwise.
- **Parsed:** the file was linted. A file that was **skipped** (an obsolete Compose v1 layout or a fragment) or that failed to parse is counted separately and is never counted as clean.
- **Lane:** a set of files reported on its own and not mixed into the main rates. Overlay files are a lane.

## Methodology

### This edition

The corpus is the snapshot the third edition used, captured on 2026-08-27: `compose-lint-corpus-11111-20260827.tar.gz`, sha256 `049d2b5bf7167f0ca694aca23fa5483c761fbfccfa2ca7b78520a4ba8b3a5f98`. This edition's run is `20261115T050406Z`.

Because the files are the same and only the tool changed, from 0.26.0 to 1.6.0, the two editions can be compared file by file. That comparison is in [What changed since the last edition](#what-changed-since-the-last-edition). I also recomputed every third-edition figure. Five came out different, and [Corrections to the third edition](#corrections-to-the-third-edition) lists them with the measured values.

### Corpus

The corpus lives outside the repo at `~/.cache/compose-lint-corpus/`. Each unique Compose file is stored by content hash. An index maps the content hash to the source repo, path, blob SHA, tier, repo metadata and the date the captured content was authored (`blob_authored_at`). The fetch and lint pipeline is in [`scripts/corpus/`](https://github.com/tmatens/compose-lint/tree/main/scripts/corpus). All numbers in this report come from corpus run `20261115T050406Z` unless a section says otherwise.

The corpus has eight tiers. Five carry prevalence claims. Three are excluded from them and are reported separately, never blended in. The attribution rules live in `scripts/corpus/retier.py`. They were frozen before the third edition's sweep, so the tier separations below were tested on data the rules had not seen ([The replication test](#the-replication-test)).

| Tier | Files | Prevalence | What it represents |
| --- | ---: | :---: | --- |
| `canonical` | 249 | yes | Official upstream examples (awesome-compose, bitnami, grafana, vaultwarden and others). These are the examples that documentation tells people to copy. |
| `selfhosted` | 596 | yes | Curated app-store and template-registry repos (CasaOS-AppStore, runtipi-appstore, Compose-Examples, dockge and others). The threat model is a home LAN, which differs from a cloud deployment. |
| `collections` | 1,485 | yes | Template and recipe collection repos, defined as 20 or more corpus entries from one repo (vimagick/dockerfiles, laradock, ScaleTail and others). They are example libraries that happened to clear the popular tier's star bar. |
| `popular` | 1,231 | yes | The Compose files that ordinary projects with 50 or more stars use themselves. This is the closest the corpus gets to production code. |
| `longtail` | 3,105 | yes | A stratified GitHub code-search sweep across anchor terms, filenames and size buckets. This is the large number of ordinary, low-visibility repos. The sweep runs to the search API's 1,000-hit cap per query. Earlier editions stopped at 200 hits, which [over-sampled old files](#is-practice-improving-over-time). |
| `overlay` | 3,579 | no (own lane) | Variant files that are merge fragments by design: `*.override.*`, `*.prod.*`, `*.dev.*` and similar. They show real deployment intent, but their standalone lint rates are not comparable to full files. See [The overlay lane](#the-overlay-lane). |
| `synthetic` | 554 | no | Test inputs to Compose tooling: files under test, fixture or e2e path segments anywhere, plus whole tool repos (docker/compose, podman-compose, kompose). Minimal snippets leave out every hardening key by construction. |
| `lab` | 312 | no | Deliberately vulnerable environments: vulhub CVE reproductions and CTF challenge archives. When measured they lower the rates, and they are excluded because of what they are for. |

Examples, templates and demos are deliberately kept out of `synthetic`, because copy-paste material is what the `canonical`, `selfhosted` and `collections` tiers exist to measure.

### Tool

All findings come from [compose-lint 1.6.0](https://github.com/tmatens/compose-lint/releases/tag/v1.6.0), which has **28 rules**. It was installed from PyPI and run with `--fail-on low`, so every severity is reported and none is gated. Each rule cites OWASP, CIS or Docker docs, and the rule definitions are in [`docs/rules/`](index.md#rules). Severities come from the derived two-axis model in [`docs/severity.md`](severity.md).

Hardening that compose-lint has no rule for is outside what this report counts. A missing `user:`, a process limit and network segmentation are examples. They were left out of the linter on purpose, and [the hardening guide](hardening.md#hardening-compose-lint-does-not-grade) records the reason for each.

## Findings overview

Across the 5,907 parsed files in the five prevalence tiers (of 6,666 in total, with 466 skipped as Compose v1 or fragments and 293 parse errors):

| Metric | Value |
| --- | ---: |
| Files with ≥1 finding | 5,860 (99.2%) |
| Files clean | 47 (0.8%) |
| Total findings | 82,015 |
| Findings per file (mean) | 13.9 |
| Findings per file (median) | 8 |
| Findings per file (max) | 324 |

Severity distribution across the 82,015 findings:

| Severity | Count | Share |
| --- | ---: | ---: |
| CRITICAL | 921 | 1.1% |
| HIGH | 5,785 | 7.1% |
| MEDIUM | 61,585 | 75.1% |
| LOW | 13,724 | 16.7% |

![Waffle chart of 100 squares, each 1 in 100 of the 5,907 parsed files, colored by the worst finding in the file: 11 in 100 carry a CRITICAL finding (red), another 30 in 100 top out at HIGH (orange), 58 in 100 carry only MEDIUM or LOW findings (sand), and fewer than 1 in 100 is clean (one outlined square).](assets/file-severity.svg)

The distribution leans to MEDIUM because of how the rules are rated: the missing hardening flags that fire on nearly every file are MEDIUM. CRITICAL findings are rarer. **10.7% of parsed files carry at least one CRITICAL finding**, and 7.8% mount a host control socket. **40.9% of parsed files carry at least one finding rated HIGH or CRITICAL.**

**LOW is one rule.** 99.8% of the 13,724 LOW findings are [CL-0007](rules/CL-0007.md) (filesystem not read-only, 13,694). The remaining 30 come from [CL-0014](rules/CL-0014.md) (20), [CL-0017](rules/CL-0017.md) (5) and [CL-0022](rules/CL-0022.md) (5), which fire only when a file explicitly opts out of a default. Read the LOW share as "almost every file omits `read_only: true`".

## Skipped is not clean

**In plain terms:** some files exit the linter with zero findings because there was nothing in them to lint. One kind is the obsolete Compose v1 layout, with services at the top level, which Docker retired in 2023. The other is a structural fragment with no services. The first two editions counted those files as "clean", which inflated the clean population. Since the third edition the harness puts them in their own bucket.

![Stacked bar chart titled "One in nine files was never linted": per group of files, the share that was skipped (Compose v1 files and fragments, blue) or failed to parse (orange). Vendor examples 23%, app-store templates 0, template collections 12%, popular projects 3%, long tail 16%.](assets/never-linted.svg)

**466 files in the prevalence tiers were skipped** (447 Compose v1, 19 fragments), which is 7.0% of those tiers. With them out of the count, **47 of 5,907 files are clean**: 46 in `longtail` and 1 in `collections`. The v1 files are old. They are 44.9% of files authored five or more years before the snapshot and 0.7% of files under a year old.

## Per-tier breakdown

### Files with at least one finding

| Tier | Total | Parsed | Skipped | Parse-err | With findings | Clean | Rate (of parsed) | Findings per parsed file | Source repos |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `canonical` | 249 | 191 | 55 | 3 | 191 | 0 | **100%** | 13.23 | **8** |
| `selfhosted` | 596 | 596 | 0 | 0 | 596 | 0 | **100%** | 9.38 | **4** |
| `collections` | 1,485 | 1,310 | 159 | 16 | 1,309 | 1 | 99.9% | 9.98 | 16 |
| `popular` | 1,231 | 1,192 | 5 | 34 | 1,192 | 0 | **100%** | **19.97** | 734 |
| `longtail` | 3,105 | 2,618 | 247 | 240 | 2,572 | 46 | 98.2% | 14.14 | 2,583 |

"Source repos" counts the repos behind the parsed files. A tier built on few repos describes those repos, however many files they contribute: `selfhosted` is four registries and `canonical` is eight vendors. The with-findings rate does not separate the tiers, since every one is at or near 100%. Findings per file, findings per service and the acute rules below do.

### The fair comparison: per service, not per file

![Two-panel bar chart titled "Popular projects' files are bigger, with the same findings per service": findings per file by group (popular projects 20.0 highlighted in red, long tail 14.1, vendor examples 13.2, template collections 10.0, app-store templates 9.4) beside findings per service (every group within a shaded 5.8 to 6.3 band).](assets/bigger-not-sloppier.svg)

**In plain terms:** a file with six services has six chances to miss a hardening flag. When tiers differ in file size, a per-file comparison partly measures size. The per-service view is the fair one.

| Tier | Services per file | Findings per **service** | Files w/ CRITICAL | Files w/ HIGH+ | Socket: files | Socket: **services** |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `canonical` | 2.14 | 6.19 | 8.9% | 45.5% | 7.3% | 4.4% |
| `selfhosted` | 1.50 | 6.26 | 9.4% | 31.4% | 5.2% | 3.5% |
| `collections` | 1.64 | 6.08 | 11.6% | 40.2% | 7.6% | 5.0% |
| `popular` | **3.32** | 6.01 | **20.1%** | **52.7%** | **16.1%** | **6.0%** |
| `longtail` | 2.43 | 5.81 | 6.4% | 37.8% | 4.7% | 2.4% |

Whoever writes a Compose service, it goes out without hardening at about the same rate. What differs is stack size. Popular projects write 3.3 services per file, so their files have about twice the findings of a template, and one in five carries a CRITICAL finding.

On the control socket ([CL-0001](rules/CL-0001.md)), popular services mount it about 2.5 times as often as longtail services, and `collections` services also mount it more often. Those two differences pass the noise check in [A statistician's reading of these numbers](#a-statisticians-reading-of-these-numbers). The `canonical` and `selfhosted` tiers have too few source repos to claim one.

## Top findings

Ten rules account for 98% of all findings. They fall into three groups: hardening flags left at their defaults, network and supply-chain shortcuts, and acute privilege grants.

![Grouped horizontal bar chart titled "Ten rules account for 98% of all findings", share of linted files with each finding. Hardening flags left unset: read-only filesystem not set 99%, no capability restrictions 99%, no resource limits 97%, privilege escalation not blocked 97%. Network and supply-chain shortcuts: ports on 0.0.0.0 72%, no digest pin 50%, unpinned tag 50%. Acute privilege grants, where bars turn orange and red: literal credential in environment 28%, host control socket mounted 8%, credential in connection string 5%.](assets/top-findings.svg)

### Hardening defaults (the bulk of the findings)

| Rule | Severity | Files affected | Share of parsed |
| --- | --- | ---: | ---: |
| [CL-0007](rules/CL-0007.md) Filesystem not read-only | LOW | 5,833 | 98.7% |
| [CL-0006](rules/CL-0006.md) No capability restrictions | MEDIUM | 5,826 | 98.6% |
| [CL-0026](rules/CL-0026.md) No resource limits | MEDIUM | 5,754 | 97.4% |
| [CL-0003](rules/CL-0003.md) Privilege escalation not blocked | MEDIUM | 5,748 | 97.3% |

Each of these is a hardening flag that was never set, and none is an active misuse. 5,682 files (96.2%) have all four findings. That is the main observation of this report: `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]` and a `deploy.resources.limits` block are almost never used.

### Network and supply-chain shortcuts

| Rule | Severity | Files affected | Share of parsed |
| --- | --- | ---: | ---: |
| [CL-0005](rules/CL-0005.md) Ports bound to all interfaces | MEDIUM | 4,261 | 72.1% |
| [CL-0019](rules/CL-0019.md) Image tag without digest | MEDIUM | 2,967 | 50.2% |
| [CL-0004](rules/CL-0004.md) Image not pinned to version | MEDIUM | 2,963 | 50.2% |

### Acute privilege grants

| Rule | Severity | Files affected | Share of parsed |
| --- | --- | ---: | ---: |
| [CL-0020](rules/CL-0020.md) Credential-shaped env key with literal value | HIGH | 1,665 | 28.2% |
| [CL-0001](rules/CL-0001.md) Host control socket exposed | CRITICAL | 458 | 7.8% |
| [CL-0021](rules/CL-0021.md) Credential embedded in connection-string env value | HIGH | 301 | 5.1% |
| [CL-0011](rules/CL-0011.md) Strong host-adjacent capability added | HIGH | 205 | 3.5% |
| [CL-0008](rules/CL-0008.md) Host network mode | HIGH | 164 | 2.8% |
| [CL-0013](rules/CL-0013.md) Sensitive host path exposed | HIGH | 148 | 2.5% |
| [CL-0002](rules/CL-0002.md) Privileged mode enabled | CRITICAL | 141 | 2.4% |

**Plaintext credentials are the most common acute finding.** 28.4% of parsed files carry a literal credential under CL-0020 or CL-0021 (1,677 files), which is more than one in four.

The remaining rules each fire on under 2% of files. All 28 rules fire somewhere in the corpus. [CL-0031](rules/CL-0031.md), added in 1.1.0 for `use_api_socket: true`, fires on 8 files, all in the `popular` tier.

## The overlay lane

The corpus holds 3,579 overlay and variant files (`docker-compose.override.yml`, `*.prod.*`, `*.dev.*`, `*.staging.*`, `*.local.*` and similar). They are reported as their own lane, because an overlay is a merge fragment and linting it alone is a partial view. Three findings:

1. **Most overlays are full files.** 97% lint on their own (3,487 of 3,579, with 13 skipped as v1 or fragments and 79 parse errors), at **3.46 services per file**, which is as large as popular projects' main files. In this sample, multi-environment Compose is mostly a full parallel file per environment. A base file plus a sparse patch is the less common shape.
2. **Local and dev overlays carry more literal credentials.** The rate is 36.8% for `local` and 34.8% for `dev`, against 28.4% for full files, which is 1.3 times the full-file rate. Production variants sit near 21%. That is below the full-file rate, and it is still one production overlay in five. Overlays also publish ports more often, at 76.7% against 72.1%.
3. **Overlays are current practice.** 49% were authored within a year of the snapshot and 80% within three.

![Bar chart titled "Local and dev overlay files hardcode more credentials": share of overlay files with a literal credential by filename variant. Local 37%, dev 35% and development 31% in orange. Staging 22%, prod 21%, override 21% and production 21% in blue. A dashed reference line marks the main-file rate of 28.4%.](assets/overlay-credentials.svg)

Their findings per service (5.40) sit just below the full-file band. Overlays are ordinary unhardened Compose in more files and more places.

## Is practice improving over time?

No. Each file's `blob_authored_at` records when the captured content was last authored (98.8% of the corpus has one). Ages are measured against the snapshot date, 2026-08-27.

![Line chart titled "Compose hardening is not improving over time": findings per service by file age, each group of files in grey and the all-files line in red, flat at 5.99 / 5.98 / 5.82 across files written in the last year, 1 to 3 years ago, and 3+ years ago. The y-axis starts at zero.](assets/not-improving.svg)

Findings per service, by file age, within each tier:

| Tier | <1y | 1 to 3y | ≥3y |
| --- | ---: | ---: | ---: |
| `canonical` | 6.15 | 6.40 | 6.04 |
| `selfhosted` | 6.29 | 6.19 | none |
| `collections` | 5.81 | 6.15 | 6.41 |
| `popular` | 6.05 | 5.97 | 5.79 |
| `longtail` | 5.88 | 5.90 | 5.51 |
| **All prevalence** | **5.99** | **5.98** | **5.82** |

A Compose file written in the twelve months before the snapshot misses hardening at the same per-service rate as one written three or more years earlier, in every tier. The missing hardening is how Compose files are being written now. The result held a second time on 2,035 files fetched after the claim was first derived ([The replication test](#the-replication-test)).

The corpus is fairly recent: 44% of dated files in the prevalence tiers were authored within a year of the snapshot and 74% within three.

## What changed since the last edition

The corpus did not change. I ran 0.26.0 and 1.6.0 over the same 11,111 files and compared the results file by file. The 0.26.0 rerun matches the third edition's tables.

- **No file changed status.** 10,230 files parse, 492 are skipped and 389 fail to parse under both versions.
- **No file flipped** between "has findings" and "clean".
- **Findings in the prevalence tiers rose 0.17%** (81,879 to 82,015). Across the whole corpus 223 files changed, with 244 findings added and 40 removed.

Every change traces to a rule change:

| Change | Release | Whole corpus | Prevalence tiers |
| --- | --- | ---: | ---: |
| CL-0020 reads `command:`, `entrypoint:` and `healthcheck.test`, for example `redis-server --requirepass` with a literal | 0.35.0 | +175 | +121 |
| CL-0005 grades a port written with an unbraced variable (`$PORT:80`) | 0.33.0 | +45 | +20 |
| Hooks are graded as their own units (CL-0004, CL-0018, CL-0019, CL-0020) | 1.2.0 | +13 | +7 |
| New rule CL-0031, `use_api_socket: true` | 1.1.0 | +8 | +8 |
| CL-0016 flags device cgroup rules | 0.33.0 | +2 | 0 |
| CL-0020 on one more environment key, which I did not trace to a release | | +1 | +1 |
| CL-0020 stops flagging URLs and limits that are named after a credential, such as `MAILER_DSN: smtp://mailpit:1025` | 1.3.1 | −40 | −21 |

The third edition's own delta (0.16.0 to 0.26.0 on the 5,417 files of the second edition) stays in the [third edition](https://github.com/tmatens/compose-lint/blob/878a18bae9ed671c65fe4cea057e1dc06cbd5523/docs/state-of-compose.md#what-changed-since-the-last-edition).

## Parse errors as a finding

293 prevalence-tier files (4.4% of the 6,666) failed to lint as v2 or v3 Compose. They are separate from the 466 skipped files, which exited cleanly having linted nothing. Most are shape errors, and few are malformed YAML: `services-not-mapping` 116, `service-not-mapping` 77, `invalid-yaml` 38, a cross-file `extends:` that cannot be resolved for a file stored alone 20, `empty-file` 18, an `include:` that cannot be resolved 15, and 9 others. The longtail has most of them (240 errors, 7.7% of the tier). A Compose file that doesn't parse is not deployed by a real engine, so these are documentation, copy-paste fragments and first attempts.

## A statistician's reading of these numbers

*This section is the report's own statistical review. It asks the questions a methods referee would ask and answers each first in plain terms and then precisely.*

### What "n" really is: files cluster by repo

**In plain terms:** two files from the same repo were usually written by the same person with the same habits, and counting them as independent observations overstates the evidence. The 5,907 parsed files come from 3,345 repos, very unevenly. `selfhosted` is 596 files from 4 registries and `canonical` is 8 vendor repos, so their numbers describe those few sources and not self-hosting or vendors at large. `popular` (734 repos) and `longtail` (2,583) are diverse.

**Precisely:** I resample repos, not files (a cluster bootstrap, 2,000 draws), and read the middle 95% of the results as the interval. The longtail's with-findings interval is 97.7 to 98.7%, the collections interval is 99.7 to 100%, and the other three tiers are at 100%.

### When a difference counts as real

Two rates are treated as different only when their repo-resampling intervals separate. Under that rule, "popular services mount the socket about 2.5 times as often as longtail services" is claimed (4.7 to 7.5% against 2.0 to 2.9%), the popular and collections socket difference is not, and the findings per service across tiers (5.8 to 6.3) are described as flat and are not ranked.

## The replication test

The tier-attribution rules (the synthetic path set, the lab and tool-repo lists and the 20-file collections threshold) were frozen before the third edition's sweep. The files that sweep added are an out-of-sample test of the earlier claims. On the 2,035 longtail files that existed in no prior analysis, measured with 1.6.0:

- 98.4% have a finding, against 97.9% for the earlier longtail files.
- Findings per service are 5.86, against 5.63.
- Findings per service by age are 5.88, 5.99 and 5.62, which is flat.
- The socket rate per service is 2.6%, against 1.9%, and both are low as claimed.

The frozen rules routed every file added after the freeze without manual correction: 78 to `synthetic` and 2 to `lab`. The longtail kept its diversity at depth, with 2,013 repos for those 2,035 files. The main claims of this report were derived on one dataset and confirmed on another.

## Related work

- **Ibrahim, Truong, Wadia, Zhang & Wahsheh (EMSE 27(1), 2021).** *A study of how Docker Compose is used to compose multi-component systems.* [Springer link.](https://link.springer.com/article/10.1007/s10664-021-10025-1) The closest existing corpus study of Docker Compose. It covers composition patterns and does not cover security. This report's tier model is partly informed by their findings on how hobbyist and production usage differ.
- **Liu, Wang, Tao & Lu (ESORICS 2020).** *A large-scale empirical study of Docker container security.* [Paper PDF.](https://www-users.cse.umn.edu/~kjlu/papers/docker.pdf) A Docker Hub image corpus study that names `docker-compose.yml` as an attack surface that has had little study. This report responds to that.

## What this study does NOT claim

### Out of scope by design

- **Exploit rate.** Findings count misconfigurations that diverge from hardening guidance. They do not count observed exploitation, and a finding is not evidence of compromise.
- **Runtime behavior.** compose-lint reads YAML and does not run containers. The corpus shows what people write. It does not show what their containers do once started.
- **Production usage.** A Compose file in a public repo is evidence that someone wrote it. It is not evidence that anything runs it.
- **Private-repo prevalence.** The corpus is public GitHub only. Files inside companies may differ.
- **Hardening outside the rule set.** A file with no findings can still lack hardening that compose-lint has no rule for. Those settings were left out of the linter on purpose and this report does not measure them.

### Sampling caveats

- **GitHub only.** No GitLab, Codeberg, Bitbucket, Docker Hub snippets or blog YAML. Query design and inherited biases are in [`scripts/corpus/README.md`](https://github.com/tmatens/compose-lint/blob/main/scripts/corpus/README.md#longtail-sampling-methodology).
- **Pinned to filenames.** The main tiers cover the four spec filenames and the overlay lane covers 28 variant basenames. Files under other names (`stack.yml` and similar) are not sampled, and that was a decision.
- **Search depth changes the age mix.** A 200-hit sweep over-samples the top of GitHub's relevance ranking, which is older. The 1,000-hit sweep measures the difference (11.3% of its files are five or more years old, against 28.6% in the shallow-swept part). Treat longtail age mixes across editions with that in mind.
- **Size stratification distorts the size mix.** Equal query effort per size bucket over-samples large files compared with how often they occur. That is one more reason per-service rates are the fair comparison across tiers.
- **Excluding unparseable files is a selection.** Parse failures are concentrated in the longtail and plausibly among its least experienced authors, so longtail rates over parsed files probably flatter the tier.
- **No statistical inference.** This is descriptive sampling to estimate prevalence in the sample, with no hypothesis tests and no population estimates. The repo-resampling intervals describe how stable a rate is when this sample's repos are reshuffled. They are not confidence intervals for GitHub at large.
- **Exclusions are judgments about intent.** The `synthetic`, `lab` and `overlay` lines are deterministic and published (`scripts/corpus/retier.py`), but where they are drawn is a judgment. Every excluded lane's numbers are reported so a reader can re-blend.
- **Editions are not a time series, except where stated.** The same-files delta above is measured on one snapshot with two tool versions and is a fair comparison. Nothing else across editions is.

### Tool caveats

- **Rules are based on hardening guidance. They are not based on incident data.** A firing rule means the file diverges from OWASP, CIS or Docker guidance. It does not mean the file is exploitable.
- **compose-lint does not validate the full Compose schema.** Compose v1 files and structural fragments are skipped with a note and counted in [Skipped is not clean](#skipped-is-not-clean). Parse failures are bucketed by class. `${VAR:-default}` resolves to the value Compose uses when the variable is unset. A reference to another file is merged when the file is inside the repository that holds the project. In the single-file corpus no such file is present, so a file that needs one is refused and is not half-linted.

## Corrections to the third edition

I recomputed every figure in the third edition from a 0.26.0 rerun. Five did not reproduce, and each had been carried over from an earlier corpus or an earlier build of the tool.

| Third edition said | Measured | Cause |
| --- | --- | --- |
| Dev and local overlays carry credentials at 1.7 times the full-file rate | 1.3 times (36.8% and 34.8% against 28.4%) | The baseline was a 20.3% full-file rate from an older build |
| 61% of files five or more years old are Compose v1 | 44.9% (372 of 829) | The figure came from the 5,417-file corpus |
| Every curated and popular tier mounts the socket more often per service than the longtail | Holds for `popular` and `collections` only | The `canonical` and `selfhosted` intervals overlap the longtail's |
| Overlays average 3.48 services per file, with 48% authored within a year and 79% within three | 3.46, 49% and 80% | Measured before five files were moved out of the tier |
| The prevalence tiers span 3,345 repos for 6,666 files | 3,345 repos for the 5,907 parsed files, 3,811 for all 6,666 | Two denominators were mixed |

The third edition also listed 35 parse errors as `include:` files. They are 15 `include:` files and 20 files with a cross-file `extends:`.

## Reproducibility

The corpus is not committed to the repo because it is third-party content. The pipeline that builds it is committed, and the snapshot is archived. To reproduce the tables from the snapshot:

```bash
git clone https://github.com/tmatens/compose-lint
cd compose-lint
python -m venv .venv && .venv/bin/pip install compose-lint==1.6.0

# Restore the archived snapshot this edition is measured on.
# sha256 049d2b5bf7167f0ca694aca23fa5483c761fbfccfa2ca7b78520a4ba8b3a5f98
mkdir -p ~/.cache/compose-lint-corpus
tar -xzf compose-lint-corpus-11111-20260827.tar.gz -C ~/.cache/compose-lint-corpus

# Lint the corpus and write summary.md + tier_summary.md.
COMPOSE_LINT_BIN=$PWD/.venv/bin/compose-lint python scripts/corpus/run.py

# Every number in this report that the summaries do not carry
# (per service, age, overlay, replication, intervals).
.venv/bin/python scripts/corpus/report_numbers.py latest

# The same-files delta: lint again with 0.26.0, then compare the two runs.
.venv/bin/python scripts/corpus/report_numbers.py latest --base <0.26.0 run id>

# Re-render the charts (matplotlib is a maintainer-only extra)
pip install -e '.[corpus]'
python scripts/corpus/charts.py latest
```

The snapshot archive holds other people's files under their own licenses, so I don't redistribute it. If you want to check a number, open an issue on the tracker and I can share the list of content hashes with each file's source repository and blob SHA, which is enough to fetch the same bytes from GitHub. The `summary.md` and `tier_summary.md` in `runs/<ts>/` and the output of `report_numbers.py` are the source for every table here. `charts.py` reads the same run, so the figures in `docs/assets/` cannot disagree with the tables.

**Why fetching again does not reproduce this corpus.** The curated tiers fetch again closely, and the derived tiers (`collections`, `synthetic`, `lab`, `overlay`) are deterministic given an index. The `longtail` tier is a stratified sweep of a search engine that has no random-document primitive and no stable result sets, so a new fetch produces a different longtail. Each edition's snapshot is archived as a file for that reason, and only relints of an archived snapshot may carry comparisons.
