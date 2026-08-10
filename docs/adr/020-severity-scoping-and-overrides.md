# ADR-020: Scoping assumptions for rule grounding, and calibration overrides

**Status:** Accepted. Extends [ADR-002](002-rule-grounding.md) (rules cite OWASP,
CIS, or Docker docs) and [ADR-016](016-runtime-rule-premise-validation.md)
(premises are validated against a live container).

**Context:** A 2026-08 audit of the severity model found seven of twenty-four
assignment rows in `docs/severity.md` naming a matrix cell that does not produce
the severity printed beside it, and the `Hardening gap × Single container` cell
alone holding five rules that ship three different severities. Those were not
seven independent mistakes. They shared two root causes, and both are absences
rather than errors.

**The first absence: nothing said what a rule is scored *against*.** `dockerd`
can change several defaults a rule's premise depends on:

| Flag / `daemon.json` key | Default assumed | Rules whose grounding depends on it |
|---|---|---|
| `--no-new-privileges` | off | CL-0003 — its entire premise |
| `--seccomp-profile` | builtin | CL-0011 (every per-capability syscall gate), CL-0009 |
| `--selinux-enabled` | off | CL-0009 |
| `--userns-remap` | off | CL-0010's `userns_mode` branch |
| `--default-ipc-mode` | private | CL-0010's `ipc: host` branch |
| `--icc` | true | CL-0006's cross-container reach |
| `--default-ulimit` | unset | CL-0012's resource story |
| `--add-runtime` / `--default-runtime` | `runc` | anything — a wrapper runtime can rewrite the OCI spec before `runc` sees it |

Without a stated posture, each rule made its own silent assumption, and they
disagreed. `userns_mode: host` was priced at MEDIUM on the reasoning that it is
"conditionally live under `userns-remap`, which a linter provably cannot
observe" — calibrated ignorance — while CL-0003 was priced as though its
equivalent uncertainty (`--no-new-privileges`) did not exist. The same gap let
Podman behaviour be reasoned about as though it constrained a Docker rule, in
two separate places.

Capabilities are the instructive exception: `dockerd --help` has zero matches
for "capab", there is no `daemon.json` key, and the default fourteen are
compiled into moby's `DefaultCapabilities()`. That premise holds
unconditionally rather than by assumption.

**The second absence: there was no sanctioned way to ship a severity different
from the derived one.** A contributor who believed the derivation was right
about the risk and wrong for the product had no legal exit, so they changed the
derivation instead — and that change is invisible to review. Every one of the
seven mismatches is that manoeuvre. CL-0006 is the clearest case: the MEDIUM was
a deliberate calibration taken in April 2026 about *gate behaviour*, recorded in
the table as though it were a derivation.

**Decision:** Four scoping statements, adopted together.

1. **Grounded posture.** Every rule's premise and severity assume **rootful
   Docker Engine on Linux at default configuration** — the most severe supported
   posture. Rules are not scored against hardened or loosened daemons. Other
   Docker postures (rootless, Docker Desktop's LinuxKit VM, Swarm) reduce these
   severities rather than increase them.
2. **Docker Engine is the only supported target.** Podman (`podman compose`,
   `podman-compose`) and nerdctl are out of scope. A rule whose grounding rests
   on non-Docker behaviour fails review.
3. **Analysis reads files only** — the compose file(s) named on the command line
   plus `.compose-lint.yml`. No registry, no daemon, no image contents.
   *Grounding* is the separate phase that validates a premise, and it does use
   live containers at the posture above ([ADR-016](016-runtime-rule-premise-validation.md)).
4. **Calibration overrides are adopted.** A rule may ship a severity different
   from its derived one, but only by declaring it with a reason from a closed
   list and a link. The derivation is never altered to reach a desired number.

**Rationale:**

1. **A stated posture removes the problem for every rule at once**, where
   per-rule special-casing removed it for none. It is also the honest answer to
   "there may be controls I cannot see": compose-lint cannot observe rootless
   mode, a sandboxed runtime, an authorization plugin, a custom LSM policy,
   userns-remap, or a socket proxy — all of which lower real risk. Scoring
   against the most severe supported posture and saying so lets a reader
   discount the number for their own deployment, which is strictly better than
   a number that silently averages postures.
2. **Naming the posture buys a conservatism argument rather than a hedge.** It
   pre-empts "but on Docker Desktop…" without weakening any rule, because the
   named posture is the ceiling.
3. **The Docker-only scope closes arguments, not just instances.** CL-0012's
   last defence was that Podman ships `pids_limit = 2048`, making `pids_limit: -1`
   a genuine opt-out *there*; on Docker, `-1`, `0`, and omitting the key all
   produce `pids.max = 18751`. A stated boundary removes the whole category of
   error.
4. **The file-only constraint turns three arbitrary-looking decisions into
   consequences of a stated rule** — CL-0018 not flagging an absent `user:` (the
   image's `USER` is unknowable), CL-0015 not flagging an absent `HEALTHCHECK`,
   and CL-0004/CL-0019 being unable to tell a rolling tag such as `:main` from a
   stable one. It creates a matching obligation: where a rule's correctness
   depends on something unobservable, the rule states the assumption instead of
   guessing.
5. **An override is a reviewable decision; a re-chosen cell is not.** The closed
   list plus a required link plus the enforcement test
   (`tests/test_severity_matrix.py`) make back-solving structurally impossible
   rather than merely discouraged.

**Consequences:**

- **`docs/severity.md` carries the canonical posture statement**, in its
  baseline section, because scoring is what depends on it. Per-rule pages carry
  a `Daemon assumptions:` field *only* where a rule departs from it — an
  exception list, not a field every rule repeats.
- **Users get a consequence note**, not just an assumption:
  `--no-new-privileges` makes CL-0003 a false positive; a permissive
  `--seccomp-profile` under-scores several CL-0011 members; `--icc=false`
  removes CL-0006's cross-container reach; `--userns-remap` makes
  `userns_mode: host` real.
- **`scripts/validate_rule_premises.py` must first assert the daemon under test
  is at defaults** — builtin seccomp, AppArmor enforcing, no userns-remap, icc
  on — and fail loudly otherwise. A premise measured in the wrong posture
  returns a confidently wrong answer, which is the failure mode this whole audit
  kept finding.
- **`userns_mode: host` collapses to a no-op.** Under an assumption of engine
  defaults there is no remap to opt out of; `/proc/self/uid_map` is identical
  with and without it, exactly like `uts: host`. Both branches leave CL-0010.
  Keeping one silent exception to the assumption is how the severity table
  reached the state this ADR exists to fix.
- **CL-0001's socket list is core Docker coverage, not partial multi-engine
  support.** Docker Engine *is* containerd since 18.09: on a plain Docker
  install, `/run/containerd/containerd.sock` is present, `containerd` is active
  alongside `dockerd`, and it is a *lower-level* API with no authorization-plugin
  layer above it. Only `podman.sock` and `crio.sock` belong to other ecosystems,
  and they stay flagged because the rule is about what a compose file *exposes
  into a container*, not about which engine started it. Stated on the rule page
  so the list does not read as an invitation to "finish the job" with
  Podman-specific rules.
- **One user-facing line, not a banner.** Compose files do get run by other
  tools, so a single sentence in the user docs lets a Podman user who receives a
  finding that feels wrong tell why, rather than filing it as a bug.
- **The file-only constraint does not excuse `extends`, `include`, or
  `env_file`.** Those are other *files*, resolved client-side with no daemon at
  all. Lumping them in with image contents would launder three real defects into
  a principle; all three were fixed separately
  ([#520](https://github.com/tmatens/compose-lint/pull/520),
  [#521](https://github.com/tmatens/compose-lint/pull/521),
  [#522](https://github.com/tmatens/compose-lint/pull/522)).

## The closed reason list

| Reason | Use when |
|---|---|
| `detection-precision` | The matcher flags a superset of the dangerous case and cannot yet tell the two apart. The override must name the case being over-covered. |
| `pending-split` | The rule holds members at different tiers; the row is priced at its most dangerous member until the split lands. |
| `pending-move` | Transitional. The derivation has been corrected and ratified, and the code relabel or removal lands in a later change of the same release train. Must be empty once that train completes. |

Extending this list is an ADR-level decision. The risk the list exists to
manage is that "just override it" becomes a shrug; the mitigations are the
closed list, the required link, the visibility in the assignment table, and the
enforcement test.

### The reason that is deliberately absent

An earlier draft of this ADR opened the list with `gate-frequency` — "the
derived severity is right about risk but would make the default `--fail-on high`
gate unusable." It is **rejected**, and the rules that would have used it ship
under `detection-precision` instead. Four reasons:

1. **It prices a product threshold into a risk number.** Severity describes
   risk; `--fail-on` decides how much risk a given pipeline tolerates. If a rule
   honestly derives HIGH and fires on 91% of files, the true statement is that
   91% of real compose files carry a HIGH-risk config — not that the risk is
   smaller than the derivation says.
2. **It is circular.** Severity determines gate behaviour, so using gate
   behaviour to set severity is feedback, and it makes severity a function of
   corpus prevalence: refresh the corpus and the justification moves.
3. **It has no exit condition.** `pending-split` and `pending-move` expire on a
   schedule; `detection-precision` names a fixable defect. A frequency override
   names a permanent property of the world, so nothing ever retires it.
4. **It has no genuine constituency.** Checked against the corpus: of the rules
   firing on more than 45% of files, CL-0003 (89.9%) derives MEDIUM, CL-0007
   (90.8%) derives LOW, CL-0004 (45.6%) and CL-0019 (51.8%) derive MEDIUM. High
   frequency and a high derivation almost never coincide. The only two rules
   that derive HIGH and need an override — CL-0005 and CL-0006 — share
   *conditional impact*, not frequency. Frequency was never the property they
   had in common; it was a correlate.

Of the four reasons in any candidate list, a frequency one is also the only one
whose appeal grows with how annoying a rule is, which makes it the entry most
likely to become the shrug the list exists to prevent.

## Appendix A — CL-0006, `detection-precision` (shipped)

CL-0006 (no `cap_drop`) derives **Technique × Cross-container = HIGH** and ships
**MEDIUM**. All evidence live-captured on Docker 29.1.3, rootful Debian,
AppArmor enforcing, builtin seccomp — the posture above.

**The mechanism is verified end to end, so HIGH is the honest derivation:**

| # | Claim | Observation |
|---|---|---|
| 1 | `NET_RAW` is in Docker's default set | `CapEff 00000000a80425fb` |
| 2 | `NET_RAW` alone gates the raw packet socket | default caps → `tcpdump` captures; `--cap-drop ALL` → "Attempt to create packet socket failed - CAP_NET_RAW may be required"; `--cap-drop ALL --cap-add NET_RAW` → captures again |
| 3 | Neighbours are reachable by default (`icc` on) | two containers on a user-defined bridge ping each other *even with* `--cap-drop ALL` — reachability is not capability-gated |
| 4 | Raw L2 send/receive to a neighbour works at default caps | `arping` → `Unicast reply from 10.100.4.2`; with `--cap-drop ALL` → `arping: socket: Operation not permitted` |
| 5 | **ARP cache overwrite of a neighbour** — the payoff | a default-caps container sending a self-authored raw-socket ARP reply flipped the victim's gateway entry to the attacker's MAC, held across 5/5 polls |
| 6 | Risk is scoped to the *same* Docker network | attacker on network A vs victim on network B: `ping` 100% loss, `arping` 0 responses |

Impact ceiling at default capabilities is interception plus blackhole/redirect
denial of service. *Transparent* MITM relay needs `net.ipv4.ip_forward`, which
requires `CAP_NET_ADMIN` — not in the default set.

**MEDIUM is nonetheless correct, because the matcher flags a superset of the
dangerous case.**

The derived impact requires three things: no `cap_drop: [ALL]`, a co-resident
neighbour on the same Docker network, and interceptable traffic between them.
The evidence above establishes all three as load-bearing — the ARP overwrite
worked between neighbours, the same attempt across two networks got nothing, and
TLS reduces the payoff to ciphertext plus denial of service. The matcher asks
only the first question. It therefore fires on single-service stacks with no
neighbour to attack and on stacks that encrypt inter-service traffic, neither of
which carries the derived impact.

That over-coverage is `detection-precision`, and unlike most instances of it
this one has a visible path off: services and networks are both declared in the
compose file, so a future CL-0006 can check whether a reachable neighbour
actually exists and reserve the higher severity for the case that has one. The
override should be revisited when it does.

Frequency is the *evidence* for the over-coverage rather than the reason for the
override: CL-0006 fires on 90.8% of corpus files (5,691/6,266, run 20260503),
the large majority with no exploitable neighbour. Shipping HIGH would also make
the default `--fail-on high` gate fail nearly every real file — a real
consequence, but a consequence, not a justification (see
[the reason that is deliberately absent](#the-reason-that-is-deliberately-absent)).

*Comparative severity.* Of compose-lint's four runtime cross-container rules,
`NET_RAW` is the weakest on every axis but reliability:

| Rule | Reach | Precondition | Impact | Shipped |
|---|---|---|---|---|
| **CL-0006** `NET_RAW` | one bridge, same network (verified) | Technique (ARP) | intercept plaintext + DoS a neighbour | MEDIUM |
| CL-0008 host network | whole host netns — every interface, every bridge's routed traffic, host loopback | Technique | sniff everything + reach 127.0.0.1-trusted services | HIGH |
| CL-0010 `pid`/`ipc: host` | all containers' processes and IPC | Technique | recon, kill/DoS, cmdline args | HIGH |
| CL-0009 profile off | kernel → everything | Second flaw (kernel vuln) | total escape if it lands | HIGH |

CL-0008 is the same sniffing and injection primitive on the host's entire
network namespace: it strictly dominates CL-0006.

**Note what this argument does *not* establish.** An earlier draft claimed the
neighbour check *forbids* shipping CL-0006 at HIGH. It does not: step 6 requires
the stronger rule to score "at least as high", which equal severities satisfy —
and CL-0006 and CL-0008 occupy the same matrix cell in any case. The comparison
supports MEDIUM as the better of two permissible answers; it does not rule HIGH
out. The override rests on the over-coverage argument above.

`NET_RAW` is also the most conditional (needs a co-resident neighbour sending
interceptable traffic; TLS degrades it to ciphertext plus DoS; a single-service
stack has no neighbour) and the most mitigable (defused by `cap_drop: [ALL]`, by
TLS between services, or by separate Docker networks — all verified).

**Industry cross-check** (live sources, 2026-08): Snyk IaC SNYK-CC-00610
MEDIUM; Checkov/Prisma CKV_K8S_28, the same ARP mechanism, MEDIUM; Trivy/Aqua
KSV003 LOW; CIS Docker 5.3, OWASP Docker Cheat Sheet, NIST 800-190 and NSA-CISA
treat it as a Level-1 hardening recommendation with no numeric severity. Nothing
surveyed rates it HIGH or CRITICAL.

Note the frequency/severity inversion inside the set: CL-0006 is the most
*common* cross-container risk (~91%, because it is an absence) and the weakest;
CL-0008/0009/0010 are rare (<4.1% each, explicit opt-in) and stronger.

## Appendix B — CL-0005, `detection-precision` (ratified, lands with the severity moves)

CL-0005 (ports bound to `0.0.0.0`) derives **Second flaw × Single container +
pre-foothold reach = HIGH** and will ship **MEDIUM**, exactly parallel to
CL-0006. Recorded here when the decision was taken; the assignment row and the
rule's `metadata.severity` change together in the severity-moves change of this
release train, so the two never disagree.

Same shape as CL-0006: the matcher flags every `0.0.0.0` bind, where the
dangerous case is the subset that was not *meant* to be public. An exposed
database is a serious finding; an exposed web server is the design. The rule
fires on ~58% of files, including intended-public web servers, and the file does
not say which is which — so the higher severity would be applied mostly to
configurations that are working as intended.

The over-covered case is nameable and the path off the override is a split
rather than a smarter matcher: well-known datastore and admin ports (5432, 3306,
6379, 27017, 9200, 2375) are a usable proxy for "not meant to be public", and
one rule may not carry two severities. Splitting exposed-datastore from
exposed-service would let the first ship at its derived HIGH.

Two further signals support the lower tier rather than establishing it: CL-0005
has no adversary-technique home in ATT&CK — it is attack surface that *enables*
T1190, and Microsoft's Kubernetes matrix lists only the defender-side "Exposed
sensitive interfaces" — and no comparable tool anchors it.

The rule keeps its teeth in documentation: Docker's iptables manipulation
bypasses UFW and firewalld, so a `0.0.0.0` bind is exposed even behind a host
firewall. It is documented as an attack-surface rule rather than an
isolation-breaking one.

**This is the one move in the redesign that changes default-gate outcomes.** It
crosses the `--fail-on high` line, so a file whose only ≥HIGH finding was
CL-0005 now passes where it used to fail. That is deliberate — the point is to
stop failing CI on intended-public exposure. Users who want exposed-database
stacks to fail can use `--fail-on medium`, or override CL-0005 back to HIGH in
`.compose-lint.yml`.

**Alternatives considered:**

- *Score each rule against whatever daemon posture makes it most defensible.*
  Rejected — that is the status quo, and it produced a table where the same
  epistemic problem (an unobservable daemon setting) was priced two different
  ways in two different rules.
- *Keep `userns_mode: host` as the single documented exception to the defaults
  assumption.* Rejected. An assumption with one silent exception is exactly how
  the current table got into its state; a stated baseline with an exception the
  baseline cannot justify is not a baseline.
- *Support Podman and nerdctl as grounded targets.* Rejected for now. Each is a
  distinct posture with distinct defaults (Podman's eleven-capability set alone
  invalidates CL-0006's premise), so each multiplies the premise-validation
  matrix. Revisit as its own ADR with its own validator lane if there is demand.
- *Allow a free-text override reason.* Rejected. The value of the mechanism is
  that a deviation is legible at a glance and countable in review; free text
  degrades to a shrug within a handful of rules.
- *Fix the seven mismatches individually and leave the model alone.* Rejected —
  that is a repair constrained to preserve its own answer, and it leaves the
  mechanism that generated all seven fully intact.
