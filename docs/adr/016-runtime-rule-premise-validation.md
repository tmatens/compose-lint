# ADR-016: Runtime Validation of Rule Premises

**Status:** Accepted (extends [ADR-002](002-rule-grounding.md))

**Context:** ADR-002 requires every rule to map to an authoritative source
(OWASP Docker Security Cheat Sheet, CIS Docker Benchmark, or Docker docs). That
bar turned out to be necessary but not sufficient. compose-lint flags *runtime*
misconfigurations, and a citation can be authoritative for **host/Linux**
hardening while being false **inside a container**, where Docker's defaults
already neutralize the risk. Two rules shipped on a source citation alone and
were both wrong about the container's actual runtime state:

- **CL-0022** flagged `tmpfs` mounts for missing `noexec,nosuid,nodev`. Docker
  already mounts `tmpfs` with `noexec,nosuid,nodev` by default, so the rule
  fired on the secure default. It was reworked (commit `88cfd84`) to flag only
  the *explicit* re-enabling of `exec`/`suid`/`dev`.
- **CL-0023** flagged the absence of `net.ipv4.ip_forward=0`. That sysctl is
  `1` by default in a container's network namespace and the rule's premise did
  not describe a real, attacker-relevant container state. It was **removed**
  (commit `0cf44ed`) and its ID reclaimed under the pre-1.0 reclamation rule.

Both failures share a root cause: nobody had checked the premise against a
live container before shipping. A generic host-hardening source read as
"authoritative grounding" under ADR-002 even though the container default made
the finding a false positive. We need a check that proves the *runtime
premise*, not just the existence of a citation.

**Decision:** Add a second, runtime arm to the rule-grounding bar.

A rule is admissible if it satisfies **either**:

1. **Container-context source.** It cites OWASP/CIS/Docker documentation that
   demonstrates the need **in a container context** (not generic host/Linux
   hardening a container's defaults already neutralize); **or**
2. **Runtime-validated premise.** If container-context grounding is thin, the
   rule's premise is validated at runtime by a check in
   `scripts/validate_rule_premises.py` that proves, via a short `docker run`:
   - for an **absence rule** (fires when a hardening directive is missing) —
     that the insecure state is genuinely Docker's *default*; and
   - for a **presence rule** (fires on an explicit insecure directive) — that
     the flagged configuration actually produces the insecure behavior.

Concretely:

- Any rule that **describes container runtime state** must have a premise check
  in `scripts/validate_rule_premises.py`. Rules with no observable runtime state
  — image/supply-chain and config-only concerns (currently CL-0004, CL-0014,
  CL-0015, CL-0019, CL-0020, CL-0021) — are listed in that script's `_NON_RUNTIME`
  set as intentionally out of scope and rely on source grounding alone.
- The check is the *premise*, not the rule's parsing logic: it asserts the
  underlying container behavior the rule warns about is real, independent of how
  the rule reads the Compose file.
- The suite runs in CI as the `rule-premises` job (`.github/workflows/ci.yml`),
  feeds the `ci-ok` rollup gate, and uses a manifest-list-digest-pinned busybox
  image so it carries no mutable ref. Locally it needs a working Docker; with no
  Docker it skips (exit 0) rather than failing, so contributors without Docker
  are not blocked but CI still enforces it.

**Rationale:**

- **Defends against the exact failure that produced it.** CL-0022 and CL-0023
  would not have shipped in their original form had a `docker run` confirmed the
  default. The runtime arm makes "is this actually insecure in a container?" a
  CI gate rather than a reviewer's judgment call.
- **Closes the gap ADR-002 left open.** ADR-002 ended the debate over *whether a
  rule is opinion vs. standard*; it did not test whether the standard's premise
  survives Docker's container defaults. This ADR adds that test without
  weakening ADR-002 — source grounding is still required when it exists; runtime
  validation is the alternative when container-context grounding is thin.
- **Keeps false positives out before they become permanent.** From 1.0, rule
  IDs and behavior are far costlier to change ([ADR-005](005-rule-id-scheme.md);
  pre-1.0 reclamation is how CL-0023's ID was freed). A false-positive-prone
  rule that ships into 1.0 is a long-lived liability and erodes trust in every
  other finding. The runtime gate is cheapest to apply before the GA freeze.
- **Premise vs. logic separation is deliberate.** Unit tests already prove a
  rule parses Compose correctly; they cannot prove the parsed-for state is
  insecure in a real container. The two test layers answer different questions
  and both are required.

**Consequences:**

- Adding a runtime-describing rule now costs a `docker run`-based premise check
  in addition to the unit tests and docs (codified as step 10 of the
  CONTRIBUTING rule checklist). This is friction by design.
- The `rule-premises` suite's wall-clock grows roughly linearly with the number
  of runtime-testable rules (one+ container launch each). At 22 rules this is
  well within the job's 10-minute budget; if it becomes a bottleneck, batching
  multiple premise checks into a single container is the obvious lever.
- A rule whose premise cannot be reduced to an observable busybox check, and
  whose container-context source is thin, is not admissible — that is the
  intended outcome, not a gap.

**Alternatives rejected:**

- **Source citation alone (status quo under ADR-002).** This is precisely what
  let CL-0022 and CL-0023 ship. A citation proves a concern exists *somewhere*,
  not that it is real inside a container.
- **Trust unit tests to cover it.** Unit tests assert the rule reads YAML
  correctly against fixtures the author wrote; they share the author's
  assumption about the container default and so reproduce, rather than catch,
  the CL-0022/CL-0023 error.
- **A one-off manual review checklist instead of an automated gate.** Manual
  review is what missed these two. An executable, CI-enforced check is the only
  form that reliably blocks the regression.
- **Validate against the full Docker/Compose runtime (real compose up).**
  Heavier and flakier than a single pinned-busybox `docker run`, with no extra
  signal for premises that reduce to "what is the namespace/mount/cgroup default."

**Interaction with other work:**

- **ADR-002 (rule grounding)** is extended, not superseded: source grounding
  remains the primary bar; this ADR adds the runtime alternative and is the
  authoritative record of *why* (the CL-0022/CL-0023 reversal, which previously
  lived only in the CHANGELOG and the script's docstring).
- **ADR-005 (rule ID scheme)** supplies the permanence/reclamation rule that
  makes pre-1.0 the right window for this gate; CL-0023's reclaimed ID is the
  worked example.
- **CONTRIBUTING.md** already encodes the operational checklist (rule step 10
  and the "Rule requirements" section); this ADR records the decision behind it.
