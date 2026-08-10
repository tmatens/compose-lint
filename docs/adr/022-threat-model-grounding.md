# ADR-022: Ground the threat model in ATT&CK for Containers and CVSS 4.0

**Status:** Accepted. Depends on
[ADR-020](020-severity-scoping-and-overrides.md) (the derivation model and its
scoping assumptions) and [ADR-002](002-rule-grounding.md) (rules cite OWASP,
CIS, or Docker docs).

**Context:** [ADR-002](002-rule-grounding.md) requires every rule to cite an
authoritative source, and it does its job: no rule ships ungrounded. But it
grounds each rule *individually*, against a benchmark or a cheat sheet. Nothing
grounded the rule **set** against a threat model — the attacker baseline in
`docs/severity.md` was asserted from first principles and never checked against
an external adversary taxonomy. Two questions therefore had no evidence-backed
answer:

1. **Is anything missing?** A set of individually-cited rules can still leave a
   whole adversary objective uncovered, and citations cannot reveal that.
2. **Are the scoring axes sound, or merely internally consistent?** "Attacker
   precondition × impact scope" is a defensible model, but a bespoke one is hard
   to defend to a security audience without showing it maps onto something they
   already trust.

A 2026-08 mapping pass answered both against the **MITRE ATT&CK for Containers**
matrix and Microsoft's Threat Matrix for Kubernetes, with a **CVSS 4.0**
crosswalk of the scoring axes.

**Decision:** Adopt ATT&CK for Containers as the threat model of record, pinned
to **v18**, and record the CVSS 4.0 crosswalk as the validation of the scoring
axes. Ship the mapping as a user-facing feature — rule docs plus a SARIF
taxonomy — framed as **mitigation** coverage: each rule describes a
misconfiguration whose remediation mitigates the named techniques.

**Rationale:**

1. **The model survived the check.** Every technique in the container
   escape, credential-access and impact space is either flagged by a rule or
   legitimately out of scope (runtime exploitation, image contents, registry
   internals, orchestrator control plane — all outside the file-only input
   boundary of [ADR-020](020-severity-scoping-and-overrides.md)). The mapping
   found exactly one genuine coverage gap, described below.
2. **CVSS 4.0 independently validates the two most distinctive axes.** Our
   impact-scope axis is 4.0's new Vulnerable-System versus Subsequent-System
   split: Single container maps to VC/VI/VA, Cross-container and Host map to
   SC/SI/SA. Our "second flaw" precondition is 4.0's new Attack Requirements
   metric (`AT:Present` — a prerequisite or configuration must be present). The
   baseline maps to PR and AV, the precondition to AC, the qualifiers to C/I/A,
   the pre-foothold modifier to `AV:Network`, and User Interaction is implicitly
   None. No CVSS base dimension is unrepresented; we bucket the six impact
   sub-metrics into scope plus qualifier, which is a deliberate simplification.
   Our tier bands match the CVSS qualitative ranges, as do Kubescape's. The
   model is therefore a defensible simplification of CVSS 4.0 rather than
   something bespoke.
3. **The mapping is worth more to users than to us.** Corporate and SOC
   audiences already pivot on ATT&CK IDs; publishing them turns a linter finding
   into something that joins their existing detection and coverage
   conversations.
4. **Pinning the version is not optional.** The Containers matrix was
   restructured in v18 — Defense Evasion renamed to **Stealth**, a new **Defense
   Impairment** tactic, and `T1562.001` promoted to top-level **T1685**. An
   unpinned mapping silently rots into wrong tactic names.

**Consequences:**

- **Four intuitive mappings were wrong and are corrected**, because a security
  audience will check them:
    - CL-0002 and CL-0009 map to **T1685 Disable or Modify Tools**, not
      `T1562.001` — that sub-technique was promoted in v18.
    - CL-0014 maps to **T1070 Indicator Removal**, not `T1562.008`; Containers
      is not a platform for `.008`.
    - CL-0004 and CL-0019 map to **T1204.003 Malicious Image** and **T1525
      Implant Internal Image**, not `T1195`; Containers is not a platform for
      the supply-chain technique.
- **Four techniques we rely on are Enterprise-Linux, not Containers**, and must
  be labelled as such rather than passed off as Containers coverage: T1040
  Network Sniffing and T1557 Adversary-in-the-Middle (CL-0006's `NET_RAW`,
  CL-0011's `NET_ADMIN`), T1057 Process Discovery, and T1548 Abuse Elevation
  Control (CL-0003's no-new-privileges). CL-0008's honest Containers mapping is
  **T1046 Network Service Discovery**; its scarier consequences are off-platform.
- **One real coverage gap surfaced, and it changed a rule's design.** T1496
  Resource Hijacking's marquee vector — cryptomining — is *compute* hijacking
  (T1496.001) and therefore CPU-bound, which a memory limit does not bound. The
  planned memory-limit rule (CL-0026) is consequently defined as a combined
  memory **and** CPU resource-limit rule, firing when either is absent.
- **Two decisions were validated rather than changed.** CL-0014 (`logging:
  driver: none`) does have an attacker in its story after all — T1070 Indicator
  Removal, mirroring Microsoft's "Clear container logs" — which resolves the
  standing "no attacker, drop it" objection and confirms keeping it at LOW as an
  anti-forensics enabler. And CL-0001 is the best-defended member of the
  CRITICAL tier ([ADR-021](021-critical-tier-posture.md)): one mount spans
  T1610, T1609, T1611, T1612, T1552.007 and T1613 — five tactics.
- **CL-0005 is confirmed as the odd rule out.** It has no adversary-technique
  home at all: it is attack surface that *enables* T1190, and Microsoft's matrix
  lists only the defender-side "Exposed sensitive interfaces". Combined with the
  absence of any external-tool anchor, this is part of the basis for shipping it
  at MEDIUM under a `detection-precision` override
  ([ADR-020](020-severity-scoping-and-overrides.md), Appendix B) and documenting
  it as an attack-surface rule rather than an isolation-breaking one.
- **The mapping is presented as mitigation coverage, never as detection.**
  compose-lint reads a file; it observes no adversary behaviour and produces no
  telemetry. Publishing ATT&CK IDs as though they were detections would
  misrepresent the tool to precisely the audience the mapping is for.
- **Maintenance cost.** The pin has to be revisited when ATT&CK publishes a new
  version, and technique IDs live in rule docs and in the SARIF taxonomy. That
  is accepted: an unpinned mapping is worse than a stale one, because it is
  wrong without appearing to change.
- **`restart: always` is documented as deliberate non-coverage.** It is a real
  Persistence technique (T1543.005), but it is benign and near-universal in real
  compose files, so a rule would be noise. Saying so is better than leaving a
  mapped technique silently unflagged.

**Alternatives considered:**

- *Leave the threat model asserted from first principles.* Rejected. It read as
  sound and still contained a coverage gap (compute hijacking) and four wrong
  technique attributions. The check was cheap and it found real defects.
- *Adopt CVSS 4.0 as the scoring model outright, replacing the matrix.*
  Rejected. Per-finding vector strings would need environmental metrics
  compose-lint cannot observe from a file, and the output would be a score with
  false precision rather than a tier a user can act on. Using CVSS as a
  *validation* of the axes gets the defensibility without the false precision.
- *Map to the Kubernetes matrix as the primary taxonomy.* Rejected — it grades a
  different platform, and Microsoft's matrix is a defender-side threat matrix
  rather than an adversary technique catalogue. It is used as a corroborating
  source where the Containers matrix is silent.
- *Ship the mapping without pinning a version.* Rejected: v18's tactic renames
  would have silently invalidated the published tactic names.
