# ADR-021: The CRITICAL tier sits one tier above the field, on a mechanism basis

**Status:** Accepted. Depends on [ADR-020](020-severity-scoping-and-overrides.md)
(the grounded posture and the derivation model).

**Context:** A 2026-08 cross-check of compose-lint's severities against Trivy,
Checkov/Prisma, Snyk IaC, Kubescape, CIS and OWASP found a systematic pattern
rather than scattered disagreement:

- On **hardening and absence rules** — missing `cap_drop`, missing `read_only`,
  unpinned images — compose-lint sits *exactly* on the field's consensus.
- On **acute isolation-breaking rules** — a mounted runtime socket,
  `privileged: true`, a raw block device, host-code-execution capabilities, a
  writable host root — compose-lint runs one tier hot. We rate five of these
  CRITICAL where the comparable scanners cap the same primitives at HIGH.

That is a deliberate-looking pattern with no written justification, which makes
it indistinguishable from severity inflation. Since severity is the whole
product — the `--fail-on` gate, the SARIF `security-severity`, what a user fixes
first — an unexplained tier of divergence is a liability.

An earlier draft justified the divergence as *"Compose has no admission-control
layer — the file **is** the deployed state, so a dangerous config here is not
gated the way a Kubernetes manifest is by PSA, OPA, or Gatekeeper."* That
argument is **withdrawn**. It does not survive examination:

- **Symmetry defeats it.** A Kubernetes scanner reads a static manifest without
  knowing whether admission control is enabled on the target cluster, exactly as
  compose-lint reads a compose file without knowing the runtime. Neither tool
  credits a downstream gate it cannot see, so "Compose lacks admission" is not a
  real differentiator between the two.
- **compose-lint is *more* blind, not less.** The controls it cannot see —
  rootless Docker, a sandboxed runtime such as gVisor or Kata, an authorization
  plugin, a custom SELinux or AppArmor policy, userns-remap, a socket proxy —
  all *lower* the true risk of a config we call CRITICAL. "I cannot see the
  safety net" is an argument against inflating a severity, not for it.
- **It is redundant.** [ADR-020](020-severity-scoping-and-overrides.md) already
  handles unobservable controls honestly, by grounding every severity against
  rootful Docker at defaults — the most severe supported posture — and stating
  that hardened postures read the numbers down. That scoping assumption *is* the
  answer to "there may be controls I do not know about."

**Decision:** Keep the CRITICAL tier and its five members
(CL-0001, CL-0002, CL-0016, CL-0024, CL-0025), and justify it as an **internal
triage distinction grounded in mechanism** — not as a claim that Compose is more
dangerous than Kubernetes:

> CRITICAL is reserved for configurations that, under the grounded default
> posture, hand the host over **outright, with no further attacker technique**.
> Each member is verified by mechanism: a mounted control socket reaches the
> daemon API; `privileged` and `SYS_MODULE` reach host code execution; a raw
> block device reaches the host disk; a writable `/` or `/proc` reaches host
> root. That is a triage distinction from HIGH, which means "strong compromise,
> but it needs a published technique or a second flaw." That mature scanners cap
> the same primitives at HIGH is a convention of *their* scales, not a
> disagreement about the mechanism. All severities are default-posture;
> hardened deployments read them down.

"Compose has no built-in policy gate" survives at most as a caveated aside. It
is never the load-bearing reason.

**Rationale:**

1. **The tier earns its keep as triage, and only as triage.** Its user-facing
   job is the sentence "these are game-over, fix them first" versus "these are
   serious." Collapsing CRITICAL into HIGH would put a mounted `docker.sock` in
   the same bucket as a missing seccomp profile, which is a worse answer for the
   person reading the report than being one tier away from Trivy.
2. **Every member is verified, not reasoned.** Nothing was minted CRITICAL on a
   doc citation. A `:ro`-mounted `docker.sock` still completed a `GET /version`;
   `/run/systemd/private` accepted a connection and authenticated from a
   container at default capabilities; `/proc`'s `core_pattern` is writable at
   default capabilities through an `rw` bind; a block device mapped via
   `devices:` gave a raw host-disk read at default capabilities. The tier's
   defence is a set of observations, which is a defence the field's convention
   cannot rebut.
3. **The divergence is bounded and disclosed, which is what makes it
   defensible.** It is five rules, all in one mechanism class, documented here
   and in `docs/severity.md`'s tier table. A reader who prefers the field's
   convention can map CRITICAL onto HIGH; a reader who cannot see the
   justification can only guess whether we inflate everywhere.
4. **Being exactly on consensus for the frequent rules is what buys the
   divergence.** The rules that fire on 45–91% of real files — CL-0004, CL-0006,
   CL-0007, CL-0019 — are where inflation would actually distort a user's
   backlog, and there compose-lint matches the field or sits below it. The
   divergence is confined to rules that fire on under ~10% of files.
5. **CL-0001 is the tier's strongest case.** A single mount spans five ATT&CK
   tactics (see [ADR-022](022-threat-model-grounding.md)) — execution, privilege
   escalation, stealth, credential access, and discovery — through supported API
   calls alone.

**Consequences:**

- **`docs/severity.md`'s tier table carries the CRITICAL definition and the
  one-tier-hot disclaimer**, so the posture is visible where severities are
  looked up, not only in an ADR.
- **New CRITICAL rules must clear the mechanism bar.** A rule enters the tier
  only with a premise check or a captured observation showing host takeover with
  no further technique, under the ADR-020 posture. "It feels critical" and "an
  analogous Kubernetes control is severe" are both insufficient.
- **`SYS_ADMIN`'s placement in CL-0024 is a stated judgment call**, not a
  verified mechanism: escape from `SYS_ADMIN` needs a technique. It sits at
  CRITICAL on consistency grounds with the rest of the host-code-execution
  capability set, and its rule page says so plainly rather than implying an
  observation that does not exist.
- **Rootless and Docker Desktop users are over-served by one tier** on these
  five rules, and the posture statement is where they learn it. Docker Desktop's
  case is *reasoned, not measured* — the daemon runs in a LinuxKit VM, so
  `-v /:/host` mounts the VM's root rather than the user's operating system — and
  is labelled as reasoned because no Desktop install was available to test.
- **The withdrawn argument stays on the record.** The admission-layer framing is
  intuitive enough that someone will re-derive it; the reason it fails is more
  useful to keep than the conclusion alone.

**Alternatives considered:**

- *Collapse CRITICAL into HIGH to match the field.* Rejected. It destroys the
  triage signal that is the tier's entire purpose, and it would price a mounted
  control socket identically to a missing hardening directive.
- *Keep the tier, justified by the missing admission layer.* Rejected for the
  three reasons above. Shipping a justification we know to be weak is worse than
  shipping none, because it invites a reviewer to conclude the severities were
  reverse-engineered.
- *Add a fifth tier above CRITICAL.* Rejected. Four tiers already map onto the
  CVSS qualitative bands and onto every consuming format (SARIF, SonarQube,
  GitHub code scanning); a fifth would have to be flattened at every boundary.
- *Ship both scales — ours and a "field-normalised" one.* Rejected as
  unactionable: two numbers on one finding leaves the user to pick, which is the
  decision the severity was supposed to make for them.
