# ADR-030: The Compatibility Policy Is Part of the Contract

**Status:** Accepted

**Context:** `docs/compatibility.md` promises users what stays stable and how
change is signalled; users choose version ranges (`>=1.0,<2`, unpinned Action
majors) based on those promises. But the policy said nothing about changing
*itself*. Under the bump table a policy edit is a docs-only change — a PATCH —
so the promise could be weakened by the one release class that asserts
"nothing changed": reclassify severity upgrades as MINOR in a patch release,
and the next MINOR breaks the user who chose their range because the old
policy said upgrades were MAJOR. [ADR-029](029-scheduled-python-drops-are-minor.md)
showed the mechanism in the benign direction — an ADR amending the policy —
but nothing recorded what an amendment may do post-1.0 or what it costs.

**Decision:** The policy is part of the 1.0 surface. Amendments require an
ADR, and the required bump follows the amendment's direction:

- **Clarification** (same obligations, better words) — any release.
- **Tightening** (promising more) — MINOR.
- **Loosening** (promising less) — **MAJOR**, never retroactive: a change
  already shipped is judged under the policy in force when it shipped.

**Rationale:** A loosening breaks exactly the users the contract exists for —
those who relied on the stronger promise when choosing how to depend on the
tool — which is the definition of a MAJOR. The alternative (loosenings take
effect after an announced runway, as a MINOR) was considered and declined:
it would let the promise erode by increments, and the maintainer judged that
a contract whose weakenings are cheap is not much of a contract. The cost is
accepted knowingly: a future ADR-029-shaped change — one that *relaxes* a
bump rule, however well-argued — waits for a 2.0 once 1.0 ships. That is the
last pre-1.0 window closing deliberately, the same shape as ADR-028's
reclamation window.

**Consequences:**

- `docs/compatibility.md` gains the "Changing this policy" section stating
  the rule; the PATCH definition in `docs/RELEASING.md` is clarified (a
  false-positive fix removes *incorrect* findings and stays a PATCH), and
  the severity-upgrade MAJOR bullet records the sanctioned MINOR
  alternative — the ADR-028 split pattern — so the pressure valve is a
  documented design choice rather than a loophole.
- Any further loosening anyone wants (severity-upgrade semantics included)
  must land **before 1.0** or wait for 2.0.
