# ADR-043: Standards Mappings Are Published as SARIF Tags

**Status:** Accepted

**Context:** Every rule cites the sources it is grounded in: CIS Docker
Benchmark controls, OWASP Docker Security Cheat Sheet rules, and the MITRE
ATT&CK techniques its fix mitigates. In SARIF those reached a consumer in two
forms. The CIS and OWASP citations were sentences in the rule's `help.text`.
The ATT&CK mapping was a taxonomy with a relationship from each rule, added
with [ADR-022](022-threat-model-grounding.md).

Neither form can be filtered on in GitHub Code Scanning, the consumer most
compose-lint SARIF goes to. Its documentation lists the rule properties it
uses, and `relationships` and `taxonomies` are not among them. What it does
use is `properties.tags`: "Code scanning uses `tags` to allow you to filter
results on GitHub." Someone who wants every finding that bears on a control
had to keep their own rule-to-control table (#1280).

Facts that shaped the decision:

- GitHub accepts up to 20 tags per rule and includes 10. It does not say
  which. GitLab's SARIF ingestion keeps 10 per rule by default.
- GitLab gives meaning only to tags shaped like a CWE or CVE identifier,
  which it uses to choose a report type. Any other tag has no effect there.
- GitHub treats a result as a security result because its rule has a
  `security-severity`. A repository with compose-lint alerts and no tags at
  all shows a security severity on every alert.
- Before tagging, every citation was re-read against its source: the CIS
  numbers against Benchmark v1.9.0, and each OWASP rule against what the
  compose-lint rule grades. That found one rule citing the wrong CIS numbers,
  one citing controls it no longer graded, and two citing an OWASP rule that
  does not mention their subject. A citation in prose can be loose. A tag
  cannot, because a filter returns it as a match.

**Decision:**

1. **Each SARIF rule descriptor carries `properties.tags`** with the rule's
   CIS controls, OWASP rules and ATT&CK techniques, in that order.
2. **The tag shape is `external/<source>/<id>`:** `external/cis-docker/5.4`,
   `external/owasp-docker/rule-3`, `external/mitre-attack/T1611`. This is the
   shape CodeQL uses for its own `external/cwe/...` tags, so it is one a Code
   Scanning user has met. Control and technique ids are written as their
   publisher writes them.
3. **A CIS tag does not carry the benchmark version.** The version is pinned
   in one constant and stated in the docs. A version in the tag would change
   every CIS tag at each benchmark revision for anyone filtering on one,
   including the controls whose number did not move.
4. **The mapping is data.** `compose_lint.standards` holds the CIS and OWASP
   mapping the way `compose_lint.attack` holds the ATT&CK one. A test fails
   when a rule's `references` and the mapping disagree, and a rule with no
   control from a source is listed with the reason.
5. **The tags are informational, not contract.**
   [ADR-015](015-machine-readable-output-contract.md) already excludes
   `properties.*` beyond the keys it names, and this ADR does not add `tags`
   to that list. A wrong mapping can then be corrected in any release. Adding
   the tags to the contract later is a loosening no one is harmed by. Taking
   them out of it later would be a MAJOR.
6. **No `security` tag.** It would match every rule, so within compose-lint's
   results it filters nothing, and it would cost one of ten slots on each
   rule. Adding it later breaks no one.
7. **No rule may exceed ten tags.** A test fails first. Nothing is truncated
   at run time: which tag a rule gives up is a decision for the change that
   would add the eleventh.
8. **The ATT&CK taxonomy stays.** It is the more precise form and other
   consumers can read it. CIS and OWASP are not added as taxonomies: no
   consumer measured here reads one.

**What a tag claims.** That the rule relates to the control or technique. Not
that a file with no findings complies with the benchmark: compose-lint reads
a Compose file, and most of the benchmark is about the host, the daemon and
image builds. The standards page says so, in the way `attack.py` says its
mapping is mitigation coverage and never detection.

**Not done:**

- **CWE tags.** GitLab uses one to choose the report type, so adding one can
  move a project's findings between report types. That is a separate
  decision with its own consumer to measure.
- **The mapping in JSON output.** The JSON envelope is contract
  ([ADR-015](015-machine-readable-output-contract.md)), so a field added
  there is one that cannot be corrected freely. No one has asked for it.
- **Other frameworks.** Each is new mapping work with its own grounding.
  CL-0031 already has nine tags, so a fourth source does not fit on it
  without giving one up.

**Consequences:**

- Alerts can be filtered by control or technique in Code Scanning with
  `tag:`.
- Existing alerts keep their identity. `partialFingerprints` is computed from
  the file, rule, service, evidence and mount target
  ([ADR-024](024-finding-identity-is-not-prose.md)); tags are not an input,
  and a test holds that.
- A new rule adds a row per source, or a reason, in its own PR.
- A benchmark revision means re-reading every cited control against the new
  text before moving the pinned version.
- A tag people filter on can still change. The changelog records each change,
  and the docs say the tags are informational.
