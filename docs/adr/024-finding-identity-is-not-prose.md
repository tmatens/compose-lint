# ADR-024: A Finding's Identity Is Structured Data, Not Its Prose

**Status:** Accepted

**Context:** GitHub Code Scanning matches an alert across commits, and
deduplicates repeated uploads, using `partialFingerprints`. The value is the
alert's identity: change it and GitHub closes the old alert and opens a new
one in its place.

compose-lint's v1 fingerprint digested `[uri, rule_id, service, message]`.
The message was included deliberately — a rule that fires more than once for
one service (two published ports, two mounted host paths) needs something to
tell those hits apart, and the message was the only field carrying the
specific offending value.

The cost was that **prose became API**. Rewording a rule's message — fixing a
typo, clarifying a sentence, improving the fix guidance embedded in it — was
a silent breaking change for every consumer: every matching alert closed,
every replacement reopened as new, dismissals lost. Nothing in the repository
signalled this, no test asserted it, and the work most likely to trigger it
was ordinary documentation polish. A tool whose own quality work breaks its
consumers has the incentive pointed the wrong way.

The second cost was to the reader. Because the service was in the *digest*
and nowhere in the *document*, GitHub deduplicated on a value the user was
never shown: SARIF results carried `ruleId`, `artifactLocation` and
`startLine` only, so a Code Scanning user disambiguated a dozen services by
line number while a terminal user was told `service: web` outright.

**Decision:** A finding's identity is `(file, rule, service, evidence)`,
where `evidence` is a new structured field on `Finding` holding the specific
offending value — the port spec, the device path, the capability, the mounted
source. Prose is excluded from every identity in the SARIF layer, including
the internal finding-to-edit key.

1. **Evidence is normalized, not as-written.** CL-0024/CL-0027 key on the
   bare capability rather than the literal `cap_add` entry, CL-0009 on the
   profile key rather than the raw `security_opt` string. Rewriting
   `SYS_ADMIN` as `CAP_SYS_ADMIN` is the same capability and must keep the
   same alert.
2. **A rule that can fire more than once per service must set it.**
   Seventeen do. Rules that fire at most once per service leave it `None`;
   `(file, rule, service)` already distinguishes those.

   The obligation is enforced **structurally**, by reading the rule source:
   any module that constructs a `Finding` inside a loop must pass
   `evidence`. A fixture sweep also runs, but it is the weaker check and
   knowing why matters. The first version of this work enforced the rule
   *only* by sweeping fixtures, and shipped four colliding rules — CL-0001
   among them, the tool's flagship CRITICAL — because no fixture happened
   to put two socket mounts on one service. Three more (the `cap_add`
   family) were missed again by a hand-written grep. A guard whose coverage
   equals fixture coverage silently degrades every time a rule grows a case
   nobody wrote a fixture for. Both checks live in
   `tests/test_finding_identity.py`.

   A collision is not cosmetic: GitHub shows one alert per fingerprint, so
   the other findings never appear at all.

3. **Each rule's evidence derivation is a contract.** `evidence` never
   appears in the output, which makes it easy to mistake for an
   implementation detail and "tidy up" — silently re-keying that rule's
   alerts, a partial unannounced repeat of the transition this ADR exists
   to make unnecessary. `EVIDENCE_CONTRACT` pins the exact derived value
   per rule against a fixed document, so changing one is a reviewed act.
4. **The key is versioned, and the version was bumped.**
   `composeLintFinding/v1` -> `/v2`. The key was versioned from the start
   precisely so a consumer can tell an algorithm change from a genuine new
   finding; this is the first use of that affordance.
5. **The service becomes visible.** It rides as a SARIF `logicalLocation`
   (`{name, fullyQualifiedName: services.<name>, kind: resource}`) — the
   construct for a named element *within* an artifact, as opposed to the file
   and line it occupies — and is threaded into `message.text`, because GitHub
   renders the message as the alert title and offers no guarantee that a
   logical location surfaces anywhere a reader looks.

**Consequences:** The v1 -> v2 move **re-keys every existing alert once**:
consumers uploading compose-lint SARIF see their current alerts close and
reopen, losing dismissal state. This is a real, one-time cost, accepted
because it is paid once now and avoided permanently afterwards — the
alternative is paying a smaller version of it on every future message edit,
unpredictably and without warning. Measured public exposure at the time of
the decision was zero: GitHub code search found no repository outside this
one referencing the action in a workflow, and none referencing the
pre-commit hook. Private usage is structurally invisible to that search, so
the figure is a floor, not a count — the decision is that the cost is worth
paying even if it is not zero.

Messages are now free to change. That is the point: a rule's wording can be
improved without asking what it will break.

**Validating future SARIF changes.** The ingestion probe
(`sarif-ingestion.yml`, ADR-referenced from #610) originally exercised only
the *published* package, so a change to the emitted document would have met
GitHub for the first time after publishing — past the point of no return.
It now uploads the working tree's SARIF as a second, separately-categorised
analysis. Any future change to the SARIF shape is therefore checked against
real ingestion before it ships, which is the condition under which this
transition never needs repeating.

Out of scope, deliberately: **region spans.** A `region` covering the whole
service block (`startLine`..`endLine`) would let the location itself scope to
the service, complementing the logical location. The loader records start
lines only (`parser.py`), and extending it touches the line map that `fix`
depends on for its edits — a larger and riskier change than this one, and
independent of identity. It stays available as later work.
