# ADR-015: Machine-Readable Output Contract

**Status:** Accepted

**Context:** `check` emits three formats: `text` (human), `json`, and `sarif`
(both machine-readable). The 1.0 release is a SemVer stability commitment —
once tagged, breaking the shape of a machine-readable format requires a major
version bump, because external consumers (CI pipelines, dashboards, scripts)
parse it.

Through 0.x the JSON output was a bare top-level array of finding objects:

```json
[ { "file": "...", "rule_id": "CL-0001", "severity": "critical", "...": "..." } ]
```

A bare array is the hardest shape to evolve. It has nowhere to carry run-level
metadata — tool version, the files that failed to parse, or any future summary
— so adding any of those later would move consumers from `data[i]` to
`data["findings"][i]`, a breaking change. SARIF already carries this metadata
(tool driver version, and `invocations[].toolExecutionNotifications` for parse
errors), so JSON consumers were strictly worse off: a file that failed to parse
was invisible in JSON, with exit code 2 the only signal.

**Decision:** Before 1.0, wrap the JSON output in a versioned envelope:

```json
{
  "version": "2",
  "tool": { "name": "compose-lint", "version": "0.24.0" },
  "findings": [ "..." ],
  "errors": [ { "file": "...", "message": "...", "kind": "parse" } ],
  "warnings": []
}
```

- `version` is the envelope schema version (a string). It is bumped **only** on
  a breaking change to the shape. Adding a new top-level field (e.g. a future
  `summary`) is additive and does **not** bump it — that is the point of the
  envelope.
- `findings[]` carries these fields on **every** finding:

  | field | type | meaning |
  |-------|------|---------|
  | `file` | string | the document the evidence is written in, relative to the working directory (see amendment) |
  | `line` | integer or null | 1-indexed line **within `file`**; null when no line there names the key (see amendment) |
  | `rule_id` | string | **opaque** — match exact values, never the `CL-\d{4}` shape (see [compatibility.md](../compatibility.md)) |
  | `severity` | string | one of `critical`, `high`, `medium`, `low` — a closed set |
  | `service` | string | the Compose service the finding is about |
  | `message` | string | what is wrong |
  | `fix` | string or null | how to fix it; null when a rule has none |
  | `references` | array of string | authoritative sources |
  | `suppressed` | boolean | whether config suppressed it |

  And these **only** on the branch that produces them. Each is conditional, so
  a consumer that does not know the key sees the document it always did:

  | field | present when |
  |-------|--------------|
  | `suppression_reason` | `suppressed` is true and the config gave a reason |
  | `severity_overridden_from` | the config regraded the finding; carries the original severity |
  | `graded_file` | `file` differs from the document being graded: the evidence is written in an overlay, an included or extended file, or an `env_file:` |
  | `source_file` | *deprecated alias* of `file`, emitted alongside `graded_file`; schema-1 consumers used it to learn where `line` pointed |

  **Schema 2 changed what `file` means.** In schema 1 it always named the
  document being *graded*, while `line` indexed wherever the evidence actually
  came from — so on a merged run (default since [ADR-025](025-lint-the-merged-configuration.md))
  or an `env_file:` run (default since [ADR-027](027-grade-env-file-where-the-document-routes-it.md))
  the pair named a real line of the wrong file. SARIF had already been
  corrected the same way, after the mismatch made Code Scanning annotate an
  unrelated line of the base file. Correcting JSON is a breaking change to a
  required field, which is why it ships **before** the 1.0 freeze rather than
  after it.
- `errors[]` lists every condition that made the run exit 2 (a file that could
  not be parsed, a coverage gap, a crashed rule, a run-level failure; see the
  amendment below for `kind`), mirroring SARIF's `toolExecutionNotifications`.
  Conditions reported without failing the run go to `warnings[]`, added by the
  same amendment. ADR-013 "not applicable"
  skips (Compose v1 / fragments, exit 0) are deliberately excluded — they are
  not errors.

The JSON envelope and the SARIF 2.1.0 log are the **frozen 1.0 contract**. Both
change only additively post-1.0; any breaking change is a major version bump,
recorded by superseding this ADR.

The representation of fixes in SARIF (currently `result.properties.fix`,
possibly moving to native `fixes[]`) is **out of scope here** and tracked with
the auto-fix work in [ADR-014](014-fix-remediation.md). *Superseded by the
SARIF contract amendment below: native `fixes[]` shipped (0.11.0) and is the
contract; `properties.fix` is prose.*

**Consequences:**

- One-time breaking change to JSON consumers at the 0.x → 1.0 boundary (bare
  array → object). This is deliberate: the last chance to make it before the
  stability freeze.
- JSON and SARIF now report parse failures symmetrically.
- New run-level data (severity summary, timing, config path) can be added later
  without a major bump.

**Alternatives considered:**

- *Freeze the bare array as-is.* Rejected: permanently forecloses run-level
  metadata in JSON and leaves parse errors unreportable there.
- *Add a `summary` block now.* Deferred: no consumer needs it yet, and the
  envelope makes it a safe additive change whenever one does. Freezing its
  exact shape (count semantics, severity keys) at 1.0 with no demand is
  unnecessary surface.

**Amendment (pre-1.0 freeze):** `rule_id` / `ruleId` is declared an opaque
string in [compatibility.md](../compatibility.md#the-10-commitment): consumers
match exact values, not the `CL-` prefix or the four-digit shape. Declared
before the 1.0 freeze because afterwards it would be a contract loosening —
a MAJOR under [ADR-030](030-the-policy-is-part-of-the-contract.md) — while
today it is a clarification of surface no consumer was promised. It keeps a
future rule source with foreign ids (shellcheck's `SC####`,
[ADR-007](007-shellcheck-integration.md)) an additive MINOR rather than a
breaking-change argument.

**Amendment (pre-1.0 freeze): diagnostic kinds, a warning channel, nullable
fields.** Four additions and clarifications, made before the freeze because
each would cost a MAJOR afterwards or leave the frozen shape ambiguous.

- *`kind` on every diagnostic.* `errors[]` entries gain `kind`, a closed set:
  `parse`, `coverage_gap`, `rule_crash`, `run`. It is assigned where the
  condition is detected, never inferred from the message. Before it, a consumer
  that wanted "fail on a gap but not on a parse error" had to match message
  text, which made prose a de-facto API: the failure
  [ADR-024](024-finding-identity-is-not-prose.md) removed from results. SARIF
  carries the same string as each notification's `descriptor.id`, resolved
  against a `notifications` catalogue in the driver. `descriptor` was chosen
  over `properties` because it is the typed, resolvable place the format
  provides for a notification's category.
- *`warnings[]`.* Same element shape as `errors[]`, always present, for
  conditions reported without failing the run. A coverage gap accepted with
  `--allow-partial-coverage` used to leave JSON and SARIF exactly as if there
  had been no gap. It now lands here, and in SARIF as a `level: "warning"`
  notification that leaves `executionSuccessful` true. This is also the
  machine-readable channel the compatibility policy relies on to announce a new
  gap condition one release before enforcing it
  ([ADR-036](036-resolve-references-that-stay-inside-the-project.md)).
- *Run-level entries.* `kind: run` entries (no Compose files found, a
  configuration error, output truncation) have `file: ""`. That empty string is
  contract, not a placeholder. In SARIF such a notification carries no
  `locations` at all. It previously resolved the empty path to the working
  directory and reported a directory as the failing artifact. A truncated SARIF
  document now reports its truncation once; the CLI and the formatter each used
  to add a notification with different text.
- *Nullable `line` and `fix`.* Both were documented as non-null but have always
  been nullable in code and pinned so by tests. `line` is null when no line
  in `file` is known for the offending key. When this was written, a finding
  inherited through a same-file `extends:` was the common case; since #910 an
  inherited key names the line that wrote it, so null is now rare, but it
  stays part of the type. Declaring it now is a clarification;
  after 1.0 it would be a loosening of a typed field under
  [ADR-030](030-the-policy-is-part-of-the-contract.md).

*Addition (pre-1.0): `unread_input`.* A fifth kind, for an input the run
would read for values or for its file list — the sibling `.env`, an
`env_file:` target, a `COMPOSE_FILE` entry — that was refused for leaving the
project or could not be read. It is only ever a warning: the stack was linted,
but values Compose deploys from that input were not graded, and before this the
fact reached stderr alone. `coverage_gap` was not reused because it means a
document that was not linted and, unwaived, exit 2.

*Amendment (pre-1.0): an unread `.env` is a coverage gap.* The sibling `.env`
(and an included file's own) that exists but could not be read, and a
`COMPOSE_FILE` list that was refused, moved from `unread_input` to
`coverage_gap`. Compose deploys what either sets, so a run that graded the rest
without them could pass a stack whose real values it never saw; "anything that
couldn't be read or graded fails closed" is the rule a gate needs, and exit 2 is
what it already means for an `include:` that was not followed.
`--allow-partial-coverage` accepts them like any other gap. `unread_input`
stays, for a refused `env_file:` target: only CL-0020 and CL-0021 read those
keys, so a refusal is stated without failing the run.

*Amendment (pre-1.0): SARIF truncation is a warning.* A SARIF log holds at most
5,000 results (`MAX_SARIF_RESULTS`), because a larger one passes GitHub Code
Scanning's 10 MB limit and is rejected whole. A truncated log used to report a
`level: "error"` notification, set `executionSuccessful: false` and exit 2, so
the same file under the same `--fail-on` passed as JSON or text and failed as
SARIF. Truncation is now a `kind: run`, `level: "warning"` notification that
leaves `executionSuccessful` true, and the exit code follows `--fail-on`. Every
finding is graded before any is dropped, so the verdict is complete; only the
document is short, and the notification says by how much. None of ADR-006's
exit-2 causes (the run could not start, a rule crashed, part of the stack was
not seen) describes it. A consumer that needs every result re-runs with
`--format json`, which has no result cap.

*Amendment (pre-1.0): one path form (#887).* `file`, `graded_file`, the
deprecated `source_file`, `errors[].file`/`warnings[].file`, and SARIF's
artifact `uri` all spell a path the same way: relative to the working
directory, joined lexically (a symlinked directory keeps the spelling the user
sees), with `/` separators on every platform; absolute only when the file lies
outside the working directory, where no relative spelling stays inside it.
JSON and SARIF report the same value for the same finding, SARIF's
percent-encoded under `SRCROOT`. Before this the form depended on how the
document was reached: the argv spelling for the primary file and an overlay,
the lint host's absolute path in JSON (relative in SARIF) for an `include:` or
cross-file `extends:` document, and the path as the Compose file wrote it for
an `env_file:` target, which named nothing when the run started outside the
project directory. The working directory was chosen over the document's own
directory because it is where every consumer of the path looks it up (a CI log,
git, Code Scanning), and over an absolute path because that leaks the runner's
checkout directory and differs between two checkouts of one repository. The
primary file's `./compose.yml` spelling now reports as `compose.yml`. The field
types and presence rules are unchanged, so `version` does not change.

`kind` and `warnings` are additive, so `version` does not change. Every exit-2
path writes the envelope except the two that fail before an output format is
known: an argument the parser rejects, and an `--explain` error.

*Amendment (pre-1.0): a findings limit is a coverage gap.* One document grades
at most `MAX_FINDINGS` (20,000) findings. A rule reports one finding per item,
and an aliased list multiplies items by the services that share it, so a
100 KB file could build two million findings before printing any. Past the
limit the engine stops, so the rest of the document is not graded, and that is
reported as `coverage_gap` with the findings graded so far: exit 2 unless
`--allow-partial-coverage`. Unlike SARIF's result cap, which drops results from
a verdict that was complete, this one leaves the verdict incomplete, so it
fails closed. The largest count in the corpus is 323.

<a id="sarif-contract"></a>
*Amendment (pre-1.0): the SARIF contract.* This ADR froze "the SARIF 2.1.0 log
shape" without saying which parts of it are shape, and deferred fixes to
ADR-014, which then shipped native `fixes[]`. Left implicit, every prose string
in the log would be arguably frozen, including descriptor text a review had
already found stale. A consumer may rely on:

- `ruleId`, an opaque string, and `ruleIndex` when present;
- `level`, mapped from severity (critical and high `error`, medium `warning`,
  low `note`);
- `locations[0].physicalLocation`: `artifactLocation.uri` with `uriBaseId`, and
  `region.startLine` when a line is known;
- the `partialFingerprints` key name and its
  [ADR-024](024-finding-identity-is-not-prose.md) derivation, whose changes are
  announced as a MINOR;
- `suppressions[]`, with `kind` and, when the config gave a reason,
  `justification`;
- `invocations[0].executionSuccessful`, and each notification's `level` and
  `descriptor.id`;
- `fixes[]`, which may be absent, and when present applies to the result's own
  artifact.

Not contract: every `message.text`, rule and notification descriptor prose,
`properties.*` beyond keys named above, the order of results, and which results
a truncated log keeps beyond "the most severe 5,000, plus a notification". So a
stale descriptor sentence is a docs bug, not a breaking change, and the
truncation order can be tuned without a policy argument. Excluding anything
after 1.0 would be a loosening, a MAJOR under
[ADR-030](030-the-policy-is-part-of-the-contract.md), which is why the list is
written now.

*Amendment (pre-1.0): `kind` is open across versions.* `kind` is a closed set
within one version and may grow across versions: a new value is a MINOR, and a
consumer handles an unknown one by its channel (`errors[]` means exit 2,
`warnings[]` never changes the exit code). The alternative, a set closed
forever, would make every new diagnostic class a 2.0 or force it into a kind
that fits it badly. `kind` and the channel are independent axes; `rule_crash`
already appears on both (a crashed rule fails the run, a crashed fixer is a
SARIF warning). `severity` stays closed, because its four values are the
grading model, not a catalogue that grows.
