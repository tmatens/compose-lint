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
  "errors": [ { "file": "...", "message": "..." } ]
}
```

- `version` is the envelope schema version (a string). It is bumped **only** on
  a breaking change to the shape. Adding a new top-level field (e.g. a future
  `summary`) is additive and does **not** bump it — that is the point of the
  envelope.
- `findings[]` carries these fields on **every** finding:

  | field | type | meaning |
  |-------|------|---------|
  | `file` | string | the document the evidence is written in |
  | `line` | integer | 1-indexed line **within `file`** |
  | `rule_id` | string | **opaque** — match exact values, never the `CL-\d{4}` shape (see [compatibility.md](../compatibility.md)) |
  | `severity` | string | one of `critical`, `high`, `medium`, `low` — a closed set |
  | `service` | string | the Compose service the finding is about |
  | `message` | string | what is wrong |
  | `fix` | string | how to fix it |
  | `references` | array of string | authoritative sources |
  | `suppressed` | boolean | whether config suppressed it |

  And these **only** on the branch that produces them. Each is conditional, so
  a consumer that does not know the key sees the document it always did:

  | field | present when |
  |-------|--------------|
  | `suppression_reason` | `suppressed` is true and the config gave a reason |
  | `severity_overridden_from` | the config regraded the finding; carries the original severity |
  | `graded_file` | `file` differs from the document being graded — a merged or `env_file:` run |
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
- `errors[]` lists files that could not be parsed (the exit-2 cases),
  mirroring SARIF's `toolExecutionNotifications`. ADR-013 "not applicable"
  skips (Compose v1 / fragments, exit 0) are deliberately excluded — they are
  not errors.

The JSON envelope and the SARIF 2.1.0 log are the **frozen 1.0 contract**. Both
change only additively post-1.0; any breaking change is a major version bump,
recorded by superseding this ADR.

The representation of fixes in SARIF (currently `result.properties.fix`,
possibly moving to native `fixes[]`) is **out of scope here** and tracked with
the auto-fix work in [ADR-014](014-fix-remediation.md).

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
