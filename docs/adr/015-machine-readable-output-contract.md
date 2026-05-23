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
  "version": "1",
  "tool": { "name": "compose-lint", "version": "0.8.0" },
  "findings": [ "..." ],
  "errors": [ { "file": "...", "message": "..." } ]
}
```

- `version` is the envelope schema version (a string). It is bumped **only** on
  a breaking change to the shape. Adding a new top-level field (e.g. a future
  `summary`) is additive and does **not** bump it — that is the point of the
  envelope.
- `findings[]` keeps the exact per-finding fields from 0.x: `file`, `line`,
  `rule_id`, `severity`, `service`, `message`, `fix`, `references`,
  `suppressed`, and `suppression_reason` (only when suppressed).
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
