"""The JSON envelope is a frozen surface; this is what freezes it.

`docs/compatibility.md` lists machine output among the four things 1.0 makes
stable, and every neighbouring commitment has a test that fails when it drifts
— exit codes, action inputs, rule surfaces, and SARIF alert identity. The JSON
envelope had none. `tests/test_json.py` covers edge cases only (odd YAML key
types, NaN handling, `allow_nan=False`); it never asserts the key set and never
references `SCHEMA_VERSION`, so renaming `rule_id`, dropping `references`, or
changing `version` from `"1"` would pass the suite.

ADR-024 is the precedent for why prose is not enough: the v1 -> v2
`partialFingerprints` change was exactly this class of drift, a
machine-consumed shape whose identity had quietly become load-bearing. Post-1.0
an accidental key change is a MAJOR-version incident rather than a bug, and a
freeze that exists only in documentation is not a freeze.

The rule these tests enforce:

* **Additive is allowed.** A new top-level or per-finding key may be added
  without bumping `SCHEMA_VERSION` — that is what the envelope is for.
* **Renames and removals are breaking.** They require a deliberate
  `SCHEMA_VERSION` bump and a CHANGELOG `Changed` entry, which means editing
  this file on purpose rather than discovering it in a consumer's pipeline.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import TYPE_CHECKING

from compose_lint import __version__
from compose_lint.formatters.json import SCHEMA_VERSION, build_json_log
from compose_lint.formatters.json import format_findings as format_json
from compose_lint.models import Finding, Severity

if TYPE_CHECKING:
    from pathlib import Path

# The frozen surface. Editing either of these constants is the deliberate act
# the contract exists to require.
ENVELOPE_KEYS = {"version", "tool", "findings", "errors"}
TOOL_KEYS = {"name", "version"}
ERROR_KEYS = {"file", "message"}

FINDING_KEYS = {
    "file",
    "line",
    "rule_id",
    "severity",
    "service",
    "message",
    "fix",
    "references",
    "suppressed",
}
# Present only on the branch that produces them. Each is additive: a consumer
# that does not know the key sees the same document it always did.
CONDITIONAL_FINDING_KEYS = {
    "suppression_reason",
    "severity_overridden_from",
    "source_file",
    "graded_file",
}

_RULE = (
    "The JSON envelope is frozen at 1.0 (docs/compatibility.md, ADR-015).\n"
    "  Adding a key is allowed and must NOT bump SCHEMA_VERSION.\n"
    "  Renaming or removing one is breaking: bump SCHEMA_VERSION deliberately\n"
    "  and record it under `Changed` in CHANGELOG.md, then update this test."
)


def _plain() -> Finding:
    return Finding(
        rule_id="CL-0001",
        severity=Severity.CRITICAL,
        service="web",
        message="Docker runtime socket mounted.",
        line=4,
        fix="Remove the mount.",
        references=["https://example.invalid/ref"],
        evidence="/var/run/docker.sock",
    )


def _suppressed() -> Finding:
    return Finding(
        rule_id="CL-0007",
        severity=Severity.LOW,
        service="web",
        message="Root filesystem is writable.",
        line=5,
        suppressed=True,
        suppression_reason="needs a writable /tmp",
    )


def _regraded() -> Finding:
    return Finding(
        rule_id="CL-0005",
        severity=Severity.LOW,
        service="web",
        message="Port bound to all interfaces.",
        line=6,
        severity_overridden_from=Severity.MEDIUM,
    )


def _from_overlay() -> Finding:
    return Finding(
        rule_id="CL-0001",
        severity=Severity.CRITICAL,
        service="web",
        message="Docker runtime socket mounted.",
        line=3,
        source_file="compose.override.yml",
    )


def test_schema_version_is_pinned_to_its_literal_value() -> None:
    """The version is a contract constant, so it is pinned as a literal.

    Asserting `log["version"] == SCHEMA_VERSION` proves nothing: both sides move
    together, so a silent bump passes. That tautology is the exact hole this
    contract was filed to close, and writing it was the first thing that
    happened here — it survived until a mutation test changed the constant and
    the suite stayed green.

    Bumping this is a deliberate breaking-change act: every consumer keying on
    `version` is told the shape moved, so it belongs with a CHANGELOG `Changed`
    entry and a documented migration, not with a refactor.
    """
    assert SCHEMA_VERSION == "2", (
        "SCHEMA_VERSION changed. That is a breaking change to the JSON "
        "envelope, not a version bump of the tool.\n" + _RULE
    )


def test_envelope_key_set_is_exact() -> None:
    """The top-level shape, including `version` carrying SCHEMA_VERSION."""
    log = build_json_log(format_json([_plain()], "compose.yml"))

    assert set(log) == ENVELOPE_KEYS, _RULE
    assert log["version"] == SCHEMA_VERSION, _RULE
    assert set(log["tool"]) == TOOL_KEYS, _RULE  # type: ignore[arg-type]
    assert log["tool"] == {"name": "compose-lint", "version": __version__}


def test_envelope_value_types_are_pinned() -> None:
    """A consumer indexes on these types, not only on the names."""
    log = build_json_log(
        format_json([_plain()], "compose.yml"),
        parse_errors=[("broken.yml", "Invalid YAML")],
    )

    assert isinstance(log["version"], str), _RULE
    assert isinstance(log["tool"], dict), _RULE
    assert isinstance(log["findings"], list), _RULE
    assert isinstance(log["errors"], list), _RULE
    errors = log["errors"]
    assert isinstance(errors, list)
    assert set(errors[0]) == ERROR_KEYS, _RULE
    assert all(isinstance(v, str) for v in errors[0].values()), _RULE


def test_finding_key_set_is_exact_with_no_optional_branch_taken() -> None:
    """A plain finding carries the required keys and nothing else.

    `evidence` is deliberately absent: it is the finding's *identity* for SARIF
    fingerprints (ADR-024) and has never been part of the JSON contract. If it
    is ever added, that is an additive change and this set moves with it.
    """
    (entry,) = format_json([_plain()], "compose.yml")
    assert set(entry) == FINDING_KEYS, _RULE


def test_finding_value_types_are_pinned() -> None:
    (entry,) = format_json([_plain()], "compose.yml")

    assert isinstance(entry["file"], str), _RULE
    assert isinstance(entry["line"], int), _RULE
    assert isinstance(entry["rule_id"], str), _RULE
    assert isinstance(entry["severity"], str), _RULE
    assert isinstance(entry["service"], str), _RULE
    assert isinstance(entry["message"], str), _RULE
    assert isinstance(entry["fix"], str), _RULE
    assert isinstance(entry["references"], list), _RULE
    assert isinstance(entry["suppressed"], bool), _RULE


def test_line_and_fix_are_nullable_but_present() -> None:
    """Absent data is `null`, not a missing key — consumers index directly."""
    bare = Finding(
        rule_id="CL-0006",
        severity=Severity.MEDIUM,
        service="web",
        message="Capabilities are not dropped.",
    )
    (entry,) = format_json([bare], "compose.yml")

    assert set(entry) == FINDING_KEYS, _RULE
    assert entry["line"] is None
    assert entry["fix"] is None


def test_suppression_reason_appears_only_when_suppressed() -> None:
    (suppressed,) = format_json([_suppressed()], "compose.yml")
    (plain,) = format_json([_plain()], "compose.yml")

    assert set(suppressed) == FINDING_KEYS | {"suppression_reason"}, _RULE
    assert suppressed["suppression_reason"] == "needs a writable /tmp"
    assert suppressed["suppressed"] is True
    assert "suppression_reason" not in plain, _RULE


def test_severity_overridden_from_appears_only_when_regraded() -> None:
    (regraded,) = format_json([_regraded()], "compose.yml")
    (plain,) = format_json([_plain()], "compose.yml")

    assert set(regraded) == FINDING_KEYS | {"severity_overridden_from"}, _RULE
    # Serialised as the severity's string value, like `severity` itself.
    assert regraded["severity_overridden_from"] == "medium"
    assert "severity_overridden_from" not in plain, _RULE


def test_source_file_appears_only_on_a_merged_run() -> None:
    """ADR-025 added this key. It must stay conditional.

    Emitting it unconditionally would change the shape of every single-file
    run — the exact drift this contract exists to catch, arriving as a
    well-meaning simplification.
    """
    (merged,) = format_json([_from_overlay()], "compose.yml")
    (plain,) = format_json([_plain()], "compose.yml")

    assert set(merged) == FINDING_KEYS | {"source_file", "graded_file"}, _RULE
    assert merged["source_file"] == "compose.override.yml"
    assert "source_file" not in plain, _RULE
    assert "graded_file" not in plain, _RULE


def test_file_and_line_name_the_same_document() -> None:
    """Schema 2. `line` indexes `file`, on every run shape.

    They had disagreed: `file` was always the graded document while `line`
    indexed wherever the evidence came from, so a merged or `env_file:` run —
    both default behaviour — pointed at a real line of the wrong file. SARIF
    had already been corrected the same way after the mismatch made Code
    Scanning annotate an unrelated line of the base file.
    """
    (merged,) = format_json([_from_overlay()], "compose.yml")
    assert merged["file"] == "compose.override.yml"
    assert merged["graded_file"] == "compose.yml"

    (plain,) = format_json([_plain()], "compose.yml")
    assert plain["file"] == "compose.yml"


def test_every_conditional_key_is_accounted_for() -> None:
    """Guard the guard: a new conditional key must be added above, not just shipped.

    Without this, a key added to `format_findings` behind an `if` is invisible
    to every test in this file — each of which asserts about one branch it
    already knows about.
    """
    findings = [_plain(), _suppressed(), _regraded(), _from_overlay()]
    emitted: set[str] = set()
    for entry in format_json(findings, "compose.yml"):
        emitted |= set(entry)

    assert emitted == FINDING_KEYS | CONDITIONAL_FINDING_KEYS, (
        "a finding key is emitted that this contract does not know about, or a\n"
        "conditional key no longer appears on the fixture that produced it.\n" + _RULE
    )


def test_the_envelope_round_trips_through_json() -> None:
    """The contract is about the serialised document, not the Python dict."""
    log = build_json_log(
        format_json([_plain(), _suppressed(), _regraded(), _from_overlay()], "c.yml"),
        parse_errors=[("broken.yml", "Invalid YAML")],
    )
    reloaded = json.loads(json.dumps(log, allow_nan=False))

    assert set(reloaded) == ENVELOPE_KEYS, _RULE
    assert reloaded["version"] == SCHEMA_VERSION, _RULE
    assert len(reloaded["findings"]) == 4


# --- SARIF ------------------------------------------------------------------
#
# #644 asked whether SARIF deserves the same treatment. It does, and for the
# same reason: `docs/compatibility.md` freezes "the JSON envelope **and** the
# SARIF 2.1.0 log shapes" together. `EVIDENCE_CONTRACT` in
# tests/test_finding_identity.py pins alert *identity*; nothing pinned the
# emitted document's key sets, so a result could gain or lose a member without
# any test noticing — and #647 showed what an unconstrained derivation costs
# when only part of a surface is held.
#
# Pinned at the structural level rather than field by field: `tests/test_sarif.py`
# already covers the semantics of individual members in depth. What was missing
# is the assertion that the *set* has not moved.

SARIF_TOP_KEYS = {"$schema", "version", "runs"}
SARIF_RUN_KEYS = {
    "tool",
    "results",
    "invocations",
    "originalUriBaseIds",
    "taxonomies",
}
SARIF_DRIVER_KEYS = {"name", "version", "informationUri", "rules"}
SARIF_RESULT_KEYS = {
    "ruleId",
    "ruleIndex",
    "level",
    "message",
    "locations",
    "partialFingerprints",
    "properties",
}
# Emitted only when a finding has a machine-applicable edit (ADR-014).
SARIF_CONDITIONAL_RESULT_KEYS = {"fixes"}

_SARIF_RULE = (
    "The SARIF log shape is frozen at 1.0 alongside the JSON envelope\n"
    "  (docs/compatibility.md, ADR-015). Adding a member is additive; removing\n"
    "  or renaming one is breaking and needs a CHANGELOG `Changed` entry."
)


def _sarif_of(document: str, tmp_path: Path) -> dict:
    target = tmp_path / "compose.yml"
    target.write_text(document)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "compose_lint",
            "check",
            "--format",
            "sarif",
            "--fail-on",
            "low",
            "compose.yml",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(result.stdout)


_FIXABLE_DOC = (
    'services:\n  web:\n    image: myapp:1.0\n    ports:\n      - "8080:80"\n'
)


def test_sarif_top_level_and_run_key_sets_are_exact(tmp_path: Path) -> None:
    log = _sarif_of(_FIXABLE_DOC, tmp_path)

    assert set(log) == SARIF_TOP_KEYS, _SARIF_RULE
    assert log["version"] == "2.1.0", _SARIF_RULE
    (run,) = log["runs"]
    assert set(run) == SARIF_RUN_KEYS, _SARIF_RULE
    assert set(run["tool"]["driver"]) == SARIF_DRIVER_KEYS, _SARIF_RULE


def test_sarif_result_key_set_is_exact(tmp_path: Path) -> None:
    """Every result carries the required members; `fixes` only when there is one."""
    log = _sarif_of(_FIXABLE_DOC, tmp_path)
    results = log["runs"][0]["results"]
    assert results, "fixture produced no results"

    for result in results:
        extra = set(result) - SARIF_RESULT_KEYS
        assert extra <= SARIF_CONDITIONAL_RESULT_KEYS, _SARIF_RULE
        assert set(result) >= SARIF_RESULT_KEYS, _SARIF_RULE

    # CL-0005 has a fixer, so at least one result must exercise the branch.
    assert any("fixes" in r for r in results), (
        "no result carried `fixes`, so the conditional branch is unpinned"
    )
