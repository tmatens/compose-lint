"""SARIF 2.1.0 formatter for GitHub Code Scanning integration."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from compose_lint import __version__
from compose_lint.models import Severity
from compose_lint.rules import get_registered_rules

if TYPE_CHECKING:
    from collections.abc import Sequence

    from compose_lint.models import Finding, TextEdit

# The schema's canonical `$id`, served from the OASIS errata01 OS publication.
# It is an immutable, versioned URL — unlike the previous raw.githubusercontent
# `main`-branch link, which was a mutable ref (and so conflicted with this
# repo's no-mutable-refs principle as well as not being the schema's own `$id`).
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)

# Symbolic base for relativized artifact URIs. Declared once per run in
# ``originalUriBaseIds`` (pointed at the working directory) and referenced from
# each in-tree ``artifactLocation`` via ``uriBaseId``; GitHub Code Scanning
# resolves the pair to a repo-relative path.
_URI_BASE_ID = "SRCROOT"


def _working_dir_uri() -> str:
    """The current working directory as a ``file:`` URI with a trailing slash.

    A base URI for relative-reference resolution must end in ``/`` (RFC 3986
    §5.3); ``Path.as_uri`` percent-encodes any spaces/Unicode in the path.
    """
    return Path.cwd().as_uri() + "/"


def _artifact_location(filepath: str) -> dict[str, Any]:
    """Build a SARIF ``artifactLocation`` with a conformant URI reference.

    SARIF §3.4.1 requires ``uri`` to be a valid RFC-3986 URI reference, and
    GitHub Code Scanning resolves it against the repository root — so emitting a
    raw OS path verbatim is wrong twice over: an absolute path won't resolve on
    GitHub, and a space or non-ASCII byte (``/tmp/my dir/café.yml``) is not a
    legal URI reference. When the file lives under the working directory, emit a
    percent-encoded repo-relative path tagged with the ``SRCROOT`` base id;
    otherwise fall back to an absolute, percent-encoded ``file:`` URI.
    """
    try:
        rel = os.path.relpath(filepath, os.getcwd())
    except ValueError:
        # No common base (e.g. different drive on Windows).
        rel = ".."
    if not rel.startswith(".."):
        return {"uri": quote(rel.replace(os.sep, "/")), "uriBaseId": _URI_BASE_ID}
    return {"uri": Path(filepath).resolve().as_uri()}


def _physical_location(filepath: str, line: int | None) -> dict[str, Any]:
    """Build a SARIF ``physicalLocation``, including ``region`` only when known.

    SARIF requires ``region.startLine`` to be >= 1, so a missing or non-positive
    line cannot be expressed as a region. Rather than fabricate ``startLine: 1``
    (which mislocates the result at the top of the file), omit the region
    entirely — a location with only an ``artifactLocation`` is valid and lets a
    consumer attribute the result to the file as a whole.
    """
    location: dict[str, Any] = {"artifactLocation": _artifact_location(filepath)}
    if line is not None and line >= 1:
        location["region"] = {"startLine": line}
    return location


# Fingerprint scheme version. Bump if the inputs below change, so a consumer can
# tell an algorithm change from a genuine new finding.
_FINGERPRINT_KEY = "composeLintFinding/v1"


def _partial_fingerprints(uri: str, finding: Finding) -> dict[str, str]:
    """A stable per-finding fingerprint for GitHub alert dedup/tracking.

    GitHub uses ``partialFingerprints`` to match the *same* alert across commits
    and to deduplicate uploads; without them, repeated SARIF uploads create
    duplicate alerts and lose continuity when code moves. The digest covers the
    finding's logical identity — file, rule, service, and message (the message
    carries the specific offending value, which distinguishes multiple hits of
    one rule on one service) — but deliberately **not** the line number, so an
    alert survives unrelated line shifts. Optional in base SARIF; emitting it is
    additive to the contract (ADR-015).
    """
    # repr() of the component list is an unambiguous, collision-safe
    # serialization (it escapes embedded quotes), so distinct findings
    # cannot alias by component-boundary coincidence.
    parts = [uri, finding.rule_id, str(finding.service), finding.message]
    digest = hashlib.sha256(repr(parts).encode("utf-8")).hexdigest()
    return {_FINGERPRINT_KEY: digest}


# GitHub Code Scanning security-severity mapping (numeric).
# Over 9.0 = critical, 7.0-8.9 = high, 4.0-6.9 = medium, 0.1-3.9 = low.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
}

_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _build_rules() -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Build SARIF rule definitions from the rule registry.

    Returns the rules array and a mapping of rule ID to index.
    """
    rules: list[dict[str, Any]] = []
    index_map: dict[str, int] = {}

    for cls in get_registered_rules():
        rule = cls()
        meta = rule.metadata
        index_map[meta.id] = len(rules)

        rule_obj: dict[str, Any] = {
            "id": meta.id,
            "name": meta.name,
            "shortDescription": {"text": meta.name},
            "fullDescription": {"text": meta.description},
            "defaultConfiguration": {
                "level": _SARIF_LEVEL[meta.severity],
            },
            "properties": {
                "security-severity": _SECURITY_SEVERITY[meta.severity],
            },
        }

        if meta.references:
            rule_obj["helpUri"] = meta.references[0]
            help_lines = [meta.description, "", "References:"]
            help_lines.extend(f"- {ref}" for ref in meta.references)
            rule_obj["help"] = {"text": "\n".join(help_lines)}

        rules.append(rule_obj)

    return rules, index_map


def _build_fix(edits: list[TextEdit], filepath: str) -> dict[str, Any]:
    """Build one SARIF ``fix`` object from a finding's :class:`TextEdit`s.

    Each edit becomes a ``replacement``: ``TextEdit``'s half-open, 1-indexed
    ``[start, end)`` region maps directly onto SARIF's ``deletedRegion`` (whose
    ``endColumn`` is likewise the column *after* the region), so no coordinate
    translation is needed. A non-empty ``replacement`` supplies
    ``insertedContent``; a pure deletion omits it. Any per-edit ``caveat``
    becomes the fix's ``description`` so a SARIF consumer sees the
    behavior-changing warning the dry-run diff shows.
    """
    replacements: list[dict[str, Any]] = []
    caveats: list[str] = []
    for edit in edits:
        replacement: dict[str, Any] = {
            "deletedRegion": {
                "startLine": edit.start_line,
                "startColumn": edit.start_col,
                "endLine": edit.end_line,
                "endColumn": edit.end_col,
            },
        }
        if edit.replacement:
            replacement["insertedContent"] = {"text": edit.replacement}
        replacements.append(replacement)
        if edit.caveat and edit.caveat not in caveats:
            caveats.append(edit.caveat)

    fix: dict[str, Any] = {
        "artifactChanges": [
            {
                "artifactLocation": _artifact_location(filepath),
                "replacements": replacements,
            },
        ],
    }
    if caveats:
        fix["description"] = {"text": " ".join(caveats)}
    return fix


def format_findings(
    findings: list[Finding],
    filepath: str,
    fixes: Sequence[tuple[Finding, list[TextEdit]]] | None = None,
) -> list[dict[str, Any]]:
    """Format findings as SARIF result objects.

    When ``fixes`` is given (each entry pairs a finding with the edits a fixer
    produced for it, e.g. ``FixResult.fixed_edits``), the matching result gains a
    schema-valid ``fixes[]`` carrying the concrete ``artifactChanges``. Findings
    without structured edits, and every finding when ``fixes`` is ``None``, keep
    the human-readable ``properties.fix`` guidance string and nothing more. The
    caller gates whether to pass ``fixes`` at all (experimental until the ``fix``
    feature is promoted), so the default output shape is unchanged.
    """
    rules, index_map = _build_rules()
    results: list[dict[str, Any]] = []
    edits_by_finding = {id(finding): edits for finding, edits in (fixes or [])}

    for f in findings:
        physical_location = _physical_location(filepath, f.line)
        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{"physicalLocation": physical_location}],
            "partialFingerprints": _partial_fingerprints(
                physical_location["artifactLocation"]["uri"], f
            ),
        }

        # ruleIndex must identify the descriptor the result refers to (SARIF
        # §3.52.5). Emit it only when the rule is actually in the registry;
        # defaulting to 0 would point an unregistered rule at CL-0001 while
        # ruleId named the real one — a self-contradiction.
        if f.rule_id in index_map:
            result["ruleIndex"] = index_map[f.rule_id]

        if f.fix:
            result["properties"] = {"fix": f.fix}

        edits = edits_by_finding.get(id(f))
        if edits:
            result["fixes"] = [_build_fix(edits, filepath)]

        if f.suppressed:
            result["suppressions"] = [
                {
                    "kind": "external",
                    "justification": f.suppression_reason
                    or "disabled in .compose-lint.yml",
                },
            ]

        results.append(result)

    return results


def build_sarif_log(
    all_results: list[dict[str, Any]],
    parse_errors: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Build a complete SARIF log object.

    parse_errors entries (filepath, message) become invocation
    toolExecutionNotifications so SARIF consumers (GitHub code scanning)
    can report files that were skipped during the run.
    """
    rules, _ = _build_rules()

    working_dir_uri = _working_dir_uri()
    invocation: dict[str, Any] = {
        "executionSuccessful": not parse_errors,
        "workingDirectory": {"uri": working_dir_uri},
    }
    if parse_errors:
        invocation["toolExecutionNotifications"] = [
            {
                "level": "error",
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": _artifact_location(filepath),
                        },
                    },
                ],
            }
            for filepath, message in parse_errors
        ]

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "compose-lint",
                        "version": __version__,
                        "informationUri": ("https://github.com/tmatens/compose-lint"),
                        "rules": rules,
                    },
                },
                "originalUriBaseIds": {_URI_BASE_ID: {"uri": working_dir_uri}},
                "invocations": [invocation],
                "results": all_results,
            },
        ],
    }
