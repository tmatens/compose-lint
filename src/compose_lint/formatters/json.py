"""JSON formatter for machine-readable output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from compose_lint import __version__

if TYPE_CHECKING:
    from compose_lint.models import Finding

# Envelope schema version (ADR-015). Bumped only on a breaking change to the
# output shape; additive top-level fields do not bump it.
#
# 2: `file` now names the document the evidence is *in*, and the document that
# was graded moved to `graded_file`. Before 1.0 that costs a version bump; the
# same correction after the freeze would be a MAJOR, because `file` and `line`
# are the required fields ADR-015 froze. See `format_findings`.
SCHEMA_VERSION = "2"


def format_findings(findings: list[Finding], filepath: str) -> list[dict[str, object]]:
    """Format findings as JSON-serializable dicts.

    ``file`` and ``line`` name the same place: the document the evidence is
    written in, and a line within *that* document. A merged run grades more
    than one document, so those had disagreed — ``file`` was always the graded
    document while ``line`` indexed wherever the evidence actually came from,
    which on any overlay or ``env_file:`` run pointed at a real line of the
    wrong file. Both are default behaviour (ADR-025, ADR-027), so that was the
    common path, and both are required fields ADR-015 froze.

    SARIF already resolved this the same way — ``result_path = f.source_file or
    filepath`` — after the mismatch made Code Scanning annotate an unrelated
    line of the base file. The graded document is still reported, as
    ``graded_file``, because "which project did this come from" is a real
    question a merged run has to answer; it is emitted only when it differs
    from ``file``.
    """
    results: list[dict[str, object]] = []
    for f in findings:
        evidence_file = f.source_file or filepath
        entry: dict[str, object] = {
            "file": evidence_file,
            "line": f.line,
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            # A service name is a YAML mapping key, which the loader may resolve
            # into a non-string scalar (a bool from `true:`, an int from a bare
            # number, a float from `.nan`). ADR-015 contracts `service` as a
            # string, and a float NaN/Inf would also serialize as invalid JSON,
            # so coerce here regardless of what the key resolved to.
            "service": str(f.service),
            "message": f.message,
            "fix": f.fix,
            "references": list(f.references),
            "suppressed": f.suppressed,
        }
        if f.suppressed:
            entry["suppression_reason"] = f.suppression_reason
        if f.severity_overridden_from is not None:
            entry["severity_overridden_from"] = f.severity_overridden_from.value
        if evidence_file != filepath:
            # The project this finding was graded under, when that is not the
            # document the evidence sits in. Emitted only for a merged or
            # `env_file:` run, so a single-file run's shape is unchanged.
            entry["graded_file"] = filepath
            # Retained as an alias of `file` for consumers written against
            # schema 1, where it was the only way to learn where `line`
            # actually pointed. Deprecated; `file` now answers it directly.
            entry["source_file"] = f.source_file
        results.append(entry)
    return results


def build_json_log(
    findings: list[dict[str, object]],
    parse_errors: list[tuple[str, str]] | None = None,
) -> dict[str, object]:
    """Wrap findings in the top-level JSON output envelope (ADR-015).

    The envelope exists so run-level metadata can be added over time without
    breaking consumers: new top-level fields are additive and never change
    ``version``. ``parse_errors`` entries ``(filepath, message)`` surface files
    that could not be parsed (exit 2), mirroring the SARIF invocation
    notifications; ADR-013 "not applicable" skips are not included.
    """
    errors = [
        {"file": filepath, "message": message}
        for filepath, message in (parse_errors or [])
    ]
    return {
        "version": SCHEMA_VERSION,
        "tool": {"name": "compose-lint", "version": __version__},
        "findings": findings,
        "errors": errors,
    }
