"""JSON formatter for machine-readable output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from compose_lint import __version__

if TYPE_CHECKING:
    from compose_lint.models import Finding

# Envelope schema version (ADR-015). Bumped only on a breaking change to the
# output shape; additive top-level fields do not bump it.
SCHEMA_VERSION = "1"


def format_findings(findings: list[Finding], filepath: str) -> list[dict[str, object]]:
    """Format findings as JSON-serializable dicts."""
    results: list[dict[str, object]] = []
    for f in findings:
        entry: dict[str, object] = {
            "file": filepath,
            "line": f.line,
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "service": f.service,
            "message": f.message,
            "fix": f.fix,
            "references": list(f.references),
            "suppressed": f.suppressed,
        }
        if f.suppressed:
            entry["suppression_reason"] = f.suppression_reason
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
