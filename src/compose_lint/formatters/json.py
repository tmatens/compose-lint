"""JSON formatter for machine-readable output."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from compose_lint.models import Finding


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
        }
        results.append(entry)
    return results
