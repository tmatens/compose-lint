"""SARIF 2.1.0 formatter for GitHub Code Scanning integration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint import __version__
from compose_lint.models import Severity
from compose_lint.rules import get_registered_rules

if TYPE_CHECKING:
    from compose_lint.models import Finding

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

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


def format_findings(
    findings: list[Finding],
    filepath: str,
) -> list[dict[str, Any]]:
    """Format findings as SARIF result objects."""
    rules, index_map = _build_rules()
    results: list[dict[str, Any]] = []

    for f in findings:
        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": index_map.get(f.rule_id, 0),
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": filepath},
                        "region": {"startLine": f.line or 1},
                    },
                },
            ],
        }

        if f.fix:
            result["fixes"] = [
                {
                    "description": {"text": f.fix},
                },
            ]

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
) -> dict[str, Any]:
    """Build a complete SARIF log object."""
    rules, _ = _build_rules()

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
                "results": all_results,
            },
        ],
    }
