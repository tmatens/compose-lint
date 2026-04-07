"""Command-line interface for compose-lint."""

from __future__ import annotations

import argparse
import json
import sys
from typing import NoReturn

from compose_lint import __version__
from compose_lint.engine import filter_findings, run_rules
from compose_lint.models import Finding, Severity
from compose_lint.parser import ComposeError, load_compose


def _severity_type(value: str) -> Severity:
    """Parse a severity string into a Severity enum value."""
    try:
        return Severity(value.lower())
    except ValueError:
        choices = ", ".join(s.value for s in Severity)
        raise argparse.ArgumentTypeError(
            f"invalid severity: '{value}' (choose from {choices})"
        ) from None


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="compose-lint",
        description="A security-focused linter for Docker Compose files.",
    )
    parser.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="Docker Compose file(s) to lint",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        dest="output_format",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        type=_severity_type,
        default=Severity.ERROR,
        help="minimum severity to trigger exit 1 (default: error)",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="path to .compose-lint.yml config file",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _format_text(findings: list[Finding], filepath: str) -> str:
    """Format findings as human-readable text."""
    if not findings:
        return ""
    lines = []
    for f in findings:
        loc = f"{filepath}:{f.line}" if f.line else filepath
        lines.append(f"{loc}: [{f.severity.value.upper()}] {f.rule_id} - {f.message}")
        if f.fix:
            lines.append(f"  Fix: {f.fix}")
    return "\n".join(lines)


def _format_json(findings: list[Finding], filepath: str) -> list[dict[str, object]]:
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


def main(argv: list[str] | None = None) -> NoReturn:
    """Main entry point for the CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    json_results: list[dict[str, object]] = []
    has_errors = False

    for filepath in args.files:
        try:
            data, lines = load_compose(filepath)
        except FileNotFoundError:
            print(f"Error: file not found: {filepath}", file=sys.stderr)
            sys.exit(2)
        except ComposeError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(2)

        findings = run_rules(data, lines)

        if args.output_format == "text":
            output = _format_text(findings, filepath)
            if output:
                print(output)
        else:
            json_results.extend(_format_json(findings, filepath))

        failing = filter_findings(findings, args.fail_on)
        if failing:
            has_errors = True

    if args.output_format == "json":
        print(json.dumps(json_results, indent=2))

    sys.exit(1 if has_errors else 0)
