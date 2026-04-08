"""Command-line interface for compose-lint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import NoReturn

from compose_lint import __version__
from compose_lint.config import ConfigError, load_config
from compose_lint.engine import filter_findings, run_rules
from compose_lint.formatters.json import format_findings as format_json
from compose_lint.formatters.sarif import build_sarif_log
from compose_lint.formatters.sarif import format_findings as format_sarif
from compose_lint.formatters.text import format_findings as format_text
from compose_lint.formatters.text import format_summary
from compose_lint.models import Severity
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


_COMPOSE_FILENAMES = [
    "compose.yml",
    "compose.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
]


def _discover_compose_files() -> list[str]:
    """Find Compose files in the current directory."""
    return [name for name in _COMPOSE_FILENAMES if Path(name).is_file()]


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="compose-lint",
        description="A security-focused linter for Docker Compose files.",
    )
    parser.add_argument(
        "files",
        nargs="*",
        metavar="FILE",
        help=(
            "Docker Compose file(s) to lint. If omitted, searches the "
            "current directory for compose.yml, compose.yaml, "
            "docker-compose.yml, or docker-compose.yaml."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
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


def main(argv: list[str] | None = None) -> NoReturn:
    """Main entry point for the CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        disabled_rules, severity_overrides = load_config(args.config)
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    if not args.files:
        args.files = _discover_compose_files()
        if not args.files:
            print(
                "Error: no Compose files found. Searched for: "
                "compose.yml, compose.yaml, "
                "docker-compose.yml, docker-compose.yaml",
                file=sys.stderr,
            )
            sys.exit(2)

    all_json: list[dict[str, object]] = []
    all_sarif: list[dict[str, object]] = []
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

        findings = run_rules(
            data,
            lines,
            disabled_rules=disabled_rules,
            severity_overrides=severity_overrides,
        )

        if args.output_format == "text":
            output = format_text(findings, filepath)
            if output:
                print(output)
            print(format_summary(findings, filepath))
        elif args.output_format == "sarif":
            all_sarif.extend(format_sarif(findings, filepath))
        else:
            all_json.extend(format_json(findings, filepath))

        failing = filter_findings(findings, args.fail_on)
        if failing:
            has_errors = True

    if args.output_format == "json":
        print(json.dumps(all_json, indent=2))
    elif args.output_format == "sarif":
        print(json.dumps(build_sarif_log(all_sarif), indent=2))

    sys.exit(1 if has_errors else 0)
