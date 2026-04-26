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
from compose_lint.explain import UnknownRuleError, load_rule_doc
from compose_lint.formatters.json import format_findings as format_json
from compose_lint.formatters.sarif import build_sarif_log
from compose_lint.formatters.sarif import format_findings as format_sarif
from compose_lint.formatters.text import (
    format_aggregate_summary,
    format_header,
    format_summary,
    format_verdict,
)
from compose_lint.formatters.text import format_findings as format_text
from compose_lint.models import Finding, Severity
from compose_lint.parser import ComposeError, ComposeNotApplicableError, load_compose


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


def _effective_config_path(explicit: str | None) -> Path | None:
    """Return the config file path that will be used, or None if no config."""
    if explicit:
        return Path(explicit)
    p = Path(".compose-lint.yml")
    return p if p.exists() else None


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
        default=Severity.HIGH,
        help="minimum severity to trigger exit 1 (default: high)",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="path to .compose-lint.yml config file",
    )
    parser.add_argument(
        "--skip-suppressed",
        action="store_true",
        default=False,
        help="hide suppressed findings from output",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help=(
            "in text mode, repeat the fix block and reference URL for every "
            "finding instead of only the first occurrence per (file, rule). "
            "No effect on JSON or SARIF output."
        ),
    )
    parser.add_argument(
        "--explain",
        metavar="CL-XXXX",
        help=(
            "print the prose documentation for a single rule and exit. "
            "Cannot be combined with FILE arguments."
        ),
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

    if args.explain is not None:
        if args.files:
            print(
                "Error: --explain cannot be combined with FILE arguments",
                file=sys.stderr,
            )
            sys.exit(2)
        try:
            print(load_rule_doc(args.explain))
        except UnknownRuleError:
            print(
                f"Error: unknown rule id '{args.explain}' (expected format: CL-XXXX)",
                file=sys.stderr,
            )
            sys.exit(2)
        sys.exit(0)

    config_path = _effective_config_path(args.config)

    try:
        disabled_rules, severity_overrides, excluded_services = load_config(args.config)
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

    # Print branded header in text mode before scanning begins.
    if args.output_format == "text":
        print(
            format_header(
                args.files,
                str(config_path) if config_path else None,
                args.fail_on,
                __version__,
            )
        )

    all_json: list[dict[str, object]] = []
    all_sarif: list[dict[str, object]] = []
    all_file_findings: list[tuple[list[Finding], str]] = []
    parse_errors: list[tuple[str, str]] = []
    has_errors = False
    seen_services: set[str] = set()

    for filepath in args.files:
        try:
            data, lines = load_compose(filepath)
        except FileNotFoundError:
            msg = "file not found"
            parse_errors.append((filepath, msg))
            print(f"Error: {filepath}: {msg}", file=sys.stderr)
            continue
        except ComposeNotApplicableError as e:
            # v1 / fragment file: not malformed, just outside what we lint.
            # Per ADR-013 this is exit 0 (skipped, not a parse error).
            print(f"{filepath}: {e}", file=sys.stderr)
            continue
        except ComposeError as e:
            parse_errors.append((filepath, str(e)))
            print(f"Error: {filepath}: {e}", file=sys.stderr)
            continue

        seen_services.update(data.get("services", {}).keys())

        findings = run_rules(
            data,
            lines,
            disabled_rules=disabled_rules,
            severity_overrides=severity_overrides,
            excluded_services=excluded_services,
        )

        if args.skip_suppressed:
            findings = [f for f in findings if not f.suppressed]

        if args.output_format == "text":
            output = format_text(findings, filepath, verbose=args.verbose)
            if output:
                print(output)
            print(format_summary(findings, filepath))
            all_file_findings.append((findings, filepath))
        elif args.output_format == "sarif":
            all_sarif.extend(format_sarif(findings, filepath))
        else:
            all_json.extend(format_json(findings, filepath))

        failing = filter_findings(findings, args.fail_on)
        if failing:
            has_errors = True

    for rule_id, services_map in excluded_services.items():
        for service_name in services_map:
            if service_name not in seen_services:
                print(
                    f"Warning: exclude_services for {rule_id} references "
                    f"unknown service '{service_name}'",
                    file=sys.stderr,
                )

    if args.output_format == "text":
        if len(args.files) > 1:
            print()
            print(format_aggregate_summary(all_file_findings, len(parse_errors)))
        print(format_verdict(all_file_findings, args.fail_on, len(parse_errors)))
    elif args.output_format == "json":
        print(json.dumps(all_json, indent=2))
    elif args.output_format == "sarif":
        print(json.dumps(build_sarif_log(all_sarif, parse_errors), indent=2))

    if parse_errors:
        sys.exit(2)
    sys.exit(1 if has_errors else 0)
