"""Command-line interface for compose-lint."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

from compose_lint import __version__
from compose_lint.config import ConfigError, load_config
from compose_lint.config_emit import render_config
from compose_lint.engine import filter_findings, run_rules
from compose_lint.explain import UnknownRuleError, load_rule_doc
from compose_lint.fix import (
    apply_edits,
    collect_edits,
    render_file_diff,
    reparse_or_error,
    verify_apply,
)
from compose_lint.formatters.json import build_json_log
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


# Flags handled by the top-level parser, not `check`. A flag-only invocation
# carrying one of these (e.g. `compose-lint --version`) is left untouched so the
# top-level parser sees it; any other flag-only invocation routes to `check`.
_GLOBAL_FLAGS = frozenset({"-h", "--help", "--version"})


def _subcommands() -> set[str]:
    """Return the subcommand names the argv shim should recognize.

    Bare ``compose-lint <file>`` is kept working as an implicit ``check``
    (ADR-011): when the first non-flag token is not one of these, the shim
    prepends ``check``. ``fix`` and ``init`` are recognized so
    ``compose-lint fix ...`` / ``compose-lint init ...`` route to them.
    """
    return {"check", "fix", "init"}


def _add_check_subparser(
    subparsers: argparse._SubParsersAction,  # type: ignore[type-arg]
) -> None:
    """Register the `check` subcommand (the default lint operation)."""
    check = subparsers.add_parser(
        "check",
        help="lint Docker Compose file(s) for security issues (default)",
        description="A security-focused linter for Docker Compose files.",
    )
    check.add_argument(
        "files",
        nargs="*",
        metavar="FILE",
        help=(
            "Docker Compose file(s) to lint. If omitted, searches the "
            "current directory for compose.yml, compose.yaml, "
            "docker-compose.yml, or docker-compose.yaml."
        ),
    )
    check.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        dest="output_format",
        help="output format (default: text)",
    )
    check.add_argument(
        "--fail-on",
        type=_severity_type,
        default=Severity.HIGH,
        metavar="{" + ",".join(s.value for s in Severity) + "}",
        help="minimum severity to trigger exit 1 (default: high)",
    )
    check.add_argument(
        "--config",
        metavar="PATH",
        help="path to .compose-lint.yml config file",
    )
    check.add_argument(
        "--skip-suppressed",
        action="store_true",
        default=False,
        help="hide suppressed findings from output",
    )
    verbosity = check.add_mutually_exclusive_group()
    verbosity.add_argument(
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
    verbosity.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help=(
            "in text mode, print one line per finding (no fix block, "
            "reference URL, or source excerpt). Useful for CI and repeat "
            "users. No effect on JSON or SARIF output."
        ),
    )
    check.add_argument(
        "--explain",
        metavar="CL-XXXX",
        help=(
            "print the prose documentation for a single rule and exit. "
            "Cannot be combined with FILE arguments."
        ),
    )


def _add_fix_subparser(
    subparsers: argparse._SubParsersAction,  # type: ignore[type-arg]
) -> None:
    """Register the `fix` subcommand (ADR-014).

    Promoted to the documented, SemVer-covered surface in 0.11.0: it carries a
    ``help=`` string so it lists in ``compose-lint --help`` like ``check``.
    """
    fix = subparsers.add_parser(
        "fix",
        help="auto-remediate auto-fixable findings (dry-run; --apply to write)",
        description=(
            "Auto-remediate auto-fixable findings. Dry-run by default: prints a "
            "unified diff and writes nothing. Pass --apply to write fixes in "
            "place. Findings with no safe automatic fix are left for manual "
            "review; suppressed findings are never touched."
        ),
    )
    fix.add_argument(
        "files",
        nargs="*",
        metavar="FILE",
        help="Docker Compose file(s) to fix (defaults to discovery, like check)",
    )
    fix.add_argument(
        "--apply",
        action="store_true",
        default=False,
        help="write fixes in place instead of printing a dry-run diff",
    )
    fix.add_argument(
        "--only",
        action="append",
        metavar="CL-XXXX",
        dest="only",
        help="restrict fixes to the named rule(s); repeatable",
    )
    fix.add_argument(
        "--config",
        metavar="PATH",
        help="path to .compose-lint.yml config file (suppressions are honored)",
    )


def _add_init_subparser(
    subparsers: argparse._SubParsersAction,  # type: ignore[type-arg]
) -> None:
    """Register the `init` subcommand (ADR-011).

    Bootstraps a starter ``.compose-lint.yml`` from a file's findings so users
    triage suppressions deliberately instead of hand-authoring the config.
    """
    init = subparsers.add_parser(
        "init",
        help="generate a starter .compose-lint.yml from a file's findings",
        description=(
            "Generate a starter .compose-lint.yml from the findings in a single "
            "Compose file. Every finding becomes a per-service exclude_services "
            "entry with a placeholder reason for you to triage — replace it with "
            "a real justification or delete the entry and fix the issue. Refuses "
            "to overwrite an existing config without --force."
        ),
    )
    init.add_argument(
        "file",
        metavar="FILE",
        help="Docker Compose file to analyze",
    )
    init.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        default=".compose-lint.yml",
        help="where to write the config (default: .compose-lint.yml)",
    )
    init.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="overwrite an existing config file",
    )


def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser and its subcommands."""
    parser = argparse.ArgumentParser(
        prog="compose-lint",
        description="A security-focused linter for Docker Compose files.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    _add_check_subparser(subparsers)
    _add_fix_subparser(subparsers)
    _add_init_subparser(subparsers)
    return parser


def _normalize_argv(argv: list[str]) -> list[str]:
    """Rewrite ``argv`` so bare invocations route to the ``check`` subcommand.

    Preserves the pre-subcommand CLI: ``compose-lint <file>``,
    ``compose-lint -q``, and ``compose-lint --explain CL-XXXX`` keep working as
    ``check``. An explicit subcommand (``check ...``) is left untouched, as is a
    flag-only invocation of a global flag (``--version``, ``--help``) so the
    top-level parser handles it. The heuristic keys off the first non-flag
    token, mirroring ADR-011's implementation note.
    """
    if not argv:
        return ["check"]
    first_positional = next((tok for tok in argv if not tok.startswith("-")), None)
    if first_positional in _subcommands():
        return argv
    if first_positional is None and _GLOBAL_FLAGS.intersection(argv):
        return argv
    return ["check", *argv]


def main(argv: list[str] | None = None) -> NoReturn:
    """Main entry point for the CLI."""
    parser = _build_parser()
    raw = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(_normalize_argv(raw))
    if args.command == "fix":
        _run_fix(args)
    if args.command == "init":
        _run_init(args)
    _run_check(args)


def _run_check(args: argparse.Namespace) -> NoReturn:
    """Run the `check` operation: lint files and exit with the verdict code."""
    if args.explain is not None:
        if args.files:
            print(
                "Error: --explain cannot be combined with FILE arguments",
                file=sys.stderr,
            )
            sys.exit(2)
        # --explain emits human-readable rule prose to stdout (the requested
        # artifact of this mode). There is no JSON/SARIF form, so reject those
        # rather than silently printing markdown when one is requested.
        if args.output_format != "text":
            print(
                "Error: --explain has no JSON or SARIF form; "
                "use the default text output",
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

    # Print branded header in text mode before scanning begins. flush=True here
    # (and on the per-file text prints below) keeps block-buffered stdout from
    # landing after unbuffered stderr when both are captured together (2>&1).
    if args.output_format == "text":
        print(
            format_header(
                args.files,
                str(config_path) if config_path else None,
                args.fail_on,
                __version__,
            ),
            flush=True,
        )

    all_json: list[dict[str, object]] = []
    all_sarif: list[dict[str, object]] = []
    all_file_findings: list[tuple[list[Finding], str]] = []
    parse_errors: list[tuple[str, str]] = []
    rule_errors: list[tuple[str, str]] = []
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

        def _record_rule_error(
            rule_id: str,
            service_name: str,
            exc: Exception,
            _filepath: str = filepath,
        ) -> None:
            msg = (
                f"rule {rule_id} failed on service '{service_name}': "
                f"{type(exc).__name__}: {exc}"
            )
            rule_errors.append((_filepath, msg))
            print(f"Error: {_filepath}: {msg}", file=sys.stderr)

        findings = run_rules(
            data,
            lines,
            disabled_rules=disabled_rules,
            severity_overrides=severity_overrides,
            excluded_services=excluded_services,
            on_error=_record_rule_error,
        )

        if args.skip_suppressed:
            findings = [f for f in findings if not f.suppressed]

        if args.output_format == "text":
            output = format_text(
                findings, filepath, verbose=args.verbose, quiet=args.quiet
            )
            if output:
                print(output, flush=True)
            print(format_summary(findings, filepath), flush=True)
            all_file_findings.append((findings, filepath))
        elif args.output_format == "sarif":
            # Structured SARIF fixes (ADR-014, promoted in 0.11.0): every
            # auto-fixable finding carries its machine-applicable edit so GitHub
            # Code Scanning can render a suggested change. Findings with no safe
            # fixer keep the prose `properties.fix` only.
            text = Path(filepath).read_text(encoding="utf-8")
            fixes = collect_edits(findings, data, lines, text).fixed_edits
            all_sarif.extend(format_sarif(findings, filepath, fixes=fixes))
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
        # allow_nan=False makes a stray float NaN/Infinity raise rather than emit
        # bare `NaN`/`Infinity` tokens, which RFC 8259 forbids and strict parsers
        # reject. The formatter already coerces `service` to str, so this guards
        # any future numeric field; the same applies to the SARIF dump below.
        json_log = build_json_log(all_json, parse_errors)
        print(json.dumps(json_log, indent=2, allow_nan=False))
    elif args.output_format == "sarif":
        sarif_log = build_sarif_log(
            all_sarif, parse_errors, severity_overrides=severity_overrides
        )
        print(json.dumps(sarif_log, indent=2, allow_nan=False))

    if parse_errors or rule_errors:
        sys.exit(2)
    sys.exit(1 if has_errors else 0)


def _atomic_write(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` atomically, preserving its mode.

    A fix must never leave a half-written Compose file: an interrupted in-place
    write (crash, full disk) would corrupt a file ``docker compose`` then
    refuses to start. Write to a temp file in the same directory, flush it to
    disk, and ``os.replace`` it into place — a reader sees either the old file or
    the complete new one, never a truncated mix. The original file's permission
    bits carry over so the fix neither relaxes nor tightens them. ``newline=""``
    writes the computed text verbatim, with no newline translation.
    """
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as tmp:
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
        # Best-effort mode carry-over; the swap below still lands the content.
        with contextlib.suppress(OSError):
            os.chmod(tmp_path, stat.S_IMODE(path.stat().st_mode))
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _run_fix(args: argparse.Namespace) -> NoReturn:
    """Run the `fix` operation (ADR-014).

    Dry-run by default: a unified diff of proposed edits goes to stdout and
    status goes to stderr; nothing is written. ``--apply`` writes edits in
    place. Suppressed/excluded findings (``.compose-lint.yml``) are never fixed.
    Exit 0 on success, 2 on usage/parse error — findings are the input, not the
    failure signal, so residual manual-only findings do not change the code.
    """
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

    only = set(args.only) if args.only else None
    had_error = False

    for filepath in args.files:
        try:
            data, lines = load_compose(filepath)
        except FileNotFoundError:
            print(f"Error: {filepath}: file not found", file=sys.stderr)
            had_error = True
            continue
        except ComposeNotApplicableError as e:
            # v1 / fragment file: skipped, not an error (ADR-013).
            print(f"{filepath}: {e}", file=sys.stderr)
            continue
        except ComposeError as e:
            print(f"Error: {filepath}: {e}", file=sys.stderr)
            had_error = True
            continue

        text = Path(filepath).read_text(encoding="utf-8")
        findings = run_rules(
            data,
            lines,
            disabled_rules=disabled_rules,
            severity_overrides=severity_overrides,
            excluded_services=excluded_services,
        )
        result = collect_edits(findings, data, lines, text, only=only)

        if not result.edits:
            if result.manual:
                print(
                    f"{filepath}: nothing to auto-fix; "
                    f"{len(result.manual)} finding(s) need manual review",
                    file=sys.stderr,
                )
            else:
                print(f"{filepath}: nothing to fix", file=sys.stderr)
            continue

        patched = apply_edits(text, result.edits)

        # Safety net (ADR-014): re-parse the candidate before persisting it. If
        # the combined edits do not produce valid Compose, that is a fixer bug,
        # not user error — refuse the whole apply, write nothing, and surface the
        # diff plus the parse error so it is diagnosable (issue #261).
        guard_error = reparse_or_error(patched)
        if guard_error is not None:
            print(
                render_file_diff(filepath, text, patched, result.caveats),
                end="",
                file=sys.stderr,
            )
            print(
                f"Error: {filepath}: computed fix does not parse as Compose "
                f"({guard_error}); no changes written",
                file=sys.stderr,
            )
            had_error = True
            continue

        # Layer above the parse net (ADR-014): valid Compose is not enough — the
        # patch must also leave untouched config intact, converge on a second
        # pass, and raise no new finding. A failure here is a fixer bug too:
        # refuse, write nothing, and surface the diff for diagnosis.
        verify_error = verify_apply(
            data,
            findings,
            result,
            patched,
            only=only,
            disabled_rules=disabled_rules,
            severity_overrides=severity_overrides,
            excluded_services=excluded_services,
        )
        if verify_error is not None:
            print(
                render_file_diff(filepath, text, patched, result.caveats),
                end="",
                file=sys.stderr,
            )
            print(
                f"Error: {filepath}: {verify_error}; no changes written",
                file=sys.stderr,
            )
            had_error = True
            continue

        if args.apply:
            _atomic_write(Path(filepath), patched)
            print(
                f"{filepath}: applied {len(result.edits)} fix(es) across "
                f"{len(result.fixed)} finding(s)",
                file=sys.stderr,
            )
        else:
            print(
                render_file_diff(filepath, text, patched, result.caveats),
                end="",
                flush=True,
            )
            print(
                f"{filepath}: {len(result.edits)} fix(es) available; "
                f"{len(result.manual)} finding(s) need manual review",
                file=sys.stderr,
            )

    sys.exit(2 if had_error else 0)


def _run_init(args: argparse.Namespace) -> NoReturn:
    """Run the `init` operation (ADR-011).

    Lint a single Compose file with no existing config (raw findings) and write
    a starter ``.compose-lint.yml`` whose entries the user triages. Refuses to
    clobber an existing config without ``--force``. Status goes to stderr; the
    artifact lands on disk. Exit 0 on a successful write (or when there is
    nothing to suppress), 2 on usage/parse error or overwrite-without-force —
    findings are the input here, not the failure signal.
    """
    try:
        data, lines = load_compose(args.file)
    except FileNotFoundError:
        print(f"Error: {args.file}: file not found", file=sys.stderr)
        sys.exit(2)
    except ComposeNotApplicableError as e:
        # v1 / fragment file: skipped, not an error (ADR-013). Nothing to lint,
        # so nothing to bootstrap.
        print(f"{args.file}: {e}", file=sys.stderr)
        sys.exit(0)
    except ComposeError as e:
        print(f"Error: {args.file}: {e}", file=sys.stderr)
        sys.exit(2)

    findings = run_rules(data, lines)
    if not findings:
        print(
            f"{args.file}: no findings; nothing to suppress, not writing {args.output}",
            file=sys.stderr,
        )
        sys.exit(0)

    out_path = Path(args.output)
    # Refuse only when we would actually write: a parse error or a clean file
    # above already exited, so reaching here means there is a config to land.
    # Protect deliberate human suppression decisions from a silent clobber.
    if out_path.exists() and not args.force:
        print(
            f"Error: {out_path} already exists; pass --force to overwrite",
            file=sys.stderr,
        )
        sys.exit(2)

    existed = out_path.exists()
    _atomic_write(out_path, render_config(findings))
    if not existed:
        # _atomic_write carries over an existing file's mode but a fresh file
        # inherits mkstemp's restrictive 0600. A config meant to be committed and
        # read in CI wants the usual 0644; best-effort, never fatal.
        with contextlib.suppress(OSError):
            out_path.chmod(0o644)

    rule_count = len({f.rule_id for f in findings})
    pair_count = len({(f.rule_id, f.service) for f in findings})
    print(
        f"wrote {out_path} with {pair_count} suppression(s) across "
        f"{rule_count} rule(s)",
        file=sys.stderr,
    )
    sys.exit(0)
