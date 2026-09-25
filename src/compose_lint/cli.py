"""Command-line interface for compose-lint."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shlex
import stat
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

from compose_lint import __version__
from compose_lint._env_file import ENV_FILENAME
from compose_lint._output import emit, emit_block
from compose_lint._selection import Selection, plan_documents
from compose_lint._service_env import describe_unread, resolve_env_files
from compose_lint.config import (
    CONFIG_FILENAMES,
    ConfigError,
    discover_config_path,
    load_config,
    warn_unknown_excluded_services,
)
from compose_lint.config_emit import render_config
from compose_lint.engine import filter_findings, run_rules
from compose_lint.explain import UnknownRuleError, load_rule_doc, normalize_rule_id
from compose_lint.fix import (
    LineOutOfRangeError,
    apply_edits,
    collect_edits,
    render_caveat_banner,
    render_file_diff,
    reparse_or_error,
    verify_apply,
)
from compose_lint.formatters.json import build_json_log
from compose_lint.formatters.json import format_findings as format_json
from compose_lint.formatters.sarif import build_sarif_log, truncation_notice
from compose_lint.formatters.sarif import format_findings as format_sarif
from compose_lint.formatters.text import (
    format_aggregate_summary,
    format_header,
    format_summary,
    format_verdict,
)
from compose_lint.formatters.text import format_findings as format_text
from compose_lint.models import Diagnostic, DiagnosticKind, Finding, Severity
from compose_lint.parser import (
    ComposeError,
    ComposeFileError,
    ComposeNotApplicableError,
    load_compose_full,
    load_merged,
    merge_patched,
    unresolved_mount_sources,
)
from compose_lint.rules import get_registered_rules


def _severity_type(value: str) -> Severity:
    """Parse a severity string into a Severity enum value."""
    try:
        return Severity(value.lower())
    except ValueError:
        choices = ", ".join(s.value for s in Severity)
        raise argparse.ArgumentTypeError(
            f"invalid severity: '{value}' (choose from {choices})"
        ) from None


_FORMAT_CHOICES = ("text", "json", "sarif")


def _format_type(value: str) -> str:
    """Parse an output-format name, folding case the way ``--fail-on`` does."""
    folded = value.lower()
    if folded in _FORMAT_CHOICES:
        return folded
    choices = ", ".join(_FORMAT_CHOICES)
    raise argparse.ArgumentTypeError(
        f"invalid format: '{value}' (choose from {choices})"
    )


if TYPE_CHECKING:
    from collections.abc import Callable

    from compose_lint._merge import Merged


def _plan(args: argparse.Namespace, files: list[str] | None = None) -> Selection:
    """Decide which documents this run grades, and say how it decided.

    Running `docker compose up` with no `-f` loads the base file *and* a sibling
    `compose.override.yml`, with no flag and no opt-in — unless a `.env` sets
    `COMPOSE_FILE`, which replaces discovery and suppresses that pairing.
    Linting the wrong set grades a document nobody deploys in either direction:
    a socket mount added by an overlay is missed entirely, and an overlay
    Compose never loads contributes findings against a stack that does not run
    it.

    The notes are stderr-only and never touch the exit code. What was read and
    what it selected is the declared input ADR-023 clause 2 requires; a run that
    silently changed its own file set would be the undeclared kind.

    ``files`` defaults to ``args.files``; ``init`` passes its single ``FILE``
    so the one document it baselines is planned exactly as ``check`` would
    plan it (ADR-011 amendment).
    """
    selection = plan_documents(
        args.files if files is None else files,
        read_env_files=not args.no_env,
        merge_overrides=not args.no_merge_overrides,
    )
    for note in selection.notes:
        emit(f"note: {note}")
    if args.no_env:
        _note_env_not_read(selection)
    return selection


def _note_env_not_read(selection: Selection) -> None:
    """Say when a `.env` was there and deliberately skipped (ADR-026 §6).

    An escape hatch that silently changes what is graded is the failure the
    hatch was meant to prevent, one level up. Nothing here touches the exit
    code; the point is only that the difference is stated, so a run that
    disagrees with another machine's can be explained by reading its header
    and notes instead of guessed at.
    """
    skipped = sorted(
        {
            str(Path(group.primary).parent / ENV_FILENAME)
            for group in selection.groups
            if (Path(group.primary).parent / ENV_FILENAME).is_file()
        }
    )
    for path in skipped:
        emit(
            f"note: {path} was not read (--no-env), so it selected no documents "
            "and supplied no values."
        )


def _why_merged(overlays: list[str], *, selected_by_env: bool) -> str:
    """The reason a run merged ``overlays``, for the note that announces it.

    The reason is not decoration. "Compose merges it automatically" is true
    of a discovered override and false of a COMPOSE_FILE list, and stating the
    wrong one is how the pre-ADR-026 report justified reading a file Compose
    never loaded.
    """
    if selected_by_env:
        return f"because COMPOSE_FILE in {ENV_FILENAME} selects them"
    return (
        "because Compose merges "
        + ("them" if len(overlays) > 1 else "it")
        + " automatically"
    )


def _attribute_sources(findings: list[Finding], primary: str) -> list[Finding]:
    """Tag each finding with the merged file its evidence was written in.

    Exact, not inferred: the line number a rule looked up is a
    :class:`SourcedLine` carrying its own document path, so a finding already
    knows where it came from. Only findings originating outside ``primary`` are
    tagged — the report is already headed by the primary file, and repeating it
    on every finding would be noise.
    """
    tagged: list[Finding] = []
    for finding in findings:
        source = getattr(finding.line, "source", None)
        if source is not None and Path(source).absolute() != Path(primary).absolute():
            tagged.append(replace(finding, source_file=source))
        else:
            tagged.append(finding)
    return tagged


def _report_parse_error(filepath: str, exc: FileNotFoundError | ComposeError) -> str:
    """Report a ``load_compose`` parse failure to stderr and return the reason.

    Centralizes the canonical ``Error: <file>: <reason>`` line and the
    ``FileNotFoundError`` -> ``"file not found"`` wording shared by ``check``,
    ``fix`` and ``init``, so the three stay consistent. Callers keep their own
    control flow (record / flag / exit); the returned reason is for callers
    (``check``) that also collect it. Only the two true parse errors go through
    here — ``ComposeNotApplicableError`` is not an error (ADR-013) and is
    handled separately by each caller.
    """
    if isinstance(exc, ComposeFileError):
        filepath = exc.path
    reason = "file not found" if isinstance(exc, FileNotFoundError) else str(exc)
    emit(f"Error: {filepath}: {reason}")
    return reason


def _config_name(explicit: str | None, effective: Path | None) -> str | None:
    """How a suppression reason names the config the run read.

    An explicit ``--config`` keeps the user's own spelling: rendering it
    through ``Path`` turns ``other/ci.yml`` into ``other\\ci.yml`` on
    Windows. With no ``--config``, the discovered file's bare name.
    """
    if explicit:
        return explicit
    return effective.name if effective is not None else None


def _effective_config_path(explicit: str | None) -> Path | None:
    """Return the config file path that will be used, or None if no config."""
    if explicit:
        return Path(explicit)
    return discover_config_path()


def _note_no_config_in_effect() -> None:
    """Say that nothing was suppressed, naming the directory we looked in.

    A config that was never found is indistinguishable from one that was
    never written, so this cannot be an error — most runs legitimately have
    no config. What it can do is name the directory, which is the whole
    diagnosis for the case it exists for: the image's working directory is
    ``/src``, so a ``docker run -v "$(pwd)/docker-compose.yml:/src/docker-
    compose.yml"`` mounts the file and not the config beside it, and every
    suppression the user wrote is silently absent (#625). Seeing ``/src``
    in the message is what makes that click.

    Deliberately not printed on every run. It is emitted only where the
    missing config would have changed the outcome — a failing ``check``, or
    a ``fix`` that is about to touch a file — because a line on every green
    run is noise, and noise on green runs is how a diagnostic stops being
    read at all.
    """
    emit(
        f"Note: no {' or '.join(CONFIG_FILENAMES)} found in '{Path.cwd()}' — "
        "all rules are enabled and no suppressions are in effect."
    )


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


def _add_document_selection_flags(parser: argparse.ArgumentParser) -> None:
    """Add the two flags that change *which documents* a command grades.

    One definition for ``check``, ``fix`` and ``init``, because the three must
    agree: a baseline written by ``init`` is only useful if it describes the
    document ``check`` grades, so whatever narrows one must narrow the other
    the same way and under the same name.
    """
    parser.add_argument(
        "--no-merge-overrides",
        action="store_true",
        default=False,
        help=(
            "lint each file on its own instead of merging the "
            "'compose.override.yml' Compose would merge beside it. The merged "
            "view is what actually runs, so this is only right when the base "
            "file is deliberately graded in isolation"
        ),
    )
    parser.add_argument(
        "--no-env",
        action="store_true",
        default=False,
        help=(
            "ignore the env files beside the Compose file: the sibling '.env' "
            "and every 'env_file:' a service names. Compose reads the '.env' "
            "to choose which documents to load (COMPOSE_FILE), so this "
            "reproduces the previous file selection exactly -- including "
            "merging an override that COMPOSE_FILE would have suppressed -- "
            "and leaves CL-0020 and CL-0021 blind to any credential an "
            "'env_file:' supplies"
        ),
    )


def _add_check_subparser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
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
        type=_format_type,
        default="text",
        dest="output_format",
        metavar="{" + ",".join(_FORMAT_CHOICES) + "}",
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
        "--strict-config",
        action="store_true",
        default=False,
        help=(
            "treat config diagnostics (unknown/typo'd rule id, unknown key, an "
            "inert reason or severity, a stale exclude_services name) as errors "
            "instead of stderr warnings, so a malformed config fails loudly "
            "rather than silently disabling the wrong rule"
        ),
    )
    check.add_argument(
        "--skip-suppressed",
        action="store_true",
        default=False,
        help="hide suppressed findings from output",
    )
    check.add_argument(
        "--allow-partial-coverage",
        action="store_true",
        default=False,
        help=(
            "grade a file even though part of its stack could not be linted "
            "(unresolved 'include:' or cross-file 'extends:'). Without this, "
            "such a gap is an error (exit 2) so a merge gate cannot pass on a "
            "partial view; with it, the gap is reported on stderr only"
        ),
    )
    _add_document_selection_flags(check)
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
            "print the prose documentation for a single rule and exit, "
            "through a pager on an interactive terminal. "
            "Cannot be combined with FILE arguments."
        ),
    )
    check.add_argument(
        "--no-pager",
        action="store_true",
        default=False,
        help=(
            "print --explain output directly, bypassing the pager it uses "
            "on interactive terminals. PAGER selects the pager (default: "
            "less -RFX); NO_PAGER or TERM=dumb also disables it."
        ),
    )


def _add_fix_subparser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
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
    _add_document_selection_flags(fix)
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
    fix.add_argument(
        "--strict-config",
        action="store_true",
        default=False,
        help=(
            "treat config diagnostics (unknown/typo'd rule id, unknown key, an "
            "inert reason or severity) as errors instead of stderr warnings"
        ),
    )


def _add_init_subparser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
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
            "Compose file, graded the way check grades it: merged with the "
            "'compose.override.yml' beside it and with its env files read, so "
            "the suppressions it writes are the findings check will report. "
            "Every finding becomes a per-service exclude_services entry with a "
            "placeholder reason for you to triage — replace it with a real "
            "justification or delete the entry and fix the issue. Refuses to "
            "overwrite an existing config without --force."
        ),
    )
    init.add_argument(
        "file",
        metavar="FILE",
        help="Docker Compose file to analyze",
    )
    _add_document_selection_flags(init)
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


def _value_options(parser: argparse.ArgumentParser) -> frozenset[str]:
    """Option strings, across every subcommand, that consume the next token.

    Derived from the parsers rather than listed by hand, so adding a
    ``--flag VALUE`` to any subcommand cannot quietly reintroduce the
    misrouting the argv shim guards against.
    """
    options: set[str] = set()
    pending = [parser]
    while pending:
        current = pending.pop()
        for action in current._actions:  # noqa: SLF001 - argparse has no public walk
            if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
                pending.extend(action.choices.values())
            elif action.option_strings and action.nargs != 0:
                options.update(action.option_strings)
    return frozenset(options)


def _first_positional(argv: list[str], value_options: frozenset[str]) -> str | None:
    """The first token that could be a subcommand, or None if there is none.

    ``--`` ends the search: by the documented contract everything after it is
    a path. The value of an option that takes one (``--config PATH``) is
    skipped, so ``--config fix`` reads as a path for ``--config``, not as the
    ``fix`` subcommand. An option with its value attached (``--config=fix``)
    is a single dash-prefixed token and needs no skipping.
    """
    tokens = iter(argv)
    for token in tokens:
        if token == "--":
            return None
        if token in value_options:
            next(tokens, None)
            continue
        if token.startswith("-"):
            continue
        return token
    return None


def _normalize_argv(argv: list[str], value_options: frozenset[str]) -> list[str]:
    """Rewrite ``argv`` so bare invocations route to the ``check`` subcommand.

    Preserves the pre-subcommand CLI: ``compose-lint <file>``,
    ``compose-lint -q``, and ``compose-lint --explain CL-XXXX`` keep working as
    ``check``. An explicit subcommand (``check ...``) is left untouched, as is a
    flag-only invocation of a global flag (``--version``, ``--help``) so the
    top-level parser handles it. The heuristic keys off the first positional
    token, mirroring ADR-011's implementation note, and stops at ``--`` — so
    ``compose-lint -- init`` lints a file named ``init`` rather than routing to
    ``init``, and ``--config fix compose.yml`` is a ``check`` with a config
    named ``fix``. Known limit: an abbreviated long option (``--conf fix``,
    which argparse accepts) is not in ``value_options``, so only the
    spelled-out option protects its value.
    """
    if not argv:
        return ["check"]
    first_positional = _first_positional(argv, value_options)
    if first_positional in _subcommands():
        return argv
    before_end_of_options = argv[: argv.index("--")] if "--" in argv else argv
    if first_positional is None and _GLOBAL_FLAGS.intersection(before_end_of_options):
        return argv
    return ["check", *argv]


def _utf8_stdio() -> None:
    """Make stdout/stderr UTF-8 on Windows, matching every other platform.

    Windows pipes and redirected files inherit the locale code page
    (typically cp1252), which cannot encode the characters this tool
    prints — the ⚠/· verdict marks and the │/─ excerpt gutters — so any
    run with findings died with UnicodeEncodeError instead of a report.
    Interactive consoles are unaffected: modern Python drives them through
    the wide-character API and they are already UTF-8-capable, so this
    only changes what lands in pipes and files — where UTF-8 is what the
    other platforms (and PEP 686's direction) already produce.
    """
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper) and stream.encoding.lower() not in (
            "utf-8",
            "utf8",
        ):
            stream.reconfigure(encoding="utf-8")


def _discard_stdout() -> None:
    """Point stdout at the null device so no further write can fail.

    The interpreter flushes ``sys.stdout`` one last time after ``main``
    returns, outside any handler this module can install. If the earlier write
    failed, that flush raises again and CPython reports the unraisable error
    and exits **120** — overriding whatever code we chose. Replacing the
    underlying file descriptor is what makes the chosen exit code stick.
    """
    with contextlib.suppress(AttributeError, OSError, ValueError):
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, sys.stdout.fileno())
        os.close(null)


def _abort_on_write_failure(exc: OSError) -> NoReturn:
    """Report a failed stdout write as exit 2 (ADR-006).

    A run whose verdict never reached stdout did not complete, which is
    exactly what exit 2 means — "compose-lint itself couldn't run" — and is
    the reason this is not left to the shell convention of dying quietly on
    ``EPIPE``. Exit 1 is worse than either: it means "findings at or above
    the threshold", so ``compose-lint check clean.yml | head`` would report a
    clean file as a failing gate.
    """
    _discard_stdout()
    emit(f"Error: could not write output: {exc.strerror or exc}")
    sys.exit(2)


def _stdout_print(*args: object, **kwargs: Any) -> None:
    """``print`` to stdout, turning a failed write into the documented exit 2.

    Wrapping the writes themselves — rather than catching ``OSError`` around
    the whole run — is what keeps the diagnostic honest: only an error raised
    by writing the report becomes "could not write output". An ``OSError``
    from anywhere else still surfaces as itself.
    """
    try:
        print(*args, **kwargs)
    except OSError as exc:
        _abort_on_write_failure(exc)


# `less` flags mirror git's defaults: -R passes ANSI color through, -F exits
# immediately when the doc fits one screen (short docs never trap the reader
# in a pager), -X skips the alternate screen so the tail stays in scrollback.
_DEFAULT_PAGER = ("less", "-R", "-F", "-X")

# Labels for less's otherwise-bare `:` prompt. The pager's controls are pure
# convention, so the default pager names the ones a reader needs; a user's
# own PAGER keeps whatever prompt they configured. The text must avoid the
# characters less expands in prompt strings (`%`, `?`, `:`, `.`, `\`) —
# rule ids (CL-NNNN) are safe by construction.
_PAGER_HINTS = "Space next · b back · q quit"


def _pager_argv(*, tty: bool, rule_id: str) -> list[str] | None:
    """Resolve the pager command for ``--explain``, or None to print directly.

    Paging is presentation only and engages solely for a human at an
    interactive terminal, so machine consumers (pipes, redirects, CI) always
    receive the byte-identical plain dump (ADR-034). ``NO_PAGER`` (any
    non-empty value) disables it, mirroring ``NO_COLOR``'s contract for
    color; ``TERM`` unset or ``dumb`` means no terminal worth paging on;
    ``PAGER`` overrides the default command, and a blank ``PAGER`` disables
    paging outright.
    """
    if not tty:
        return None
    if os.environ.get("NO_PAGER"):
        return None
    if os.environ.get("TERM", "") in ("", "dumb"):
        return None
    pager = os.environ.get("PAGER")
    if pager is None:
        return [*_DEFAULT_PAGER, f"-Ps{rule_id} · {_PAGER_HINTS}"]
    return shlex.split(pager) or None


def _page_rule_doc(text: str, rule_id: str) -> bool:
    """Try to display rule prose through a pager; True when it displayed.

    A pager that cannot be spawned is a signal to fall back, not an error:
    the published image is distroless, so ``docker run -t`` yields a TTY
    with no pager binary behind it. A pager that exits nonzero is treated
    the same way — busybox's ``less`` rejects flags like ``-Ps`` with a
    usage error, which would otherwise swallow the doc on Alpine. The cost
    of that rescue is bounded: a pager that dies nonzero *after* showing
    content leads to the doc printing twice, never to it printing not at
    all. A viewer quitting before EOF (EPIPE, then ``q`` → exit 0) still
    counts as displayed.
    """
    argv = _pager_argv(tty=sys.stdout.isatty(), rule_id=rule_id)
    if argv is None:
        return False
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE)
    except OSError:
        return False
    stdin = proc.stdin
    if stdin is not None:
        with contextlib.suppress(BrokenPipeError, OSError):
            stdin.write((text + "\n").encode("utf-8"))
            stdin.close()
    return proc.wait() == 0


def _dispatch(args: argparse.Namespace) -> NoReturn:
    """Route to the subcommand handler; every branch exits."""
    if args.command == "fix":
        _run_fix(args)
    if args.command == "init":
        _run_init(args)
    _run_check(args)


def main(argv: list[str] | None = None) -> NoReturn:
    """Main entry point for the CLI."""
    _utf8_stdio()
    if sys.stdout is None:
        # Started with file descriptor 1 already closed (`compose-lint … >&-`).
        # CPython leaves `sys.stdout` as None rather than a stream that fails
        # on write, so this never reaches the handlers below — it surfaces as
        # an AttributeError from whichever formatter touches stdout first.
        emit("Error: could not write output: stdout is closed")
        sys.exit(2)
    raw = sys.argv[1:] if argv is None else argv
    try:
        parser = _build_parser()
        args = parser.parse_args(_normalize_argv(raw, _value_options(parser)))
        _dispatch(args)
    except BrokenPipeError as exc:
        # Raised by a `print` when the reader closed early (`| head`).
        _abort_on_write_failure(exc)
    except SystemExit:
        # Buffered stdout is not written until it is flushed, so a write
        # failure surfaces here rather than at the `print` that caused it.
        # Flush while the exit is in flight so the error can still be turned
        # into the documented code instead of escaping as an exit 120.
        try:
            sys.stdout.flush()
        except OSError as exc:
            _abort_on_write_failure(exc)
        raise


# The remedy sentence appended to every coverage gap, per command. ``check``
# can accept the gap with a flag; ``fix`` has no such flag — it never fails on
# a gap, so there is nothing to accept — and telling it to pass one sent users
# to an argument the subcommand rejects (#779). What ``fix`` needs to hear is
# that the unseen part was not fixed either.
_CHECK_GAP_REMEDY = (
    "Lint the merged output (docker compose config) to cover the gap, or pass "
    "--allow-partial-coverage to accept it."
)
# Once the flag is passed the gap is accepted, and repeating the offer told
# users to do what they had just done. The merged-output route still applies:
# accepting a gap is not the same as closing it.
_CHECK_GAP_ACCEPTED_REMEDY = (
    "Lint the merged output (docker compose config) to cover the gap."
)
_FIX_GAP_REMEDY = (
    "What was not seen was not fixed. Lint the merged output "
    "(docker compose config) to cover the gap."
)
_INIT_GAP_REMEDY = (
    "What was not seen got no suppression, and check will refuse the same gap. "
    "Lint the merged output (docker compose config) to cover it."
)


def _report_coverage_gaps(
    filepath: str, gaps: tuple[str, ...], *, fatal: bool, remedy: str
) -> list[Diagnostic]:
    """Report parts of ``filepath`` that were not linted; return each as a diagnostic.

    A coverage gap used to be a stderr warning, which is the one channel no
    machine consumer reads: the verdict, the exit code, JSON ``errors`` and
    SARIF ``executionSuccessful`` all still said clean while a service carrying
    ``privileged: true`` sat unparsed in an included file. For a tool whose
    shipped deployment model is a merge gate, "I could not see all of it" has
    to reach the same channels as "I found something".

    Every gap is returned, tagged ``coverage_gap``, whether or not it is
    fatal; the caller decides the channel. Fatal ones join the error channel,
    so they surface as JSON ``errors[]`` and SARIF ``toolExecutionNotifications``
    and force exit 2. With ``--allow-partial-coverage`` the gap is stated on
    stderr, the run is graded on what could be seen, and the gap still
    reaches the machine output — JSON ``warnings[]``, a ``level: warning``
    notification — because a waived gap that leaves no trace is
    indistinguishable from full coverage to anything that reads the artifact
    (ADR-015). It is also the channel the compatibility policy names for
    announcing a new gap condition one release before it is enforced.

    ``remedy`` is the caller's closing sentence, so the advice names only
    what that command can actually do.

    ``gaps`` comes from the parser rather than from the document, because
    since ADR-036 the document cannot answer the question: whether an
    ``include:`` or ``extends: {file: ...}`` is a gap depends on where its path
    resolved and whether the target was readable, and only the pass that tried
    to follow it knows.
    """
    messages = [f"{gap} {remedy}" for gap in gaps]
    if not messages:
        return []
    label = "Error" if fatal else "Warning"
    for message in messages:
        emit(f"{label}: {filepath}: {message}")
    return [
        Diagnostic(filepath, message, DiagnosticKind.COVERAGE_GAP)
        for message in messages
    ]


def _exit_2_with_envelope(args: argparse.Namespace, message: str) -> NoReturn:
    """Report a pre-scan failure on the machine channel too, then exit 2.

    These two branches exit before any formatter runs, so `--format json`
    produced **zero bytes** on stdout for them while every other exit-2 shape
    — a missing file, a parse error, a directory argument — produced a full
    envelope. A `jq` pipeline therefore broke or not depending on which kind
    of exit 2 it hit, and both of these are the commonest CI
    misconfigurations: the wrong working directory, and a typo'd `--config`.
    Run-level metadata a consumer can read is what the envelope exists for
    (ADR-015).
    """
    emit(f"Error: {message}")
    # `fix` has no --format, so its namespace has no output_format: it reports
    # on stderr only, and its exit 2 must come from here and not from an
    # AttributeError one line later, which exited 1 with a traceback on every
    # pre-scan failure of `fix` from 0.25.0 to 0.29.0.
    output_format = getattr(args, "output_format", "text")
    # Run-level: there is no file to name, and `""` is the documented way of
    # saying so (ADR-015). SARIF omits `locations` for it rather than turning
    # the empty path into the working directory.
    failure = [Diagnostic("", message, DiagnosticKind.RUN)]
    if output_format == "json":
        _stdout_print(json.dumps(build_json_log([], failure), indent=2))
    elif output_format == "sarif":
        _stdout_print(json.dumps(build_sarif_log([], failure), indent=2))
    sys.exit(2)


def _run_check(args: argparse.Namespace) -> NoReturn:
    """Run the `check` operation: lint files and exit with the verdict code."""
    if args.explain is not None:
        if args.files:
            emit("Error: --explain cannot be combined with FILE arguments")
            sys.exit(2)
        # --explain emits human-readable rule prose to stdout (the requested
        # artifact of this mode). There is no JSON/SARIF form, so reject those
        # rather than silently printing markdown when one is requested.
        if args.output_format != "text":
            emit(
                "Error: --explain has no JSON or SARIF form; "
                "use the default text output"
            )
            sys.exit(2)
        try:
            canonical = normalize_rule_id(args.explain)
            doc = load_rule_doc(canonical)
        except UnknownRuleError as exc:
            if exc.kind == "malformed":
                emit(
                    f"Error: unknown rule id '{args.explain}' "
                    "(expected format: CL-XXXX)"
                )
            elif exc.kind == "retired":
                emit(f"Error: rule {exc.rule_id} was retired and is not reused")
            else:
                emit(f"Error: unknown rule id '{exc.rule_id}'")
            sys.exit(2)
        if args.no_pager or not _page_rule_doc(doc, canonical):
            _stdout_print(doc)
        sys.exit(0)

    config_path = _effective_config_path(args.config)

    try:
        disabled_rules, severity_overrides, excluded_services = load_config(
            args.config, strict=args.strict_config
        )
    except ConfigError as e:
        _exit_2_with_envelope(args, str(e))

    selection = _plan(args)
    if not selection.groups:
        _exit_2_with_envelope(
            args,
            "no Compose files found. Searched for: "
            "compose.yml, compose.yaml, "
            "docker-compose.yml, docker-compose.yaml",
        )
    args.files = [group.primary for group in selection.groups]
    overlay_of = {
        group.primary: list(group.overlays)
        for group in selection.groups
        if group.overlays
    }
    merge_reason = {
        group.primary: group.selected_by_env
        for group in selection.groups
        if group.overlays
    }

    # Print branded header in text mode before scanning begins. flush=True here
    # (and on the per-file text prints below) keeps block-buffered stdout from
    # landing after unbuffered stderr when both are captured together (2>&1).
    if args.output_format == "text":
        _stdout_print(
            format_header(
                args.files,
                str(config_path) if config_path else None,
                args.fail_on,
                __version__,
                merged=overlay_of,
                env_files=selection.env_files,
            ),
            flush=True,
        )

    all_json: list[dict[str, object]] = []
    all_sarif: list[dict[str, object]] = []
    all_file_findings: list[tuple[list[Finding], str]] = []
    parse_errors: list[Diagnostic] = []
    coverage_errors: list[Diagnostic] = []
    coverage_warnings: list[Diagnostic] = []
    rule_errors: list[Diagnostic] = []
    has_errors = False
    seen_services: set[str] = set()

    for filepath in args.files:
        overlays = overlay_of.get(filepath)
        merged: Merged | None = None
        try:
            if overlays:
                merged = load_merged([filepath, *overlays], use_env=not args.no_env)
                data, lines, gaps = merged.data, merged.lines, merged.gaps
                # Not a coverage gap — coverage was achieved, not missed — so
                # this warns without touching the exit code. What it must never
                # do is stay silent: the findings below describe a document that
                # is not the file named in the report.
                why = _why_merged(
                    overlays, selected_by_env=bool(merge_reason.get(filepath))
                )
                emit(
                    f"warning: {filepath}: merged {', '.join(overlays)} before "
                    f"linting, {why}. Findings describe the combined "
                    "configuration."
                )
            else:
                loaded = load_compose_full(filepath, use_env=not args.no_env)
                data, lines, gaps = loaded.data, loaded.lines, loaded.gaps
        except ComposeNotApplicableError as e:
            # v1 / fragment file: not malformed, just outside what we lint.
            # Per ADR-013 this is exit 0 (skipped, not a parse error). Must
            # precede the ComposeError clause below — it is a subclass.
            emit(f"{filepath}: {e}")
            continue
        except (FileNotFoundError, ComposeError) as e:
            error_path = e.path if isinstance(e, ComposeFileError) else filepath
            parse_errors.append(
                Diagnostic(
                    error_path, _report_parse_error(filepath, e), DiagnosticKind.PARSE
                )
            )
            continue

        gap_is_fatal = not args.allow_partial_coverage
        # A waived gap is still reported, on the non-fatal channel.
        gap_channel = coverage_errors if gap_is_fatal else coverage_warnings
        gap_channel.extend(
            _report_coverage_gaps(
                filepath,
                gaps,
                fatal=gap_is_fatal,
                remedy=_CHECK_GAP_REMEDY
                if gap_is_fatal
                else _CHECK_GAP_ACCEPTED_REMEDY,
            )
        )
        for note in unresolved_mount_sources(data):
            emit(f"note: {filepath}: {note}")
        # `--no-env` covers both env files beside the document, per ADR-027 §8:
        # the flag's promise is that it reproduces the previous release, and
        # after this change that release read `env_file:` targets too.
        service_env_files = (
            {}
            if args.no_env
            else resolve_env_files(data, Path(filepath).absolute().parent)
        )
        for note in describe_unread(service_env_files):
            emit(f"note: {filepath}: {note}")
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
            rule_errors.append(Diagnostic(_filepath, msg, DiagnosticKind.RULE_CRASH))
            emit(f"Error: {_filepath}: {msg}")

        findings = run_rules(
            data,
            lines,
            disabled_rules=disabled_rules,
            severity_overrides=severity_overrides,
            excluded_services=excluded_services,
            on_error=_record_rule_error,
            env_files=service_env_files,
            config_path=_config_name(args.config, config_path),
        )
        # Also on the single-file path: a resolved cross-file `extends:` puts
        # lines from another document into this one's map, so a finding can be
        # written in a file the report is not headed by even with no overlay.
        findings = _attribute_sources(findings, filepath)

        if args.skip_suppressed:
            findings = [f for f in findings if not f.suppressed]

        if args.output_format == "text":
            output = format_text(
                findings, filepath, verbose=args.verbose, quiet=args.quiet
            )
            if output:
                _stdout_print(output, flush=True)
            _stdout_print(format_summary(findings, filepath), flush=True)
            all_file_findings.append((findings, filepath))
        elif args.output_format == "sarif":
            # Structured SARIF fixes (ADR-014, promoted in 0.11.0): every
            # auto-fixable finding carries its machine-applicable edit so GitHub
            # Code Scanning can render a suggested change. Findings with no safe
            # fixer keep the prose `properties.fix` only.
            try:
                text = Path(filepath).read_text(encoding="utf-8")
            except OSError as e:
                # Parsed above, but unreadable before this second read (deleted,
                # unmounted, permission change). Record it and move on so one bad
                # file can't abort the rest of the batch.
                parse_errors.append(Diagnostic(filepath, str(e), DiagnosticKind.PARSE))
                emit(f"Error: {filepath}: {e}")
                continue
            try:
                # Suggested changes are computed against one file's text using
                # the merged line map, so on a merged run they would splice at a
                # line belonging to the other document. `fix` refuses the same
                # case; SARIF must not offer through a different door what the
                # fixer declines to do.
                fixes = (
                    []
                    if merged is not None
                    else collect_edits(findings, data, lines, text).fixed_edits
                )
            except LineOutOfRangeError as e:
                # A fixer addressed a line this file does not have. Report the
                # file and keep going: SARIF is serialized once for the whole
                # batch, so letting this escape would destroy every *other*
                # file's findings too (VULN-017 consequence c).
                # A fixer is part of its rule, so this is a rule crash, not a
                # parse failure: the document parsed, the rule's code did not
                # hold up. It stays in `parse_errors` only for the text
                # verdict's count; the machine channels see the kind.
                msg = f"could not compute fixes: {e}"
                parse_errors.append(
                    Diagnostic(filepath, msg, DiagnosticKind.RULE_CRASH)
                )
                emit(f"Error: {filepath}: {msg}")
                continue
            all_sarif.extend(format_sarif(findings, filepath, fixes=fixes))
        else:
            all_json.extend(format_json(findings, filepath))

        failing = filter_findings(findings, args.fail_on)
        if failing:
            has_errors = True

    config_errors: list[Diagnostic] = []
    try:
        warn_unknown_excluded_services(
            excluded_services, seen_services, strict=args.strict_config
        )
    except ConfigError as e:
        # Raised after the scan, so `_exit_2_with_envelope` is the wrong
        # shape: the findings are already collected, and a JSON or SARIF
        # consumer should get them beside the error rather than an envelope
        # with nothing else in it. It rides the run-error channel instead
        # (ADR-015), which is also what makes the exit 2 below.
        emit(f"Error: {e}")
        config_errors.append(Diagnostic("", str(e), DiagnosticKind.RUN))

    # Coverage gaps ride the same structured channel as parse errors — JSON
    # `errors[]`, SARIF `toolExecutionNotifications`, exit 2 — but are counted
    # separately in the text verdict, because "could not be parsed" is not what
    # happened and the tool must not report a state that is not true.
    #
    # A crashed rule rides it too. It already sets exit 2 (below) and prints to
    # stderr, but it was absent from both machine channels: JSON reported
    # `errors: []` and SARIF reported `executionSuccessful: true` while that
    # rule's findings were silently missing from a document a gate uploads.
    # For Code Scanning that is worse than an omission — a declared rule with
    # zero results reads as "every alert for this rule is fixed", so a crash
    # closed the alerts instead of reporting itself. ADR-015 exists so a run
    # that could not complete says so in the machine output, not only on a
    # channel a gate does not read.
    run_errors = parse_errors + coverage_errors + rule_errors + config_errors
    truncation: Diagnostic | None = None

    if args.output_format == "text":
        if len(args.files) > 1:
            _stdout_print()
            _stdout_print(
                format_aggregate_summary(
                    all_file_findings, len(parse_errors), len(coverage_errors)
                )
            )
        _stdout_print(
            format_verdict(
                all_file_findings,
                args.fail_on,
                len(parse_errors),
                len(coverage_errors),
            )
        )
    elif args.output_format == "json":
        # allow_nan=False makes a stray float NaN/Infinity raise rather than emit
        # bare `NaN`/`Infinity` tokens, which RFC 8259 forbids and strict parsers
        # reject. The formatter already coerces `service` to str, so this guards
        # any future numeric field; the same applies to the SARIF dump below.
        json_log = build_json_log(all_json, run_errors, coverage_warnings)
        _stdout_print(json.dumps(json_log, indent=2, allow_nan=False))
    elif args.output_format == "sarif":
        # The document reports its own truncation (one notification, owned by
        # the formatter that truncates); this side only says so on stderr and
        # exits 2, because a gate must not read "success" from an artifact
        # that is knowingly incomplete. It used to be recorded twice.
        truncation = truncation_notice(len(all_sarif))
        if truncation is not None:
            emit(f"Error: {truncation.message}")
        sarif_log = build_sarif_log(
            all_sarif,
            run_errors,
            severity_overrides=severity_overrides,
            warnings=coverage_warnings,
        )
        _stdout_print(json.dumps(sarif_log, indent=2, allow_nan=False))

    # A failing run with no config loaded is the shape of a config that was
    # never found. This is the moment the user asks "why is this failing?",
    # so it is the moment naming the working directory is worth a line.
    if has_errors and config_path is None:
        _note_no_config_in_effect()

    # Parse errors, coverage gaps, crashed rules, a strict config error, or a
    # truncated SARIF document.
    if run_errors or truncation is not None:
        sys.exit(2)
    sys.exit(1 if has_errors else 0)


def _refuses_write(path: Path) -> bool:
    """Whether ``path`` exists and is marked read-only.

    A 0444 file is an explicit "do not modify" signal, and `os.replace` would
    still swap it out through the writable parent directory — so the mode has
    to be checked, not relied on. `fix --apply` did; `init --force` did not,
    and the file it overwrites is the policy governing which security rules are
    suppressed.
    """
    return path.exists() and not os.access(path, os.W_OK)


class UnwritableTargetError(OSError):
    """Raised when a write target exists but is not a regular file."""


class LinkedPathError(OSError):
    """Raised when a fix target is a symlink or a multiply-linked file."""


def _write_failure(exc: OSError) -> str:
    """Describe a write failure without echoing the internal temp path.

    An unhandled ``OSError`` renders as ``[Errno 13] Permission denied:
    '/abs/path/.compose.yml.k6ydh20a.tmp'`` — an errno decoration and a scratch
    filename the caller never chose. The caller already names the file it was
    asked to write, so only the condition belongs here.
    """
    return exc.strerror or str(exc)


def _atomic_write(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` atomically, preserving its mode.

    A fix must never leave a half-written Compose file: an interrupted in-place
    write (crash, full disk) would corrupt a file ``docker compose`` then
    refuses to start. Write to a temp file in the same directory, flush it to
    disk, and ``os.replace`` it into place — a reader sees either the old file or
    the complete new one, never a truncated mix. The original file's permission
    bits carry over so the fix neither relaxes nor tightens them. ``newline=""``
    writes the computed text verbatim, with no newline translation.

    Raises :class:`LinkedPathError` when the target is a symlink or has more
    than one name. ``os.replace`` swaps the *entry*, not the inode behind it, so
    on a symlink it drops a regular file over the link and leaves the file the
    stack actually deploys untouched — while the run reports the fix applied.
    On a hard link it breaks the link, so the two names silently diverge. In
    both cases the honest answer is that this write cannot do what the caller
    asked, which is a refusal, not a success (ADR-014: refuse, never guess).
    """
    try:
        info: os.stat_result | None = path.lstat()
    except FileNotFoundError:
        info = None  # a new file (`init`): nothing to link past or preserve
    if info is not None and stat.S_ISLNK(info.st_mode):
        raise LinkedPathError(
            "is a symbolic link; writing here would replace the link and leave "
            "its target — the file that is actually deployed — unchanged; "
            "point the fix at the target instead"
        )
    if info is not None and not stat.S_ISREG(info.st_mode):
        # A directory has st_nlink >= 2, so without this it would be reported
        # as a hard link, which is not what is wrong with it.
        raise UnwritableTargetError("not a regular file; refusing to write over it")
    if info is not None and info.st_nlink > 1:
        raise LinkedPathError(
            f"has {info.st_nlink} hard links; replacing it would break the link "
            "and leave the other names on the old content"
        )

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
        # setuid/setgid/sticky are deliberately dropped: a Compose file has no
        # business carrying them, and re-applying them to a file this process
        # just created would hand those bits to a new inode.
        if info is not None:
            with contextlib.suppress(OSError):
                os.chmod(tmp_path, stat.S_IMODE(info.st_mode) & 0o777)
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _merged_reparser(
    filepath: str, overlays: list[str] | None, *, use_env: bool = True
) -> Callable[[str], tuple[dict[str, Any], dict[str, int]]] | None:
    """Re-parse hook that merges a candidate patch with its overlay.

    ``verify_apply`` checks properties of the document Compose runs. On a merged
    run that is the patched base *plus* the overlay, so the candidate has to be
    re-merged before the engine sees it. Returns None when nothing is merged,
    which leaves the default single-file re-parse in place.
    """
    if not overlays:
        return None

    def reparse(candidate: str) -> tuple[dict[str, Any], dict[str, int]]:
        return merge_patched(candidate, filepath, overlays, use_env=use_env)

    return reparse


def _validated_only(raw: list[str] | None, *, strict: bool) -> set[str] | None:
    """Normalize ``--only`` ids and say so when one names no rule.

    ``--only`` took any string. ``--only cl-0014`` — the right id, lower-cased
    — matched nothing, printed "nothing to fix" and exited 0, which is
    indistinguishable from a clean repo; so did ``CL-9999`` and ``banana``. A
    CI remediation step pinned to a typo therefore goes green forever, which
    is the failure a gate must not have.

    Case is normalized because ``--explain`` already does it, and answering
    the same input two different ways on one CLI is the inconsistency that
    gets frozen at 1.0. An id that matches no rule is a diagnostic rather
    than a hard error, matching how an unknown rule id in the config file is
    treated — and ``--strict-config`` promotes it the same way.
    """
    if not raw:
        return None
    known = {cls().metadata.id for cls in get_registered_rules()}
    resolved: set[str] = set()
    for value in raw:
        candidate = value.strip().upper()
        if candidate in known:
            resolved.add(candidate)
            continue
        message = (
            f"--only {value!r} names no rule, so it selects nothing "
            "(check for a typo or a retired rule)"
        )
        if strict:
            emit(f"Error: {message}")
            sys.exit(2)
        emit(f"Warning: {message}")
    return resolved


def _run_fix(args: argparse.Namespace) -> NoReturn:
    """Run the `fix` operation (ADR-014).

    Dry-run by default: a unified diff of proposed edits goes to stdout and
    status goes to stderr; nothing is written. ``--apply`` writes edits in
    place. Suppressed/excluded findings (``.compose-lint.yml``) are never fixed.
    Exit 0 on success, 2 on usage/parse error — findings are the input, not the
    failure signal, so residual manual-only findings do not change the code.
    """
    try:
        disabled_rules, severity_overrides, excluded_services = load_config(
            args.config, strict=args.strict_config
        )
    except ConfigError as e:
        _exit_2_with_envelope(args, str(e))

    selection = _plan(args)
    if not selection.groups:
        _exit_2_with_envelope(
            args,
            "no Compose files found. Searched for: "
            "compose.yml, compose.yaml, "
            "docker-compose.yml, docker-compose.yaml",
        )
    args.files = [group.primary for group in selection.groups]
    fix_overlay_of = {
        group.primary: list(group.overlays)
        for group in selection.groups
        if group.overlays
    }

    only = _validated_only(args.only, strict=args.strict_config)
    # The suppression reason names the file actually read, which with no
    # --config may be a discovered .compose-lint.yaml rather than the .yml
    # the engine defaults to.
    fix_config_name = _config_name(args.config, _effective_config_path(args.config))
    had_error = False
    # Whether any file had a fix applied or offered — see the note below.
    touched = False

    for filepath in args.files:
        overlays = fix_overlay_of.get(filepath)
        try:
            if overlays:
                merged = load_merged([filepath, *overlays], use_env=not args.no_env)
                data, lines, gaps = merged.data, merged.lines, merged.gaps
                resets = merged.resets
                emit(
                    f"note: {filepath}: merged {', '.join(overlays)} before "
                    "linting. Only findings written in this file can be fixed here."
                )
            else:
                loaded = load_compose_full(filepath, use_env=not args.no_env)
                data, lines, gaps = loaded.data, loaded.lines, loaded.gaps
                # A `!reset` needs no second document to matter: it deletes the
                # key from this file's own parsed data, and the key is still
                # written here for a fixer's insertion to collide with.
                resets = loaded.resets
        except ComposeNotApplicableError as e:
            # v1 / fragment file: skipped, not an error (ADR-013). Must precede
            # the ComposeError clause below — it is a subclass.
            emit(f"{filepath}: {e}")
            continue
        except (FileNotFoundError, ComposeError) as e:
            _report_parse_error(filepath, e)
            had_error = True
            continue

        _report_coverage_gaps(filepath, gaps, fatal=False, remedy=_FIX_GAP_REMEDY)

        try:
            # newline="" preserves the file's original line endings: read_text's
            # universal-newline translation would turn a CRLF file into LF and
            # _atomic_write would then persist the LF verbatim, so `fix --apply`
            # would rewrite every line's ending though the diff showed only one.
            with Path(filepath).open(encoding="utf-8", newline="") as fh:
                text = fh.read()
        except OSError as e:
            # Parsed above, but unreadable now (deleted, unmounted, permission
            # change) — record and continue so the rest of the batch still runs.
            emit(f"Error: {filepath}: {e}")
            had_error = True
            continue
        findings = run_rules(
            data,
            lines,
            disabled_rules=disabled_rules,
            severity_overrides=severity_overrides,
            excluded_services=excluded_services,
            config_path=fix_config_name,
        )

        # A finding's line knows which document it came from. Only the ones
        # written in *this* file can be edited here: its line is a line in this
        # text, and its fix lands where the user would put it by hand. A finding
        # from the overlay is left to manual review — writing it into the base
        # would put the key in a file the overlay overrides anyway.
        def _is_local(f: Finding, _path: str = filepath) -> bool:
            origin = getattr(f.line, "source", None)
            return origin is None or Path(origin).absolute() == Path(_path).absolute()

        fixable_findings = [f for f in findings if _is_local(f)]
        deferred = [f for f in findings if not _is_local(f)]
        if deferred:
            # Named from the findings themselves, not from `overlays`: since
            # ADR-036 a finding can come from a document this file `extends:`
            # rather than from an overlay merged beside it, and the overlay
            # list is empty in that case — which printed the sentence with a
            # blank where the file should be.
            origins = sorted({str(getattr(f.line, "source", "")) for f in deferred})
            emit(
                f"{filepath}: {len(deferred)} finding(s) come from "
                f"{', '.join(origins)} and need manual review there"
            )
        try:
            result = collect_edits(
                fixable_findings, data, lines, text, only=only, resets=resets
            )
        except LineOutOfRangeError as e:
            # Same fail-closed treatment as the check path: refuse this file,
            # write nothing, let the rest of the batch run (VULN-017).
            emit(f"Error: {filepath}: could not compute fixes: {e}")
            had_error = True
            continue

        # Emitted before the edits are weighed so the reason survives every
        # path below: a refusal a count cannot explain is the one the user has
        # to be told about, whether or not anything else in the file was fixed.
        for note in result.notes:
            emit(f"{filepath}: {note}")

        if not result.edits:
            if result.manual:
                emit(
                    f"{filepath}: nothing to auto-fix; "
                    f"{len(result.manual)} finding(s) need manual review"
                )
            else:
                emit(f"{filepath}: nothing to fix")
            continue

        try:
            patched = apply_edits(text, result.edits)
        except LineOutOfRangeError as e:
            emit(f"Error: {filepath}: could not apply fixes: {e}")
            had_error = True
            continue

        # Safety net (ADR-014): re-parse the candidate before persisting it. If
        # the combined edits do not produce valid Compose, that is a fixer bug,
        # not user error — refuse the whole apply, write nothing, and surface the
        # diff plus the parse error so it is diagnosable (issue #261).
        guard_error = reparse_or_error(patched, Path(filepath).absolute().parent)
        if guard_error is not None:
            emit_block(render_file_diff(filepath, text, patched, result.caveats))
            emit(
                f"Error: {filepath}: computed fix does not parse as Compose "
                f"({guard_error}); no changes written"
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
            base_dir=Path(filepath).absolute().parent,
            only=only,
            disabled_rules=disabled_rules,
            severity_overrides=severity_overrides,
            excluded_services=excluded_services,
            # The properties being verified — structure preserved, converges,
            # no new finding — are properties of the document Compose runs, so
            # the candidate is re-merged with the overlay before they are
            # checked. Verifying the patched base alone would compare a
            # single-file result against a merged one.
            reparse=_merged_reparser(filepath, overlays, use_env=not args.no_env),
            # Unconditional, like the edit pass above: since ADR-036 a document
            # merges others through `include:` and cross-file `extends:` with no
            # overlay at all, and `_is_local` answers from the finding's own
            # source file rather than from how the document was assembled.
            fixable=_is_local,
            resets=resets,
        )
        if verify_error is not None:
            emit_block(render_file_diff(filepath, text, patched, result.caveats))
            emit(f"Error: {filepath}: {verify_error}; no changes written")
            had_error = True
            continue

        if args.apply:
            if _refuses_write(Path(filepath)):
                # Exit 2, matching the three sibling write refusals — a symlink
                # target, a hard link, and an unwritable directory all report
                # the same way, and `init --force` on this same predicate does
                # too. Reporting exit 0 here meant the documented Docker recipe
                # (`docker run -v "$(pwd):/src" ... fix --apply`, where the
                # image runs as UID 65532) wrote nothing and told a gate it had
                # succeeded.
                emit(
                    f"Error: {filepath}: file is not writable; no changes "
                    "written (make it writable to allow `fix --apply` to "
                    "modify it)"
                )
                had_error = True
                continue
            try:
                _atomic_write(Path(filepath), patched)
            except OSError as e:
                # Any write failure — a link refusal, a full disk, a read-only
                # mount, a directory that vanished — belongs to this file, not
                # to the run. Unwrapped it reached the CLI as a traceback: exit
                # 1 where the contract says 2, every later file in the batch
                # never examined, and the absolute path printed into the log.
                emit(f"Error: {filepath}: {_write_failure(e)}; no changes written")
                had_error = True
                continue
            # The behavior-changing caveats must surface here too, not only on
            # the dry run — nothing forces a dry run first, so a one-shot
            # `fix --apply` would otherwise mutate files silently (issue #428).
            emit_block(render_caveat_banner(result.caveats))
            emit(
                f"{filepath}: applied {len(result.edits)} fix(es) across "
                f"{len(result.fixed)} finding(s)"
            )
            touched = True
        else:
            _stdout_print(
                render_file_diff(filepath, text, patched, result.caveats),
                end="",
                flush=True,
            )
            emit(
                f"{filepath}: {len(result.edits)} fix(es) available; "
                f"{len(result.manual)} finding(s) need manual review"
            )
            touched = touched or bool(result.edits)

    # `fix` honours suppressions — a suppressed finding is never touched — so a
    # config that went missing here does not just change a report, it changes
    # which of the user's files get written. Say so whenever there was
    # something to fix, applied or merely offered.
    if touched and _effective_config_path(args.config) is None:
        _note_no_config_in_effect()

    sys.exit(2 if had_error else 0)


def _run_init(args: argparse.Namespace) -> NoReturn:
    """Run the `init` operation (ADR-011).

    Lint a single Compose file with no existing config (raw findings) and write
    a starter ``.compose-lint.yml`` whose entries the user triages. Refuses to
    clobber an existing config without ``--force``. Status goes to stderr; the
    artifact lands on disk. Exit 0 on a successful write (or when there is
    nothing to suppress), 2 on usage/parse error or overwrite-without-force —
    findings are the input here, not the failure signal.

    The file is planned and loaded the way ``check`` plans and loads it: the
    sibling override is merged (ADR-025), the ``.env`` may select the
    documents (ADR-026), and ``env_file:`` targets are read (ADR-027). A
    baseline that graded the raw file left ``check`` red on the first stack
    with an override, which is the opposite of what a baseline is for.
    """
    # A named file is never dropped (ADR-026 §4), so the plan has exactly one
    # group; its primary may differ from FILE when COMPOSE_FILE orders the
    # project differently, in which case the note above says so.
    (group,) = _plan(args, [args.file]).groups
    use_env = not args.no_env
    try:
        if group.overlays:
            merged = load_merged(list(group.paths), use_env=use_env)
            data, lines, gaps = merged.data, merged.lines, merged.gaps
            overlays = list(group.overlays)
            why = _why_merged(overlays, selected_by_env=group.selected_by_env)
            emit(
                f"note: {group.primary}: merged {', '.join(overlays)} before "
                f"linting, {why}. Suppressions describe the combined configuration."
            )
        else:
            loaded = load_compose_full(group.primary, use_env=use_env)
            data, lines, gaps = loaded.data, loaded.lines, loaded.gaps
    except ComposeNotApplicableError as e:
        # v1 / fragment file: skipped, not an error (ADR-013). Nothing to lint,
        # so nothing to bootstrap. Must precede the ComposeError clause below —
        # it is a subclass.
        emit(f"{args.file}: {e}")
        sys.exit(0)
    except (FileNotFoundError, ComposeError) as e:
        _report_parse_error(args.file, e)
        sys.exit(2)

    # Not the gate (that is `check`), so a gap is reported and not fatal, as
    # `fix` does — but it is said, because a suppression cannot be written for
    # a finding that was never seen.
    _report_coverage_gaps(group.primary, gaps, fatal=False, remedy=_INIT_GAP_REMEDY)
    service_env_files = (
        resolve_env_files(data, Path(group.primary).absolute().parent)
        if use_env
        else {}
    )
    for note in describe_unread(service_env_files):
        emit(f"note: {group.primary}: {note}")

    findings = run_rules(data, lines, env_files=service_env_files)
    if not findings:
        emit(
            f"{args.file}: no findings; nothing to suppress, not writing {args.output}"
        )
        sys.exit(0)

    out_path = Path(args.output)
    # Refuse only when we would actually write: a parse error or a clean file
    # above already exited, so reaching here means there is a config to land.
    # Protect deliberate human suppression decisions from a silent clobber.
    if out_path.exists() and not args.force:
        emit(f"Error: {out_path} already exists; pass --force to overwrite")
        sys.exit(2)

    if _refuses_write(out_path):
        # --force overrides the "already exists" refusal above; it does not
        # override the file's own mode. `fix --apply` has always honoured this
        # and the init path did not, so the one file whose contents decide
        # which rules are suppressed was the one without the guard.
        emit(
            f"Error: {out_path} is not writable; "
            "make it writable to allow `init --force` to replace it"
        )
        sys.exit(2)

    existed = out_path.exists()
    try:
        _atomic_write(out_path, render_config(findings))
    except OSError as e:
        emit(f"Error: {out_path}: {_write_failure(e)}")
        sys.exit(2)
    if not existed:
        # _atomic_write carries over an existing file's mode but a fresh file
        # inherits mkstemp's restrictive 0600. A config meant to be committed and
        # read in CI wants the usual 0644; best-effort, never fatal.
        with contextlib.suppress(OSError):
            out_path.chmod(0o644)

    rule_count = len({f.rule_id for f in findings})
    pair_count = len({(f.rule_id, f.service) for f in findings})
    emit(
        f"wrote {out_path} with {pair_count} suppression(s) across {rule_count} rule(s)"
    )
    sys.exit(0)
