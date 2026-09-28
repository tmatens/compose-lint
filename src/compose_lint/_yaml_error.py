"""PyYAML error text that says what is wrong and where, and quotes nothing."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import yaml

__all__ = ["describe_yaml_error"]


def describe_yaml_error(exc: yaml.YAMLError) -> str:
    """PyYAML's diagnosis, without the source line it quotes.

    ``MarkedYAMLError.__str__`` renders a snippet of the document under a
    caret. That is genuinely the most useful part of the message for a human
    fixing their own file, and it is also a verbatim line of a file the run
    read — which reaches ``errors[].message`` in JSON, the SARIF
    ``toolExecutionNotifications`` uploaded to Code Scanning, and the job log.
    Two shapes make that a disclosure rather than a nicety: a syntax error on a
    line carrying a credential reproduces the credential, and an ``env_file:``
    or ``COMPOSE_FILE`` naming a file the document chose makes it a line of
    *that* file. The policy loader uses it too: a ``.compose-lint.yml`` is
    committed with the change under review, so a line of it is no safer to
    quote than a line of the Compose file.

    So the diagnosis and the position are kept — they say what is wrong and
    exactly where — and only the quoted bytes are dropped. The user still has
    the file open in front of them; a reader of the report does not.
    """
    problem = getattr(exc, "problem", None)
    if problem is None:
        return str(exc)
    context = getattr(exc, "context", None)
    parts = [context, problem] if context else [problem]
    mark = getattr(exc, "problem_mark", None)
    if mark is not None:
        # Marks are 0-indexed; every other line number compose-lint prints is 1-indexed.
        parts.append(f"at line {mark.line + 1}, column {mark.column + 1}")
    return ", ".join(parts)
