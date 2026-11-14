"""PyYAML error text that says what is wrong and where, and quotes nothing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["describe_yaml_error", "guard_scalar_constructors"]

# The scalar types whose PyYAML constructor converts text with a bare Python
# call (`int()`, `float()`, a dict lookup, `datetime.date()`), and what those
# calls raise for text the type cannot hold.
_GUARDED_TYPES = ("bool", "int", "float", "timestamp")
_CONVERSION_ERRORS = (
    ValueError,
    KeyError,
    AttributeError,
    IndexError,
    OverflowError,
)


def guard_scalar_constructors(loader_cls: type[yaml.SafeLoader]) -> None:
    """Make ``loader_cls`` report an unconvertible scalar as a YAML error.

    PyYAML checks a value against its type only when the type was resolved
    from the value's own shape. An explicit tag skips that check, so
    ``!!int "abc"`` reaches ``int("abc")`` and the ``ValueError`` leaves the
    loader as it is: not a ``YAMLError``, so every caller that translates
    ``YAMLError`` into "this file is not valid YAML" let it through as an
    internal error with a traceback. ``!!bool`` raises ``KeyError`` the same
    way, ``!!timestamp`` ``AttributeError``, and an empty ``!!int``
    ``IndexError``. An untagged value can do it too: a run of digits longer
    than the interpreter's integer-string limit, or a date-shaped value
    naming a month that does not exist.

    Wrapping the constructors, not widening the callers' ``except``, keeps the
    translation to exactly the conversions that can fail this way and gives
    the error a position. The message does not repeat the value, for the
    reason ``describe_yaml_error`` drops the quoted line.

    Only ``loader_cls`` is changed: ``add_constructor`` copies the constructor
    table to the subclass before writing to it.
    """
    for name in _GUARDED_TYPES:
        tag = f"tag:yaml.org,2002:{name}"
        loader_cls.add_constructor(
            tag, _guarded(name, loader_cls.yaml_constructors[tag])
        )


def _guarded(
    name: str, construct: Callable[[Any, Any], Any]
) -> Callable[[Any, Any], Any]:
    def constructor(loader: Any, node: Any) -> Any:
        try:
            return construct(loader, node)
        except _CONVERSION_ERRORS as exc:
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f"the value cannot be read as the type it is given ({name})",
                node.start_mark,
            ) from exc

    return constructor


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
