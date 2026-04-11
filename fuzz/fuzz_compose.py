"""Atheris fuzz harness exercising the parser and rule engine end-to-end.

The harness feeds arbitrary bytes through the full lint pipeline: YAML decode
under LineLoader, Compose validation, line-number collection, and the rule
runner. Any exception that isn't in the expected-error set is treated as a
crash — that's how fuzzing surfaces real bugs (parser state corruption, rule
assumptions that break on exotic inputs, etc.).
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    import yaml

    from compose_lint import engine, parser


def _test_one_input(data: bytes) -> None:
    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError:
        return

    try:
        raw = yaml.load(content, Loader=parser.LineLoader)  # noqa: S506
    except yaml.YAMLError:
        return
    except (OverflowError, ValueError):
        # PyYAML converts some malformed scalars (e.g. massive ints, bad
        # timestamps) into Python exceptions before our ComposeError wrapper.
        return

    if raw is None:
        return

    try:
        parser._validate_compose(raw)
    except parser.ComposeError:
        return

    lines = parser._collect_lines(raw)
    stripped = parser._strip_lines(raw)

    if not isinstance(stripped, dict):
        return

    engine.run_rules(stripped, lines)


def main() -> None:
    atheris.Setup(sys.argv, _test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
