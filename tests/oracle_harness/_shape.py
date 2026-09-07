"""Compare the merged *document*, normalised by Compose rather than by us.

The findings comparator is blind to any field no rule reads. That is not a
corner: #797 shipped a `depends_on` merge that produced a Python `repr`, and
the finding multisets agreed perfectly the whole time, because no rule reads
`depends_on`. Comparing the documents is the only thing that sees it.

The obvious way to compare them is wrong. Compose emits a canonical form —
short volume syntax expanded, ports structured, `environment:` a mapping,
`env_file:` folded in — and this project deliberately does not, because rules
read the spelling the user wrote. Writing a normaliser to bridge that would be
a second hand-transcribed copy of Compose's semantics, which is the thing this
harness exists to retire.

So Compose normalises both sides. Our merged document is dumped back out as a
Compose file and handed to the same binary, and its output is compared with the
output for the original project. Two Compose renderings, no normaliser to be
wrong.

Three things the dump has to get right, each measured rather than reasoned:

* **It is written into the project root**, not a scratch directory. A relative
  `env_file:` target has to still resolve, and Compose folds it into
  `environment:` on both passes only if it does. The truth pass runs first, so
  the dump never exists while the original project is being resolved, and the
  second pass names it with `-f` rather than relying on discovery.
* **`$` is escaped to `$$`.** Our merged text is already interpolated, so a
  literal `$` in a resolved value would be re-interpolated on the second pass.
  `--no-interpolate` looks like the alternative and is not: measured on
  Compose 5.5.0, it also skips normalisation steps, leaving `bind: {}` where a
  normal pass writes `bind: {create_host_path: true}` and leaving `env_file:`
  unfolded — differences that have nothing to do with the loader.
* **`include:` and `extends:` are stripped.** Both are already consumed; the
  dump is the post-merge document. Left in, Compose would resolve them a
  second time, and a cross-file `extends:` would name a path relative to a file
  that no longer needs to follow it.

**Known blind spot**, and it is the same one any normaliser would have: a merge
bug that round-trips to the same canonical form is invisible. A merge bug that
produces a document Compose *rejects* is not — it surfaces as the dump pass
failing, which is still a failure, and is how #805 was found.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from pathlib import Path

# Not a name Compose discovers on its own, so writing it into the project
# cannot change what the project resolves to.
DUMP_NAME = "compose-lint-shape-dump.yaml"

# Directives the loader has already acted on. They describe how the document
# was assembled, not what it says, so the post-merge document must not carry
# them back to a binary that would act on them again.
_CONSUMED_TOP_LEVEL = frozenset({"include"})
_CONSUMED_SERVICE = frozenset({"extends"})


def _escaped(value: Any) -> Any:
    """`$` doubled, so an already-interpolated value survives a second pass."""
    if isinstance(value, str):
        return value.replace("$", "$$")
    if isinstance(value, dict):
        return {key: _escaped(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_escaped(item) for item in value]
    return value


def dump_document(data: dict[str, Any]) -> str:
    """Our merged document as a Compose file Compose can resolve again."""
    document = {
        key: value for key, value in data.items() if key not in _CONSUMED_TOP_LEVEL
    }
    services = document.get("services")
    if isinstance(services, dict):
        document["services"] = {
            name: {
                key: _escaped(value)
                for key, value in body.items()
                if key not in _CONSUMED_SERVICE
            }
            if isinstance(body, dict)
            else body
            for name, body in services.items()
        }
    return yaml.safe_dump(document, sort_keys=True)


def write_dump(data: dict[str, Any], project_root: Path) -> Path:
    """Write the dump beside the project's own documents and return its path."""
    target = project_root / DUMP_NAME
    target.write_text(dump_document(data))
    return target


def shape_of(resolved: str) -> Any:
    """A resolved configuration as data, so key order is not part of the diff.

    Compose emits top-level keys in the order the input wrote them, and our
    dump writes them sorted. That is a property of the writer, not of the
    configuration.
    """
    return yaml.safe_load(resolved)


def describe_shape_difference(theirs: Any, ours: Any) -> str:
    """The paths where two resolved configurations disagree."""
    lines: list[str] = []
    _walk("", theirs, ours, lines)
    return "\n".join(lines[:20]) or "  (documents differ but no leaf did)"


def _walk(path: str, theirs: Any, ours: Any, lines: list[str]) -> None:
    if theirs == ours:
        return
    if isinstance(theirs, dict) and isinstance(ours, dict):
        for key in sorted(set(theirs) | set(ours)):
            _walk(
                f"{path}.{key}" if path else str(key),
                theirs.get(key),
                ours.get(key),
                lines,
            )
        return
    lines.append(f"  {path or '<root>'}:\n    theirs: {theirs!r}\n    ours:   {ours!r}")
