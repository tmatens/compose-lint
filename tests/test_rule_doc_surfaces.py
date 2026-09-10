"""A rule's doc page must list exactly the names its code matches on.

`docs/rules/CL-0020.md` spells its key patterns and exemptions out as
backticked names in prose. That page is what someone opens to find out why
CL-0020 flagged — or spared — their key, so a name the page lists that the
code does not match sends them hunting for a typo in their own file, and a
name the code matches that the page omits leaves them with no explanation at
all. #685 shipped the first kind three ways in one PR — an exemption the
tuples did not have, and three suffix-anchored entries listed without the
underscore that does the anchoring — and it was caught by a reviewer
re-reading the tuples against the page by hand, twice. Nothing else could
have caught it: CONTRIBUTING asks for the doc edit, and no gate checked it.

Same idea as `tests/test_rule_surfaces.py`, one level down: that test holds
the *set of rules* together across its surfaces; this one holds a *single
rule's* constants together with the page describing them. Each surface is
anchored to the line that carries it, so a failure names the list and the
names, not the file.

The `cap_add` rules get the same treatment further down, discovered rather
than listed: any rule module with a public `*_CAPS` dict is one, so a seventh
tier is covered the day it lands. That half found CL-0011's cross-rule table
claiming CL-0027 flags `PERFMON` and `SYS_TIME` at MEDIUM, which moved to
CL-0028 at HIGH — a reader following the table would have been told the wrong
rule and the wrong severity.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import pytest

from compose_lint import cli
from compose_lint.rules import CL0020_credential_env_keys as cl0020
from compose_lint.rules import get_registered_rules

DOCS_RULES = Path(__file__).parent.parent / "docs" / "rules"
DOC = DOCS_RULES / "CL-0020.md"

# A backticked name as the code would spell it: upper-case, possibly anchored
# with a leading or trailing underscore. Excludes the illustrative
# `KEY: value` pairs and bare numbers that share the same lines.
_NAME = re.compile(r"`(_?[A-Z][A-Z0-9_]*)`")
# The boolean-flag values are the one lower-case list.
_VALUE = re.compile(r"`([a-z0-9]+)`")


def _line(anchor: str) -> str:
    lines = DOC.read_text(encoding="utf-8").splitlines()
    matches = [ln for ln in lines if anchor in ln]
    assert len(matches) == 1, (
        f"expected one line containing {anchor!r}, found {len(matches)}"
    )
    return matches[0]


def _table_cell(anchor: str) -> str:
    """The Pattern cell of a `| type | patterns | notes |` row.

    The Notes cell can legitimately quote a name the code does *not* match —
    the suffix row explains why raw `PASS` is excluded — so only the cell
    that claims to list patterns is read.
    """
    return _line(anchor).split("|")[2]


SURFACES: dict[str, tuple[str, re.Pattern[str], frozenset[str]]] = {
    "substring patterns": (
        _table_cell("| substring |"),
        _NAME,
        frozenset(cl0020._SUBSTRING_PATTERNS),
    ),
    "suffix patterns": (
        _table_cell("| suffix "),
        _NAME,
        frozenset(cl0020._SUFFIX_PATTERNS),
    ),
    "file-suffix exemption": (
        _line("- Keys ending in"),
        _NAME,
        frozenset({cl0020._FILE_SUFFIX}),
    ),
    "flag-key exemption": (
        _line("- Keys containing"),
        _NAME,
        frozenset(cl0020._FLAG_KEY_FRAGMENTS),
    ),
    "flag-value exemption": (
        _line("- Values that are exactly"),
        _VALUE,
        frozenset(cl0020._FLAG_VALUES),
    ),
    "quantity-knob exemption": (
        _line("- Keys that name a **quantity about**"),
        _NAME,
        frozenset(cl0020._QUANTITY_KEY_FRAGMENTS)
        | frozenset(cl0020._QUANTITY_KEY_SUFFIXES),
    ),
}


@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_doc_lists_exactly_what_the_code_matches(surface: str) -> None:
    line, pattern, in_code = SURFACES[surface]
    in_doc = frozenset(pattern.findall(line))
    promised = sorted(in_doc - in_code)
    undocumented = sorted(in_code - in_doc)
    assert not promised, (
        f"CL-0020.md lists {promised} under '{surface}' but the code does not "
        "match them — a documented pattern that does not exist. Check the "
        "spelling, including a leading underscore on suffix-anchored names."
    )
    assert not undocumented, (
        f"the code matches {undocumented} under '{surface}' but CL-0020.md does "
        "not list them — add them to that line so the page explains every key "
        "the rule treats this way."
    )


# ---- `cap_add` tier rules ---------------------------------------------------

CAP_DOC_ROW = re.compile(r"^\| `(CAP_)?([A-Z][A-Z0-9_]*)` \|", re.M)
# `| Rule | Tier | Members |` in CL-0011's disambiguation table. The rule cell
# is a link except for CL-0011's own row, which is bolded plain text.
TIER_ROW = re.compile(
    r"^\| (?:\[(CL-\d{4})\]\([^)]*\)|\*\*(CL-\d{4})\*\*) \|"
    r" \*{0,2}(\w+)\*{0,2} \|([^|]*)\|",
    re.M,
)


def _cap_rules() -> dict[str, tuple[frozenset[str], str]]:
    """Every registered rule whose module carries a public ``*_CAPS`` dict.

    Discovered, not listed: the capability tiers have grown from three to six
    (CL-0024/0011/0027, then 0028/0029/0030) and the next one gets covered
    without anybody remembering to add it here.
    """
    found: dict[str, tuple[frozenset[str], str]] = {}
    for cls in get_registered_rules():
        module = sys.modules[cls.__module__]
        for name, value in vars(module).items():
            if (
                name.endswith("_CAPS")
                and not name.startswith("_")
                and isinstance(value, dict)
            ):
                meta = cls().metadata
                found[meta.id] = (frozenset(value), meta.severity.name)
    return found


CAP_RULES = _cap_rules()


@pytest.mark.parametrize("rule_id", sorted(CAP_RULES))
def test_cap_rule_doc_table_lists_exactly_its_capabilities(rule_id: str) -> None:
    """The `| Capability | Grants |` table is the rule's member list in prose."""
    in_code, _severity = CAP_RULES[rule_id]
    doc = (DOCS_RULES / f"{rule_id}.md").read_text(encoding="utf-8")
    in_doc = {name for _prefix, name in CAP_DOC_ROW.findall(doc)}
    assert in_doc == in_code, (
        f"{rule_id}.md's capability table and the rule's *_CAPS dict disagree — "
        f"only on the page: {sorted(in_doc - in_code)}; "
        f"only in the code: {sorted(in_code - in_doc)}"
    )


def test_the_tier_table_matches_every_cap_rule() -> None:
    """CL-0011 carries the table that says which tier flags which capability.

    It is the page a reader lands on to find out why their `cap_add` entry was
    graded the way it was, and it is the only surface that spans the tiers — so
    a rule missing from it, or a member on the wrong row, sends them to a rule
    that does not flag their capability. Held to both the membership and the
    severity, since the split exists because SARIF advertises one
    `security-severity` per rule descriptor.
    """
    doc = (DOCS_RULES / "CL-0011.md").read_text(encoding="utf-8")
    rows = {
        (linked or bolded): (tier, frozenset(re.findall(r"`(\w+)`", members)))
        for linked, bolded, tier, members in TIER_ROW.findall(doc)
    }
    assert set(rows) == set(CAP_RULES), (
        "CL-0011.md's tier table does not cover every cap_add rule — "
        f"missing: {sorted(set(CAP_RULES) - set(rows))}; "
        f"listed but not a cap_add rule: {sorted(set(rows) - set(CAP_RULES))}"
    )
    for rule_id, (tier, members) in sorted(rows.items()):
        in_code, severity = CAP_RULES[rule_id]
        assert members == in_code, (
            f"CL-0011.md's tier table gives {rule_id} {sorted(members)}, "
            f"the rule flags {sorted(in_code)}"
        )
        assert tier == severity, (
            f"CL-0011.md's tier table grades {rule_id} {tier}, "
            f"its metadata says {severity}"
        )


# ---- `docs/cli.md` ----------------------------------------------------------

CLI_DOC = Path(__file__).parent.parent / "docs" / "cli.md"
# `  --flag`, `  -v, --verbose`. The wrapped continuation lines of a long help
# string are indented further and carry no leading dash, so they don't match.
DOC_FLAG = re.compile(r"^ {2}(-\w, )?(--[a-z][a-z0-9-]*)", re.M)


def _documented_flags(section: str) -> set[str]:
    """The flags listed under one `<command> options:` block of the fenced help."""
    body = CLI_DOC.read_text(encoding="utf-8")
    start = body.index(f"\n{section} options:\n")
    rest = body[start + 1 :]
    end = min(
        (i for i in (rest.find("\n\n"), rest.find("\n```")) if i != -1),
        default=len(rest),
    )
    return {flag for _short, flag in DOC_FLAG.findall(rest[:end])}


def _flags(parser: argparse.ArgumentParser) -> set[str]:
    return {
        option
        for action in parser._actions
        for option in action.option_strings
        if option.startswith("--") and option != "--help"
    }


def _parser_flags(command: str) -> set[str]:
    parser = cli._build_parser()
    subparsers = next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    flags = _flags(subparsers.choices[command])
    if command == "check":
        # `check` is the default command, so the page documents the top-level
        # flags (`--version`) in its block rather than giving them one of
        # their own. Reachable as `compose-lint --version`, so that is right.
        flags |= _flags(parser)
    return flags


@pytest.mark.parametrize("command", ["check", "fix", "init"])
def test_cli_doc_lists_exactly_the_flags_the_parser_defines(command: str) -> None:
    """`docs/cli.md` calls itself the web copy of `--help`; hold it to that.

    It is hand-maintained — the descriptions are re-worded, so it cannot be a
    byte-for-byte diff — which is exactly the shape that goes stale. A flag
    added without a row here is undocumented on the page most users read
    instead of running `--help`, and a row left behind after a flag is removed
    sends them to an option that no longer exists.
    """
    in_doc = _documented_flags(command)
    in_parser = _parser_flags(command)
    assert in_doc == in_parser, (
        f"docs/cli.md's `{command} options:` block and the parser disagree — "
        f"only on the page: {sorted(in_doc - in_parser)}; "
        f"only in the parser: {sorted(in_parser - in_doc)}"
    )
