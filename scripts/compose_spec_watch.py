#!/usr/bin/env python3
"""Watch the Compose Specification for keys and container slots (issue #1187).

compose-lint's parser keeps keys it does not know, by design, so a key Compose
adds is silent: it is neither an error nor graded. Three that carried a
container or a grant (``use_api_socket``, the lifecycle hooks, ``jobs:``)
went unnoticed for months that way. This script turns the next one into an
issue that names it.

It reads the spec's JSON schema at upstream ``main`` and reduces it to a
*shape*: the key names allowed at the top level, on a service, on a job, on
a ``pre_start`` hook and on an exec hook, plus the **container slots**, the
keys whose value holds a container (``container_spec``) or a command run
inside one (``service_hook``). It compares that shape with the one committed
in ``scripts/compose_spec_keys.json`` and prints what changed.

Exit codes, like ``eol_watch.py``: 0 the shape matches, 1 it changed (the
report is on stdout and ``compose-spec-watch.yml`` opens or updates an
issue), 2 no trustworthy answer (network, a response that is not the Compose
schema), which fails the run.

The committed file holds key names and the upstream commit they were read
at: facts about the spec, not a copy of it. After the change is triaged
(a rule, a traversal, or a recorded decision not to grade), a maintainer
runs ``--write`` and commits the result; the next weekly run then closes the
issue.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import sys
import urllib.request
from typing import Any

REPO = pathlib.Path(__file__).resolve().parent.parent
RECORD = REPO / "scripts" / "compose_spec_keys.json"
UPSTREAM = "compose-spec/compose-spec"
SCHEMA_PATH = "schema/compose-spec.json"
COMMIT_API = f"https://api.github.com/repos/{UPSTREAM}/commits/main"
RAW = f"https://raw.githubusercontent.com/{UPSTREAM}/{{sha}}/{SCHEMA_PATH}"

# Where keys are listed. Each maps to the schema definition whose properties
# are the keys allowed there; "top-level" is the schema root.
PLACES = {
    "top-level": None,
    "service": "service",
    "job": "job",
    "pre_start_hook": "pre_start_hook",
    "service_hook": "service_hook",
}

# A key is a container slot when its value reaches one of these definitions.
CONTAINER_DEFS = ("container_spec", "service_hook")

# Keywords whose subschemas describe the *same* object, so their properties
# are keys of that object too.
_SAME_OBJECT = ("allOf", "anyOf", "oneOf")
_SAME_OBJECT_SINGLE = ("if", "then", "else")

# Keywords whose subschemas describe *values inside* the node: a property's
# value, an item, a map entry. Walking these is how a container nested inside
# an object or a list is found.
_NESTED_MAPS = ("properties", "patternProperties", "dependentSchemas", "$defs")
_NESTED_SINGLE = ("items", "additionalProperties", "unevaluatedProperties", "not")
_NESTED_LISTS = ("prefixItems",)


def _ref_name(ref: str) -> str:
    if not ref.startswith("#/$defs/"):
        raise ValueError(f"unsupported $ref {ref!r}: only local #/$defs/ references")
    return ref.rsplit("/", 1)[-1]


def keys_of(schema: dict[str, Any], node: dict[str, Any]) -> set[str]:
    """Every property name an object described by ``node`` may carry."""
    return set(property_schemas(schema, node))


def property_schemas(
    schema: dict[str, Any], node: dict[str, Any]
) -> dict[str, list[Any]]:
    """``key -> [subschemas]`` for every property of the object ``node`` describes.

    Follows ``$ref`` (alongside any sibling keywords, which 2020-12 evaluates
    too), ``allOf``/``anyOf``/``oneOf``, ``if``/``then``/``else`` and
    ``dependentSchemas``: every way a schema can add a key to the same object.
    A key defined in two branches has both subschemas, so a container
    reachable through either is found.
    """
    defs = schema.get("$defs", {})
    out: dict[str, list[Any]] = {}
    seen: set[int] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if not isinstance(current, dict) or id(current) in seen:
            continue
        seen.add(id(current))
        for key, sub in current.get("properties", {}).items():
            out.setdefault(key, []).append(sub)
        ref = current.get("$ref")
        if isinstance(ref, str):
            stack.append(defs[_ref_name(ref)])
        for keyword in _SAME_OBJECT:
            stack.extend(current.get(keyword, []))
        for keyword in _SAME_OBJECT_SINGLE:
            if keyword in current:
                stack.append(current[keyword])
        stack.extend(current.get("dependentSchemas", {}).values())
    return out


def reaches(schema: dict[str, Any], node: Any, targets: tuple[str, ...]) -> bool:
    """Whether ``node`` reaches any ``$defs/<target>``, through any keyword.

    Deliberately exhaustive: a container written as a list of them, a map of
    them, an object property holding one, a branch of a ``oneOf``, or a
    ``$ref`` with sibling keywords is still a container slot.
    """
    defs = schema.get("$defs", {})
    seen: set[int] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, list):
            stack.extend(current)
            continue
        if not isinstance(current, dict) or id(current) in seen:
            continue
        seen.add(id(current))
        ref = current.get("$ref")
        if isinstance(ref, str):
            name = _ref_name(ref)
            if name in targets:
                return True
            stack.append(defs[name])
        for keyword in (*_SAME_OBJECT, *_NESTED_LISTS):
            stack.extend(current.get(keyword, []))
        for keyword in (*_SAME_OBJECT_SINGLE, *_NESTED_SINGLE):
            if keyword in current:
                stack.append(current[keyword])
        for keyword in _NESTED_MAPS:
            stack.extend(current.get(keyword, {}).values())
    return False


def shape(schema: dict[str, Any]) -> dict[str, Any]:
    """The spec reduced to key names per place and the container slots."""
    if schema.get("title") != "Compose Specification":
        raise ValueError("not the Compose Specification schema")
    defs = schema.get("$defs", {})
    keys: dict[str, list[str]] = {}
    slots: set[str] = set()
    for place, definition in PLACES.items():
        node = schema if definition is None else defs.get(definition)
        if node is None:
            raise ValueError(f"the schema has no $defs/{definition}")
        keys[place] = sorted(keys_of(schema, node))
        for key, subs in property_schemas(schema, node).items():
            if reaches(schema, subs, CONTAINER_DEFS):
                slots.add(key if place == "top-level" else f"{place}.{key}")
    return {"keys": keys, "container_slots": sorted(slots)}


def diff(recorded: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Report lines for every difference; empty when the shapes match."""
    lines: list[str] = []
    for place in PLACES:
        was = set(recorded["keys"].get(place, []))
        now = set(current["keys"].get(place, []))
        for key in sorted(now - was):
            lines.append(f"- **added** `{key}` ({place})")
        for key in sorted(was - now):
            lines.append(f"- **removed** `{key}` ({place})")
    was_slots = set(recorded["container_slots"])
    now_slots = set(current["container_slots"])
    for slot in sorted(now_slots - was_slots):
        lines.append(
            f"- **new container slot** `{slot}`: holds containers the engine "
            "does not traverse until it is added to compose_lint._units"
        )
    for slot in sorted(was_slots - now_slots):
        lines.append(f"- **container slot gone** `{slot}`")
    return lines


def render(lines: list[str], commit: str, recorded_commit: str) -> str:
    return "\n".join(
        [
            "The Compose Specification schema changed in a way compose-lint has "
            "not triaged.",
            "",
            f"Upstream `main` at `{commit[:12]}` against the shape recorded at "
            f"`{recorded_commit[:12]}` in `scripts/compose_spec_keys.json`:",
            "",
            *lines,
            "",
            "For each change, decide: a rule or an extension of one, traversal in "
            "the engine for a container slot, or a recorded decision not to "
            "grade (with its reason, in an issue). Then run "
            "`python3 scripts/compose_spec_watch.py --write` and commit the "
            "record; the next weekly run closes this issue.",
        ]
    )


def _get(url: str, *, accept: str) -> bytes:
    request = urllib.request.Request(url, headers={"Accept": accept})
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        body: bytes = response.read()
    return body


def fetch() -> tuple[str, dict[str, Any]]:
    """Upstream ``main``'s commit and the schema at exactly that commit."""
    commit = json.loads(_get(COMMIT_API, accept="application/vnd.github+json"))["sha"]
    if not (isinstance(commit, str) and len(commit) == 40):
        raise ValueError("upstream main did not resolve to a commit")
    schema = json.loads(_get(RAW.format(sha=commit), accept="application/json"))
    return commit, schema


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--write",
        action="store_true",
        help="record the current upstream shape in scripts/compose_spec_keys.json",
    )
    args = parser.parse_args(argv)
    commit, schema = fetch()
    current = shape(schema)
    if args.write:
        record = {
            "source": {
                "repository": f"https://github.com/{UPSTREAM}",
                "path": SCHEMA_PATH,
                "commit": commit,
                "recorded": dt.date.today().isoformat(),
            },
            **current,
        }
        RECORD.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(f"recorded the shape at {commit[:12]}")
        return 0
    recorded = json.loads(RECORD.read_text(encoding="utf-8"))
    lines = diff(recorded, current)
    if not lines:
        print(f"The spec at {commit[:12]} matches the recorded shape.")
        return 0
    print(render(lines, commit, recorded["source"]["commit"]))
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - exit 2 must cover every failure
        print(f"compose_spec_watch: no trustworthy answer: {exc}", file=sys.stderr)
        sys.exit(2)
