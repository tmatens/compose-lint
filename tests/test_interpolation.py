"""Tests for interpolation normalization (``rules/_interpolation`` + the parser pass).

Classification has to happen after canonicalization. With substitution wired
into a single call site, every rule but one compared its dangerous-value set
against the literal text ``"${P:-true}"`` while Compose deploys ``true``, so
``${VAR:-danger}`` was a general-purpose bypass.

Every expectation about what Compose ships was captured with
``docker compose config`` on Docker Compose 29.7.2 and is named in the test that
relies on it, rather than reasoned from the substitution syntax.
"""

from __future__ import annotations

import pytest

from compose_lint.parser import loads
from compose_lint.rules._interpolation import (
    _MAX_SCAN_LEN,
    ships_no_literal,
    substitute_defaults,
)

# --- The parser normalizes the whole document ------------------------------


@pytest.mark.parametrize(
    "field,written,shipped",
    [
        # Each row was confirmed with `docker compose config`: an unset variable
        # makes Compose deploy the default verbatim. Substitution yields a
        # *string* — YAML already typed the scalar as one — so a rule reads it
        # through `as_bool`/the normalizers rather than as a native bool.
        ("privileged", "${P:-true}", "true"),
        ("network_mode", "${NM:-host}", "host"),
        ("user", "${U:-root}", "root"),
        ("pid", "${PID:-host}", "host"),
        ("image", "nginx:${T:-latest}", "nginx:latest"),
        # A default containing a literal tail keeps it.
        ("working_dir", "${D:-/srv}/data", "/srv/data"),
        # Partial interpolation: `pre${U:-root}post` ships `prerootpost`.
        ("user", "pre${U2:-root}post", "prerootpost"),
    ],
)
def test_defaulted_values_are_normalized(
    field: str, written: str, shipped: object
) -> None:
    data, _lines = loads(f"services:\n  web:\n    {field}: {written}\n")
    assert data["services"]["web"][field] == shipped


def test_reference_without_a_default_is_left_as_written() -> None:
    """Nothing to resolve to, and inventing a value would invent a finding."""
    data, _lines = loads("services:\n  web:\n    image: nginx:${TAG}\n")
    assert data["services"]["web"]["image"] == "nginx:${TAG}"


@pytest.mark.parametrize(
    "written,shipped",
    [
        # Captured with `docker compose config` on Docker Compose 5.4.0, in an
        # empty directory with no `.env` and an empty environment. A single
        # regex pass resolved the *outer* reference against the *inner* one's
        # closing brace, producing text Compose never ships:
        # `${OUTER:-postgresql://user:${INNER:-pw}@db/x}` became
        # `postgresql://user:${INNER:-pw@db/x}`, moving the userinfo boundary
        # and relocating the brace past the host (issue #561).
        (
            "${OUTER:-postgresql://user:${INNER:-placeholder}@db:5432/x}",
            "postgresql://user:placeholder@db:5432/x",
        ),
        ("${A:-front-${B:-back}-tail}", "front-back-tail"),
        # Three deep, the shape corpus files use for a compose-project path.
        ("${A:-${B:-${C:-leaf}}}", "leaf"),
        # A default may contain literal braces, so the closing one is found by
        # balanced counting rather than by taking the first `}`. This row is a
        # control: taking the first `}` also happened to land here, because the
        # brace it dropped was re-added as a trailing literal. It pins what the
        # balanced counting must not break.
        ('${CONF:-{"a":1}}', '{"a":1}'),
    ],
)
def test_nested_defaults_resolve_innermost_first(written: str, shipped: str) -> None:
    assert substitute_defaults(written) == shipped


def test_nested_reference_without_a_default_is_left_as_written() -> None:
    """One un-defaulted reference anywhere makes the whole value unknowable.

    Compose ships `${GOPATH:-${HOME}/go}/pkg/mod/cache` as `/go/pkg/mod/cache`
    with an empty environment, but `$HOME` is set in every real one — so this
    file does not determine the path, and resolving it would invent a finding.
    Left as written, `ships_no_literal` still classifies it correctly.
    """
    assert substitute_defaults("${GOPATH:-${HOME}/go}/pkg/mod/cache") is None


def test_nesting_deeper_than_the_bound_is_left_as_written() -> None:
    """Resolution recurses per level, so the depth is what a scalar can buy.

    Unbounded, `${A:-` repeated ~1,200 times — 7 KB, under `MAX_SCAN_LEN` —
    exhausted the interpreter stack, and the parser reports a RecursionError as
    a usage error: a file that lints clean would exit 2 instead. That is the
    denial of service `_limits.MAX_SCAN_LEN` exists to close, reached by
    recursion rather than by backtracking.
    """
    from compose_lint.rules._interpolation import _MAX_NESTING

    at_bound = "${A:-" * _MAX_NESTING + "leaf" + "}" * _MAX_NESTING
    assert substitute_defaults(at_bound) == "leaf"

    too_deep = "${A:-" * 1200 + "leaf" + "}" * 1200
    assert len(too_deep) < _MAX_SCAN_LEN, "must be under the size cap to prove anything"
    assert substitute_defaults(too_deep) is None
    # And it reaches the parser as a lintable document, not an exit-2 error.
    data, _lines = loads(f"services:\n  web:\n    working_dir: '{too_deep}'\n")
    assert data["services"]["web"]["working_dir"] == too_deep


def test_operators_other_than_default_carry_no_default() -> None:
    """`:?`/`?` take an error message and `:+`/`+` an alternate, not a default."""
    for written in ("${A:?err}", "${A?err}", "${A:+alt}", "${A+alt}"):
        assert substitute_defaults(written) is None, written


def test_normalization_reaches_nested_lists_and_maps() -> None:
    data, _lines = loads(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.25\n"
        "    cap_add:\n"
        "      - ${C:-SYS_ADMIN}\n"
        "    volumes:\n"
        "      - type: ${VT:-bind}\n"
        "        source: /srv\n"
        "        target: /out\n"
    )
    web = data["services"]["web"]
    assert web["cap_add"] == ["SYS_ADMIN"]
    assert web["volumes"][0]["type"] == "bind"


def test_mapping_keys_are_not_rewritten() -> None:
    """Keys index the ``lines`` map; rewriting one would break every lookup."""
    source = (
        "services:\n  web:\n    image: nginx:1.25\n    environment:\n      ${K:-A}: v\n"
    )
    data, lines = loads(source)
    assert "${K:-A}" in data["services"]["web"]["environment"]
    assert any(path.endswith("${K:-A}") for path in lines)


def test_alias_shared_nodes_are_visited_once() -> None:
    """The walk is id-memoized, so an alias DAG cannot blow up or double-apply."""
    data, _lines = loads(
        "x-common: &common\n"
        "  user: ${U:-root}\n"
        "services:\n"
        "  a:\n"
        "    image: nginx:1.25\n"
        "    <<: *common\n"
        "  b:\n"
        "    image: nginx:1.25\n"
        "    <<: *common\n"
    )
    assert data["services"]["a"]["user"] == "root"
    assert data["services"]["b"]["user"] == "root"


# --- ships_no_literal: the exemption, stated as what Compose does ----------


@pytest.mark.parametrize(
    "value",
    [
        "${PW}",  # ships ""
        "$PW",
        "${PW:?err}",
        "${A}${B}",
        '"${PW}"',  # list-form entry: the quotes are literal characters
        "'${PW}'",
        "",
    ],
)
def test_values_that_ship_nothing_are_exempt(value: str) -> None:
    assert ships_no_literal(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "hunter2$X",  # ships "hunter2" — the VULN-006 bypass
        "prefix-${TOKEN}",  # ships "prefix-"
        "hunter2",
        "${PW:-hunter2}",  # a default is a literal the file ships
        "$${PW}",  # `$$` is an escaped dollar, not a reference
    ],
)
def test_values_that_ship_a_literal_are_not_exempt(value: str) -> None:
    assert ships_no_literal(value) is False


# --- The length cap that keeps the document-wide pass affordable -----------


def test_substitute_defaults_declines_an_oversized_scalar() -> None:
    """Both regexes are quadratic; past the cap, answer without scanning.

    Returning ``None`` is the conservative answer — callers leave the scalar as
    written, which is what happened before substitution went document-wide.
    """
    assert substitute_defaults("${A:-b}" * 10) == "b" * 10
    assert substitute_defaults("${a-" * (_MAX_SCAN_LEN // 2)) is None


def test_ships_no_literal_declines_an_oversized_scalar() -> None:
    assert ships_no_literal("${PW}" + "x" * _MAX_SCAN_LEN) is False


def test_oversized_scalar_is_left_intact_by_the_parser() -> None:
    big = "${A:-b}" * (_MAX_SCAN_LEN // 4)
    data, _lines = loads(
        f"services:\n  web:\n    image: nginx:1.25\n    command: {big}\n"
    )
    assert data["services"]["web"]["command"] == big
