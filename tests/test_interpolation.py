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
