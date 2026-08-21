"""Differential test: does our ``.env`` reader agree with Docker Compose?

The grammar in ``compose_lint._env_file`` was derived by probing ``docker
compose config``, because ``.env`` is godotenv's format and is nowhere
normatively specified for Compose. Comments rot and probes get forgotten, so
this re-derives the same behaviour from the real binary on every run: a Compose
release that changes how a ``.env`` is read fails here rather than silently
mis-resolving a user's stack.

The comparison is on the **resolved value**, asked the only way Compose will
answer it — put ``${K}`` in a Compose document, run ``config``, read back what
came out. That is exactly the question a rule ends up asking.

Cases where we deliberately diverge live in ``test_env_file.py`` and are listed
in ``DIVERGENT`` below with the reason, so the split is visible in one place
rather than being an unexplained gap in coverage.

Skipped when the ``docker compose`` CLI is unavailable, so the suite still runs
in environments without it.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest
import yaml

from compose_lint._env_file import parse_env

if TYPE_CHECKING:
    from pathlib import Path


def _compose_cli_works() -> bool:
    """Whether ``docker compose`` can actually run, not merely whether it exists.

    ``shutil.which`` alone is not enough: the Windows runners carry a ``docker``
    on PATH that cannot serve ``compose``, and a bare presence check turned that
    into a fixture failure rather than a skip.
    """
    if shutil.which("docker") is None:
        return False
    try:
        return (
            subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                timeout=30,
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = pytest.mark.skipif(
    not _compose_cli_works(),
    reason="differential .env test needs a working docker compose CLI",
)

_COMPOSE = """\
services:
  s:
    image: i
    environment:
      OUT: "${K}"
"""

# Every case is `.env` text defining K. The assertion is that Compose and this
# module ship the same string for `${K}`.
AGREED = [
    pytest.param("K=v", id="plain"),
    pytest.param("  K  =  v  ", id="trimmed"),
    pytest.param("export K=v", id="export-prefix"),
    pytest.param('K="v w"', id="double-quoted"),
    pytest.param("K='v w'", id="single-quoted"),
    pytest.param("K=v # trail", id="unquoted-trailing-comment"),
    pytest.param('K="v # trail"', id="quoted-hash-is-literal"),
    pytest.param("# note\nK=v", id="leading-comment"),
    pytest.param("K=", id="empty-value"),
    pytest.param("K", id="no-equals"),
    pytest.param("K=a=b", id="first-equals-splits"),
    pytest.param("K=first\nK=second", id="last-duplicate-wins"),
    pytest.param('K="a\\nb"', id="double-quote-escapes"),
    pytest.param("K='a\\nb'", id="single-quote-literal"),
    pytest.param("K=a\\nb", id="unquoted-literal"),
    pytest.param("A=one\nK=${A}-two", id="braced-reference"),
    pytest.param("A=one\nK=$A-two", id="bare-reference"),
    pytest.param("A=one\nK='${A}'", id="single-quotes-suppress-expansion"),
    pytest.param("K=${MISSING:-dflt}", id="default-applies"),
    pytest.param("BASE=/var/run\nK=${BASE}/docker.sock", id="chained"),
    pytest.param("﻿K=v", id="bom"),
    pytest.param("K=v\r", id="crlf"),
    pytest.param("K=v\rJ=w", id="bare-cr-is-not-a-break"),
    pytest.param("K=v\fJ=w", id="form-feed-is-not-a-break"),
    pytest.param("K=v\x85J=w", id="u0085-is-not-a-break"),
    pytest.param("K=v J=w", id="u2028-is-not-a-break"),
    pytest.param("K=a$$b", id="escaped-dollar"),
    pytest.param("A=one\nK=a$$A", id="escaped-dollar-suppresses-reference"),
    pytest.param("K='cost $5 total'", id="literal-dollar-in-single-quotes"),
]

# Deliberate divergences, with the reason each one exists. Listed rather than
# omitted so the gap is legible; the behaviour itself is asserted in
# test_env_file.py.
DIVERGENT = {
    "K=${SOME_UNDEFINED_NAME}": (
        "Compose falls back to the process environment and then to empty; "
        "both describe the lint host rather than the project (ADR-026)."
    ),
    "K=${LATER}\nLATER=x": (
        "Compose ships empty for a forward reference; we report it unresolved "
        "rather than claim a value the file does not build."
    ),
    "this is not a pair\nK=v": (
        "Compose refuses the whole file; a lint run skips the line and "
        "continues, because the .env is not the artifact under lint."
    ),
}


def _compose_resolves(directory: Path, env_text: str) -> str | None:
    """Ground truth: what Compose itself substitutes for ``${K}``.

    ``None`` means Compose refused the file. That is a real answer for one of
    the divergences below, not a broken fixture, so it is returned rather than
    skipped — an earlier version called ``pytest.skip`` here and the malformed
    case silently never ran.
    """
    # Explicit UTF-8 and no newline translation: the default is the locale
    # encoding, which is cp1252 on the Windows runners and cannot encode the
    # BOM or U+0085 these fixtures are made of. A differential test compares
    # byte-level behaviour, so the bytes must be the ones written here on every
    # platform rather than whatever the local codec produced.
    (directory / "compose.yml").write_text(_COMPOSE, encoding="utf-8", newline="")
    (directory / ".env").write_text(env_text, encoding="utf-8", newline="")
    result = subprocess.run(
        ["docker", "compose", "config"],
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        return None
    document = yaml.safe_load(result.stdout)
    return _decode_dollars(str(document["services"]["s"]["environment"]["OUT"]))


def _decode_dollars(rendered: str) -> str:
    """Undo the literal-dollar escaping ``config`` applies on the way out.

    ``config`` emits a document that must round-trip through Compose's own
    interpolation, so a value carrying a literal ``$`` is printed ``$$``. A
    value of ``${A}`` prints as ``$${A}``. Comparing against the printed form
    would make the reader assert Compose's *serialisation*, not the value it
    ships, and would have flagged a correct implementation as a disagreement.
    """
    return rendered.replace("$$", "$")


@pytest.mark.parametrize("env_text", AGREED)
def test_agrees_with_compose(env_text: str, tmp_path: Path) -> None:
    theirs = _compose_resolves(tmp_path, env_text)
    assert theirs is not None, f"compose refused an AGREED fixture: {env_text!r}"
    ours = parse_env(env_text, ["K"]).values.get("K", "")
    assert ours == theirs, (
        f"disagreement for {env_text!r}: compose ships {theirs!r}, we ship {ours!r}"
    )


@pytest.mark.parametrize("env_text", sorted(DIVERGENT))
def test_divergences_are_still_divergences(env_text: str, tmp_path: Path) -> None:
    """The listed cases must keep differing, and for the recorded reason.

    If Compose ever changes to match us, this fails and the entry should move
    to ``AGREED`` — a divergence that no longer exists is a comment claiming a
    difference the code no longer makes.
    """
    theirs = _compose_resolves(tmp_path, env_text)
    parsed = parse_env(env_text, ["K"])
    reason = DIVERGENT[env_text]

    if theirs is None:
        # Compose refused the whole file. We keep the well-formed lines.
        assert parsed.values == {"K": "v"}, reason
        assert parsed.skipped_lines, reason
        return

    # Compose resolved it to empty by falling back to the host; we decline to.
    assert theirs == "", reason
    assert "K" not in parsed.values, f"{reason} -- but we shipped a value"
    assert parsed.unresolved == {"K"}, reason
