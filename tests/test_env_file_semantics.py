"""Differential test: does our ``env_file:`` reader agree with Docker Compose?

The sibling of ``test_env_semantics.py``, asking the same question about the
other file. It is a separate module because the question is asked differently:
a ``.env`` is interrogated one ``${K}`` at a time, while an ``env_file:``
contributes the service's whole ``environment:`` mapping, so the ground truth is
that mapping rather than a single substitution.

The grammar mostly coincides with the ``.env`` one — godotenv, both times — and
diverges in three places Compose does not document together: a bare ``KEY`` is a
process-environment lookup rather than an empty value, ``format: raw`` is a
different grammar rather than a relaxed one, and the resolution scope spans the
sibling ``.env`` and every earlier ``env_file:`` on the same service. Each is
re-derived here on every run, so a Compose release that moves one fails the
suite instead of silently mis-reading a user's stack.

Skipped when the ``docker compose`` CLI is unavailable, like its sibling.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest
import yaml

from compose_lint._env_file import parse_env_file

if TYPE_CHECKING:
    from pathlib import Path


def _compose_cli_works() -> bool:
    """Whether ``docker compose`` can actually run, not merely whether it exists."""
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
    reason="differential env_file: test needs a working docker compose CLI",
)

_COMPOSE = """\
services:
  s:
    image: i
    env_file: [app.env]
"""

_COMPOSE_RAW = """\
services:
  s:
    image: i
    env_file:
      - path: app.env
        format: raw
"""

# Every case is ``env_file:`` text. The assertion is that Compose and this
# module contribute the same mapping to the service's environment.
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
    pytest.param("\ufeffK=v", id="bom"),
    pytest.param("K=v\r", id="crlf"),
    pytest.param("K=a$$b", id="escaped-dollar"),
    pytest.param("PW=hunter2\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE", id="pair"),
]

# ``format: raw`` keeps the bytes: no trimming, no quote stripping, no comment
# stripping inside a value, and no interpolation at all.
AGREED_RAW = [
    pytest.param("K=v", id="raw-plain"),
    pytest.param("K=v # trail", id="raw-hash-is-payload"),
    pytest.param('K="quoted"', id="raw-quotes-are-payload"),
    pytest.param("K=  spaced  ", id="raw-no-trimming"),
    pytest.param("A=one\nK=${A}-two", id="raw-no-interpolation"),
    pytest.param("# note\nK=v", id="raw-full-line-comment-still-skipped"),
    pytest.param("K=a\\nb", id="raw-backslash-literal"),
]

# Deliberate divergences, with the reason each one exists.
DIVERGENT = {
    "K=${SOME_UNDEFINED_NAME}": (
        "Compose falls back to the process environment and then to empty; both "
        "describe the lint host rather than the project (ADR-023)."
    ),
    "K=${LATER}\nLATER=x": (
        "Compose ships empty for a forward reference; we report it unresolved "
        "rather than claim a value the file does not build."
    ),
    "K\n": (
        "A bare key is purely a process-environment lookup. Compose imports the "
        "lint host's value; we report it unresolved."
    ),
    "not a pair\nK=v": (
        "Compose refuses the whole file and starts nothing; a lint run skips the "
        "line and grades the rest, because the env file is not the artifact "
        "under lint."
    ),
}

# The one name a divergence needs present in the process environment, so that
# Compose has something to import and the disagreement is observable at all.
_HOST_VALUE = "from-the-lint-host"


def _compose_environment(
    directory: Path,
    env_text: str,
    *,
    raw: bool = False,
    host_env: dict[str, str] | None = None,
) -> dict[str, str] | None:
    """Ground truth: the ``environment:`` mapping Compose builds for the service.

    ``None`` means Compose refused the file, which is a real answer for one of
    the divergences rather than a broken fixture.
    """
    document = _COMPOSE_RAW if raw else _COMPOSE
    (directory / "compose.yml").write_text(document, encoding="utf-8", newline="")
    (directory / "app.env").write_text(env_text, encoding="utf-8", newline="")
    result = subprocess.run(
        ["docker", "compose", "config"],
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=60,
        env=host_env,
    )
    if result.returncode != 0:
        return None
    parsed = yaml.safe_load(result.stdout)
    environment = parsed["services"]["s"].get("environment") or {}
    return {key: _decode_dollars(str(value)) for key, value in environment.items()}


def _decode_dollars(rendered: str) -> str:
    """Undo the literal-dollar escaping ``config`` applies on the way out."""
    return rendered.replace("$$", "$")


@pytest.mark.parametrize("env_text", AGREED)
def test_agrees_with_compose(env_text: str, tmp_path: Path) -> None:
    theirs = _compose_environment(tmp_path, env_text)
    assert theirs is not None, f"compose refused an AGREED fixture: {env_text!r}"
    ours = dict(parse_env_file(env_text).values)
    assert ours == theirs, (
        f"disagreement for {env_text!r}: compose ships {theirs!r}, we ship {ours!r}"
    )


@pytest.mark.parametrize("env_text", AGREED_RAW)
def test_agrees_with_compose_in_raw_format(env_text: str, tmp_path: Path) -> None:
    theirs = _compose_environment(tmp_path, env_text, raw=True)
    assert theirs is not None, f"compose refused an AGREED_RAW fixture: {env_text!r}"
    ours = dict(parse_env_file(env_text, raw=True).values)
    assert ours == theirs, (
        f"disagreement for {env_text!r}: compose ships {theirs!r}, we ship {ours!r}"
    )


@pytest.mark.parametrize("env_text", sorted(DIVERGENT))
def test_divergences_are_still_divergences(env_text: str, tmp_path: Path) -> None:
    """The listed cases must keep differing, and for the recorded reason.

    If Compose ever changes to match us, this fails and the entry should move to
    ``AGREED`` — a divergence that no longer exists is a comment claiming a
    difference the code no longer makes.
    """
    host_env = {**os.environ, "K": _HOST_VALUE}
    theirs = _compose_environment(tmp_path, env_text, host_env=host_env)
    parsed = parse_env_file(env_text)
    reason = DIVERGENT[env_text]

    if theirs is None:
        # Compose refused the whole file. We keep the well-formed lines.
        assert parsed.values == {"K": "v"}, reason
        assert parsed.skipped_lines, reason
        return

    # Compose supplied a value out of the lint host's environment, or an empty
    # string once its fallback chain ran out. We decline to do either.
    assert theirs.get("K") in {_HOST_VALUE, ""}, reason
    assert "K" not in parsed.values, f"{reason} -- but we shipped a value"
    assert "K" in parsed.unresolved, reason


def test_raw_rejects_an_export_prefix_that_the_default_grammar_accepts(
    tmp_path: Path,
) -> None:
    """``format: raw`` has no ``export`` prefix, and the key then has a space.

    Compose refuses the file outright (``variable 'export D' contains
    whitespaces``); we skip the line for the same reason we skip any malformed
    one. Recorded as its own case because it is the sharpest evidence that raw
    is a different grammar rather than a lenient one — the same bytes are valid
    in the default format and fatal here.
    """
    assert _compose_environment(tmp_path, "export D=v", raw=True) is None
    parsed = parse_env_file("export D=v", raw=True)
    assert parsed.values == {}
    assert parsed.skipped_lines == (1,)


def test_resolution_scope_spans_the_sibling_env_and_earlier_files(
    tmp_path: Path,
) -> None:
    """A value may reference a name defined in ``.env`` or an earlier env file.

    Verified against Compose: with ``BASE=/opt`` in the first file, ``P=${BASE}/p``
    in the second ships ``/opt/p``. The reader takes that scope as ``defined``,
    and returns only the keys the file itself writes.
    """
    (tmp_path / "compose.yml").write_text(
        "services:\n  s:\n    image: i\n    env_file: [one.env, two.env]\n",
        encoding="utf-8",
        newline="",
    )
    (tmp_path / "one.env").write_text("BASE=/opt\n", encoding="utf-8", newline="")
    (tmp_path / "two.env").write_text("P=${BASE}/p\n", encoding="utf-8", newline="")
    result = subprocess.run(
        ["docker", "compose", "config"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    theirs = yaml.safe_load(result.stdout)["services"]["s"]["environment"]
    assert theirs == {"BASE": "/opt", "P": "/opt/p"}

    first = parse_env_file("BASE=/opt\n")
    second = parse_env_file("P=${BASE}/p\n", defined=first.values)
    assert dict(first.values) == {"BASE": "/opt"}
    assert dict(second.values) == {"P": "/opt/p"}, (
        "an earlier file's name must be in scope, and must not be returned twice"
    )


def test_a_bare_key_at_eof_without_a_newline_is_a_compose_defect(
    tmp_path: Path,
) -> None:
    """Compose reads a trailing bare key as an *unnamed* variable. We do not.

    ``K`` followed by a newline yields ``K: <host value>``; the same byte
    without the newline yields ``"": K`` — an environment entry with an empty
    name, holding the key text as its value. Reproduced across both spellings
    and with a preceding pair, so it is the missing newline and not the file
    length. Only the bare form is affected: ``K=v`` at EOF is read correctly.

    Not reproduced, and deliberately: an empty-named variable is not a
    configuration any rule can grade, and matching the defect would mean
    inventing a key name no author wrote. Recorded as a test so that a Compose
    release which fixes it is noticed here rather than in a user's report.
    """
    host_env = {**os.environ, "K": _HOST_VALUE}
    assert _compose_environment(tmp_path, "K\n", host_env=host_env) == {
        "K": _HOST_VALUE
    }
    assert _compose_environment(tmp_path, "K", host_env=host_env) == {"": "K"}

    parsed = parse_env_file("K")
    assert parsed.values == {}
    assert parsed.unresolved == frozenset({"K"})
