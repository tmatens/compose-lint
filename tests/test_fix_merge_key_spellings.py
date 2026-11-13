"""A merge key is refused by ``fix`` however it is spelled (#1252).

Whether a mapping key is a merge key is its YAML tag, not its text. The guard
every fixer shares read the line for a leading ``<<``, so ``!!merge <<``, the
verbatim tag and the explicit form ``? <<`` inherited from an anchor like the
plain spelling and were edited all the same. The answer now comes from the
composed node tree, with the text test kept beside it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from compose_lint import cli
from compose_lint._lines import split_lines
from compose_lint._yaml_edit import has_merge_key_child, is_anchored_or_merged

if TYPE_CHECKING:
    from pathlib import Path

# One service that every fixer with a shared guard has something to do for:
# CL-0003 and CL-0009 (security_opt), CL-0005 (ports), CL-0014 (logging) and
# CL-0022 (tmpfs).
DOCUMENT = """x-base: &base
  logging:
    driver: json-file
  read_only: true
services:
  svc:
{merge}
    image: nginx:1.27
    logging:
      driver: none
    security_opt:
      - seccomp:unconfined
    ports:
      - "8080:80"
    tmpfs:
      - /run:exec
"""

MERGES = {
    "plain": "    <<: *base",
    "tagged": "    !!merge <<: *base",
    "verbatim": "    !<tag:yaml.org,2002:merge> <<: *base",
    "explicit": "    ? <<\n    : *base",
    "explicit-tagged": "    ? !!merge <<\n    : *base",
    "list": "    !!merge <<: [*base]",
}
NOT_MERGES = {
    "quoted": '    "<<": 1',
    "single-quoted": "    '<<': 1",
    "tagged-str": "    !!str <<: 1",
    "none": "    labels: {a: b}",
}
SERVICE_LINE = 6


@pytest.mark.parametrize("merge", MERGES.values(), ids=MERGES.keys())
def test_every_spelling_of_a_merge_key_is_one(merge: str) -> None:
    lines = split_lines(DOCUMENT.format(merge=merge))
    assert lines[SERVICE_LINE - 1] == "  svc:\n"
    assert has_merge_key_child(lines, SERVICE_LINE)
    assert is_anchored_or_merged(lines, SERVICE_LINE)


@pytest.mark.parametrize("key", NOT_MERGES.values(), ids=NOT_MERGES.keys())
def test_a_key_that_only_looks_like_one_is_not(key: str) -> None:
    lines = split_lines(DOCUMENT.format(merge=key))
    assert not has_merge_key_child(lines, SERVICE_LINE)


def test_only_the_mapping_that_holds_the_key_is_refused() -> None:
    text = (
        "x-base: &base\n  read_only: true\n"
        "services:\n"
        "  merged:\n    !!merge <<: *base\n    image: nginx:1.27\n"
        "  plain:\n    image: nginx:1.27\n    logging:\n      driver: none\n"
    )
    lines = split_lines(text)
    assert has_merge_key_child(lines, 4)
    assert not has_merge_key_child(lines, 7)
    assert not has_merge_key_child(lines, 9)


def test_a_fragment_that_does_not_compose_keeps_the_text_test() -> None:
    # `*base` has no anchor here, so there is no tree to ask.
    assert has_merge_key_child(["web:\n", "  <<: *base\n"], 1)
    assert not has_merge_key_child(["web:\n", "  image: *base\n"], 1)


def test_an_aliased_mapping_is_walked_once() -> None:
    text = (
        "x-a: &a\n  !!merge <<: {read_only: true}\n  image: nginx:1.27\n"
        "services:\n  one: *a\n  two: *a\n"
    )
    lines = split_lines(text)
    assert has_merge_key_child(lines, 1)
    assert not has_merge_key_child(lines, 4)


def _apply(
    tmp_path: Path,
    text: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[str, str]:
    compose = tmp_path / "compose.yml"
    compose.write_text(text, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NO_COLOR", "1")
    capsys.readouterr()
    with pytest.raises(SystemExit):
        cli.main(["fix", "--apply", "compose.yml"])
    return compose.read_text(encoding="utf-8"), capsys.readouterr().err


@pytest.mark.parametrize("merge", MERGES.values(), ids=MERGES.keys())
def test_fix_edits_nothing_in_a_service_that_inherits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    merge: str,
) -> None:
    text = DOCUMENT.format(merge=merge)
    after, err = _apply(tmp_path, text, monkeypatch, capsys)
    assert after == text
    assert "nothing fix can apply automatically" in err


@pytest.mark.parametrize("key", NOT_MERGES.values(), ids=NOT_MERGES.keys())
def test_fix_still_edits_a_service_that_does_not(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    key: str,
) -> None:
    text = DOCUMENT.format(merge=key)
    after, _ = _apply(tmp_path, text, monkeypatch, capsys)
    assert after != text
    assert "driver: none" not in after
