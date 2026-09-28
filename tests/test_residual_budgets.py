"""Two costs left after the line map and substitution were bounded.

- The line map's keys spell whole paths, so a service name thousands of
  characters long is repeated in every key under it: an 8,000-character name
  over 60,000 labels made a 1 MB file cost 600 MB. Key characters now have a
  budget, and scalar leaves are no longer queued with their full paths.
- Past the substitution budget, each distinct reference to a large `.env`
  value was still built in full before being discarded.
"""

from __future__ import annotations

from typing import Any

from compose_lint import parser
from compose_lint.parser import _cannot_fit, _collect_lines, loads


def test_key_characters_stop_at_the_budget(monkeypatch: Any) -> None:
    monkeypatch.setattr(parser, "MAX_LINE_KEY_CHARS", 1000)
    name = ".".join(["a"] * 200)  # a 399-character service name
    labels = "".join(f"      K{i}: v\n" for i in range(50))
    text = f"services:\n  ? '{name}'\n  :\n    image: nginx:1.27\n    labels:\n{labels}"
    data, lines = loads(text)
    assert len(data["services"][name]["labels"]) == 50
    assert sum(len(key) for key in lines) <= 1000
    assert "services" in lines


def test_ordinary_documents_keep_every_line() -> None:
    _, lines = loads(
        "services:\n  web:\n    image: nginx:1.27\n    labels:\n      a: b\n"
    )
    assert lines["services.web.labels.a"] == 5


def test_scalar_leaves_are_still_recorded() -> None:
    """Not queuing a scalar must not lose its own line."""
    shared: dict[Any, Any] = {"a": "x", "b": ["y"]}
    lines = _collect_lines({"one": shared})
    assert lines == {}  # no line metadata on a hand-built dict
    _, parsed = loads("x:\n  a: 1\n  b: [2]\nservices:\n  w:\n    image: i\n")
    assert parsed["x.a"] == 2
    assert parsed["x.b[0]"] == 3


class TestCannotFit:
    def test_a_value_bigger_than_what_is_left(self) -> None:
        assert _cannot_fit("${X}b", {"X": "a" * 100}, remaining=50)

    def test_a_value_that_fits(self) -> None:
        assert not _cannot_fit("${X}b", {"X": "a" * 100}, remaining=500)

    def test_an_unsupplied_name_costs_nothing(self) -> None:
        assert not _cannot_fit("${Y:-default}", {"X": "a" * 100}, remaining=0)
