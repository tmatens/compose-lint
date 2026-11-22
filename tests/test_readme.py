"""The README's two mechanical rules (AGENTS.md, "What the README is for").

PyPI renders README.md as the project page and resolves no relative path, so a
link written for GitHub (`docs/adr/005-...md`) is a dead link on PyPI. Three
such links sat in the README until a review caught them; nothing failed.

The README also tells readers to pin actions by SHA, and a copy-paste snippet
that shows `uses: actions/setup-python@v6` under that advice contradicts it.
That shipped too.

Everything else about the README (what earns a place, the section order) is
a judgement call and is reviewed by hand.
"""

from __future__ import annotations

import re
from pathlib import Path

README = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")

# Inline links and images: [text](target) / ![alt](target). Alt text can hold
# nested backticks and brackets, so match on the `](` boundary instead.
_INLINE_TARGET = re.compile(r"\]\(\s*([^)\s]+)")
# Reference definitions: [label]: target
_REFERENCE_TARGET = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)", re.MULTILINE)
_ABSOLUTE = ("https://", "http://", "mailto:", "#")

_USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.MULTILINE)
_SHA_PINNED = re.compile(r"@[0-9a-f]{40}$")


def _targets() -> list[str]:
    return _INLINE_TARGET.findall(README) + _REFERENCE_TARGET.findall(README)


def test_the_readme_has_links_to_check() -> None:
    # Guards the regexes: a pattern that matched nothing would pass every test.
    assert len(_targets()) > 20


def test_every_readme_link_is_absolute() -> None:
    relative = [t for t in _targets() if not t.startswith(_ABSOLUTE)]
    assert not relative, (
        "README.md is also the PyPI page, which resolves no relative path. "
        f"Use https://github.com/tmatens/compose-lint/blob/main/... for: {relative}"
    )


def test_every_readme_action_is_sha_pinned() -> None:
    uses = _USES.findall(README)
    assert uses, "no `uses:` lines found; has the Action snippet moved?"
    unpinned = [u for u in uses if not _SHA_PINNED.search(u)]
    assert not unpinned, (
        "README snippets pin actions by full commit SHA, as the README tells "
        f"readers to: {unpinned}"
    )
