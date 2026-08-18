"""The [Unreleased] shape rules that gate PRs and release-prep (#593).

``scripts/check_changelog_unreleased.py`` is the single definition used by
both ci.yml's changelog-gate and release-prep.yml. These are the first
tests the shape rules have had: before extraction they lived in a workflow
heredoc, where verifying a change meant regex-extracting the script and
running it by hand against synthetic changelogs.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "check_changelog_unreleased",
    REPO_ROOT / "scripts" / "check_changelog_unreleased.py",
)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
validate = _mod.validate


def _doc(body: str) -> str:
    return f"# Changelog\n\n## [Unreleased]\n{body}\n## [0.19.0] - 2026-08-18\n"


def test_a_well_formed_section_passes() -> None:
    body = "\n### Added\n\n- a thing\n\n### Fixed\n\n- a fix\n"
    assert validate(_doc(body), require_content=True) is None


def test_the_real_changelog_passes() -> None:
    text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert validate(text, require_content=False) is None


def test_missing_unreleased_section_fails() -> None:
    error = validate("# Changelog\n\n## [0.19.0]\n", require_content=False)
    assert error is not None and "No '## [Unreleased]'" in error


def test_empty_section_fails_only_when_content_is_required() -> None:
    doc = _doc("\n")
    assert validate(doc, require_content=False) is None
    error = validate(doc, require_content=True)
    assert error is not None and "empty" in error


def test_duplicate_sections_fail() -> None:
    body = "\n### Fixed\n\n- one\n\n### Changed\n\n- two\n\n### Fixed\n\n- three\n"
    error = validate(_doc(body), require_content=True)
    assert error is not None and "duplicate" in error and "Fixed" in error


def test_an_unknown_heading_fails() -> None:
    # The 0.19.0 dispatch failure before #591 taught the vocabulary; an
    # actually-unknown heading must still be refused.
    body = "\n### Awesome stuff\n\n- a thing\n"
    error = validate(_doc(body), require_content=True)
    assert error is not None and "unrecognised" in error


def test_known_limitations_is_recognised_and_ordered_last() -> None:
    body = "\n### Fixed\n\n- a fix\n\n### Known limitations\n\n- an edge\n"
    assert validate(_doc(body), require_content=True) is None


def test_out_of_order_sections_fail() -> None:
    body = "\n### Fixed\n\n- a fix\n\n### Added\n\n- a thing\n"
    error = validate(_doc(body), require_content=True)
    assert error is not None and "out of order" in error


def test_versioned_upgrading_heading_is_normalised() -> None:
    body = "\n### Upgrading from 0.18.x\n\n- do this\n\n### Added\n\n- a thing\n"
    assert validate(_doc(body), require_content=True) is None


def test_a_heading_inside_a_fenced_block_is_ignored() -> None:
    body = "\n### Added\n\n- a thing\n\n```markdown\n### Bogus\n```\n"
    assert validate(_doc(body), require_content=True) is None
