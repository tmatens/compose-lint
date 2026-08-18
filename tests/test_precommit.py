"""Tests for the file-matching config in ``.pre-commit-hooks.yaml`` (#465).

The hook's effective selection is ``files`` minus ``exclude``, so both patterns
are read here. Asserting against ``files`` alone would miss the dotless
``compose-lint.yml`` spelling that ``exclude`` exists to catch: ``compose-lint
init -o compose-lint.yml`` makes that a legal config filename, and linting our
own config is what made the hook fail in #465.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
import yaml

# pre-commit's defaults when a hook omits the key (its MANIFEST_HOOK_DICT):
# an empty ``files`` matches every path, ``^$`` excludes nothing.
DEFAULT_FILES = ""
DEFAULT_EXCLUDE = "^$"

# (path, is selected for linting by the hook)
TEST_DATA = [
    # compose-lint's own config is never a compose file — both spellings
    # (dotted and dotless), both extensions, root and nested.
    (".compose-lint.yml", False),
    (".compose-lint.yaml", False),
    ("foo/.compose-lint.yml", False),
    ("compose-lint.yml", False),
    ("compose-lint.yaml", False),
    ("foo/compose-lint.yml", False),
    # Prefixed names are outside the pattern (documented narrowing).
    ("dev-compose.yml", False),
    # Standard compose filenames, root and nested.
    ("docker-compose.yaml", True),
    ("docker-compose.yml", True),
    ("compose.yaml", True),
    ("compose.yml", True),
    ("foo/docker-compose.yml", True),
    ("foo/bar/compose.yml", True),
    # Environment-specific suffixes still match.
    ("foo/bar/baz/compose-test.yml", True),
    ("foo/bar/baz/docker-compose-test.yaml", True),
]


@pytest.fixture(scope="module")
def hooks(pytestconfig: pytest.Config) -> list[dict[str, Any]]:
    """The parsed hook definitions from the repo's ``.pre-commit-hooks.yaml``."""
    manifest = pytestconfig.rootpath / ".pre-commit-hooks.yaml"
    with open(manifest) as f:
        loaded: list[dict[str, Any]] = yaml.safe_load(f)
    return loaded


@pytest.fixture(scope="module")
def hook_patterns(
    hooks: list[dict[str, Any]],
) -> dict[str, tuple[re.Pattern[str], re.Pattern[str]]]:
    """Map each hook id to its compiled ``(files, exclude)`` pair."""
    return {
        hook["id"]: (
            re.compile(hook.get("files", DEFAULT_FILES)),
            re.compile(hook.get("exclude", DEFAULT_EXCLUDE)),
        )
        for hook in hooks
    }


def test_manifest_declares_at_least_one_hook(hooks: list[dict[str, Any]]) -> None:
    # Guards the fixtures below against silently testing nothing.
    assert hooks


def test_default_args_end_with_the_option_terminator(
    hooks: list[dict[str, Any]],
) -> None:
    """The trailing ``--`` keeps a flag-shaped repository path a path.

    pre-commit runs ``entry + args + filenames``, so without the terminator
    a path like ``--config=cfgdir/compose.yml`` is absorbed as a flag and
    an attacker-authored policy is installed for the run. A user's own
    ``args:`` replaces this default entirely; ci.yml's ``precommit-smoke``
    pins both override shapes live.
    """
    for hook in hooks:
        args = hook.get("args", [])
        assert args and args[-1] == "--", (
            f"hook '{hook['id']}' default args must end with '--'"
        )


def test_every_hook_declares_a_files_pattern(hooks: list[dict[str, Any]]) -> None:
    # pre-commit defaults an absent ``files`` to "", which matches every path
    # the ``types`` filter admits — every YAML file in the repo, for us.
    for hook in hooks:
        assert hook.get("files"), f"hook '{hook['id']}' has no 'files' pattern"


@pytest.mark.parametrize("path, expected", TEST_DATA)
def test_hook_selects_only_compose_files(
    hook_patterns: dict[str, tuple[re.Pattern[str], re.Pattern[str]]],
    path: str,
    expected: bool,
) -> None:
    # Mirrors pre-commit's own filtering: a path is passed to the hook when
    # ``files`` matches it and ``exclude`` does not.
    for hook_id, (files, exclude) in hook_patterns.items():
        selected = files.search(path) is not None and exclude.search(path) is None

        assert selected == expected, (
            f"Hook '{hook_id}' failed for path '{path}'. "
            f"Expected selected to be {expected}."
        )
