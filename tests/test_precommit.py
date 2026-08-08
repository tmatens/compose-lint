"""Tests that the 'files' regex in .pre-commit-hooks.yaml does not match
.compose-lint.yml (#465).

Errors if file a .pre-commit-hooks.yaml file is not found in the root of
the repository.

Checks that there at least one hook present in the config file. Allowing
for additional to be added, e.g. using docker in the future.

Reads the configured regexes and checks then against list of file paths that
should/shouldn't match.
"""

from __future__ import annotations

import re

import pytest
import yaml

TEST_DATA = [
    # (string, expected)
    (".compose-lint.yml", False),
    (".compose-lint.yaml", False),
    ("foo/.compose-lint.yml", False),
    ("dev-compose.yml", False),
    ("docker-compose.yaml", True),
    ("compose.yaml", True),
    ("docker-compose.yml", True),
    ("compose.yml", True),
    ("foo/docker-compose.yml", True),
    ("foo/bar/compose.yml", True),
    ("foo/bar/baz/compose-test.yml", True),
    ("foo/bar/baz/docker-compose-test.yaml", True),
]


@pytest.fixture(scope="module")
def _load_patterns_from_config(pytestconfig):
    precommit_file = pytestconfig.rootpath / ".pre-commit-hooks.yaml"
    with open(precommit_file) as f:
        config = yaml.safe_load(f)
        return {item["id"]: re.compile(item["files"]) for item in config}


def test_precommit_config_has_at_least_one_entry(_load_patterns_from_config):
    # Verifies that at least one hook is configured.
    assert len(_load_patterns_from_config) > 0


@pytest.mark.parametrize("string, expected", TEST_DATA)
def test_regex_only_match_valid_compose_files(
    _load_patterns_from_config, string, expected
):
    # Verifies the extracted pre-commit regex against target file paths.
    # Iterates over multiple hooks if more than one is configured.
    for id, pattern in _load_patterns_from_config.items():
        match = pattern.search(string)
        is_match = match is not None

        assert is_match == expected, (
            f"Linter '{id}' failed for path '{string}'. "
            f"Expected match to be {expected}."
        )
