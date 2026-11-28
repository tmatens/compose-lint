"""What the MegaLinter plugin descriptor depends on in compose-lint itself.

MegaLinter runs compose-lint from the descriptor in
mega-linter-plugin-compose-lint/ (docs/megalinter.md). Four things in that
file are claims about this project, and nothing in MegaLinter checks them:

- the release it installs, which has to be the release it is tagged with;
- the regex that counts errors, which reads the last line of the text report,
  and the text report is not a contract (docs/cli.md);
- the regex that recognises a coverage gap, which reads the stderr message;
- the two fixtures, which have to pass and fail as their names say.

ci.yml's `megalinter-plugin` job runs MegaLinter itself. These tests are the
cheap half: they fail on the commit that rewords the summary line, before any
container is pulled.

The plugin folder is not part of the sdist, so the module skips there.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from compose_lint import __version__

PLUGIN = Path(__file__).parent.parent / "mega-linter-plugin-compose-lint"
DESCRIPTOR = PLUGIN / "compose-lint.megalinter-descriptor.yml"

pytestmark = pytest.mark.skipif(
    not DESCRIPTOR.is_file(), reason="the plugin folder is not in the sdist"
)


def _linter() -> dict:
    descriptor = yaml.safe_load(DESCRIPTOR.read_text(encoding="utf-8"))
    (linter,) = descriptor["linters"]
    return linter


def _check(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", "check", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_the_descriptor_installs_this_version() -> None:
    (install,) = _linter()["install"]["dockerfile"]
    assert re.findall(r"compose-lint==(\d+\.\d+\.\d+)", install) == [__version__]


def test_every_install_line_is_a_run_instruction() -> None:
    # MegaLinter executes a plugin's `RUN` lines and ignores everything else.
    for line in _linter()["install"]["dockerfile"]:
        assert line.startswith("RUN ")


@pytest.mark.parametrize(
    "name",
    [
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
        "docker-compose.prod.yml",
        "compose.override.yml",
    ],
)
def test_the_file_name_pattern_takes_compose_files(name: str) -> None:
    descriptor = yaml.safe_load(DESCRIPTOR.read_text(encoding="utf-8"))
    (pattern,) = descriptor["file_names_regex"]
    assert re.fullmatch(pattern, name)


@pytest.mark.parametrize("name", [".compose-lint.yml", "values.yaml", "ci.yml"])
def test_the_file_name_pattern_leaves_other_yaml_alone(name: str) -> None:
    descriptor = yaml.safe_load(DESCRIPTOR.read_text(encoding="utf-8"))
    (pattern,) = descriptor["file_names_regex"]
    assert not re.fullmatch(pattern, name)


def test_the_passing_fixture_has_no_findings() -> None:
    fixture = str(PLUGIN / "fixtures" / "good" / "compose.yml")
    result = _check("--format", "json", "--", fixture)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["findings"] == []


def test_the_error_count_regex_reads_the_summary_line() -> None:
    fixture = str(PLUGIN / "fixtures" / "bad" / "compose.yml")
    as_json = _check("--format", "json", "--", fixture)
    assert as_json.returncode == 1
    failing = [
        finding
        for finding in json.loads(as_json.stdout)["findings"]
        if finding["severity"] in ("high", "critical")
    ]
    assert failing

    as_text = _check("--", fixture)
    assert as_text.returncode == 1
    match = re.search(_linter()["cli_lint_errors_regex"], as_text.stdout)
    assert match, as_text.stdout[-400:]
    assert int(match.group(1)) == len(failing)


def test_the_coverage_gap_regex_reads_the_error(tmp_path: Path) -> None:
    compose = tmp_path / "compose.yml"
    compose.write_text(
        "include:\n  - missing.yml\nservices:\n  web:\n    image: nginx\n",
        encoding="utf-8",
    )
    result = _check("--", str(compose))
    assert result.returncode == 2
    (known,) = _linter()["common_linter_errors"]
    # MegaLinter matches these against stdout and stderr together.
    assert re.search(known["regex"], result.stdout + result.stderr)
