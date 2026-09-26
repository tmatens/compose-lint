"""One path form for every finding, in JSON and SARIF alike (#887, ADR-015).

`file` in JSON and the artifact `uri` in SARIF name the document the evidence
is written in. They used to take whatever spelling the mechanism that found
the document happened to hold: the argv spelling for the primary file and an
overlay, the lint host's absolute path for an `include:` or cross-file
`extends:` document in JSON (relative in SARIF), and the path as the document
wrote it for an `env_file:` target, which names nothing when the run starts
anywhere but the project directory.

The rule: relative to the working directory, joined lexically, with `/`
separators; absolute only when the file lies outside the working directory.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote

from compose_lint._report_path import report_path
from tests._cli_env import cli_env

if TYPE_CHECKING:
    import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _stack(root: Path) -> Path:
    proj = root / "proj"
    (proj / "ext").mkdir(parents=True)
    (proj / "env").mkdir()
    (proj / "compose.yml").write_text(
        "include:\n  - inc.yml\n"
        "services:\n"
        "  web:\n    image: nginx:1.27\n    privileged: true\n"
        "    env_file:\n      - env/settings.txt\n"
        "  api:\n    extends:\n      file: ext/base.yml\n      service: base\n",
        encoding="utf-8",
    )
    (proj / "compose.override.yml").write_text(
        "services:\n  web:\n    cap_add:\n      - SYS_ADMIN\n", encoding="utf-8"
    )
    (proj / "inc.yml").write_text(
        "services:\n  cache:\n    image: redis:7\n    privileged: true\n",
        encoding="utf-8",
    )
    (proj / "ext" / "base.yml").write_text(
        "services:\n  base:\n    image: alpine:3.20\n    privileged: true\n",
        encoding="utf-8",
    )
    (proj / "env" / "settings.txt").write_text(
        "DB_PASSWORD=example-placeholder-value\n", encoding="utf-8"
    )
    return proj


def _check(cwd: Path, target: str, fmt: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "compose_lint", "check", "--format", fmt, target],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), NO_COLOR="1"),
        timeout=120,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return json.loads(proc.stdout)


_EXPECTED = {
    ("web", "CL-0002"): "proj/compose.yml",
    ("web", "CL-0024"): "proj/compose.override.yml",
    ("web", "CL-0020"): "proj/env/settings.txt",
    ("cache", "CL-0002"): "proj/inc.yml",
    ("api", "CL-0002"): "proj/ext/base.yml",
}


def test_json_names_every_document_relative_to_the_working_directory(
    tmp_path: Path,
) -> None:
    _stack(tmp_path)
    doc = _check(tmp_path, "proj/compose.yml", "json")
    files = {(f["service"], f["rule_id"]): f["file"] for f in doc["findings"]}
    for key, expected in _EXPECTED.items():
        assert files[key] == expected, key
    # Every path the run reports resolves from where it ran.
    assert all((tmp_path / path).is_file() for path in files.values())


def test_sarif_and_json_report_the_same_path(tmp_path: Path) -> None:
    _stack(tmp_path)
    as_json = _check(tmp_path, "proj/compose.yml", "json")
    as_sarif = _check(tmp_path, "proj/compose.yml", "sarif")
    json_files = {(f["service"], f["rule_id"]): f["file"] for f in as_json["findings"]}
    for result in as_sarif["runs"][0]["results"]:
        service = result["locations"][0]["logicalLocations"][0]["name"]
        location = result["locations"][0]["physicalLocation"]["artifactLocation"]
        assert location["uriBaseId"] == "SRCROOT"
        key = (service, result["ruleId"])
        assert unquote(location["uri"]) == json_files[key], key


def test_graded_file_uses_the_same_form(tmp_path: Path) -> None:
    _stack(tmp_path)
    doc = _check(tmp_path, "./proj/compose.yml", "json")
    for finding in doc["findings"]:
        assert finding.get("graded_file", "proj/compose.yml") == "proj/compose.yml"
        if "source_file" in finding:
            assert finding["source_file"] == finding["file"]
    primary = [f for f in doc["findings"] if f["file"] == "proj/compose.yml"]
    assert primary, "the argv spelling ./proj/... is normalized, not echoed"


def test_a_file_outside_the_working_directory_is_absolute(tmp_path: Path) -> None:
    proj = _stack(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    doc = _check(elsewhere, "../proj/compose.yml", "json")
    files = {(f["service"], f["rule_id"]): f["file"] for f in doc["findings"]}
    assert files[("cache", "CL-0002")] == str(proj / "inc.yml")
    assert files[("web", "CL-0002")] == str(proj / "compose.yml")
    assert all(os.path.isabs(path) for path in files.values())


def test_report_path_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert report_path("compose.yml") == "compose.yml"
    assert report_path("./a/../compose.yml") == "compose.yml"
    assert report_path(str(tmp_path / "sub" / "x.yml")) == "sub/x.yml"
    # A name that merely starts with two dots is inside the directory.
    assert report_path("..env") == "..env"
    outside = report_path("../other/compose.yml")
    assert os.path.isabs(outside)
    assert outside == str(tmp_path.parent / "other" / "compose.yml")
