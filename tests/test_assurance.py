"""The tool must not report a state that is not true.

Four defects of that shape: a fix reported as applied to a file it never
touched, a policy file whose second entry silently replaced the first, a
re-graded finding that looked exactly like one the rule declared that way, and
a line lookup that returned a line belonging to a different service — which let
an edit land that every fixer is required to refuse.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from compose_lint import cli
from compose_lint.config import ConfigError, load_config
from compose_lint.engine import run_rules
from compose_lint.parser import loads

_PRIVILEGED = "services:\n  web:\n    image: nginx:1.27\n    privileged: true\n"
_FIXABLE = (
    "services:\n  web:\n    image: nginx:1.27\n    logging:\n      driver: none\n"
)


# --- VULN-018: a line lookup must never return another node's line --------


def test_a_dotted_service_name_does_not_steal_another_services_line() -> None:
    """`services.web.logging` is spelled by two different nodes."""
    _data, lines = loads(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27\n"
        "    logging:\n"
        "      driver: none\n"
        "  web.logging:\n"
        "    image: nginx:1.27\n"
    )
    # Ambiguous: dropped rather than resolved to whichever was written last.
    assert "services.web.logging" not in lines
    # Everything unambiguous is unaffected.
    assert lines["services.web"] == 2
    assert lines["services.web.image"] == 3
    assert lines["services.web.logging.driver"] == 5


def test_an_ordinary_dotted_service_name_still_gets_its_lines() -> None:
    """17 corpus files use names like `llama.cpp`; only collisions are dropped."""
    _data, lines = loads(
        "services:\n  llama.cpp:\n    image: nginx:1.27\n    privileged: true\n"
    )
    assert lines["services.llama.cpp"] == 2
    assert lines["services.llama.cpp.privileged"] == 4


def test_the_collision_makes_the_fixer_refuse(tmp_path: Path) -> None:
    """Failing closed is the point: no line means no edit."""
    target = tmp_path / "compose.yml"
    target.write_text(
        "services:\n"
        "  web: &base\n"
        "    image: nginx:1.27\n"
        "    logging:\n"
        "      driver: none\n"
        "  web.logging:\n"
        "    <<: *base\n",
        encoding="utf-8",
    )
    before = target.read_bytes()
    with pytest.raises(SystemExit):
        cli.main(["fix", "--only", "CL-0014", "--apply", str(target)])
    assert target.read_bytes() == before


# --- VULN-019: never report a fix applied to a file it did not touch ------


def test_fix_refuses_a_symlink_instead_of_replacing_it(tmp_path: Path) -> None:
    real = tmp_path / "real-compose.yml"
    real.write_text(_FIXABLE, encoding="utf-8")
    link = tmp_path / "docker-compose.yml"
    link.symlink_to(real)

    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", "--apply", str(link)])

    assert exc.value.code != 0
    # The link is still a link, and the deployed file is untouched.
    assert link.is_symlink()
    assert real.read_text(encoding="utf-8") == _FIXABLE


def test_fix_refuses_a_hard_linked_file(tmp_path: Path) -> None:
    original = tmp_path / "docker-compose.yml"
    original.write_text(_FIXABLE, encoding="utf-8")
    second = tmp_path / "also-compose.yml"
    os.link(original, second)

    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", "--apply", str(original)])

    assert exc.value.code != 0
    # Both names still share one inode holding the original content.
    assert original.stat().st_ino == second.stat().st_ino
    assert original.read_text(encoding="utf-8") == _FIXABLE


def test_a_plain_file_is_still_fixed(tmp_path: Path) -> None:
    target = tmp_path / "docker-compose.yml"
    target.write_text(_FIXABLE, encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", "--only", "CL-0014", "--apply", str(target)])
    assert exc.value.code == 0
    assert "driver: none" not in target.read_text(encoding="utf-8")


@pytest.mark.skipif(os.name != "posix", reason="setuid mode bits are POSIX-only")
def test_setuid_is_not_carried_onto_the_replacement(tmp_path: Path) -> None:
    """A newly created inode must not inherit setuid from what it replaces."""
    target = tmp_path / "docker-compose.yml"
    target.write_text(_FIXABLE, encoding="utf-8")
    target.chmod(0o4755)

    with pytest.raises(SystemExit):
        cli.main(["fix", "--only", "CL-0014", "--apply", str(target)])

    mode = target.stat().st_mode
    assert not mode & stat.S_ISUID, oct(mode)
    assert stat.S_IMODE(mode) == 0o755, oct(mode)


# --- VULN-024: a re-graded finding says so --------------------------------


def _finding(source: str, config: dict[str, object] | None = None):
    data, lines = loads(source)
    from compose_lint.models import Severity

    overrides = {"CL-0002": Severity.LOW} if config else None
    findings = run_rules(data, lines, severity_overrides=overrides)
    return next(f for f in findings if f.rule_id == "CL-0002")


def test_an_overridden_severity_records_what_it_was() -> None:
    from compose_lint.models import Severity

    plain = _finding(_PRIVILEGED)
    assert plain.severity is Severity.CRITICAL
    assert plain.severity_overridden_from is None

    graded = _finding(_PRIVILEGED, config={"severity": "low"})
    assert graded.severity is Severity.LOW
    assert graded.severity_overridden_from is Severity.CRITICAL


def test_the_override_is_visible_in_every_output_format(tmp_path: Path) -> None:
    target = tmp_path / "compose.yml"
    target.write_text(_PRIVILEGED, encoding="utf-8")
    config = tmp_path / "downgrade.yml"
    config.write_text("rules:\n  CL-0002:\n    severity: low\n", encoding="utf-8")

    import subprocess
    import sys

    def run(*args: str) -> str:
        return subprocess.run(
            [sys.executable, "-m", "compose_lint", "check", *args, str(target)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            cwd=tmp_path,
            env={
                "PYTHONPATH": str(Path(__file__).resolve().parent.parent / "src"),
                "PATH": "/usr/bin:/bin",
                "NO_COLOR": "1",
            },
            timeout=120,
        ).stdout

    js = json.loads(run("--format", "json", "--config", str(config)))
    entry = next(f for f in js["findings"] if f["rule_id"] == "CL-0002")
    assert entry["severity"] == "low"
    assert entry["severity_overridden_from"] == "critical"

    sarif = json.loads(run("--format", "sarif", "--config", str(config)))
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "CL-0002")
    assert result["properties"]["severityOverriddenFrom"] == "critical"

    assert "severity overridden from critical" in run("--config", str(config))


def test_a_no_op_override_is_not_recorded() -> None:
    """Re-stating a rule's own severity changes nothing, so it claims nothing."""
    from compose_lint.models import Severity

    data, lines = loads(_PRIVILEGED)
    findings = run_rules(data, lines, severity_overrides={"CL-0002": Severity.CRITICAL})
    finding = next(f for f in findings if f.rule_id == "CL-0002")
    assert finding.severity_overridden_from is None


# --- VULN-025: a policy file's second entry must not win in silence -------


def test_duplicate_rule_keys_are_refused(tmp_path: Path) -> None:
    config = tmp_path / ".compose-lint.yml"
    config.write_text(
        "rules:\n"
        "  CL-0002:\n"
        "    enabled: false\n"
        '    reason: "reviewed"\n'
        "  CL-0002:\n"
        "    enabled: true\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="duplicate key"):
        load_config(config)


def test_a_config_without_duplicates_still_loads(tmp_path: Path) -> None:
    config = tmp_path / ".compose-lint.yml"
    config.write_text(
        "rules:\n"
        "  CL-0002:\n"
        "    enabled: false\n"
        '    reason: "reviewed"\n'
        "  CL-0004:\n"
        "    severity: low\n",
        encoding="utf-8",
    )
    disabled, overrides, _excluded = load_config(config)
    assert disabled == {"CL-0002": "reviewed"}
    assert [r.value for r in overrides.values()] == ["low"]
