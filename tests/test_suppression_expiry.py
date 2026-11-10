"""Suppressions with an `expires:` date (ADR-041, #1207).

An entry suppresses through the named UTC day and stops the day after. These
tests pin the config contract (shape, required reason, date format), the
engine's precedence once a date passes, every output surface that carries the
date, and that `fix` judges dates exactly as `check` does.
"""

from __future__ import annotations

import datetime
import json
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli
from compose_lint.config import ConfigError, Expiries, load_config, load_policy
from compose_lint.engine import run_rules
from compose_lint.formatters.text import EXPIRY_NOTICE_DAYS
from compose_lint.models import Severity

if TYPE_CHECKING:
    from pathlib import Path

DAY = datetime.date(2027, 3, 31)

# CL-0002 (privileged) is CRITICAL, so a lapsed entry turns the run red at the
# default threshold; `b` is there so a per-service entry has a neighbour.
COMPOSE = (
    "services:\n"
    "  a:\n    image: nginx:1.27\n    privileged: true\n"
    "  b:\n    image: nginx:1.27\n    privileged: true\n"
)


def _write(tmp_path: Path, config: str, compose: str = COMPOSE) -> Path:
    (tmp_path / "compose.yml").write_text(compose, encoding="utf-8")
    path = tmp_path / ".compose-lint.yml"
    path.write_text(config, encoding="utf-8")
    return path


def _dated(service: str = "a", expires: str = "2027-03-31") -> str:
    return (
        "rules:\n  CL-0002:\n    exclude_services:\n"
        f"      {service}:\n        reason: accepted\n        expires: {expires}\n"
    )


def _cli(
    args: list[str],
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, str, str]:
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("NO_COLOR", "1")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    out, err = capsys.readouterr()
    code = exc.value.code if isinstance(exc.value.code, int) else 1
    return code, out, err


# --- Config: shape, reason and date -----------------------------------------


class TestConfig:
    @pytest.mark.parametrize("written", ["2027-03-31", "'2027-03-31'"])
    def test_a_dated_entry_loads_quoted_or_not(
        self, tmp_path: Path, written: str
    ) -> None:
        policy = load_policy(_write(tmp_path, _dated(expires=written)))
        assert policy.excluded == {"CL-0002": {"a": "accepted"}}
        assert policy.expiries.services == {"CL-0002": {"a": DAY}}

    def test_load_config_keeps_its_shape(self, tmp_path: Path) -> None:
        """Callers that grade without a clock see the reason map only."""
        disabled, overrides, excluded = load_config(_write(tmp_path, _dated()))
        assert (disabled, overrides, excluded) == (
            {},
            {},
            {"CL-0002": {"a": "accepted"}},
        )

    def test_a_mapping_entry_without_a_date_is_a_reason(self, tmp_path: Path) -> None:
        config = "rules:\n  CL-0002:\n    exclude_services:\n      a: {reason: why}\n"
        policy = load_policy(_write(tmp_path, config))
        assert policy.excluded == {"CL-0002": {"a": "why"}}
        assert not policy.expiries

    @pytest.mark.parametrize("reason", ["", "        reason: ''\n"])
    def test_a_dated_entry_needs_a_reason(self, tmp_path: Path, reason: str) -> None:
        config = (
            "rules:\n  CL-0002:\n    exclude_services:\n"
            f"      a:\n{reason}        expires: 2027-03-31\n"
        )
        with pytest.raises(ConfigError, match="needs a 'reason'"):
            load_policy(_write(tmp_path, config))

    @pytest.mark.parametrize(
        "written",
        [
            "2027-03-31T12:00:00",  # a time of day, which YAML makes a datetime
            "'2027-03-31T12:00'",
            "'20270331'",  # fromisoformat accepts it; the config does not
            "'2027-W13-3'",
            "'2027-02-30'",
            "next-week",
            "20270331",  # an int
        ],
    )
    def test_anything_but_a_calendar_date_is_refused(
        self, tmp_path: Path, written: str
    ) -> None:
        with pytest.raises(ConfigError, match="'expires' must be a date"):
            load_policy(_write(tmp_path, _dated(expires=written)))

    def test_a_rule_level_date_dates_the_disable(self, tmp_path: Path) -> None:
        config = (
            "rules:\n  CL-0002:\n    enabled: false\n    reason: accepted\n"
            "    expires: 2027-03-31\n"
        )
        policy = load_policy(_write(tmp_path, config))
        assert policy.disabled == {"CL-0002": "accepted"}
        assert policy.expiries.rules == {"CL-0002": DAY}

    def test_a_rule_level_date_needs_a_reason(self, tmp_path: Path) -> None:
        config = "rules:\n  CL-0002:\n    enabled: false\n    expires: 2027-03-31\n"
        with pytest.raises(ConfigError, match="needs a 'reason'"):
            load_policy(_write(tmp_path, config))

    def test_a_date_with_no_disable_warns(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _write(tmp_path, "rules:\n  CL-0002:\n    expires: 2027-03-31\n")
        assert not load_policy(path).expiries
        assert "has an 'expires' without 'enabled: false'" in capsys.readouterr().err
        with pytest.raises(ConfigError, match="'expires' without"):
            load_policy(path, strict=True)

    def test_a_date_with_no_disable_is_still_validated(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "rules:\n  CL-0002:\n    expires: soon\n")
        with pytest.raises(ConfigError, match="'expires' must be a date"):
            load_policy(path)

    def test_an_unknown_key_in_an_entry_warns(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config = (
            "rules:\n  CL-0002:\n    exclude_services:\n"
            "      a:\n        reason: accepted\n        expire: 2027-03-31\n"
        )
        path = _write(tmp_path, config)
        policy = load_policy(path)
        assert policy.excluded == {"CL-0002": {"a": "accepted"}}
        assert not policy.expiries
        assert "entry 'a' has unknown key 'expire'" in capsys.readouterr().err
        with pytest.raises(ConfigError, match="unknown key 'expire'"):
            load_policy(path, strict=True)


# --- Engine: through the named day, then gone --------------------------------


class TestEngine:
    DATA: dict[str, Any] = {
        "services": {
            "a": {"image": "nginx:1.27", "privileged": True},
            "b": {"image": "nginx:1.27", "privileged": True},
        }
    }

    def _cl0002(self, **kwargs: Any) -> dict[str, Any]:
        found = run_rules(self.DATA, {}, **kwargs)
        return {f.service: f for f in found if f.rule_id == "CL-0002"}

    def test_the_entry_suppresses_through_the_named_day(self) -> None:
        by_service = self._cl0002(
            excluded_services={"CL-0002": {"a": "accepted"}},
            expiries=Expiries(services={"CL-0002": {"a": DAY}}),
            as_of=DAY,
        )
        assert by_service["a"].suppressed
        assert by_service["a"].suppression_expires == DAY
        assert by_service["a"].suppression_expired is None
        assert not by_service["b"].suppressed
        assert by_service["b"].suppression_expired is None

    def test_the_day_after_it_is_a_finding_again(self) -> None:
        by_service = self._cl0002(
            excluded_services={"CL-0002": {"a": "accepted"}},
            expiries=Expiries(services={"CL-0002": {"a": DAY}}),
            as_of=DAY + datetime.timedelta(days=1),
        )
        assert not by_service["a"].suppressed
        assert by_service["a"].suppression_reason is None
        assert by_service["a"].suppression_expires is None
        assert by_service["a"].suppression_expired == DAY

    def test_a_lapsed_disable_falls_through_to_the_exclusions(self) -> None:
        later = DAY + datetime.timedelta(days=30)
        by_service = self._cl0002(
            disabled_rules={"CL-0002": "rule accepted"},
            excluded_services={"CL-0002": {"a": "service accepted"}},
            expiries=Expiries(
                rules={"CL-0002": DAY}, services={"CL-0002": {"a": later}}
            ),
            as_of=DAY + datetime.timedelta(days=1),
        )
        assert by_service["a"].suppressed
        assert by_service["a"].suppression_reason == "service accepted"
        assert by_service["a"].suppression_expires == later
        assert not by_service["b"].suppressed
        assert by_service["b"].suppression_expired == DAY

    def test_an_active_disable_still_wins(self) -> None:
        by_service = self._cl0002(
            disabled_rules={"CL-0002": "rule accepted"},
            excluded_services={"CL-0002": {"a": "service accepted"}},
            expiries=Expiries(rules={"CL-0002": DAY}, services={"CL-0002": {"a": DAY}}),
            as_of=DAY,
        )
        assert by_service["a"].suppression_reason == "rule accepted"
        assert by_service["a"].suppressed_by == "disabled in .compose-lint.yml"

    def test_a_lapsed_disable_lets_a_severity_override_apply(self) -> None:
        by_service = self._cl0002(
            disabled_rules={"CL-0002": "rule accepted"},
            severity_overrides={"CL-0002": Severity.LOW},
            expiries=Expiries(rules={"CL-0002": DAY}),
            as_of=DAY + datetime.timedelta(days=1),
        )
        assert not by_service["a"].suppressed
        assert by_service["a"].severity is Severity.LOW

    def test_an_undated_entry_never_lapses(self) -> None:
        by_service = self._cl0002(
            excluded_services={"CL-0002": {"a": "accepted"}},
            expiries=Expiries(services={"CL-0002": {"b": DAY}}),
            as_of=datetime.date(9999, 12, 31),
        )
        assert by_service["a"].suppressed
        assert by_service["a"].suppression_expires is None


# --- CLI: the gate, --as-of, and every output surface ------------------------


class TestCheck:
    def test_the_gate_turns_red_the_day_after(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        config = (
            "rules:\n  CL-0002:\n    enabled: false\n    reason: accepted\n"
            "    expires: 2027-03-31\n"
        )
        _write(tmp_path, config)
        on_day, _, _ = _cli(
            ["--as-of", "2027-03-31", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        after, _, _ = _cli(
            ["--as-of", "2027-04-01", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert (on_day, after) == (0, 1)

    def test_the_clock_is_utc_today_by_default(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(
            tmp_path,
            _dated("a")
            + "      b:\n        reason: old\n        expires: 2027-03-01\n",
        )
        monkeypatch.setattr(cli, "utc_today", lambda: DAY)
        code, out, _ = _cli(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert code == 1
        found = {
            f["service"]: f
            for f in json.loads(out)["findings"]
            if f["rule_id"] == "CL-0002"
        }
        assert found["a"]["suppressed"] is True
        assert found["b"]["suppression_expired"] == "2027-03-01"

    @pytest.mark.parametrize(
        "value", ["20270331", "2027-03-31T00:00", "2027-02-30", "tomorrow"]
    )
    def test_as_of_takes_the_config_s_date_format_only(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        value: str,
    ) -> None:
        _write(tmp_path, _dated())
        code, _, err = _cli(
            ["--as-of", value, "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert code == 2
        assert "YYYY-MM-DD" in err

    def test_json_carries_each_date_on_its_own_branch(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(
            tmp_path,
            _dated("a")
            + "      b:\n        reason: old\n        expires: 2027-03-01\n",
        )
        _, out, _ = _cli(
            ["--format", "json", "--as-of", "2027-03-20", "compose.yml"],
            tmp_path,
            monkeypatch,
            capsys,
        )
        found = {
            f["service"]: f
            for f in json.loads(out)["findings"]
            if f["rule_id"] == "CL-0002"
        }
        assert found["a"]["suppression_expires"] == "2027-03-31"
        assert "suppression_expired" not in found["a"]
        assert found["b"]["suppressed"] is False
        assert found["b"]["suppression_expired"] == "2027-03-01"
        assert "suppression_expires" not in found["b"]
        assert "suppression_reason" not in found["b"]

    def test_sarif_carries_the_dates_in_property_bags(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(
            tmp_path,
            _dated("a")
            + "      b:\n        reason: old\n        expires: 2027-03-01\n",
        )
        _, out, _ = _cli(
            ["--format", "sarif", "--as-of", "2027-03-20", "compose.yml"],
            tmp_path,
            monkeypatch,
            capsys,
        )
        results = [
            r for r in json.loads(out)["runs"][0]["results"] if r["ruleId"] == "CL-0002"
        ]
        suppressed = [r for r in results if r.get("suppressions")]
        reported = [r for r in results if not r.get("suppressions")]
        assert suppressed[0]["suppressions"][0]["properties"] == {
            "expires": "2027-03-31"
        }
        assert reported[0]["properties"]["suppressionExpired"] == "2027-03-01"

    @pytest.mark.parametrize(
        ("as_of", "shown"),
        [
            ("2027-03-31", "(expires today)"),
            ("2027-03-30", "(expires tomorrow)"),
            ("2027-03-21", "(expires in 10 days)"),
            ("2027-04-01", "(suppression expired 2027-03-31)"),
        ],
    )
    def test_text_shows_the_countdown_even_when_quiet(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        as_of: str,
        shown: str,
    ) -> None:
        _write(tmp_path, _dated())
        _, out, _ = _cli(
            ["-q", "--as-of", as_of, "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert shown in out

    def test_no_countdown_before_the_window(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(tmp_path, _dated())
        early = DAY - datetime.timedelta(days=EXPIRY_NOTICE_DAYS + 1)
        _, out, _ = _cli(
            ["--as-of", early.isoformat(), "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert "expires" not in out
        edge = DAY - datetime.timedelta(days=EXPIRY_NOTICE_DAYS)
        _, out, _ = _cli(
            ["--as-of", edge.isoformat(), "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert f"(expires in {EXPIRY_NOTICE_DAYS} days)" in out

    def test_the_countdown_is_not_a_config_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """ADR-041 §5: an approaching date is the config working, not a fault."""
        _write(tmp_path, _dated() + "      b: accepted\n")
        code, _, err = _cli(
            ["--strict-config", "--as-of", "2027-03-31", "compose.yml"],
            tmp_path,
            monkeypatch,
            capsys,
        )
        assert code == 0
        assert "expires" not in err


class TestFix:
    """`fix` judges dates as `check` does, in both of its grading passes."""

    COMPOSE = "services:\n  a:\n    image: nginx:1.27\n"
    CONFIG = (
        "rules:\n  CL-0003:\n    exclude_services:\n"
        "      a:\n        reason: accepted\n        expires: 2027-03-31\n"
    )

    def test_a_suppressed_finding_is_not_fixed_until_it_lapses(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(tmp_path, self.CONFIG, self.COMPOSE)
        _, before, _ = _cli(
            ["fix", "--as-of", "2027-03-31", "compose.yml"],
            tmp_path,
            monkeypatch,
            capsys,
        )
        _, after, _ = _cli(
            ["fix", "--as-of", "2027-04-01", "compose.yml"],
            tmp_path,
            monkeypatch,
            capsys,
        )
        assert "no-new-privileges" not in before
        assert "no-new-privileges" in after

    def test_apply_fixes_a_lapsed_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The write path, including its verify pass, runs on the released finding."""
        _write(tmp_path, self.CONFIG, self.COMPOSE)
        code, _, err = _cli(
            ["fix", "--apply", "--as-of", "2027-04-01", "compose.yml"],
            tmp_path,
            monkeypatch,
            capsys,
        )
        assert code == 0, err
        assert "no-new-privileges" in (tmp_path / "compose.yml").read_text(
            encoding="utf-8"
        )
