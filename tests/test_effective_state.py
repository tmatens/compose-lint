"""Rules grade the state Docker actually starts the container in (#884).

`security_opt` is applied entry by entry, in order, so for a key assigned per
entry the last one wins; `no-new-privileges` is read with Go's
`strconv.ParseBool`; a numeric `user:` with Go's `strconv.Atoi`; and the
daemon compares `pid`/`ipc` modes case-sensitively. Grading any of these as a
set, or case-folded, reports a hardened container red or a weakened one green.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from compose_lint.engine import run_rules
from compose_lint.parser import load_compose, loads

if TYPE_CHECKING:
    from pathlib import Path


def _rule_hits(text: str, rule_id: str) -> dict[str, list[int | None]]:
    data, lines = loads(text)
    out: dict[str, list[int | None]] = {}
    for finding in run_rules(data, lines):
        if finding.rule_id == rule_id:
            out.setdefault(finding.service or "", []).append(finding.line)
    return out


def _security_opt(*entries: str) -> str:
    body = "".join(f"      - {entry}\n" for entry in entries)
    return f"services:\n  web:\n    image: alpine:3.20\n    security_opt:\n{body}"


class TestNoNewPrivilegesLastWins:
    def test_a_later_false_undoes_an_earlier_true(self) -> None:
        text = _security_opt("no-new-privileges:true", "no-new-privileges:false")
        assert "web" in _rule_hits(text, "CL-0003")

    def test_a_later_true_hardens_after_an_earlier_false(self) -> None:
        text = _security_opt("no-new-privileges:false", "no-new-privileges=true")
        assert _rule_hits(text, "CL-0003") == {}

    def test_the_bare_form_counts_as_true(self) -> None:
        text = _security_opt("no-new-privileges:false", "no-new-privileges")
        assert _rule_hits(text, "CL-0003") == {}

    def test_extends_un_hardening_a_base_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "compose.yml"
        path.write_text(
            "services:\n"
            "  base:\n    image: alpine:3.20\n"
            "    security_opt: [no-new-privileges:true]\n"
            "  web:\n    extends: base\n"
            "    security_opt: [no-new-privileges:false]\n",
            encoding="utf-8",
        )
        data, lines = load_compose(path)
        flagged = {f.service for f in run_rules(data, lines) if f.rule_id == "CL-0003"}
        assert flagged == {"web"}


class TestNoNewPrivilegesParseBool:
    @pytest.mark.parametrize("value", ["1", "t", "T", "TRUE", "true", "True"])
    def test_parsebool_true_spellings_harden(self, value: str) -> None:
        text = _security_opt(f"no-new-privileges:{value}")
        assert _rule_hits(text, "CL-0003") == {}

    @pytest.mark.parametrize("value", ["0", "f", "F", "FALSE", "false", "False"])
    def test_parsebool_false_spellings_do_not(self, value: str) -> None:
        text = _security_opt(f"no-new-privileges:{value}")
        assert "web" in _rule_hits(text, "CL-0003")

    def test_a_value_parsebool_refuses_does_not_harden(self) -> None:
        text = _security_opt("no-new-privileges:yes")
        assert "web" in _rule_hits(text, "CL-0003")


class TestProfileLastWins:
    def test_a_later_builtin_re_enables_seccomp(self) -> None:
        text = _security_opt("seccomp:unconfined", "seccomp:builtin")
        assert _rule_hits(text, "CL-0009") == {}

    def test_a_later_unconfined_disables_seccomp(self) -> None:
        text = _security_opt("seccomp:builtin", "seccomp=unconfined")
        assert _rule_hits(text, "CL-0009") == {"web": [6]}

    def test_apparmor_is_last_wins_too(self) -> None:
        assert (
            _rule_hits(
                _security_opt("apparmor:unconfined", "apparmor:docker-default"),
                "CL-0009",
            )
            == {}
        )
        assert _rule_hits(
            _security_opt("apparmor:docker-default", "apparmor:unconfined"), "CL-0009"
        ) == {"web": [6]}

    def test_keys_are_independent(self) -> None:
        text = _security_opt(
            "seccomp:unconfined", "apparmor:unconfined", "seccomp:builtin"
        )
        assert _rule_hits(text, "CL-0009") == {"web": [6]}

    def test_every_disable_is_flagged_when_the_last_is_one(self) -> None:
        # Removing only the last would promote the one before it.
        text = _security_opt("seccomp:unconfined", "seccomp:unconfined")
        assert _rule_hits(text, "CL-0009") == {"web": [5, 6]}

    def test_label_disable_is_not_last_wins(self) -> None:
        # Label options accumulate; `disable` anywhere among them disables
        # SELinux labelling, so a later label option does not undo it.
        text = _security_opt("label:disable", "label:type:container_t")
        assert _rule_hits(text, "CL-0009") == {"web": [5]}


class TestNumericRoot:
    @pytest.mark.parametrize("user", ["000", "+0", "-0", "00:1000", "+000:root"])
    def test_atoi_zero_is_root(self, user: str) -> None:
        text = f'services:\n  web:\n    image: alpine:3.20\n    user: "{user}"\n'
        assert "web" in _rule_hits(text, "CL-0018")

    @pytest.mark.parametrize("user", ["010", "+1000", "0x0", "0_0", "٠", "1000:0"])
    def test_other_numbers_are_not_root(self, user: str) -> None:
        text = f'services:\n  web:\n    image: alpine:3.20\n    user: "{user}"\n'
        assert _rule_hits(text, "CL-0018") == {}


class TestNamespaceModeCase:
    @pytest.mark.parametrize("key", ["pid", "ipc"])
    def test_lowercase_host_is_flagged(self, key: str) -> None:
        text = f"services:\n  web:\n    image: alpine:3.20\n    {key}: host\n"
        assert "web" in _rule_hits(text, "CL-0010")

    @pytest.mark.parametrize("key", ["pid", "ipc"])
    @pytest.mark.parametrize("value", ["HOST", "Host"])
    def test_other_cases_are_refused_by_docker(self, key: str, value: str) -> None:
        text = f"services:\n  web:\n    image: alpine:3.20\n    {key}: {value}\n"
        assert _rule_hits(text, "CL-0010") == {}
