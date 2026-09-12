"""Tests for CL-0022: tmpfs mount re-enables exec/suid."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from compose_lint import cli
from compose_lint.engine import run_rules
from compose_lint.fix import apply_edits, collect_edits
from compose_lint.models import Finding, Severity
from compose_lint.parser import loads
from compose_lint.rules.CL0022_tmpfs_insecure_options import (
    DOCKER_REF,
    TmpfsInsecureOptionsRule,
    _without_insecure_options,
)

if TYPE_CHECKING:
    from pathlib import Path

    from compose_lint.models import TextEdit


class TestTmpfsInsecureOptionsRule:
    """Detection of tmpfs mounts that remove a secure default."""

    def setup_method(self) -> None:
        self.rule = TmpfsInsecureOptionsRule()

    def _check(self, body: str) -> list:
        content = f"services:\n  a:\n    image: nginx:1.27\n{body}"
        data, lines = loads(content)
        return list(self.rule.check("a", data["services"]["a"], data, lines))

    def test_detects_exec(self) -> None:
        findings = self._check("    tmpfs:\n      - /tmp:exec\n")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0022"
        assert findings[0].severity.value == "low"
        assert "exec" in findings[0].message

    def test_detects_suid(self) -> None:
        findings = self._check("    tmpfs:\n      - /tmp:suid\n")
        assert len(findings) == 1
        assert "suid" in findings[0].message

    def test_dev_alone_is_clean(self) -> None:
        # ADR-028: `dev` removes nothing observable. The device cgroup refuses
        # every non-allow-listed node regardless of the mount, and the rootfs
        # and /dev never had nodev — so a tmpfs without it grants nothing.
        assert self._check("    tmpfs:\n      - /run:dev\n") == []

    def test_detects_multiple_on_one_entry(self) -> None:
        findings = self._check("    tmpfs:\n      - /tmp:exec,suid,dev\n")
        assert len(findings) == 1
        for tok in ("exec", "suid"):
            assert tok in findings[0].message
        # `dev` rides along in the entry but is not what the finding reports.
        assert "re-enables exec, suid." in findings[0].message

    def test_detects_scalar_form(self) -> None:
        findings = self._check("    tmpfs: /tmp:exec\n")
        assert len(findings) == 1

    def test_bare_tmpfs_is_clean(self) -> None:
        # No options => Docker applies noexec,nosuid,nodev; nothing to flag.
        assert self._check("    tmpfs:\n      - /tmp\n") == []

    def test_explicit_secure_flags_are_clean(self) -> None:
        assert self._check("    tmpfs:\n      - /tmp:noexec,nosuid,nodev\n") == []

    def test_noexec_token_not_confused_with_exec(self) -> None:
        # Whole-token match: 'noexec' must not be read as 'exec'.
        assert self._check("    tmpfs:\n      - /tmp:noexec\n") == []

    def test_benign_size_option_is_clean(self) -> None:
        assert self._check("    tmpfs:\n      - /run:size=64m\n") == []

    def test_exec_alongside_size_still_flags(self) -> None:
        findings = self._check("    tmpfs:\n      - /run:size=64m,exec\n")
        assert len(findings) == 1
        assert "exec" in findings[0].message

    def test_no_tmpfs_is_clean(self) -> None:
        assert self._check("    read_only: true\n") == []

    def test_points_at_the_entry_line(self) -> None:
        findings = self._check("    tmpfs:\n      - /tmp:exec\n")
        # Line 5: services(1) a(2) image(3) tmpfs(4) entry(5).
        assert findings[0].line == 5

    def test_metadata_and_references(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0022"
        assert meta.severity.value == "low"
        assert DOCKER_REF in meta.references


class TestTmpfsInsecureOptionsFix:
    """Tests for the CL-0022 in-scalar fix (ADR-014)."""

    def setup_method(self) -> None:
        self.rule = TmpfsInsecureOptionsRule()

    def _fix(self, content: str, service: str = "a") -> list[TextEdit] | None:
        data, lines = loads(content)
        findings = list(
            self.rule.check(service, data["services"][service], data, lines)
        )
        assert findings, "expected CL-0022 to fire"
        return self.rule.fix(findings[0], data, lines, content)

    def _body(self, body: str) -> str:
        return f"services:\n  a:\n    image: nginx:1.27\n{body}"

    def test_writes_tmpfs(self) -> None:
        assert self.rule.fix_writes_keys() == frozenset({"tmpfs"})

    def test_removes_token_and_keeps_other_options(self) -> None:
        content = self._body("    tmpfs:\n      - /run:exec,size=64m\n")
        edits = self._fix(content)
        assert edits is not None
        assert apply_edits(content, edits) == self._body(
            "    tmpfs:\n      - /run:size=64m\n"
        )

    def test_drops_colon_when_no_option_survives(self) -> None:
        content = self._body("    tmpfs:\n      - /tmp:suid,exec\n")
        edits = self._fix(content)
        assert edits is not None
        assert apply_edits(content, edits) == self._body("    tmpfs:\n      - /tmp\n")

    def test_scalar_form(self) -> None:
        content = self._body("    tmpfs: /scratch:exec\n")
        edits = self._fix(content)
        assert edits is not None
        assert apply_edits(content, edits) == self._body("    tmpfs: /scratch\n")

    def test_edits_only_the_flagged_entry(self) -> None:
        content = self._body(
            "    tmpfs:\n"
            "      - /run:size=64m\n"
            "      - /tmp:exec  # staging\n"
            "      - /var/cache:noexec\n"
        )
        edits = self._fix(content)
        assert edits is not None
        assert apply_edits(content, edits) == self._body(
            "    tmpfs:\n"
            "      - /run:size=64m\n"
            "      - /tmp  # staging\n"
            "      - /var/cache:noexec\n"
        )

    def test_preserves_quoting(self) -> None:
        content = self._body("    tmpfs:\n      - '/tmp:exec,mode=1777'\n")
        edits = self._fix(content)
        assert edits is not None
        assert apply_edits(content, edits) == self._body(
            "    tmpfs:\n      - '/tmp:mode=1777'\n"
        )

    def test_edit_carries_caveat(self) -> None:
        edits = self._fix(self._body("    tmpfs:\n      - /tmp:exec\n"))
        assert edits is not None
        assert edits[0].caveat is not None
        assert "noexec,nosuid" in edits[0].caveat

    def test_refuses_interpolated_entry(self) -> None:
        # The deployed entry is unknown; a `${VAR}` may carry the very option.
        assert (
            self._fix(self._body("    tmpfs:\n      - /tmp:exec,${TMPFS_OPTS}\n"))
            is None
        )

    def test_refuses_flow_style_list(self) -> None:
        # The item has no line of its own; the finding sits on the key line.
        assert self._fix(self._body("    tmpfs: [/tmp:exec]\n")) is None

    def test_refuses_block_scalar_item(self) -> None:
        # The line shows `>-`, not the value: an edit there would not touch the
        # option, and a line-based one could orphan the body (issue #508).
        assert (
            self._fix(self._body("    tmpfs:\n      - >-\n        /tmp:exec\n")) is None
        )

    def test_refuses_wrapped_plain_scalar(self) -> None:
        # YAML folds the continuation into the value; the first line is only
        # part of it.
        content = self._body("    tmpfs:\n      - /tmp:exec,\n        size=64m\n")
        assert self._fix(content) is None

    def test_refuses_merged_service(self) -> None:
        content = (
            "x-base: &base\n"
            "  tmpfs:\n"
            "    - /tmp:exec\n"
            "services:\n"
            "  a:\n"
            "    <<: *base\n"
            "    image: nginx:1.27\n"
        )
        assert self._fix(content) is None

    def test_fix_resolves_finding_and_is_idempotent(self) -> None:
        content = self._body(
            "    tmpfs:\n      - /run:exec,size=64m\n      - /tmp:suid\n"
        )
        data, lines = loads(content)
        findings = run_rules(data, lines)
        result = collect_edits(findings, data, lines, content, only={"CL-0022"})
        assert len(result.edits) == 2
        patched = apply_edits(content, result.edits)
        re_data, re_lines = loads(patched)
        re_findings = run_rules(re_data, re_lines)
        assert [f for f in re_findings if f.rule_id == "CL-0022"] == []
        assert not collect_edits(
            re_findings, re_data, re_lines, patched, only={"CL-0022"}
        ).edits
        # No finding traded for another: the rest of the report is unchanged.
        before = {(f.rule_id, f.service) for f in findings if f.rule_id != "CL-0022"}
        assert {(f.rule_id, f.service) for f in re_findings} == before

    def test_apply_end_to_end(self, tmp_path: Path) -> None:
        target = tmp_path / "compose.yml"
        target.write_text(
            self._body("    read_only: true\n    tmpfs:\n      - /run:exec,size=64m\n"),
            encoding="utf-8",
        )
        with pytest.raises(SystemExit) as exc:
            cli.main(["fix", "--only", "CL-0022", "--apply", str(target)])
        assert exc.value.code == 0
        assert target.read_text(encoding="utf-8") == self._body(
            "    read_only: true\n    tmpfs:\n      - /run:size=64m\n"
        )


class TestTmpfsInsecureOptionsFixRefusals:
    """Defensive refusals on shapes the rule itself never produces.

    The fixer is handed a finding and the document separately, and refuses
    rather than assumes when they disagree -- a stale line, a tmpfs that is
    neither spelling, a line that belongs to another list. Each returns
    ``None`` (ADR-014: refuse, never guess).
    """

    def setup_method(self) -> None:
        self.rule = TmpfsInsecureOptionsRule()

    @staticmethod
    def _finding(line: int | None, service: str = "a") -> Finding:
        return Finding("CL-0022", Severity.LOW, service, "synthetic", line=line)

    def _fix(self, content: str, line: int | None, service: str = "a") -> object:
        data, lines = loads(content)
        return self.rule.fix(self._finding(line, service), data, lines, content)

    def test_refuses_when_services_is_not_a_mapping(self) -> None:
        content = "services:\n  a:\n    tmpfs: /tmp:exec\n"
        data, lines = loads(content)
        assert self.rule.fix(self._finding(3), {"services": []}, lines, content) is None

    def test_refuses_unknown_service(self) -> None:
        content = "services:\n  a:\n    tmpfs: /tmp:exec\n"
        assert self._fix(content, 3, service="ghost") is None

    def test_refuses_finding_without_a_line(self) -> None:
        content = "services:\n  a:\n    tmpfs: /tmp:exec\n"
        assert self._fix(content, None) is None

    def test_refuses_line_outside_the_file(self) -> None:
        content = "services:\n  a:\n    tmpfs: /tmp:exec\n"
        assert self._fix(content, 99) is None

    def test_refuses_tmpfs_of_another_type(self) -> None:
        content = "services:\n  a:\n    tmpfs:\n      path: /tmp:exec\n"
        assert self._fix(content, 3) is None

    def test_refuses_entry_with_nothing_to_remove(self) -> None:
        # A clean entry never gets a finding; handed one anyway, there is no
        # edit to make, and an empty edit is not an edit.
        content = "services:\n  a:\n    tmpfs:\n      - /tmp:noexec\n"
        assert self._fix(content, 4) is None

    def test_refuses_line_that_belongs_to_another_list(self) -> None:
        # The line parses as a sequence item, but no tmpfs entry maps to it.
        content = (
            "services:\n"
            "  a:\n"
            "    ports:\n"
            "      - 8080:80\n"
            "    tmpfs:\n"
            "      - /tmp:exec\n"
        )
        assert self._fix(content, 4) is None


def test_without_insecure_options_grammar() -> None:
    assert _without_insecure_options("/tmp:exec") == "/tmp"
    assert _without_insecure_options("/tmp:exec,suid") == "/tmp"
    assert _without_insecure_options("/run:exec,size=64m") == "/run:size=64m"
    assert (
        _without_insecure_options("/run:size=64m,exec,mode=1777")
        == "/run:size=64m,mode=1777"
    )
    # Whole tokens only: the secure spelling stays.
    assert _without_insecure_options("/tmp:noexec,exec") == "/tmp:noexec"
    # Empty tokens name nothing and go with the rest rather than leaving `/tmp:`.
    assert _without_insecure_options("/tmp:exec,") == "/tmp"
