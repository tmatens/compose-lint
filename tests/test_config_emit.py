"""Tests for the starter-config emitter (ADR-011)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

import yaml

from compose_lint.config_emit import render_config
from compose_lint.models import Finding, Severity


def _finding(rule_id: str, service: str, severity: Severity) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        service=service,
        message="m",
    )


class TestRenderConfig:
    def test_emits_service_level_exclude_services(self) -> None:
        out = render_config([_finding("CL-0001", "web", Severity.CRITICAL)])
        data = yaml.safe_load(out)
        # Never a global enabled: false — the suppression names the service.
        assert data == {"rules": {"CL-0001": {"exclude_services": {"web": ANY_REASON}}}}

    def test_rules_ordered_by_severity_then_id(self) -> None:
        findings = [
            _finding("CL-0007", "web", Severity.MEDIUM),
            _finding("CL-0001", "web", Severity.CRITICAL),
            _finding("CL-0002", "web", Severity.CRITICAL),
            _finding("CL-0008", "web", Severity.HIGH),
        ]
        out = render_config(findings)
        order = [
            line.strip().rstrip(":").split(":")[0].split()[0]
            for line in out.splitlines()
            if line.startswith("  CL-")
        ]
        # CRITICAL first (ties broken by id), then HIGH, then MEDIUM.
        assert order == ["CL-0001", "CL-0002", "CL-0008", "CL-0007"]

    def test_services_sorted_within_a_rule(self) -> None:
        findings = [
            _finding("CL-0001", "zebra", Severity.HIGH),
            _finding("CL-0001", "alpha", Severity.HIGH),
        ]
        data = yaml.safe_load(render_config(findings))
        assert list(data["rules"]["CL-0001"]["exclude_services"]) == ["alpha", "zebra"]

    def test_duplicate_rule_service_pairs_collapse(self) -> None:
        # A rule firing twice on the same service (e.g. two ports) yields one
        # exclusion entry, not a duplicate.
        findings = [
            _finding("CL-0005", "web", Severity.HIGH),
            _finding("CL-0005", "web", Severity.HIGH),
        ]
        data = yaml.safe_load(render_config(findings))
        assert list(data["rules"]["CL-0005"]["exclude_services"]) == ["web"]

    def test_unusual_service_name_is_quoted_and_round_trips(self) -> None:
        # A service name with a colon would break an unquoted YAML scalar.
        findings = [_finding("CL-0001", "weird: name", Severity.HIGH)]
        out = render_config(findings)
        data = yaml.safe_load(out)
        assert "weird: name" in data["rules"]["CL-0001"]["exclude_services"]

    def test_includes_header_and_severity_annotations(self) -> None:
        out = render_config([_finding("CL-0001", "web", Severity.CRITICAL)])
        assert out.startswith("# .compose-lint.yml")
        assert "CRITICAL" in out

    def test_all_severities_emitted(self) -> None:
        # init does not gate on severity: a CRITICAL becomes an active
        # suppression like any other finding.
        findings = [
            _finding("CL-0001", "web", Severity.CRITICAL),
            _finding("CL-0007", "web", Severity.LOW),
        ]
        data = yaml.safe_load(render_config(findings))
        assert set(data["rules"]) == {"CL-0001", "CL-0007"}


ANY_REASON = "TODO: justify or fix"


def test_a_yaml_boolean_service_name_round_trips_through_load_config(
    tmp_path: Path,
) -> None:
    """`init` wrote a config `check` then refused, breaking that directory.

    `_PLAIN_SCALAR` says the *characters* are safe; it did not say the *token*
    was. YAML 1.1 resolves `no`, `yes`, `on`, `123`, `1.5` and `null` to
    non-strings, and every one matches an identifier-ish pattern while being a
    legal Compose service name. Emitted unquoted, such a name reloaded as a
    bool or an int, and `config.py` requires `exclude_services` keys to be
    strings — so `init` reported success and `check` exited 2.
    """
    import yaml

    from compose_lint.config import load_config

    names = ["no", "yes", "on", "off", "true", "123", "1.5", "null", "web"]
    findings = [
        Finding(
            rule_id="CL-0002",
            severity=Severity.CRITICAL,
            service=name,
            message="m",
            fix="f",
            line=1,
        )
        for name in names
    ]
    config = tmp_path / ".compose-lint.yml"
    config.write_text(render_config(findings), encoding="utf-8")

    reloaded = yaml.safe_load(config.read_text(encoding="utf-8"))
    keys = reloaded["rules"]["CL-0002"]["exclude_services"]
    assert all(isinstance(k, str) for k in keys), f"non-string keys: {keys}"
    assert set(keys) == set(names)

    load_config(config, strict=True)  # must not raise
