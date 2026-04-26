"""Tests that the parser records per-item line numbers for sequence items."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "compose.yml"
    p.write_text(body)
    return p


def test_ports_per_item_lines(tmp_path: Path) -> None:
    from compose_lint.parser import load_compose

    body = (
        "services:\n"
        "  web:\n"
        "    image: nginx\n"
        "    ports:\n"
        "      - 80:80\n"
        "      - 443:443\n"
        "      - 8080:8080\n"
    )
    _, lines = load_compose(_write(tmp_path, body))
    assert lines["services.web.ports"] == 4
    assert lines["services.web.ports[0]"] == 5
    assert lines["services.web.ports[1]"] == 6
    assert lines["services.web.ports[2]"] == 7


def test_volumes_short_and_long_syntax(tmp_path: Path) -> None:
    from compose_lint.parser import load_compose

    body = (
        "services:\n"
        "  app:\n"
        "    image: x\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n"
        "      - type: bind\n"
        "        source: /etc\n"
        "        target: /etc\n"
    )
    _, lines = load_compose(_write(tmp_path, body))
    assert lines["services.app.volumes[0]"] == 5
    # Long-syntax item: line points at the start of the dict (the line
    # carrying the first `- type:` mapping pair).
    assert lines["services.app.volumes[1]"] == 6


def test_devices_cap_add_security_opt(tmp_path: Path) -> None:
    from compose_lint.parser import load_compose

    body = (
        "services:\n"
        "  s:\n"
        "    image: x\n"
        "    cap_add:\n"
        "      - SYS_ADMIN\n"
        "      - NET_ADMIN\n"
        "    devices:\n"
        "      - /dev/sda:/dev/sda\n"
        "    security_opt:\n"
        "      - seccomp:unconfined\n"
        "      - apparmor:unconfined\n"
    )
    _, lines = load_compose(_write(tmp_path, body))
    assert lines["services.s.cap_add[0]"] == 5
    assert lines["services.s.cap_add[1]"] == 6
    assert lines["services.s.devices[0]"] == 8
    assert lines["services.s.security_opt[0]"] == 10
    assert lines["services.s.security_opt[1]"] == 11


def test_nested_sequences(tmp_path: Path) -> None:
    """Sequences nested inside sequences via long-syntax dicts."""
    from compose_lint.parser import load_compose

    body = (
        "services:\n"
        "  s:\n"
        "    image: x\n"
        "    ports:\n"
        "      - target: 80\n"
        "        published: 8080\n"
        "      - target: 443\n"
        "        published: 8443\n"
    )
    _, lines = load_compose(_write(tmp_path, body))
    assert lines["services.s.ports[0]"] == 5
    assert lines["services.s.ports[1]"] == 7


def test_anchored_sequence_alias(tmp_path: Path) -> None:
    """Aliased lists share the same id() and the same line entries.

    The first prefix that reaches the list wins; the alias path resolves
    to the same numbers — that's expected and correct because the items
    are literally on the lines defined by the anchor.
    """
    from compose_lint.parser import load_compose

    body = (
        "x-common-ports: &cports\n"
        "  - 80:80\n"
        "  - 443:443\n"
        "services:\n"
        "  a:\n"
        "    image: x\n"
        "    ports: *cports\n"
        "  b:\n"
        "    image: x\n"
        "    ports: *cports\n"
    )
    _, lines = load_compose(_write(tmp_path, body))
    # Both services point at the same list — the visited set means
    # only one prefix gets [N] entries, but the parent-key entry still
    # resolves for both. This pins behavior so future visited-set work
    # doesn't silently regress.
    assert lines["services.a.ports"] == 7 or lines["services.b.ports"] == 10
    # At least one alias path exposes per-item lines.
    has_a_items = "services.a.ports[0]" in lines
    has_b_items = "services.b.ports[0]" in lines
    assert has_a_items or has_b_items


def test_empty_sequence(tmp_path: Path) -> None:
    from compose_lint.parser import load_compose

    body = "services:\n  s:\n    image: x\n    cap_add: []\n"
    _, lines = load_compose(_write(tmp_path, body))
    assert lines["services.s.cap_add"] == 4
    assert "services.s.cap_add[0]" not in lines


def test_scalar_items_get_lines(tmp_path: Path) -> None:
    """Plain scalar items (strings, ints) still get a recorded line."""
    from compose_lint.parser import load_compose

    body = "services:\n  s:\n    image: x\n    dns:\n      - 1.1.1.1\n      - 8.8.8.8\n"
    _, lines = load_compose(_write(tmp_path, body))
    assert lines["services.s.dns[0]"] == 5
    assert lines["services.s.dns[1]"] == 6


@pytest.mark.parametrize(
    ("rule_id", "rule_module", "rule_class", "fixture", "expected_lines"),
    [
        # CL-0005: ports — each unbound port gets its own line
        (
            "CL-0005",
            "compose_lint.rules.CL0005_unbound_ports",
            "UnboundPortsRule",
            (
                "services:\n"
                "  s:\n"
                "    image: x\n"
                "    ports:\n"
                "      - 80:80\n"
                "      - 443:443\n"
                "      - 8080:8080\n"
            ),
            [5, 6, 7],
        ),
        # CL-0011: cap_add — each dangerous cap on its own line
        (
            "CL-0011",
            "compose_lint.rules.CL0011_dangerous_cap_add",
            "DangerousCapAddRule",
            (
                "services:\n"
                "  s:\n"
                "    image: x\n"
                "    cap_add:\n"
                "      - SYS_ADMIN\n"
                "      - NET_ADMIN\n"
            ),
            [5, 6],
        ),
        # CL-0013: sensitive volumes
        (
            "CL-0013",
            "compose_lint.rules.CL0013_sensitive_mount",
            "SensitiveMountRule",
            (
                "services:\n"
                "  s:\n"
                "    image: x\n"
                "    volumes:\n"
                "      - /etc:/host-etc\n"
                "      - /proc:/host-proc\n"
            ),
            [5, 6],
        ),
        # CL-0001: docker socket — already used [N] but verify still works
        (
            "CL-0001",
            "compose_lint.rules.CL0001_docker_socket",
            "DockerSocketRule",
            (
                "services:\n"
                "  s:\n"
                "    image: x\n"
                "    volumes:\n"
                "      - /tmp:/tmp\n"
                "      - /var/run/docker.sock:/var/run/docker.sock\n"
            ),
            [6],
        ),
        # CL-0016: dangerous devices
        (
            "CL-0016",
            "compose_lint.rules.CL0016_dangerous_devices",
            "DangerousDevicesRule",
            (
                "services:\n"
                "  s:\n"
                "    image: x\n"
                "    devices:\n"
                "      - /dev/sda:/dev/sda\n"
                "      - /dev/mem:/dev/mem\n"
            ),
            [5, 6],
        ),
        # CL-0009: security profile disabled
        (
            "CL-0009",
            "compose_lint.rules.CL0009_security_profile",
            "SecurityProfileRule",
            (
                "services:\n"
                "  s:\n"
                "    image: x\n"
                "    security_opt:\n"
                "      - seccomp:unconfined\n"
                "      - apparmor:unconfined\n"
            ),
            [5, 6],
        ),
    ],
)
def test_rules_attribute_per_item_lines(
    tmp_path: Path,
    rule_id: str,
    rule_module: str,
    rule_class: str,
    fixture: str,
    expected_lines: list[int],
) -> None:
    """End-to-end: rules that fire on sequence items report per-item lines."""
    import importlib

    from compose_lint.parser import load_compose

    data, lines = load_compose(_write(tmp_path, fixture))
    module = importlib.import_module(rule_module)
    rule = getattr(module, rule_class)()
    findings = list(
        rule.check("s", data["services"]["s"], data, lines),
    )
    actual_lines = sorted(f.line for f in findings if f.line is not None)
    assert actual_lines == expected_lines, (
        f"{rule_id}: expected lines {expected_lines}, got {actual_lines}"
    )
