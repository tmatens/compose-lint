"""CL-0026: services that bound neither memory nor CPU.

The rule covers two dimensions in one finding, so most of what is worth testing
is the boundary between them: which keys satisfy which limit, that a service
bounding only one is still flagged (and told which one is missing), and that a
*reservation* — which looks like a limit and is not one — does not satisfy
either.
"""

from __future__ import annotations

from compose_lint.parser import loads
from compose_lint.rules.CL0026_resource_limits import ResourceLimitsRule


def _findings(yaml: str, service: str = "app") -> list:
    rule = ResourceLimitsRule()
    data, lines = loads(yaml)
    return list(rule.check(service, data["services"][service], data, lines))


def _svc(body: str) -> str:
    return f"services:\n  app:\n    image: nginx:1.27\n{body}"


class TestResourceLimitsRule:
    def test_metadata(self) -> None:
        meta = ResourceLimitsRule().metadata
        assert meta.id == "CL-0026"
        assert meta.severity.value == "medium"
        assert len(meta.references) > 0

    def test_no_limits_at_all_fires(self) -> None:
        findings = _findings(_svc(""))
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0026"
        assert "no memory limit and no CPU limit" in findings[0].message

    def test_deploy_limits_satisfy_both(self) -> None:
        assert not _findings(
            _svc(
                "    deploy:\n"
                "      resources:\n"
                "        limits:\n"
                "          memory: 512M\n"
                "          cpus: '0.50'\n"
            )
        )

    def test_v2_spellings_satisfy_both(self) -> None:
        assert not _findings(_svc("    mem_limit: 512m\n    cpus: 0.5\n"))

    def test_cpu_quota_satisfies_the_cpu_limit(self) -> None:
        """`cpu_quota` writes the quota half of the same cpu.max as `cpus`."""
        assert not _findings(_svc("    mem_limit: 512m\n    cpu_quota: 50000\n"))

    def test_memory_only_names_the_missing_cpu_limit(self) -> None:
        findings = _findings(_svc("    mem_limit: 512m\n"))
        assert len(findings) == 1
        assert "no CPU limit" in findings[0].message
        assert "memory" not in findings[0].message.split(".")[0]

    def test_cpu_only_names_the_missing_memory_limit(self) -> None:
        findings = _findings(_svc("    cpus: 0.5\n"))
        assert len(findings) == 1
        assert "no memory limit" in findings[0].message

    def test_reservations_are_not_limits(self) -> None:
        """Soft targets under contention; the hard ceiling stays unbounded."""
        findings = _findings(
            _svc(
                "    mem_reservation: 256m\n"
                "    cpu_shares: 512\n"
                "    deploy:\n"
                "      resources:\n"
                "        reservations:\n"
                "          memory: 256M\n"
                "          cpus: '0.25'\n"
            )
        )
        assert len(findings) == 1
        assert "no memory limit and no CPU limit" in findings[0].message

    def test_valueless_key_is_not_a_limit(self) -> None:
        """`mem_limit:` with nothing after it parses to None, not a limit."""
        findings = _findings(_svc("    mem_limit:\n    cpus: 0.5\n"))
        assert len(findings) == 1
        assert "no memory limit" in findings[0].message

    def test_malformed_deploy_block_does_not_crash(self) -> None:
        """A scalar where a mapping belongs must not raise (parser tolerance)."""
        findings = _findings(_svc("    deploy: not-a-mapping\n"))
        assert len(findings) == 1

    def test_finding_points_at_the_service(self) -> None:
        findings = _findings(_svc(""))
        assert findings[0].line == 2
        assert findings[0].service == "app"
        assert findings[0].fix
