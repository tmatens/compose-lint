"""CL-0001: Docker socket mounted."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-1---do-not-expose-the-docker-daemon-socket-"
    "even-to-the-containers"
)

CIS_REF = (
    "CIS Docker Benchmark 5.31 — Do not mount the Docker socket inside any containers"
)


@register_rule
class DockerSocketRule(BaseRule):
    """Detects Docker socket mounts in service volumes."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0001",
            name="Docker socket mounted",
            description=(
                "Mounting the Docker socket gives a container full root-level "
                "access to the host's Docker daemon. A compromised container can "
                "create privileged containers, access all other containers, and "
                "escape to the host."
            ),
            severity=Severity.CRITICAL,
            references=[OWASP_REF, CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        volumes = service_config.get("volumes", [])
        if not isinstance(volumes, list):
            return

        for i, volume in enumerate(volumes):
            volume_str = str(volume)
            if "docker.sock" in volume_str:
                yield Finding(
                    rule_id="CL-0001",
                    severity=Severity.CRITICAL,
                    service=service_name,
                    message=(
                        f"Docker socket mounted via '{volume_str}'. "
                        "This gives the container full control over the Docker daemon."
                    ),
                    line=lines.get(f"services.{service_name}.volumes[{i}]")
                    or lines.get(f"services.{service_name}.volumes"),
                    fix=(
                        "Use a Docker socket proxy (e.g., "
                        "tecnativa/docker-socket-proxy) to expose only "
                        "the API endpoints your service needs."
                    ),
                    references=[OWASP_REF, CIS_REF],
                )
