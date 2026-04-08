"""CL-0004: Image not pinned to version."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-13---enhance-supply-chain-security"
)

CIS_REF = (
    "CIS Docker Benchmark 5.27"
    " — Ensure docker commands always get the latest version"
    " of the image"
)

MUTABLE_TAGS = {"latest", "stable", "edge", "nightly", "dev", "test"}


@register_rule
class ImageNotPinnedRule(BaseRule):
    """Detects services using mutable or missing image tags."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0004",
            name="Image not pinned to version",
            description=(
                "Mutable tags like 'latest' mean every pull can produce a "
                "different image. This breaks reproducibility, makes rollbacks "
                "impossible, and opens supply chain risk."
            ),
            severity=Severity.WARNING,
            references=[OWASP_REF, CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        image = service_config.get("image")

        # Build-only services (no image key) — image pinning is a Dockerfile concern
        if image is None:
            return

        image = str(image)

        # Digest-pinned images are always fine
        if "@sha256:" in image:
            return

        # Split image into name and tag
        # Handle registry prefixes like ghcr.io/org/image:tag
        parts = image.rsplit(":", 1)
        if len(parts) == 1:
            # No tag specified — defaults to :latest
            yield Finding(
                rule_id="CL-0004",
                severity=Severity.WARNING,
                service=service_name,
                message=(
                    f"Image '{image}' has no tag, which defaults to ':latest'. "
                    "Pin to a specific version for reproducible builds."
                ),
                line=lines.get(f"services.{service_name}.image"),
                fix=f"Pin to a specific version, e.g.: image: {image}:<version>",
                references=[OWASP_REF, CIS_REF],
            )
            return

        tag = parts[1]
        if tag.lower() in MUTABLE_TAGS:
            yield Finding(
                rule_id="CL-0004",
                severity=Severity.WARNING,
                service=service_name,
                message=(
                    f"Image '{image}' uses mutable tag ':{tag}'. "
                    "Pin to a specific version for reproducible builds."
                ),
                line=lines.get(f"services.{service_name}.image"),
                fix=f"Pin to a specific version, e.g.: image: {parts[0]}:<version>",
                references=[OWASP_REF, CIS_REF],
            )
