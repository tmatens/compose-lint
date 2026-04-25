"""CL-0019: Image tag without digest."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._image import split_image_ref

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-13---enhance-supply-chain-security"
)

CIS_REF = "CIS Docker Benchmark 5.27 — Ensure container images are up to date"

# Tags that CL-0004 already handles — we skip them to avoid overlap
_MUTABLE_TAGS = {"latest", "stable", "edge", "nightly", "dev", "test"}


@register_rule
class ImageNoDigestRule(BaseRule):
    """Detects images pinned to a version tag but not a digest."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0019",
            name="Image tag without digest",
            description=(
                "A version tag can be silently overwritten on the registry. "
                "Without a digest pin, pulls are not guaranteed to return the "
                "same image."
            ),
            severity=Severity.MEDIUM,
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
        if image is None:
            return

        image = str(image)

        # Already digest-pinned — clean
        if "@sha256:" in image:
            return

        _, tag = split_image_ref(image)
        if tag is None:
            # No tag at all — CL-0004 handles this
            return

        if tag.lower() in _MUTABLE_TAGS:
            # Mutable tags are CL-0004's domain
            return

        # Has a version tag but no digest
        yield Finding(
            rule_id="CL-0019",
            severity=Severity.MEDIUM,
            service=service_name,
            message=(
                f"Image '{image}' is pinned to a tag but not a digest. "
                "Tags can be overwritten on the registry, so this does not "
                "guarantee image immutability."
            ),
            line=lines.get(f"services.{service_name}.image"),
            fix=(
                f"Add a digest pin: image: {image}@sha256:<digest>\n"
                "Use Dependabot or Renovate to keep digests current."
            ),
            references=[OWASP_REF, CIS_REF],
        )
