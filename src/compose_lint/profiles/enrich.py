"""Enrich rule findings with csd-derived profile guidance (ADR-017).

Enrichment is *advisory only*: it never creates, drops, or reclassifies a
finding — it appends the observed minimum for the matched image to an existing
finding's ``fix`` text so the guidance is image-specific instead of generic.
The rules stay untouched; the engine calls ``enrich_fix`` after a rule fires.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from compose_lint.models import Finding
    from compose_lint.profiles.models import ProfileMatch

# Which profile dimension backs each rule's guidance.
DIMENSION_BY_RULE: dict[str, str] = {
    "CL-0006": "capabilities",
    "CL-0007": "filesystem",
    "CL-0002": "privileged_decomposition",
    "CL-0011": "cap_add_validation",
    "CL-0016": "devices",
}


def enrich_fix(finding: Finding, match: ProfileMatch) -> Finding:
    """Return ``finding`` with derived guidance appended to ``fix``.

    Unchanged when the rule has no backing dimension, the profile lacks that
    dimension, or the dimension yields nothing actionable.
    """
    dim_key = DIMENSION_BY_RULE.get(finding.rule_id)
    if dim_key is None:
        return finding
    dimension = match.dimensions.get(dim_key)
    if not isinstance(dimension, dict):
        return finding

    guidance = _guidance(finding.rule_id, dimension)
    if guidance is None:
        return finding

    note = f"profile hint ({_provenance(dimension, match)}): {guidance}"
    new_fix = f"{finding.fix}\n{note}" if finding.fix else note
    return replace(finding, fix=new_fix)


def _flow(items: list[Any]) -> str:
    return "[" + ", ".join(str(i) for i in items) + "]"


def _guidance(rule_id: str, dim: dict[str, Any]) -> str | None:
    if rule_id == "CL-0006":
        cap_add = dim.get("cap_add") or []
        if not cap_add:
            return "observed no added capabilities — cap_drop: [ALL]"
        return f"observed minimum is cap_drop: [ALL] + cap_add: {_flow(cap_add)}"

    if rule_id == "CL-0007":
        if not dim.get("read_only"):
            return None
        tmpfs = dim.get("tmpfs") or []
        if tmpfs:
            return f"observed read_only: true with tmpfs: {_flow(tmpfs)}"
        return "observed read_only: true (no writable paths needed)"

    if rule_id == "CL-0002":
        cap_add = dim.get("cap_add") or []
        devices = dim.get("devices") or []
        base = (
            "observed non-privileged equivalent: "
            f"cap_add: {_flow(cap_add)} + devices: {_flow(devices)}"
        )
        if dim.get("partial"):
            base += " (partial: security_opt/AppArmor/seccomp not observed)"
        return base

    if rule_id == "CL-0011":
        recommended = dim.get("recommended_cap_add") or []
        return f"observed minimized cap_add: {_flow(recommended)}"

    if rule_id == "CL-0016":
        devices = dim.get("devices") or []
        if not devices:
            return None
        text = f"observed device access: {_flow(devices)}"
        derived = dim.get("derived_caps") or []
        if derived:
            text += f" (implies cap_add: {_flow(derived)})"
        return text

    return None


def _provenance(dim: dict[str, Any], match: ProfileMatch) -> str:
    derivation = dim.get("derivation")
    derivation = derivation if isinstance(derivation, dict) else {}
    confidence = derivation.get("confidence", "unknown")
    image = _short_image(str(derivation.get("validated_image") or match.image))
    return (
        f"csd-derived, confidence {confidence}, from {image}, "
        f"{match.precision.value} match — compose-lint can't see your runtime, "
        f"confirm it fits your setup"
    )


def _short_image(image: str) -> str:
    """Shorten a name@sha256:<64hex> reference for a one-line note."""
    name, sep, digest = image.partition("@sha256:")
    if sep and len(digest) > 12:
        return f"{name}@sha256:{digest[:12]}"
    return image
