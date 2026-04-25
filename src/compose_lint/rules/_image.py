"""Shared parsing helpers for OCI image references."""

from __future__ import annotations


def split_image_ref(image: str) -> tuple[str, str | None]:
    """Split an OCI image reference into ``(name, tag)``.

    Returns ``tag = None`` when no tag is present. A registry-with-port
    prefix (``localhost:5000/foo``) is not mistaken for a tag — the
    rightmost colon is part of the registry, not a tag separator, when
    the candidate tag contains a slash.

    Any trailing ``@digest`` is stripped before splitting, so the
    returned name does not include the digest.

    Examples:
        nginx                          -> ("nginx", None)
        nginx:1.25                     -> ("nginx", "1.25")
        nginx@sha256:...               -> ("nginx", None)
        nginx:1.25@sha256:...          -> ("nginx", "1.25")
        localhost:5000/foo             -> ("localhost:5000/foo", None)
        localhost:5000/foo:v1          -> ("localhost:5000/foo", "v1")
        localhost:5000/foo@sha256:...  -> ("localhost:5000/foo", None)
    """
    if "@" in image:
        image = image.split("@", 1)[0]
    if ":" not in image:
        return image, None
    name, _, candidate = image.rpartition(":")
    if "/" in candidate:
        return image, None
    return name, candidate
