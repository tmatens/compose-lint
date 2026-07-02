"""Image-reference normalization for profile matching (ADR-017).

The catalog match key is the *canonical* repository reference — registry and
namespace expanded to their Docker defaults so that ``postgres``,
``postgres:16``, ``docker.io/library/postgres`` and
``docker.io/library/postgres@sha256:...`` all match the same profile. This
mirrors containerd/Docker reference normalization; the rules layer's
``split_image_ref`` handles only tag/digest splitting, so the registry+namespace
expansion lives here.
"""

from __future__ import annotations

from dataclasses import dataclass

from compose_lint.rules._image import split_image_ref

_DOCKER_IO = "docker.io"


@dataclass(frozen=True)
class ImageRef:
    """A parsed image reference.

    ``repository`` is the normalized match key (registry/namespace/name, no tag
    or digest). ``tag`` and ``digest`` are as written on the service, used for
    staleness checks against a profile's ``applies_to``.
    """

    repository: str
    tag: str | None
    digest: str | None


def normalize_repository(name: str) -> str:
    """Expand a bare image name to its canonical ``registry/namespace/name``.

    Examples:
        postgres                     -> docker.io/library/postgres
        linuxserver/radarr           -> docker.io/linuxserver/radarr
        lscr.io/linuxserver/radarr   -> lscr.io/linuxserver/radarr
        ghcr.io/tmatens/foo          -> ghcr.io/tmatens/foo
        localhost:5000/foo           -> localhost:5000/foo
    """
    if not name:
        return name

    first, slash, rest = name.partition("/")
    if slash and ("." in first or ":" in first or first == "localhost"):
        registry, path = first.lower(), rest
    else:
        registry, path = _DOCKER_IO, name

    if registry == _DOCKER_IO and "/" not in path:
        path = f"library/{path}"

    return f"{registry}/{path}"


def parse_image_ref(image: str) -> ImageRef:
    """Parse a service ``image:`` string into a normalized ``ImageRef``."""
    digest: str | None = None
    if "@" in image:
        digest = image.partition("@")[2] or None

    name, tag = split_image_ref(image)
    return ImageRef(repository=normalize_repository(name), tag=tag, digest=digest)
