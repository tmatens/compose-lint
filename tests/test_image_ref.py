"""Unit tests for the shared image-reference parser."""

from __future__ import annotations

import pytest

from compose_lint.rules._image import split_image_ref


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        # Simple cases
        ("nginx", ("nginx", None)),
        ("nginx:1.25", ("nginx", "1.25")),
        ("nginx:latest", ("nginx", "latest")),
        # Digest pinning — name strips digest, tag preserved or None
        ("nginx@sha256:abc", ("nginx", None)),
        ("nginx:1.25@sha256:abc", ("nginx", "1.25")),
        # Registry without explicit port — colon belongs to tag
        ("ghcr.io/org/app", ("ghcr.io/org/app", None)),
        ("ghcr.io/org/app:2.0.1", ("ghcr.io/org/app", "2.0.1")),
        ("ghcr.io/org/app:2.0.1@sha256:abc", ("ghcr.io/org/app", "2.0.1")),
        # Registry WITH explicit port — colon belongs to registry, not tag
        ("localhost:5000/foo", ("localhost:5000/foo", None)),
        ("localhost:5000/foo:v1", ("localhost:5000/foo", "v1")),
        ("localhost:5000/foo:latest", ("localhost:5000/foo", "latest")),
        ("localhost:5000/foo@sha256:abc", ("localhost:5000/foo", None)),
        ("localhost:5000/foo:v1@sha256:abc", ("localhost:5000/foo", "v1")),
        ("registry.internal:5000/foo:v1.2.3", ("registry.internal:5000/foo", "v1.2.3")),
    ],
)
def test_split_image_ref(image: str, expected: tuple[str, str | None]) -> None:
    assert split_image_ref(image) == expected
