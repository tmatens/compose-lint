"""The two scalar-locating primitives the in-scalar fixers share (#377).

``sequence_scalar_span`` came out of CL-0005 when CL-0022 needed it;
``mapping_scalar_span`` is its counterpart for a key written inline. Both
answer "where on this line is the value, and what does it say" -- and, as
importantly, ``None`` for every shape where that question has no single
answer, since the fixers turn ``None`` into a refusal.
"""

from __future__ import annotations

import pytest

from compose_lint._yaml_edit import mapping_scalar_span, sequence_scalar_span


class TestSequenceScalarSpan:
    def test_plain_item(self) -> None:
        assert sequence_scalar_span("      - /run:exec,size=64m\n") == (
            "/run:exec,size=64m",
            9,
        )

    def test_quoted_item_points_inside_the_quote(self) -> None:
        assert sequence_scalar_span("  - '/tmp:exec'  # c\n") == ("/tmp:exec", 6)
        assert sequence_scalar_span('  - "/tmp:exec"\n') == ("/tmp:exec", 6)

    def test_trailing_comment_is_not_part_of_the_value(self) -> None:
        assert sequence_scalar_span("  - /tmp:exec  # staging\n") == ("/tmp:exec", 5)

    @pytest.mark.parametrize(
        "line",
        [
            "    tmpfs:\n",  # a key, not an item
            "  -/tmp:exec\n",  # no space after the dash
            "  - \n",  # nothing after the dash
            "  - '/tmp:exec\n",  # unterminated quote
        ],
    )
    def test_refuses_shapes_with_no_single_scalar(self, line: str) -> None:
        assert sequence_scalar_span(line) is None


class TestMappingScalarSpan:
    def test_inline_value(self) -> None:
        assert mapping_scalar_span("    tmpfs: /scratch:exec\n", "tmpfs") == (
            "/scratch:exec",
            12,
        )

    def test_quoted_value_points_inside_the_quote(self) -> None:
        assert mapping_scalar_span('    tmpfs: "/a:exec" # x\n', "tmpfs") == (
            "/a:exec",
            13,
        )
        assert mapping_scalar_span("    tmpfs: '/a:exec'\n", "tmpfs") == ("/a:exec", 13)

    def test_trailing_comment_is_not_part_of_the_value(self) -> None:
        assert mapping_scalar_span("  tmpfs: /a:exec   # why\n", "tmpfs") == (
            "/a:exec",
            10,
        )

    @pytest.mark.parametrize(
        "line",
        [
            "    image: nginx\n",  # a different key
            "    tmpfs:\n",  # block body follows, nothing inline
            "    tmpfs_extra: /a\n",  # a longer key sharing the prefix
            "    tmpfs:    \n",  # only whitespace after the colon
            "    tmpfs: [/a:exec]\n",  # flow sequence
            "    tmpfs: {a: b}\n",  # flow mapping
            "    tmpfs: &t /a:exec\n",  # anchor
            "    tmpfs: *t\n",  # alias
            "    tmpfs: |\n",  # block scalar
            "    tmpfs: '/a:exec\n",  # unterminated quote
        ],
    )
    def test_refuses_shapes_with_no_single_scalar(self, line: str) -> None:
        assert mapping_scalar_span(line, "tmpfs") is None
