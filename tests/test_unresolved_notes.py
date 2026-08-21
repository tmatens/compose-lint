"""Say when a value nobody supplies left the mount rules unevaluated.

ADR-026 §6. The narrow half of the option-B "coverage signal" the issue
considered: not every defaultless ``${VAR}`` (22% of real files, which would be
noise) but the subset where the statement is unarguable — a bind source that is
*only* references ships an empty source, and Compose then refuses to start the
project at all.

Measured over the corpus: 3.3% of files, which is the difference between a
signal and a banner.
"""

from __future__ import annotations

from compose_lint.parser import loads, unresolved_mount_sources


def notes_for(document: str) -> list[str]:
    data, _ = loads(document)
    return unresolved_mount_sources(data)


class TestUndeployableSources:
    """A source that resolves to nothing is not a configuration that deploys."""

    def test_a_whole_source_reference_is_noted(self) -> None:
        assert notes_for(
            'services:\n  web:\n    image: i\n    volumes: ["${MOUNT}:/data"]\n'
        )

    def test_the_note_names_the_service_and_the_spelling(self) -> None:
        note = notes_for(
            'services:\n  web:\n    image: i\n    volumes: ["${MOUNT}:/data"]\n'
        )[0]
        assert "'web'" in note
        assert "${MOUNT}" in note

    def test_the_long_syntax_is_covered_too(self) -> None:
        assert notes_for(
            "services:\n  web:\n    image: i\n    volumes:\n"
            "      - type: bind\n        source: ${MOUNT}\n        target: /data\n"
        )

    def test_several_references_still_ship_nothing(self) -> None:
        assert notes_for(
            'services:\n  web:\n    image: i\n    volumes: ["${A}${B}:/data"]\n'
        )


class TestQuietWhereTheSourceIsKnowable:
    """Everything the tool *can* grade stays silent, which is the whole point.

    A note on 22% of real files would be a banner rather than a signal.
    """

    def test_a_literal_source_is_silent(self) -> None:
        assert not notes_for(
            'services:\n  web:\n    image: i\n    volumes: ["/srv:/data"]\n'
        )

    def test_a_defaulted_reference_is_silent(self) -> None:
        """It resolves to the default, which is what the file ships."""
        assert not notes_for(
            'services:\n  web:\n    image: i\n    volumes: ["${M:-/srv}:/data"]\n'
        )

    def test_a_segment_reference_is_silent(self) -> None:
        """``${DATA}/logs`` still ships a non-empty source, so Compose starts;
        the path is wrong rather than absent, which this note does not claim."""
        assert not notes_for(
            'services:\n  web:\n    image: i\n    volumes: ["${DATA}/logs:/x"]\n'
        )

    def test_a_named_volume_is_silent(self) -> None:
        assert not notes_for(
            'services:\n  web:\n    image: i\n    volumes: ["data:/x"]\n'
            "volumes:\n  data: {}\n"
        )

    def test_a_service_without_volumes_is_silent(self) -> None:
        assert not notes_for("services:\n  web:\n    image: i\n")

    def test_a_document_without_services_is_silent(self) -> None:
        assert not unresolved_mount_sources({})
