"""Say when an ``env_file:`` left the credential rules unevaluated.

Compose merges each named file into the container's process environment, so a
credential written there reaches every surface CL-0020's documentation names
while never appearing in the document. Moving one line out of ``environment:``
and into an ``env_file:`` silences CL-0020 and CL-0021 without changing what
deploys (issue #665).

These pin the note, not a resolution: the files are still not opened. What the
note buys is that the gap is stated rather than silent, which is the half of the
problem that needs no decision about echoing a supplied value (ADR-026 §2).

A note and not a coverage gap, deliberately — see ``unread_env_files`` for the
weighing. The exit-code assertions below are the load-bearing half of that
choice, because 7.75% of the corpus names an ``env_file:``.
"""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING

from compose_lint.parser import loads, unread_env_files

if TYPE_CHECKING:
    from pathlib import Path

_SAFE = "services:\n  web:\n    image: i:1\n"


def notes_for(document: str) -> list[str]:
    data, _ = loads(document)
    return unread_env_files(data)


class TestTheThreeSpellings:
    """All three legal spellings of ``env_file:`` are seen, not just the common one."""

    def test_a_bare_string_is_noted(self) -> None:
        assert notes_for(f"{_SAFE}    env_file: secrets.env\n")

    def test_a_list_of_strings_is_noted(self) -> None:
        assert notes_for(f"{_SAFE}    env_file: [a.env, b.env]\n")

    def test_the_mapping_form_is_noted(self) -> None:
        """The newer spelling, and the one reading only strings would miss."""
        assert notes_for(
            f"{_SAFE}    env_file:\n      - path: secrets.env\n"
            "        required: false\n"
        )

    def test_a_mixed_list_reports_every_path(self) -> None:
        note = notes_for(
            f"{_SAFE}    env_file:\n      - plain.env\n      - path: mapped.env\n"
        )[0]
        assert "plain.env" in note
        assert "mapped.env" in note

    def test_paths_keep_their_written_order(self) -> None:
        """Compose merges later files over earlier ones, so order is not cosmetic."""
        note = notes_for(f"{_SAFE}    env_file: [first.env, second.env]\n")[0]
        assert note.index("first.env") < note.index("second.env")


class TestWhatIsNotNoted:
    """The note has to stay a signal; it fires on 7.75% of real files as it is."""

    def test_a_service_without_env_file_is_silent(self) -> None:
        assert notes_for(f"{_SAFE}    environment:\n      A: b\n") == []

    def test_an_empty_env_file_names_nothing(self) -> None:
        assert notes_for(f"{_SAFE}    env_file: []\n") == []

    def test_a_mapping_entry_without_a_path_is_skipped(self) -> None:
        assert notes_for(f"{_SAFE}    env_file:\n      - required: false\n") == []

    def test_a_document_with_no_services_is_silent(self) -> None:
        """Called on a mapping directly: `loads` rejects a fragment first (ADR-013),
        so this guards the function for any other caller."""
        assert unread_env_files({"volumes": {"data": {}}}) == []

    def test_a_non_mapping_service_is_skipped(self) -> None:
        assert unread_env_files({"services": {"web": "nonsense"}}) == []


class TestTheNoteItself:
    def test_it_names_the_service_and_the_rules_it_blinded(self) -> None:
        note = notes_for(f"{_SAFE}    env_file: secrets.env\n")[0]
        assert "'web'" in note
        assert "secrets.env" in note
        assert "CL-0020" in note
        assert "CL-0021" in note

    def test_one_note_per_service_carrying_one(self) -> None:
        notes = notes_for(
            "services:\n"
            "  a:\n    image: i:1\n    env_file: a.env\n"
            "  b:\n    image: i:1\n    env_file: b.env\n"
            "  c:\n    image: i:1\n"
        )
        assert len(notes) == 2


class TestItDoesNotTouchTheExitCode:
    """The distinction from a coverage gap, asserted rather than described.

    An unresolved ``include:`` exits 2 because a whole service went ungraded.
    Here the service is graded and two rules are blind to one subtree, on 7.75%
    of real files — making that fatal would newly fail one CI run in thirteen.
    """

    def _run(self, directory: Path, document: str) -> subprocess.CompletedProcess[str]:
        (directory / "compose.yml").write_text(document, encoding="utf-8")
        (directory / "secrets.env").write_text("A=b\n", encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-m", "compose_lint", "check", "compose.yml"],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_a_clean_file_still_exits_zero(self, tmp_path: Path) -> None:
        result = self._run(
            tmp_path,
            "services:\n  web:\n    image: i:1@sha256:"
            + "0" * 64
            + "\n    env_file: secrets.env\n"
            "    read_only: true\n    cap_drop: [ALL]\n"
            "    security_opt: ['no-new-privileges:true']\n"
            "    mem_limit: 1g\n    cpus: 1\n    pids_limit: 100\n",
        )
        assert result.returncode == 0, result.stderr
        assert "env_file" in result.stderr or "secrets.env" in result.stderr

    def test_the_note_goes_to_stderr_not_stdout(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, f"{_SAFE}    env_file: secrets.env\n")
        assert "secrets.env" in result.stderr
        assert "secrets.env" not in result.stdout

    def test_it_is_not_an_error_and_not_a_coverage_gap(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, f"{_SAFE}    env_file: secrets.env\n")
        assert result.returncode != 2, result.stderr
        assert "--allow-partial-coverage" not in result.stderr
