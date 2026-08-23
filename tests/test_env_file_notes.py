"""Say what an ``env_file:`` left unevaluated — now that most are evaluated.

#669 shipped a blanket note: every service naming an ``env_file:`` was told the
credential rules had not been evaluated for it, because no target was opened.
ADR-027 opens them, so the note has to become specific. A note that fires beside
the findings it claims are missing is worse than no note at all.

What remains noted is what still contributed nothing, and the wording separates
the two absent cases. Only a *required* target's absence means the project
cannot deploy — ``docker compose config`` exits 1 — and only then is there a
configuration compose-lint failed to grade. An optional target's absence *is*
the deployed configuration.

Still a note and not a coverage gap: the service is graded either way, and the
exit-code assertions at the end are the load-bearing half of that choice,
because 7.64% of the corpus names an ``env_file:``.

The three legal spellings are read in one place and tested there
(``test_service_env.py``); this module is about what the run says.
"""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from compose_lint._service_env import describe_unread, resolve_env_files

if TYPE_CHECKING:
    from pathlib import Path

_SAFE = "services:\n  web:\n    image: i:1\n"


def notes_for(directory: Path, document: str) -> list[str]:
    import yaml

    data = yaml.safe_load(document)
    return describe_unread(resolve_env_files(data, directory))


class TestWhatIsNoted:
    def test_a_missing_required_target_says_compose_would_refuse(
        self, tmp_path: Path
    ) -> None:
        (note,) = notes_for(tmp_path, f"{_SAFE}    env_file: secrets.env\n")
        assert "'web'" in note
        assert "secrets.env" in note
        assert "refuses to start" in note
        assert "CL-0020" in note and "CL-0021" in note

    def test_a_missing_optional_target_claims_no_missed_evaluation(
        self, tmp_path: Path
    ) -> None:
        """Compose ships the service without it, so that is what was graded."""
        (note,) = notes_for(
            tmp_path,
            f"{_SAFE}    env_file:\n      - path: secrets.env\n"
            "        required: false\n",
        )
        assert "not required" in note
        assert "CL-0020" not in note, (
            "nothing was missed: the absent file is the deployed configuration"
        )

    def test_a_target_outside_the_project_says_it_was_not_opened(
        self, tmp_path: Path
    ) -> None:
        (note,) = notes_for(tmp_path, f"{_SAFE}    env_file: ../outside.env\n")
        assert "outside the project directory" in note
        assert "CL-0020" in note

    def test_an_unresolved_path_says_it_names_no_file(self, tmp_path: Path) -> None:
        (note,) = notes_for(tmp_path, f'{_SAFE}    env_file: ["${{W}}.env"]\n')
        assert "names no file" in note

    def test_an_unreadable_target_is_noted(self, tmp_path: Path) -> None:
        (tmp_path / "secrets.env").write_bytes(b"K=\xff\xfe\n")
        (note,) = notes_for(tmp_path, f"{_SAFE}    env_file: secrets.env\n")
        assert "could not be read" in note

    def test_a_malformed_line_is_noted_and_the_rest_is_graded(
        self, tmp_path: Path
    ) -> None:
        """The second question ADR-027 left open, settled toward leniency.

        Compose refuses the whole file over one such line. Refusing it here
        would drop real findings for every other key, which is the silent false
        negative the ADR exists to remove — so the entries are kept and the
        skipped line is stated instead of inferred.
        """
        (tmp_path / "secrets.env").write_text(
            "not a pair\nPW=hunter2\n", encoding="utf-8"
        )
        (note,) = notes_for(tmp_path, f"{_SAFE}    env_file: secrets.env\n")
        assert "line 1" in note
        assert "could not be read as KEY=value" in note
        assert "remaining entries were graded" in note

    def test_several_malformed_lines_are_listed(self, tmp_path: Path) -> None:
        (tmp_path / "secrets.env").write_text(
            "not a pair\nPW=hunter2\nnor this\n", encoding="utf-8"
        )
        (note,) = notes_for(tmp_path, f"{_SAFE}    env_file: secrets.env\n")
        assert "lines 1, 3" in note

    def test_one_note_per_unread_target(self, tmp_path: Path) -> None:
        notes = notes_for(tmp_path, f"{_SAFE}    env_file: [a.env, b.env]\n")
        assert len(notes) == 2

    def test_services_are_reported_in_a_stable_order(self, tmp_path: Path) -> None:
        notes = notes_for(
            tmp_path,
            "services:\n"
            "  zebra:\n    image: i:1\n    env_file: z.env\n"
            "  alpha:\n    image: i:1\n    env_file: a.env\n",
        )
        assert "'alpha'" in notes[0]
        assert "'zebra'" in notes[1]


class TestWhatIsNotNoted:
    """The note has to stay a signal, and a read file is not a gap."""

    def test_a_target_that_was_read_is_silent(self, tmp_path: Path) -> None:
        (tmp_path / "secrets.env").write_text("A=b\n", encoding="utf-8")
        assert notes_for(tmp_path, f"{_SAFE}    env_file: secrets.env\n") == []

    def test_a_service_without_env_file_is_silent(self, tmp_path: Path) -> None:
        assert notes_for(tmp_path, f"{_SAFE}    environment:\n      A: b\n") == []

    def test_an_empty_env_file_names_nothing(self, tmp_path: Path) -> None:
        assert notes_for(tmp_path, f"{_SAFE}    env_file: []\n") == []

    def test_a_document_with_no_services_is_silent(self, tmp_path: Path) -> None:
        assert describe_unread(resolve_env_files({"volumes": {}}, tmp_path)) == []

    def test_a_non_mapping_service_is_skipped(self, tmp_path: Path) -> None:
        data = {"services": {"web": "nonsense"}}
        assert describe_unread(resolve_env_files(data, tmp_path)) == []


class TestEndToEnd:
    """The exit-code contract, and that a read file actually reaches the rules."""

    @staticmethod
    def _run(
        directory: Path, document: str, env_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        (directory / "compose.yml").write_text(document, encoding="utf-8")
        if env_text is not None:
            (directory / "secrets.env").write_text(env_text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-m", "compose_lint", "check", "compose.yml"],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=60,
        )

    _HARDENED = (
        "services:\n  web:\n    image: i:1@sha256:" + "0" * 64 + "\n"
        "    env_file: secrets.env\n"
        "    read_only: true\n    cap_drop: [ALL]\n"
        "    security_opt: ['no-new-privileges:true']\n"
        "    mem_limit: 1g\n    cpus: 1\n    pids_limit: 100\n"
    )

    def test_a_clean_env_file_leaves_a_clean_run_clean(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, self._HARDENED, "A=b\n")
        assert result.returncode == 0, result.stderr
        assert "secrets.env" not in result.stderr, "nothing to say about a read file"

    def test_a_credential_beside_a_malformed_line_still_fires(
        self, tmp_path: Path
    ) -> None:
        result = self._run(
            tmp_path, self._HARDENED, "not a pair\nPOSTGRES_PASSWORD=hunter2\n"
        )
        assert result.returncode == 1, result.stderr
        assert "CL-0020" in result.stdout
        assert "could not be read as KEY=value" in result.stderr
        assert "hunter2" not in result.stdout + result.stderr

    def test_a_credential_in_the_file_is_now_reported(self, tmp_path: Path) -> None:
        """The whole point of ADR-027: this exited 0 before it."""
        result = self._run(tmp_path, self._HARDENED, "POSTGRES_PASSWORD=hunter2\n")
        assert result.returncode == 1, result.stderr
        assert "CL-0020" in result.stdout
        assert "POSTGRES_PASSWORD" in result.stdout
        assert "secrets.env" in result.stdout

    def test_the_value_is_never_printed(self, tmp_path: Path) -> None:
        """ADR-027 §5. The key names the finding; the value must not appear."""
        result = self._run(tmp_path, self._HARDENED, "POSTGRES_PASSWORD=hunter2\n")
        assert "hunter2" not in result.stdout
        assert "hunter2" not in result.stderr

    def test_a_connection_string_is_never_printed(self, tmp_path: Path) -> None:
        result = self._run(
            tmp_path, self._HARDENED, "DATABASE_URL=postgres://u:hunter2@db/x\n"
        )
        assert result.returncode == 1, result.stderr
        assert "CL-0021" in result.stdout
        assert "hunter2" not in result.stdout
        assert "hunter2" not in result.stderr

    def test_no_env_leaves_the_file_unread(self, tmp_path: Path) -> None:
        (tmp_path / "compose.yml").write_text(self._HARDENED, encoding="utf-8")
        (tmp_path / "secrets.env").write_text(
            "POSTGRES_PASSWORD=hunter2\n", encoding="utf-8"
        )
        result = subprocess.run(
            [sys.executable, "-m", "compose_lint", "check", "--no-env", "compose.yml"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        assert "CL-0020" not in result.stdout

    @pytest.mark.parametrize("required", ["true", "false"])
    def test_a_missing_target_is_not_a_coverage_gap(
        self, required: str, tmp_path: Path
    ) -> None:
        document = (
            f"{_SAFE}    env_file:\n      - path: secrets.env\n"
            f"        required: {required}\n"
        )
        result = self._run(tmp_path, document)
        assert result.returncode != 2, result.stderr
        assert "--allow-partial-coverage" not in result.stderr

    def test_the_note_goes_to_stderr_not_stdout(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, f"{_SAFE}    env_file: secrets.env\n")
        assert "secrets.env" in result.stderr
        assert "secrets.env" not in result.stdout
