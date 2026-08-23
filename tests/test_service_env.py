"""Tests for resolving and reading a service's ``env_file:`` targets.

The unit tests pin what compose-lint promises; ``TestAgreesWithCompose`` at the
end re-derives the precedence and scoping rules from the ``docker compose``
binary, so a release that changes them fails here rather than silently
mis-reading a user's stack. That class skips without a working CLI, and every
promise it checks is also pinned by a unit test above, so a Docker-less leg
still covers the behaviour.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from typing import TYPE_CHECKING

import pytest
import yaml

from compose_lint._env_file import MAX_ENV_BYTES
from compose_lint._service_env import (
    EnvFileRef,
    Unread,
    env_file_refs,
    resolve_env_files,
)

if TYPE_CHECKING:
    from pathlib import Path


def _document(env_file: object, environment: object = None) -> dict:
    service: dict = {"image": "i", "env_file": env_file}
    if environment is not None:
        service["environment"] = environment
    return {"services": {"s": service}}


def _keys(resolved: dict, service: str = "s") -> dict[str, str]:
    return {key.key: key.value for key in resolved[service].keys}


class TestEnvFileRefs:
    """The three legal spellings, which is the one place they are read."""

    def test_bare_string(self) -> None:
        assert env_file_refs("app.env") == [
            EnvFileRef(path="app.env", required=True, raw=False)
        ]

    def test_list_of_strings_keeps_written_order(self) -> None:
        assert [ref.path for ref in env_file_refs(["a.env", "b.env"])] == [
            "a.env",
            "b.env",
        ]

    def test_mapping_form_carries_required_and_format(self) -> None:
        refs = env_file_refs(
            [{"path": "a.env", "required": False, "format": "raw"}, {"path": "b.env"}]
        )
        assert refs == [
            EnvFileRef(path="a.env", required=False, raw=True),
            EnvFileRef(path="b.env", required=True, raw=False),
        ]

    @pytest.mark.parametrize(
        "value", [None, "", [], [""], [{}], [{"path": ""}], 7, {"path": "a.env"}]
    )
    def test_nothing_named(self, value: object) -> None:
        assert env_file_refs(value) == []


class TestResolution:
    def test_a_service_naming_nothing_is_absent_from_the_result(
        self, tmp_path: Path
    ) -> None:
        data = {"services": {"s": {"image": "i"}}}
        assert resolve_env_files(data, tmp_path) == {}

    def test_reads_a_target_relative_to_the_compose_file(self, tmp_path: Path) -> None:
        (tmp_path / "app.env").write_text("PW=hunter2\n", encoding="utf-8")
        resolved = resolve_env_files(_document("app.env"), tmp_path)
        assert _keys(resolved) == {"PW": "hunter2"}

    def test_reads_a_subdirectory(self, tmp_path: Path) -> None:
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "app.env").write_text("PW=hunter2\n", encoding="utf-8")
        resolved = resolve_env_files(_document("conf/app.env"), tmp_path)
        assert _keys(resolved) == {"PW": "hunter2"}
        assert resolved["s"].keys[0].source_file == "conf/app.env", (
            "the report names the path as written, not the lint host's"
        )

    def test_a_later_file_wins(self, tmp_path: Path) -> None:
        (tmp_path / "a.env").write_text("K=first\n", encoding="utf-8")
        (tmp_path / "b.env").write_text("K=second\n", encoding="utf-8")
        resolved = resolve_env_files(_document(["a.env", "b.env"]), tmp_path)
        assert _keys(resolved) == {"K": "second"}
        assert resolved["s"].keys[0].source_file == "b.env"

    def test_an_earlier_files_name_is_in_scope_for_a_later_one(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "a.env").write_text("BASE=/opt\n", encoding="utf-8")
        (tmp_path / "b.env").write_text("P=${BASE}/p\n", encoding="utf-8")
        resolved = resolve_env_files(_document(["a.env", "b.env"]), tmp_path)
        assert _keys(resolved) == {"BASE": "/opt", "P": "/opt/p"}

    def test_a_sibling_dotenv_is_in_scope(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("FROMDOTENV=dotvalue\n", encoding="utf-8")
        (tmp_path / "app.env").write_text("K=${FROMDOTENV}-tail\n", encoding="utf-8")
        resolved = resolve_env_files(_document("app.env"), tmp_path)
        assert _keys(resolved) == {"K": "dotvalue-tail"}

    def test_records_the_line_a_key_was_written_on(self, tmp_path: Path) -> None:
        (tmp_path / "app.env").write_text(
            "# a comment\nFIRST=1\nPW=hunter2\n", encoding="utf-8"
        )
        resolved = resolve_env_files(_document("app.env"), tmp_path)
        lines = {key.key: key.line for key in resolved["s"].keys}
        assert lines == {"FIRST": 2, "PW": 3}

    def test_the_mapping_form_is_read(self, tmp_path: Path) -> None:
        (tmp_path / "app.env").write_text("PW=hunter2\n", encoding="utf-8")
        resolved = resolve_env_files(
            _document([{"path": "app.env", "required": False}]), tmp_path
        )
        assert _keys(resolved) == {"PW": "hunter2"}

    def test_raw_format_is_honoured(self, tmp_path: Path) -> None:
        (tmp_path / "app.env").write_text('PW="quoted"\n', encoding="utf-8")
        resolved = resolve_env_files(
            _document([{"path": "app.env", "format": "raw"}]), tmp_path
        )
        assert _keys(resolved) == {"PW": '"quoted"'}

    def test_two_services_sharing_a_file_both_get_it(self, tmp_path: Path) -> None:
        (tmp_path / "app.env").write_text("PW=hunter2\n", encoding="utf-8")
        data = {
            "services": {
                "a": {"image": "i", "env_file": "app.env"},
                "b": {"image": "i", "env_file": "app.env"},
            }
        }
        resolved = resolve_env_files(data, tmp_path)
        assert _keys(resolved, "a") == _keys(resolved, "b") == {"PW": "hunter2"}


class TestEnvironmentPrecedence:
    """``environment:`` wins, so the file contributes nothing for that key."""

    def test_mapping_spelling_shadows(self, tmp_path: Path) -> None:
        (tmp_path / "app.env").write_text("K=from-file\nJ=kept\n", encoding="utf-8")
        resolved = resolve_env_files(
            _document("app.env", {"K": "from-environment"}), tmp_path
        )
        assert _keys(resolved) == {"J": "kept"}

    def test_list_spelling_shadows(self, tmp_path: Path) -> None:
        (tmp_path / "app.env").write_text("K=from-file\nJ=kept\n", encoding="utf-8")
        resolved = resolve_env_files(
            _document("app.env", ["K=from-environment"]), tmp_path
        )
        assert _keys(resolved) == {"J": "kept"}

    def test_a_bare_list_entry_shadows(self, tmp_path: Path) -> None:
        """``- K`` sets the key from Compose's environment, which still wins."""
        (tmp_path / "app.env").write_text("K=from-file\nJ=kept\n", encoding="utf-8")
        resolved = resolve_env_files(_document("app.env", ["K"]), tmp_path)
        assert _keys(resolved) == {"J": "kept"}


class TestUnread:
    def test_absent_and_required(self, tmp_path: Path) -> None:
        resolved = resolve_env_files(_document("nope.env"), tmp_path)
        (unread,) = resolved["s"].unread
        assert (unread.path, unread.reason, unread.required) == (
            "nope.env",
            Unread.ABSENT,
            True,
        )

    def test_absent_and_optional(self, tmp_path: Path) -> None:
        resolved = resolve_env_files(
            _document([{"path": "nope.env", "required": False}]), tmp_path
        )
        (unread,) = resolved["s"].unread
        assert unread.reason is Unread.ABSENT
        assert unread.required is False, (
            "only a required target's absence means the project cannot deploy"
        )

    def test_an_unresolved_path_names_no_file(self, tmp_path: Path) -> None:
        resolved = resolve_env_files(_document("${WHICH}.env"), tmp_path)
        (unread,) = resolved["s"].unread
        assert unread.reason is Unread.UNRESOLVED_PATH

    @pytest.mark.parametrize(
        "path",
        [
            "../outside.env",
            "conf/../../outside.env",
            "/etc/app.env",
            "~/.aws/credentials",
            "C:/Users/me/app.env",
        ],
    )
    def test_a_path_outside_the_project_is_refused(
        self, path: str, tmp_path: Path
    ) -> None:
        """Compose reads all of these. ADR-027 §7 does not."""
        resolved = resolve_env_files(_document(path), tmp_path)
        (unread,) = resolved["s"].unread
        assert unread.reason is Unread.OUTSIDE_PROJECT

    def test_a_climb_that_returns_inside_is_not_refused(self, tmp_path: Path) -> None:
        """``conf/../app.env`` never leaves, so there is nothing to refuse."""
        (tmp_path / "app.env").write_text("PW=hunter2\n", encoding="utf-8")
        resolved = resolve_env_files(_document("conf/../app.env"), tmp_path)
        assert _keys(resolved) == {"PW": "hunter2"}

    def test_over_the_byte_cap_is_unreadable(self, tmp_path: Path) -> None:
        (tmp_path / "app.env").write_text("K=" + "x" * MAX_ENV_BYTES, encoding="utf-8")
        resolved = resolve_env_files(_document("app.env"), tmp_path)
        (unread,) = resolved["s"].unread
        assert unread.reason is Unread.UNREADABLE

    def test_undecodable_is_unreadable(self, tmp_path: Path) -> None:
        (tmp_path / "app.env").write_bytes(b"K=\xff\xfe\n")
        resolved = resolve_env_files(_document("app.env"), tmp_path)
        (unread,) = resolved["s"].unread
        assert unread.reason is Unread.UNREADABLE

    def test_a_fifo_is_unreadable(self, tmp_path: Path) -> None:
        if not hasattr(os, "mkfifo"):
            pytest.skip("no mkfifo on this platform")
        os.mkfifo(tmp_path / "app.env")
        assert stat.S_ISFIFO((tmp_path / "app.env").stat().st_mode)
        resolved = resolve_env_files(_document("app.env"), tmp_path)
        (unread,) = resolved["s"].unread
        assert unread.reason is Unread.UNREADABLE

    def test_one_unread_target_does_not_stop_the_others(self, tmp_path: Path) -> None:
        (tmp_path / "b.env").write_text("PW=hunter2\n", encoding="utf-8")
        resolved = resolve_env_files(_document(["nope.env", "b.env"]), tmp_path)
        assert _keys(resolved) == {"PW": "hunter2"}
        assert len(resolved["s"].unread) == 1


def _compose_cli_works() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return (
            subprocess.run(
                ["docker", "compose", "version"], capture_output=True, timeout=30
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


@pytest.mark.skipif(
    not _compose_cli_works(),
    reason="differential env_file: selection test needs a working docker compose CLI",
)
class TestAgreesWithCompose:
    """Precedence and scoping, re-derived from the binary rather than the docs."""

    @staticmethod
    def _theirs(directory: Path, document: str) -> dict[str, str] | None:
        (directory / "compose.yml").write_text(document, encoding="utf-8", newline="")
        result = subprocess.run(
            ["docker", "compose", "config"],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            return None
        service = yaml.safe_load(result.stdout)["services"]["s"]
        return {k: str(v) for k, v in (service.get("environment") or {}).items()}

    def test_environment_beats_every_env_file(self, tmp_path: Path) -> None:
        document = (
            "services:\n  s:\n    image: i\n    env_file: [a.env]\n"
            "    environment:\n      K: from-environment\n"
        )
        (tmp_path / "a.env").write_text("K=from-file\nJ=kept\n", encoding="utf-8")
        assert self._theirs(tmp_path, document) == {
            "K": "from-environment",
            "J": "kept",
        }
        data = yaml.safe_load(document)
        assert _keys(resolve_env_files(data, tmp_path)) == {"J": "kept"}, (
            "we drop the shadowed key because the file contributes nothing for it"
        )

    def test_a_later_file_beats_an_earlier_one(self, tmp_path: Path) -> None:
        document = "services:\n  s:\n    image: i\n    env_file: [a.env, b.env]\n"
        (tmp_path / "a.env").write_text("K=first\n", encoding="utf-8")
        (tmp_path / "b.env").write_text("K=second\n", encoding="utf-8")
        assert self._theirs(tmp_path, document) == {"K": "second"}
        data = yaml.safe_load(document)
        assert _keys(resolve_env_files(data, tmp_path)) == {"K": "second"}

    def test_a_missing_required_target_aborts_the_run(self, tmp_path: Path) -> None:
        """The state ADR-027 leans on: there is no shipped configuration."""
        document = "services:\n  s:\n    image: i\n    env_file: [nope.env]\n"
        assert self._theirs(tmp_path, document) is None
        data = yaml.safe_load(document)
        (unread,) = resolve_env_files(data, tmp_path)["s"].unread
        assert (unread.reason, unread.required) == (Unread.ABSENT, True)

    def test_a_missing_optional_target_ships(self, tmp_path: Path) -> None:
        document = (
            "services:\n  s:\n    image: i\n    env_file:\n"
            "      - path: nope.env\n        required: false\n"
        )
        assert self._theirs(tmp_path, document) == {}
        data = yaml.safe_load(document)
        (unread,) = resolve_env_files(data, tmp_path)["s"].unread
        assert (unread.reason, unread.required) == (Unread.ABSENT, False)

    def test_the_path_interpolates_from_the_dotenv(self, tmp_path: Path) -> None:
        """Compose resolves it; we see it already resolved, or not at all.

        The substitution happens in the parser before this module runs, so the
        case that reaches here is the *unresolvable* one — which is why the
        document below supplies no ``.env`` and the expectation is a refusal
        rather than a read.
        """
        document = 'services:\n  s:\n    image: i\n    env_file: ["${WHICH}.env"]\n'
        (tmp_path / ".env").write_text("WHICH=prod\n", encoding="utf-8")
        (tmp_path / "prod.env").write_text("PW=prodpass\n", encoding="utf-8")
        assert self._theirs(tmp_path, document) == {"PW": "prodpass"}

        data = yaml.safe_load(document)
        (unread,) = resolve_env_files(data, tmp_path)["s"].unread
        assert unread.reason is Unread.UNRESOLVED_PATH, (
            "an unsubstituted path names no file; the parser substitutes first"
        )
