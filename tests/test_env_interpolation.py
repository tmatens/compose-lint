"""A sibling ``.env`` supplies interpolation values (ADR-026 §2).

The gap this closes is the one issue #646 opened on: ``volumes: ["${MOUNT}:/data"]``
with a ``.env`` setting ``MOUNT=/var/run/docker.sock`` deploys the control socket,
and CL-0001 — the highest-severity rule in the tool — was silent on it.

``TestCredentialRulesAreUnaffected`` is the other half, and the more important
one to keep: a ``.env`` must never turn a credential rule *on*.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from compose_lint.engine import run_rules
from compose_lint.parser import load_compose

if TYPE_CHECKING:
    from pathlib import Path


def write(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.write_text(text, encoding="utf-8", newline="")
    return path


def rules_fired(directory: Path, *, use_env: bool = True) -> set[str]:
    data, lines = load_compose(directory / "compose.yml", use_env=use_env)
    return {f.rule_id for f in run_rules(data, lines) if not f.suppressed}


def evidence_for(directory: Path, rule_id: str) -> set[str]:
    data, lines = load_compose(directory / "compose.yml")
    return {f.evidence for f in run_rules(data, lines) if f.rule_id == rule_id}


class TestDeploymentValuesResolve:
    """Values that describe what is deployed are resolved from the `.env`."""

    def test_the_issue_646_reproduction(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "compose.yml",
            'services:\n  web:\n    image: i\n    volumes: ["${MOUNT}:/data"]\n',
        )
        write(tmp_path, ".env", "MOUNT=/var/run/docker.sock\n")
        assert "CL-0001" in rules_fired(tmp_path)

    def test_silent_without_the_env(self, tmp_path: Path) -> None:
        """Unchanged behaviour: nothing is invented for an unsupplied name."""
        write(
            tmp_path,
            "compose.yml",
            'services:\n  web:\n    image: i\n    volumes: ["${MOUNT}:/data"]\n',
        )
        assert "CL-0001" not in rules_fired(tmp_path)

    def test_no_env_opts_out(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "compose.yml",
            'services:\n  web:\n    image: i\n    volumes: ["${MOUNT}:/data"]\n',
        )
        write(tmp_path, ".env", "MOUNT=/var/run/docker.sock\n")
        assert "CL-0001" not in rules_fired(tmp_path, use_env=False)

    def test_a_supplied_value_beats_a_written_default(self, tmp_path: Path) -> None:
        """Compose's own precedence: the default applies only when unset."""
        write(
            tmp_path,
            "compose.yml",
            'services:\n  web:\n    image: i\n    volumes: ["${M:-/tmp}:/data"]\n',
        )
        write(tmp_path, ".env", "M=/var/run/docker.sock\n")
        assert "CL-0001" in rules_fired(tmp_path)

    def test_a_supplied_value_can_also_clear_a_finding(self, tmp_path: Path) -> None:
        """The gap runs both ways: a pinned tag retires a CL-0004."""
        write(tmp_path, "compose.yml", 'services:\n  web:\n    image: "app:${TAG}"\n')
        write(tmp_path, ".env", "TAG=1.2.3\n")
        assert "CL-0004" not in rules_fired(tmp_path)

    def test_a_segment_reference_resolves(self, tmp_path: Path) -> None:
        """The commonest real shape: a directory from the `.env`, a fixed leaf.

        The resolved path is what reaches the rule, so the evidence is the
        joined value rather than the reference the file carries.
        """
        write(
            tmp_path,
            "compose.yml",
            'services:\n  web:\n    image: i\n    volumes: ["${D}/docker.sock:/x"]\n',
        )
        write(tmp_path, ".env", "D=/var/run\n")
        assert "/var/run/docker.sock" in evidence_for(tmp_path, "CL-0001")

    def test_a_chained_env_value_resolves(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "compose.yml",
            'services:\n  web:\n    image: i\n    volumes: ["${SOCK}:/x"]\n',
        )
        write(tmp_path, ".env", "BASE=/var/run\nSOCK=${BASE}/docker.sock\n")
        assert "CL-0001" in rules_fired(tmp_path)


class TestCredentialRulesAreUnaffected:
    """ADR-026 §2 as amended: a `.env` value never reaches `environment:`.

    Without this the tool contradicts itself — CL-0021's own fix text offers
    `postgres://user:${DB_PASSWORD}@host/db` as the remediation, so a `.env`
    supplying `DB_PASSWORD` would flag the advice the rule just gave.
    """

    @pytest.mark.parametrize("spelling", ["mapping", "list"])
    def test_a_supplied_password_does_not_fire_cl0020(
        self, tmp_path: Path, spelling: str
    ) -> None:
        """Both spellings, because a `str` marker would survive only one."""
        env_block = (
            '      POSTGRES_PASSWORD: "${PW}"'
            if spelling == "mapping"
            else '      - "POSTGRES_PASSWORD=${PW}"'
        )
        write(
            tmp_path,
            "compose.yml",
            "services:\n  db:\n    image: postgres:16\n"
            f"    environment:\n{env_block}\n",
        )
        write(tmp_path, ".env", "PW=hunter2\n")
        assert "CL-0020" not in rules_fired(tmp_path)

    def test_a_supplied_connection_string_does_not_fire_cl0021(
        self, tmp_path: Path
    ) -> None:
        write(
            tmp_path,
            "compose.yml",
            "services:\n  app:\n    image: i\n    environment:\n"
            '      DATABASE_URL: "${DB_URL}"\n',
        )
        write(tmp_path, ".env", "DB_URL=postgres://u:realpass@db/x\n")
        assert "CL-0021" not in rules_fired(tmp_path)

    def test_a_literal_still_fires(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "compose.yml",
            "services:\n  db:\n    image: postgres:16\n    environment:\n"
            '      POSTGRES_PASSWORD: "hunter2"\n',
        )
        write(tmp_path, ".env", "PW=irrelevant\n")
        assert "CL-0020" in rules_fired(tmp_path)

    def test_a_written_default_still_fires(self, tmp_path: Path) -> None:
        """A default is committed and ships to every clone, so it is the
        file's own weak credential — unlike a value from a sibling."""
        write(
            tmp_path,
            "compose.yml",
            "services:\n  db:\n    image: postgres:16\n    environment:\n"
            '      POSTGRES_PASSWORD: "${PW:-changeme}"\n',
        )
        write(tmp_path, ".env", "OTHER=x\n")
        assert "CL-0020" in rules_fired(tmp_path)

    def test_the_secret_is_never_read_out_of_the_env(self, tmp_path: Path) -> None:
        """ADR-026 §5: a name referenced only from `environment:` is not even
        in the wanted set, so its value is never retained."""
        from compose_lint.parser import _referenced_names

        data, _ = load_compose(
            write(
                tmp_path,
                "compose.yml",
                "services:\n  db:\n    image: i\n    environment:\n"
                '      POSTGRES_PASSWORD: "${PW}"\n    volumes: ["${M}:/x"]\n',
            ).parent
            / "compose.yml"
        )
        names = _referenced_names(data)
        assert "M" in names
        assert "PW" not in names
