"""``extends:`` merges the way Compose merges it (#881).

Every expected value below was measured with ``docker compose config`` on
Compose 5.5.0 against the same fixture:

- A child's ``!reset`` deletes the inherited key and ``!override`` replaces the
  inherited value, exactly as in an overlay. Both were ignored by every
  ``extends:`` path, so a child that un-hardened itself was graded as hardened,
  and one that narrowed a grant was blamed for the base's wider one.
- A service an included document declares with ``extends:`` arrives already
  resolved against that document's directory; resolving it again against the
  including project's directory read the wrong file or reported a false gap.
- ``volumes``/``devices`` merge keyed on the normalized container path, so a
  child remounting ``/var/run/docker.sock/`` replaces the base's socket mount.
- A missing in-file target and a cycle are refused by Compose, per file, so
  they are coverage gaps rather than quiet passes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from compose_lint.engine import run_rules
from compose_lint.parser import load_compose_full

if TYPE_CHECKING:
    from pathlib import Path

HARDENED_BASE = (
    "services:\n"
    "  base:\n"
    "    image: nginx:1.27\n"
    "    read_only: true\n"
    "    cap_drop: [ALL]\n"
    "    security_opt:\n"
    "      - no-new-privileges:true\n"
)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _findings(path: Path) -> dict[str, set[str]]:
    loaded = load_compose_full(path)
    out: dict[str, set[str]] = {}
    for finding in run_rules(loaded.data, loaded.lines):
        out.setdefault(finding.service or "", set()).add(finding.rule_id)
    return out


UNHARDENING_CHILD = (
    "    read_only: !reset true\n"
    "    cap_drop: !reset []\n"
    '    security_opt: !override ["apparmor=docker-default"]\n'
)


class TestResetAndOverride:
    def test_an_in_file_child_that_resets_its_hardening_is_flagged(
        self, tmp_path: Path
    ) -> None:
        path = _write(
            tmp_path / "compose.yml",
            HARDENED_BASE + "  child:\n    extends: base\n" + UNHARDENING_CHILD,
        )
        loaded = load_compose_full(path)
        child = loaded.data["services"]["child"]
        assert "read_only" not in child
        assert "cap_drop" not in child
        assert child["security_opt"] == ["apparmor=docker-default"]
        assert {"CL-0003", "CL-0006", "CL-0007"} <= _findings(path)["child"]
        assert loaded.gaps == ()

    def test_an_in_file_child_without_directives_still_inherits(
        self, tmp_path: Path
    ) -> None:
        path = _write(
            tmp_path / "compose.yml",
            HARDENED_BASE + "  child:\n    extends: base\n    cap_drop: []\n",
        )
        child = _findings(path).get("child", set())
        assert not {"CL-0003", "CL-0006", "CL-0007"} & child

    def test_an_override_that_narrows_a_grant_is_not_blamed_for_the_base(
        self, tmp_path: Path
    ) -> None:
        path = _write(
            tmp_path / "compose.yml",
            "services:\n"
            "  base:\n    image: nginx:1.27\n"
            "    cap_add: [SYS_ADMIN]\n    cap_drop: [ALL]\n"
            "  child:\n    extends: base\n    cap_add: !override [CHOWN]\n",
        )
        loaded = load_compose_full(path)
        assert loaded.data["services"]["child"]["cap_add"] == ["CHOWN"]
        findings = _findings(path)
        assert "CL-0024" in findings["base"]
        assert "CL-0024" not in findings.get("child", set())

    def test_without_override_the_grant_is_still_inherited(
        self, tmp_path: Path
    ) -> None:
        path = _write(
            tmp_path / "compose.yml",
            "services:\n"
            "  base:\n    image: nginx:1.27\n    cap_add: [SYS_ADMIN]\n"
            "  child:\n    extends: base\n    cap_add: [CHOWN]\n",
        )
        loaded = load_compose_full(path)
        assert loaded.data["services"]["child"]["cap_add"] == ["SYS_ADMIN", "CHOWN"]
        assert "CL-0024" in _findings(path)["child"]

    def test_a_cross_file_child_honours_its_directives(self, tmp_path: Path) -> None:
        _write(tmp_path / "shared" / "base.yml", HARDENED_BASE)
        path = _write(
            tmp_path / "compose.yml",
            "services:\n  child:\n"
            "    extends: {file: shared/base.yml, service: base}\n" + UNHARDENING_CHILD,
        )
        loaded = load_compose_full(path)
        assert loaded.gaps == ()
        child = loaded.data["services"]["child"]
        assert "read_only" not in child
        assert "cap_drop" not in child
        assert child["security_opt"] == ["apparmor=docker-default"]

    def test_a_cross_file_child_without_directives_still_inherits(
        self, tmp_path: Path
    ) -> None:
        _write(tmp_path / "shared" / "base.yml", HARDENED_BASE)
        path = _write(
            tmp_path / "compose.yml",
            "services:\n  child:\n"
            "    extends: {file: shared/base.yml, service: base}\n",
        )
        child = load_compose_full(path).data["services"]["child"]
        assert child["read_only"] is True
        assert child["cap_drop"] == ["ALL"]


class TestIncludedExtends:
    SUB = "services:\n  api:\n    extends:\n      file: base.yml\n      service: base\n"

    def _project(self, tmp_path: Path) -> Path:
        _write(tmp_path / "sub" / "compose.yml", self.SUB)
        _write(tmp_path / "sub" / "base.yml", HARDENED_BASE)
        return _write(
            tmp_path / "compose.yml", "include:\n  - sub/compose.yml\nservices: {}\n"
        )

    def test_it_is_not_re_resolved_against_the_including_directory(
        self, tmp_path: Path
    ) -> None:
        path = self._project(tmp_path)
        loaded = load_compose_full(path)
        assert loaded.gaps == ()
        api = loaded.data["services"]["api"]
        assert api["read_only"] is True
        assert api["cap_drop"] == ["ALL"]

    def test_a_like_named_base_at_the_root_is_not_merged(self, tmp_path: Path) -> None:
        path = self._project(tmp_path)
        _write(
            tmp_path / "base.yml",
            "services:\n  base:\n    image: nginx:1.27\n    privileged: true\n",
        )
        loaded = load_compose_full(path)
        assert loaded.gaps == ()
        assert "privileged" not in loaded.data["services"]["api"]
        assert "CL-0002" not in _findings(path).get("api", set())

    def test_a_root_service_extending_an_included_one_is_still_resolved(
        self, tmp_path: Path
    ) -> None:
        _write(tmp_path / "sub" / "compose.yml", HARDENED_BASE)
        path = _write(
            tmp_path / "compose.yml",
            "include:\n  - sub/compose.yml\nservices:\n  web:\n    extends: base\n",
        )
        loaded = load_compose_full(path)
        assert loaded.gaps == ()
        assert loaded.data["services"]["web"]["read_only"] is True


class TestNormalizedMountKey:
    BASE = (
        "services:\n"
        "  base:\n    image: nginx:1.27\n"
        "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
    )

    def test_a_trailing_slash_target_replaces_the_base_mount(
        self, tmp_path: Path
    ) -> None:
        path = _write(
            tmp_path / "compose.yml",
            self.BASE + "  worker:\n    extends: base\n"
            "    volumes:\n      - /tmp/empty:/var/run/docker.sock/\n"
            "  clean:\n    extends: base\n"
            "    volumes:\n"
            "      - type: bind\n"
            "        source: /tmp/empty\n"
            "        target: /var/run/docker.sock/.\n",
        )
        loaded = load_compose_full(path)
        assert len(loaded.data["services"]["worker"]["volumes"]) == 1
        assert len(loaded.data["services"]["clean"]["volumes"]) == 1
        findings = _findings(path)
        assert "CL-0001" in findings["base"]
        assert "CL-0001" not in findings.get("worker", set())
        assert "CL-0001" not in findings.get("clean", set())

    def test_a_different_target_still_appends(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "compose.yml",
            self.BASE + "  worker:\n    extends: base\n"
            "    volumes:\n      - /tmp/empty:/var/run/docker.sock.d/\n",
        )
        assert len(load_compose_full(path).data["services"]["worker"]["volumes"]) == 2
        assert "CL-0001" in _findings(path)["worker"]

    def test_device_targets_are_normalized_too(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "compose.yml",
            "services:\n"
            "  base:\n    image: nginx:1.27\n    devices: [/dev/sda:/dev/xvda]\n"
            "  child:\n    extends: base\n    devices: ['/dev/null:/dev//xvda/']\n",
        )
        devices = load_compose_full(path).data["services"]["child"]["devices"]
        assert devices == ["/dev/null:/dev//xvda/"]


class TestUnresolvableInFileTarget:
    def test_a_missing_target_is_a_gap(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "compose.yml",
            "services:\n  web:\n    image: nginx:1.27\n    extends: nothere\n",
        )
        (gap,) = load_compose_full(path).gaps
        assert "'extends: nothere'" in gap
        assert "no service 'nothere'" in gap
        assert "'web'" in gap

    def test_a_cycle_is_a_gap(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "compose.yml",
            "services:\n"
            "  a:\n    image: nginx:1.27\n    extends: b\n"
            "  b:\n    extends: a\n",
        )
        (gap,) = load_compose_full(path).gaps
        assert "returns to a service it already inherited" in gap

    def test_a_service_extending_itself_is_a_gap(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "compose.yml",
            "services:\n  a:\n    image: nginx:1.27\n    extends: {service: a}\n",
        )
        assert len(load_compose_full(path).gaps) == 1

    def test_a_resolvable_target_is_not_a_gap(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "compose.yml",
            HARDENED_BASE + "  web:\n    extends: base\n  api:\n    extends: web\n",
        )
        assert load_compose_full(path).gaps == ()

    def test_the_cli_exits_two_on_a_missing_target(self, tmp_path: Path) -> None:
        import pytest

        from compose_lint import cli

        path = _write(
            tmp_path / "compose.yml",
            "services:\n  web:\n    image: nginx:1.27\n    extends: nothere\n",
        )
        with pytest.raises(SystemExit) as gap:
            cli.main([str(path)])
        assert gap.value.code == 2
        with pytest.raises(SystemExit) as accepted:
            cli.main(["--allow-partial-coverage", str(path)])
        assert accepted.value.code == 0
