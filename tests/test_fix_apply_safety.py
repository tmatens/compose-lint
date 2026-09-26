"""`fix --apply` refuses the shapes that wrote a file Compose rejects (#886).

Two shapes got past every apply-time layer ADR-014 describes, and each wrote a
file `docker compose config` refuses while the re-lint passed:

- a long-syntax port whose first value wraps onto the next line took a
  `host_ip:` key between the value and its continuation;
- a `ports:` list shared by two services through an anchor was edited once per
  service at its one physical line, prefixing `127.0.0.1:` twice.

The structure check behind them was per service, so a service that collected
one legitimate fix was exempt wholesale, and an anchor edit leaked into a
service whose finding was excluded.

Where a working `docker compose` is available, every file these tests write is
also checked with `docker compose config`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli
from compose_lint.engine import run_rules
from compose_lint.fix import collect_edits
from compose_lint.parser import loads

if TYPE_CHECKING:
    from pathlib import Path


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


_HAS_COMPOSE = _compose_cli_works()


def _assert_compose_accepts(path: Path) -> None:
    if not _HAS_COMPOSE:
        return
    proc = subprocess.run(
        ["docker", "compose", "-f", path.name, "config", "-q"],
        cwd=path.parent,
        capture_output=True,
        text=True,
        timeout=60,
        # The caller's environment, so the CLI finds its compose plugin, minus
        # anything that would change which files Compose loads.
        env={k: v for k, v in os.environ.items() if not k.startswith("COMPOSE_")},
    )
    assert proc.returncode == 0, proc.stderr


def _apply(
    tmp_path: Path,
    text: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
    *,
    config: str | None = None,
) -> tuple[int, str, str]:
    path = tmp_path / "compose.yml"
    path.write_text(text, encoding="utf-8")
    if config is not None:
        (tmp_path / ".compose-lint.yml").write_text(config, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NO_COLOR", "1")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", "--apply", "compose.yml"])
    err = capsys.readouterr().err
    code = exc.value.code if isinstance(exc.value.code, int) else 1
    return code, path.read_text(encoding="utf-8"), err


WRAPPED = """\
services:
  web:
    image: nginx:1.27
    ports:
      - name: public web
          entry point
        target: 80
        published: 8080
"""

UNWRAPPED = """\
services:
  web:
    image: nginx:1.27
    ports:
      - name: public
        target: 80
        published: 8080
"""


class TestWrappedLongSyntaxValue:
    def test_host_ip_is_not_inserted_into_a_wrapped_value(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        code, written, _ = _apply(tmp_path, WRAPPED, monkeypatch, capsys)
        assert code == 0
        assert "host_ip" not in written
        assert "      - name: public web\n          entry point\n" in written
        _assert_compose_accepts(tmp_path / "compose.yml")

    def test_a_comment_after_the_value_is_not_a_continuation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        text = UNWRAPPED.replace(
            "      - name: public\n", "      - name: public\n          # note\n"
        )
        _, written, _ = _apply(tmp_path, text, monkeypatch, capsys)
        assert "host_ip: 127.0.0.1" in written
        _assert_compose_accepts(tmp_path / "compose.yml")

    def test_an_unwrapped_value_still_gets_host_ip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        _, written, _ = _apply(tmp_path, UNWRAPPED, monkeypatch, capsys)
        assert "      - name: public\n        host_ip: 127.0.0.1\n" in written
        _assert_compose_accepts(tmp_path / "compose.yml")


SHARED_PORTS = """\
services:
  web:
    image: nginx:1.27
    ports: &p
      - 8080:80
  api:
    image: nginx:1.27
    ports: *p
"""

SHARED_TMPFS = """\
services:
  web:
    image: nginx:1.27
    tmpfs: &t
      - /run:exec
  api:
    image: nginx:1.27
    tmpfs: *t
"""


class TestAnchorSharedLists:
    def test_a_shared_ports_list_is_not_edited(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        code, written, _ = _apply(tmp_path, SHARED_PORTS, monkeypatch, capsys)
        assert code == 0
        assert "      - 8080:80\n" in written
        assert "127.0.0.1" not in written
        _assert_compose_accepts(tmp_path / "compose.yml")

    def test_a_shared_tmpfs_list_is_not_edited(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        _, written, _ = _apply(tmp_path, SHARED_TMPFS, monkeypatch, capsys)
        assert "      - /run:exec\n" in written
        _assert_compose_accepts(tmp_path / "compose.yml")

    def test_unshared_lists_are_still_fixed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        text = (
            "services:\n"
            "  web:\n    image: nginx:1.27\n    ports:\n      - 8080:80\n"
            "    tmpfs:\n      - /run:exec\n"
            "  api:\n    image: nginx:1.27\n    ports:\n      - 8081:81\n"
        )
        _, written, _ = _apply(tmp_path, text, monkeypatch, capsys)
        assert "      - 127.0.0.1:8080:80\n" in written
        assert "      - 127.0.0.1:8081:81\n" in written
        assert "      - /run\n" in written
        _assert_compose_accepts(tmp_path / "compose.yml")

    def test_an_excluded_service_is_not_rewritten_through_the_anchor(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        config = 'rules:\n  CL-0005:\n    exclude_services:\n      api: "test"\n'
        _, written, _ = _apply(
            tmp_path, SHARED_PORTS, monkeypatch, capsys, config=config
        )
        assert "      - 8080:80\n" in written
        assert "127.0.0.1:8080" not in written
        _assert_compose_accepts(tmp_path / "compose.yml")

    def test_a_same_service_alias_consumer_is_not_changed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        text = (
            "services:\n  web:\n    image: nginx:1.27\n"
            "    ports: &p\n      - 8080:80\n    command: *p\n"
        )
        _, written, _ = _apply(tmp_path, text, monkeypatch, capsys)
        assert "      - 8080:80\n" in written


def test_an_edit_on_another_services_line_is_not_applied_twice() -> None:
    # Two findings that resolve to one physical line used to produce the same
    # insertion twice, and the identical-insertion conflict refused both. Since
    # #881 the engine refuses first any edit outside its finding's own service
    # block, so `api`'s edit on `web`'s line never competes: `web`'s own fix
    # applies once and `api` is left for review. The line map is what an alias
    # produces; the text keeps each `ports:` line opening a block, the case the
    # anchor refusal cannot see. The real shapes that produce it are refused
    # earlier, below.
    text = (
        "services:\n"
        "  web:\n    image: nginx:1.27\n    ports:\n      - 8080:80\n"
        "  api:\n    image: nginx:1.27\n    ports:\n      - 9090:90\n"
    )
    data, lines = loads(text)
    lines["services.api.ports[0]"] = lines["services.web.ports[0]"]
    data["services"]["api"]["ports"] = ["8080:80"]
    findings = [f for f in run_rules(data, lines) if f.rule_id == "CL-0005"]
    assert {f.service for f in findings} == {"web", "api"}
    result = collect_edits(findings, data, lines, text, only={"CL-0005"})
    assert len(result.edits) == 1
    assert result.edits[0].start_line == 5
    assert {f.service for f in result.fixed} == {"web"}
    assert {f.service for f in result.manual} == {"api"}


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "services:\n"
            "  web:\n    image: nginx:1.27\n    ports: &p\n      - 8080:80\n"
            "  api:\n    image: nginx:1.27\n    ports: *p\n",
            id="aliased-list",
        ),
        pytest.param(
            "x-base: &b\n  image: nginx:1.27\n  ports:\n    - 8080:80\n"
            "services:\n  web:\n    <<: *b\n  api:\n    <<: *b\n",
            id="merge-key-from-extension",
        ),
        pytest.param(
            "services:\n"
            "  web: &w\n    image: nginx:1.27\n    ports:\n      - 8080:80\n"
            "  api:\n    <<: *w\n",
            id="merge-key-from-service",
        ),
    ],
)
def test_a_list_two_services_share_is_refused_for_both(text: str) -> None:
    """The real shapes behind a shared line still refuse every service."""
    data, lines = loads(text)
    findings = [f for f in run_rules(data, lines) if f.rule_id == "CL-0005"]
    assert {f.service for f in findings} == {"web", "api"}
    result = collect_edits(findings, data, lines, text, only={"CL-0005"})
    assert result.edits == []
    assert {f.service for f in result.manual} == {"web", "api"}


class TestInheritedClaims:
    def test_a_fixed_child_may_inherit_a_key_its_base_fix_writes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        # The base's port fix reaches the child through `extends:`, and the
        # child collected fixes of its own. Measured on the corpus: two real
        # files have this shape, and a per-key check that ignored inheritance
        # refused the whole write for both.
        text = (
            "services:\n"
            "  base:\n    image: nginx:1.27\n    ports:\n      - 8080:80\n"
            "  child:\n    extends: base\n    image: nginx:1.27\n"
        )
        code, written, err = _apply(tmp_path, text, monkeypatch, capsys)
        assert code == 0, err
        assert "      - 127.0.0.1:8080:80\n" in written
        _assert_compose_accepts(tmp_path / "compose.yml")

    def test_inheritance_does_not_excuse_an_unclaimed_key(self) -> None:
        from compose_lint.fix import _structural_drift, _with_inherited_claims

        original = {
            "services": {
                "base": {"image": "a", "ports": ["8080:80"]},
                "child": {"extends": "base", "image": "a"},
            }
        }
        patched = {
            "services": {
                "base": {"image": "a", "ports": ["8080:80"]},
                "child": {"extends": "base", "image": "a", "privileged": True},
            }
        }
        claims = _with_inherited_claims(
            original, {"base": frozenset({"ports"}), "child": frozenset({"read_only"})}
        )
        assert claims["child"] == frozenset({"ports", "read_only"})
        assert _structural_drift(original, patched, claims) == (
            "computed fix altered 'privileged' on service 'child'"
        )

    def test_an_untouched_child_is_still_held_to_whole_service_equality(
        self,
    ) -> None:
        from compose_lint.fix import _with_inherited_claims

        original = {
            "services": {
                "base": {"image": "a"},
                "child": {"extends": "base", "image": "a"},
            }
        }
        claims = _with_inherited_claims(original, {"base": frozenset({"ports"})})
        assert "child" not in claims


def test_value_is_shared_reads_anchor_and_alias_tokens_only() -> None:
    from compose_lint._yaml_edit import value_is_shared

    assert value_is_shared("    ports: &p\n")
    assert value_is_shared("    ports: *p\n")
    assert value_is_shared("    ports: !override &p\n")
    assert not value_is_shared("    ports: !override\n")
    assert not value_is_shared("    ports:\n")
    assert not value_is_shared("    ports:  # &not-an-anchor\n")
    assert not value_is_shared("    - 8080:80\n")


def test_value_continues_skips_blanks_and_stops_at_a_comment() -> None:
    from compose_lint.rules.CL0005_unbound_ports import _value_continues

    lines = ["      - name: a\n", "\n", "          wrapped\n"]
    assert _value_continues(lines, 1, 8)
    assert not _value_continues(["      - name: a\n", "          # c\n"], 1, 8)
    assert not _value_continues(["      - name: a\n", "\n"], 1, 8)
    assert not _value_continues(["      - name: a\n", "        target: 80\n"], 1, 8)


def test_the_structure_check_tolerates_non_mapping_services() -> None:
    from compose_lint.fix import _structural_drift, _with_inherited_claims

    original = {"services": {"web": None, "api": {"extends": {"file": "x.yml"}}}}
    assert _with_inherited_claims({"services": []}, {"web": frozenset()}) == {
        "web": frozenset()
    }
    claims = _with_inherited_claims(original, {"web": frozenset({"ports"})})
    assert claims == {"web": frozenset({"ports"})}
    assert _structural_drift(original, original, claims) is None
