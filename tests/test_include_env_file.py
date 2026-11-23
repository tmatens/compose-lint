"""An ``include:`` entry's ``env_file:`` supplies the included files' values.

ADR-036 §5 recorded that the key "redirected neither" value on Compose 5.5.0,
so it was read and not acted on. That measurement does not reproduce: on
5.5.0, 5.7.1 and 5.8.0 alike the listed files are read *in place of* the
sub-project's own ``.env``. Ignoring them graded ``privileged: ${PRIV:-false}``
as ``false`` where Compose deploys ``true``, and graded a value from a ``.env``
Compose no longer reads.

The behaviour tests hold each rule. The differential test at the end asks a
real Compose (5.8 or later, skipped without one) to resolve the same projects
and compares the interpolated values. It needs 5.8 because an entry written in
an included file had its path looked up from the working directory before it
(compose-go #996).
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import TYPE_CHECKING

import pytest

from compose_lint.engine import run_rules
from compose_lint.parser import ComposeRefusesGap, load_compose_full
from tests.oracle_harness import compose_argv

if TYPE_CHECKING:
    from pathlib import Path

# Three values, so a case can tell which file supplied which name.
SERVICE = (
    "services:\n  {name}:\n    image: i:${{A:-d}}\n    user: ${{B:-d}}\n"
    "    hostname: ${{C:-d}}\n"
)


def _svc(name: str = "web") -> str:
    return SERVICE.format(name=name)


def _entry(path: str, env_file: str) -> str:
    return f"include:\n  - path: {path}\n    env_file: {env_file}\n"


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root / "compose.yml"


def _values(loaded_services: dict[str, dict[str, object]]) -> dict[str, list[object]]:
    return {
        name: [config.get("image"), config.get("user"), config.get("hostname")]
        for name, config in loaded_services.items()
    }


# Each case is a project Compose 5.8.0 accepts, and the values it ships.
CASES: dict[str, dict[str, str]] = {
    "one-file": {
        "compose.yml": _entry("i.yml", "m.env"),
        "i.yml": _svc(),
        "m.env": "A=m\n",
    },
    "replaces-own-env": {
        "compose.yml": _entry("sub/i.yml", "m.env"),
        "sub/i.yml": _svc(),
        "sub/.env": "A=own\nB=own\n",
        "m.env": "A=m\n",
    },
    "project-env-wins": {
        "compose.yml": _entry("i.yml", "m.env"),
        "i.yml": _svc(),
        "m.env": "A=m\nB=m\n",
        ".env": "B=proj\n",
    },
    "list-later-wins": {
        "compose.yml": _entry("i.yml", "[one.env, two.env]"),
        "i.yml": _svc(),
        "one.env": "A=one\nB=one\n",
        "two.env": "A=two\n",
    },
    "list-reference-to-earlier-file": {
        "compose.yml": _entry("i.yml", "[one.env, two.env]"),
        "i.yml": _svc(),
        "one.env": "X=one\n",
        "two.env": "A=${X}-two\n",
    },
    "list-own-definition-shadows-earlier-file": {
        "compose.yml": _entry("i.yml", "[one.env, two.env]"),
        "i.yml": _svc(),
        "one.env": "X=one\n",
        "two.env": "X=two\nA=${X}-a\nB=${X}\n",
    },
    "reference-reads-the-project-first": {
        "compose.yml": _entry("i.yml", "m.env"),
        ".env": "P=proj\n",
        "i.yml": _svc(),
        "m.env": "P=file\nA=${P}-a\n",
    },
    "references-and-defaults": {
        "compose.yml": _entry("i.yml", "m.env"),
        "i.yml": _svc(),
        "m.env": "X=x\nA=${X}-a\nB=${P}-b\nC=${NOPE:-dflt}\n",
        ".env": "P=proj\n",
    },
    "empty-list-reads-the-own-env": {
        "compose.yml": _entry("sub/i.yml", "[]"),
        "sub/i.yml": _svc(),
        "sub/.env": "A=own\n",
    },
    "null-reads-the-own-env": {
        "compose.yml": "include:\n  - path: sub/i.yml\n    env_file:\n",
        "sub/i.yml": _svc(),
        "sub/.env": "A=own\n",
    },
    "dev-null-is-no-env-file": {
        "compose.yml": _entry("sub/i.yml", "/dev/null"),
        "sub/i.yml": _svc(),
        "sub/.env": "A=own\n",
    },
    "dev-null-in-a-list": {
        "compose.yml": _entry("sub/i.yml", "[/dev/null, m.env]"),
        "sub/i.yml": _svc(),
        "sub/.env": "A=own\nB=own\n",
        "m.env": "A=m\n",
    },
    "explicit-own-env-in-a-list": {
        "compose.yml": _entry("sub/i.yml", "[sub/.env, m.env]"),
        "sub/i.yml": _svc(),
        "sub/.env": "A=own\nB=own\n",
        "m.env": "A=m\n",
    },
    "reaches-a-nested-include": {
        "compose.yml": _entry("p/b.yml", "e.env"),
        "e.env": "A=e\n",
        "p/b.yml": "include: [q/c.yml]\n" + _svc("b"),
        "p/q/c.yml": _svc("c"),
        "p/q/.env": "A=q-own\nB=q-own\n",
        "p/.env": "C=p-own\n",
    },
    "reaches-an-extends-base": {
        "compose.yml": _entry("sub/i.yml", "m.env"),
        "m.env": "A=m\n",
        "sub/i.yml": "services:\n  web:\n    extends: {file: base.yml, service: b}\n",
        "sub/base.yml": _svc("b"),
        "sub/.env": "B=own\n",
    },
    "two-levels-outer-wins": {
        "compose.yml": _entry("b.yml", "e1.env"),
        "e1.env": "A=e1\n",
        "b.yml": _entry("c.yml", "e2.env"),
        "e2.env": "A=e2\nB=e2\n",
        "c.yml": _svc("c"),
    },
    "nested-entry-under-a-project-env": {
        "compose.yml": "include: [p/b.yml]\n",
        "p/.env": "A=p-own\nB=p-own\n",
        "p/b.yml": _entry("q/c.yml", "m.env"),
        "p/m.env": "A=m\nC=m\n",
        "p/q/c.yml": _svc("c"),
        "p/q/.env": "A=q-own\nB=q-own\nC=q-own\n",
    },
    "nested-three-deep": {
        "compose.yml": "include: [p/inc.yml]\n",
        "p/inc.yml": "include: [q/inc2.yml]\n",
        "p/q/inc2.yml": _entry("i3.yml", "marker.env"),
        "p/q/i3.yml": _svc(),
        "p/q/marker.env": "A=p-q\n",
        "marker.env": "A=root\n",
        "p/marker.env": "A=p\n",
    },
    "with-project-directory": {
        "compose.yml": "include:\n  - path: p/i.yml\n    project_directory: pd\n"
        "    env_file: m.env\n",
        "p/i.yml": _svc(),
        "m.env": "A=root-m\n",
        "pd/m.env": "A=pd-m\n",
        "pd/.env": "B=pd-env\n",
        "p/.env": "C=p-env\n",
    },
    "writer-has-a-project-directory": {
        "compose.yml": "include:\n  - path: p/inc.yml\n    project_directory: pd\n",
        "p/inc.yml": _entry("i3.yml", "m.env"),
        "pd/i3.yml": _svc(),
        "pd/m.env": "A=pd-m\n",
        "p/m.env": "A=p-m\n",
        "m.env": "A=root-m\n",
    },
    "path-list": {
        "compose.yml": _entry("[x/a.yml, y/b.yml]", "m.env"),
        "x/a.yml": _svc("a"),
        "y/b.yml": _svc("b"),
        "m.env": "A=m\n",
        "x/.env": "B=x-own\n",
    },
    "interpolated-path-with-a-default": {
        "compose.yml": _entry("i.yml", "${EF:-m.env}"),
        "i.yml": _svc(),
        "m.env": "A=m\n",
    },
    "the-writer-is-not-affected": {
        "compose.yml": _entry("i.yml", "m.env") + _svc("root"),
        "i.yml": _svc("inc"),
        "m.env": "A=m\n",
    },
    "plain-entry-beside-it": {
        "compose.yml": "include:\n  - a.yml\n  - path: b.yml\n    env_file: m.env\n",
        "a.yml": _svc("a"),
        "b.yml": _svc("b"),
        "m.env": "A=m\n",
    },
    # An included project's own `.env` is read under the including project's
    # environment in the same way.
    "own-env-references-the-project": {
        "compose.yml": "include: [sub/i.yml]\n",
        ".env": "P=proj\n",
        "sub/i.yml": _svc(),
        "sub/.env": "A=${P}-own\n",
    },
    "own-env-reference-reads-the-project-first": {
        "compose.yml": "include: [sub/i.yml]\n",
        ".env": "P=proj\n",
        "sub/i.yml": _svc(),
        "sub/.env": "P=own\nA=${P}-k\n",
    },
    "own-env-references-a-grandparent": {
        "compose.yml": "include: [a/b.yml]\n",
        ".env": "P=proj\n",
        "a/b.yml": "include: [c/i.yml]\n",
        "a/.env": "Q=${P}-a\n",
        "a/c/i.yml": _svc(),
        "a/c/.env": "A=${Q}-c\n",
    },
    "own-env-bare-key-takes-the-project-s-value": {
        "compose.yml": "include: [sub/i.yml]\n",
        ".env": "A=parent\n",
        "sub/i.yml": _svc(),
        "sub/.env": "A\nB\n",
    },
    # Compose refuses each of these, and each is a coverage gap here.
    "refused-missing": {
        "compose.yml": _entry("i.yml", "nope.env"),
        "i.yml": _svc(),
    },
    "refused-directory": {
        "compose.yml": _entry("i.yml", "d"),
        "i.yml": _svc(),
        "d/x": "A=1\n",
    },
    "refused-empty-path": {
        "compose.yml": _entry("i.yml", "''"),
        "i.yml": _svc(),
    },
    "refused-number": {
        "compose.yml": _entry("i.yml", "5"),
        "i.yml": _svc(),
    },
    "refused-mapping-item": {
        "compose.yml": "include:\n  - path: i.yml\n    env_file:\n"
        "      - path: m.env\n        required: false\n",
        "i.yml": _svc(),
        "m.env": "A=m\n",
    },
}


class TestValues:
    def test_the_listed_file_supplies_the_value(self, tmp_path: Path) -> None:
        loaded = load_compose_full(_write(tmp_path, CASES["one-file"]))
        assert loaded.data["services"]["web"]["image"] == "i:m"
        assert loaded.gaps == ()

    def test_it_replaces_the_sub_project_s_own_env(self, tmp_path: Path) -> None:
        loaded = load_compose_full(_write(tmp_path, CASES["replaces-own-env"]))
        web = loaded.data["services"]["web"]
        assert (web["image"], web["user"]) == ("i:m", "d")

    def test_a_privileged_default_is_graded_as_deployed(self, tmp_path: Path) -> None:
        """The false negative this fixes, and the false positive beside it."""
        service = "services:\n  web:\n    image: i\n    privileged: ${PRIV:-false}\n"
        missed = _write(
            tmp_path / "missed",
            {
                "compose.yml": _entry("i.yml", "m.env"),
                "i.yml": service,
                "m.env": "PRIV=true\n",
            },
        )
        loaded = load_compose_full(missed)
        assert "CL-0002" in {f.rule_id for f in run_rules(loaded.data, loaded.lines)}

        false_alarm = _write(
            tmp_path / "alarm",
            {
                "compose.yml": _entry("sub/i.yml", "m.env"),
                "sub/i.yml": service,
                "sub/.env": "PRIV=true\n",
                "m.env": "OTHER=1\n",
            },
        )
        loaded = load_compose_full(false_alarm)
        assert "CL-0002" not in {
            f.rule_id for f in run_rules(loaded.data, loaded.lines)
        }

    def test_an_undefined_reference_leaves_the_name_unsupplied(
        self, tmp_path: Path
    ) -> None:
        """A divergence the ``.env`` reader already has, kept here.

        Compose ships ``A=-m``: the reference is empty. compose-lint declines
        to build a value from a name nothing defines, so the document's own
        default applies. The replaced ``.env`` is not consulted either way.
        """
        loaded = load_compose_full(
            _write(
                tmp_path,
                {
                    "compose.yml": _entry("sub/i.yml", "m.env"),
                    "sub/i.yml": _svc(),
                    "sub/.env": "X=own\n",
                    "m.env": "A=${X}-m\n",
                },
            )
        )
        assert loaded.data["services"]["web"]["image"] == "i:d"

    def test_no_env_reads_none_of_it(self, tmp_path: Path) -> None:
        compose = _write(tmp_path, CASES["one-file"] | {"m.env": "A=m\n"})
        loaded = load_compose_full(compose, use_env=False)
        assert loaded.data["services"]["web"]["image"] == "i:d"
        missing = _write(tmp_path / "x", CASES["refused-missing"])
        assert load_compose_full(missing, use_env=False).gaps == ()


class TestGaps:
    """A file that cannot be read is a gap, and the rest is still graded."""

    def test_a_missing_file_is_a_gap_compose_refuses_too(self, tmp_path: Path) -> None:
        loaded = load_compose_full(_write(tmp_path, CASES["refused-missing"]))
        (gap,) = loaded.gaps
        assert isinstance(gap, ComposeRefusesGap)
        assert "env_file 'nope.env'" in gap
        assert "the file was not found" in gap
        assert loaded.data["services"]["web"]["image"] == "i:d"

    @pytest.mark.parametrize("value", ["''", "5", "[m.env, 5]", "{a: b}"])
    def test_a_value_that_is_not_paths_is_refused(
        self, tmp_path: Path, value: str
    ) -> None:
        loaded = load_compose_full(
            _write(
                tmp_path,
                {
                    "compose.yml": _entry("i.yml", value),
                    "i.yml": _svc(),
                    "m.env": "A=m\n",
                    ".env": "B=proj\n",
                },
            )
        )
        (gap,) = loaded.gaps
        assert isinstance(gap, ComposeRefusesGap)
        assert "not a path or a list of paths" in gap
        web = loaded.data["services"]["web"]
        assert (web["image"], web["user"]) == ("i:d", "proj")

    def test_a_path_out_of_the_repository_is_not_read(self, tmp_path: Path) -> None:
        """Compose reads it. The containment rule every reference follows does not."""
        compose = _write(
            tmp_path,
            {
                "proj/compose.yml": _entry("i.yml", "../out.env"),
                "proj/i.yml": _svc(),
                "out.env": "A=outside\n",
            },
        )
        loaded = load_compose_full(compose.parent / "proj" / "compose.yml")
        (gap,) = loaded.gaps
        assert not isinstance(gap, ComposeRefusesGap)
        assert "resolves outside the repository" in gap
        assert loaded.data["services"]["web"]["image"] == "i:d"

    def test_an_absolute_path_is_not_read(self, tmp_path: Path) -> None:
        compose = _write(
            tmp_path,
            {
                "compose.yml": _entry("i.yml", str(tmp_path / "m.env")),
                "i.yml": _svc(),
                "m.env": "A=m\n",
            },
        )
        loaded = load_compose_full(compose)
        assert len(loaded.gaps) == 1
        assert loaded.data["services"]["web"]["image"] == "i:d"

    def test_a_link_out_of_the_repository_is_not_read(self, tmp_path: Path) -> None:
        """P1: a committed link must not carry a file outside into the output."""
        outside = tmp_path / "outside.env"
        outside.write_text("A=leaked\n", encoding="utf-8")
        compose = _write(
            tmp_path / "proj",
            {"compose.yml": _entry("i.yml", "m.env"), "i.yml": _svc()},
        )
        try:
            (tmp_path / "proj" / "m.env").symlink_to(outside)
        except OSError:  # pragma: no cover - Windows without the privilege
            pytest.skip("cannot create a symbolic link here")
        loaded = load_compose_full(compose)
        (gap,) = loaded.gaps
        assert "env_file 'm.env'" in gap
        assert loaded.data["services"]["web"]["image"] == "i:d"
        assert "leaked" not in json.dumps(loaded.data)

    def test_an_interpolated_path_with_no_value_is_a_gap(self, tmp_path: Path) -> None:
        loaded = load_compose_full(
            _write(
                tmp_path,
                {"compose.yml": _entry("i.yml", "${EF}"), "i.yml": _svc()},
            )
        )
        (gap,) = loaded.gaps
        assert "interpolated" in gap

    def test_a_file_that_is_not_utf8_is_a_gap(self, tmp_path: Path) -> None:
        compose = _write(
            tmp_path, {"compose.yml": _entry("i.yml", "m.env"), "i.yml": _svc()}
        )
        (tmp_path / "m.env").write_bytes(b"A=\xff\xfe\n")
        (gap,) = load_compose_full(compose).gaps
        assert "not valid UTF-8" in gap

    def test_a_file_over_the_read_cap_is_a_gap(self, tmp_path: Path) -> None:
        compose = _write(
            tmp_path, {"compose.yml": _entry("i.yml", "m.env"), "i.yml": _svc()}
        )
        (tmp_path / "m.env").write_text("A=m\n" + "#" * (300 * 1024), encoding="utf-8")
        (gap,) = load_compose_full(compose).gaps
        assert "could not be read safely" in gap

    def test_the_other_files_in_the_list_are_still_read(self, tmp_path: Path) -> None:
        loaded = load_compose_full(
            _write(
                tmp_path,
                {
                    "compose.yml": _entry("i.yml", "[nope.env, m.env]"),
                    "i.yml": _svc(),
                    "m.env": "A=m\n",
                },
            )
        )
        assert len(loaded.gaps) == 1
        assert loaded.data["services"]["web"]["image"] == "i:m"

    def test_env_files_count_against_the_file_budget(self, tmp_path: Path) -> None:
        files = {f"e{n}.env": f"V{n}=1\n" for n in range(70)}
        listed = "[" + ", ".join(sorted(files)) + "]"
        loaded = load_compose_full(
            _write(
                tmp_path,
                files
                | {
                    "compose.yml": _entry("i.yml", listed) + _svc("root"),
                    "i.yml": _svc(),
                },
            )
        )
        assert any(
            "env_file" in gap and "opens more than" in gap for gap in loaded.gaps
        )


def _compose_env() -> dict[str, str]:
    """PATH, plus what decides which compose plugin runs.

    Nothing else, so no name a fixture interpolates can arrive from the host.
    """
    env = {"PATH": os.environ.get("PATH", "")}
    for name in ("HOME", "DOCKER_CONFIG"):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


def _compose_resolves_nested_entries() -> bool:
    env = _compose_env()
    try:
        result = subprocess.run(
            [*compose_argv(env), "version", "--short"],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            check=False,
        )
        major, minor = (
            int(part) for part in result.stdout.strip().lstrip("v").split(".")[:2]
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    return result.returncode == 0 and (major, minor) >= (5, 8)


@pytest.mark.skipif(
    not _compose_resolves_nested_entries(),
    reason="needs a Compose that resolves a nested entry's env_file as 5.8.0 does",
)
@pytest.mark.parametrize("case", sorted(CASES))
def test_agrees_with_compose(tmp_path: Path, case: str) -> None:
    compose = _write(tmp_path, CASES[case])
    env = _compose_env()
    oracle = subprocess.run(
        [*compose_argv(env), "-f", str(compose), "config", "--format", "json"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=env,
        timeout=60,
        check=False,
    )
    loaded = load_compose_full(compose)
    if case.startswith("refused-"):
        assert oracle.returncode != 0, "Compose accepted a case recorded as refused"
        assert loaded.gaps, f"Compose refused it ({oracle.stderr.strip()}); no gap here"
        assert all(isinstance(gap, ComposeRefusesGap) for gap in loaded.gaps)
        return
    assert oracle.returncode == 0, oracle.stderr
    assert loaded.gaps == (), loaded.gaps
    theirs = _values(json.loads(oracle.stdout).get("services") or {})
    assert _values(loaded.data["services"]) == theirs
