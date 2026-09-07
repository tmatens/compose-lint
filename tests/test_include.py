"""``include:`` is followed when every reference stays inside the project.

The companion to ``test_cross_file_extends``, and the half that lifts a
*parse-time* refusal rather than a coverage gap: an include-only file — no
services of its own — was rejected outright under every command, flag included
([#516](https://github.com/tmatens/compose-lint/issues/516)), because a clean
pass over services nobody read is the one failure a merge gate cannot have.
[ADR-036](../docs/adr/036-resolve-references-that-stay-inside-the-project.md)
moves *when* that is decided, not whether: the references are followed first,
and the refusal stands only if nothing could be read.

Four orderings decide what a duplicated service ends up as, they are not the
same ordering, and every one of them was measured against Compose 5.5.0 rather
than reasoned about:

1. The **including document** overrides everything it includes.
2. An **earlier** ``include:`` entry overrides a later one — the reverse of
   ``-f a -f b``.
3. Within one object-form ``path:`` list, **later** wins again, because that
   list is one project assembled from several files.
4. ``include:`` folds in **before** ``extends:`` resolves, and the ``-f`` /
   ``compose.override`` merge happens **after** it. So an included file's
   contribution to a service is visible to whatever extends it, and an
   overriding document's is not.

Getting any of them backwards reports the wrong image and the wrong user for a
service that is really deployed, with nothing in the output to say so, which is
why each has a test naming the value Compose actually ships.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from compose_lint import cli
from compose_lint.parser import (
    MAX_REFERENCE_FILES,
    ComposeError,
    load_compose_full,
    load_merged,
)

if TYPE_CHECKING:
    from pathlib import Path

DANGEROUS = (
    "services:\n"
    "  api:\n"
    "    image: nginx:1.27\n"
    "    privileged: true\n"
    "    network_mode: host\n"
)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _project(tmp_path: Path, body: str) -> Path:
    return _write(tmp_path / "compose.yml", body)


# --- The reference is followed ---------------------------------------------


def test_an_include_only_root_is_lintable(tmp_path: Path) -> None:
    """The parse-time refusal is lifted once the references resolve.

    Nine include-only monorepo roots carry 245 of the 273 ``include:``
    references in an 11,111-file corpus, so this is where the construct
    actually lives. Verified against Compose 5.5.0: it accepts such a root and
    exits 0.
    """
    _write(tmp_path / "apps" / "api.yml", DANGEROUS)
    target = _project(tmp_path, "include:\n  - ./apps/api.yml\n")

    loaded = load_compose_full(target)
    assert loaded.gaps == ()
    assert loaded.data["services"]["api"]["privileged"] is True


def test_an_included_files_networks_and_volumes_reach_the_project(
    tmp_path: Path,
) -> None:
    """It is a whole-document merge, not a services map. Verified against
    Compose 5.5.0, whose rendered project carries both top-level keys."""
    _write(
        tmp_path / "apps" / "api.yml",
        "services:\n"
        "  api:\n"
        "    image: alpine:3.20\n"
        "networks:\n"
        "  backend:\n"
        "    driver: bridge\n"
        "volumes:\n"
        "  named-data: {}\n",
    )
    target = _project(tmp_path, "include:\n  - ./apps/api.yml\n")
    data = load_compose_full(target).data

    assert "backend" in data["networks"]
    assert "named-data" in data["volumes"]


def test_an_included_file_is_merged_alongside_local_services(
    tmp_path: Path,
) -> None:
    _write(tmp_path / "apps" / "api.yml", DANGEROUS)
    target = _project(
        tmp_path,
        "include:\n  - ./apps/api.yml\nservices:\n  web:\n    image: nginx:1.27\n",
    )
    data = load_compose_full(target).data

    assert sorted(data["services"]) == ["api", "web"]


def test_a_relative_path_resolves_against_the_included_file(tmp_path: Path) -> None:
    """Verified against Compose 5.5.0: ``./data`` in ``sub/compose.yml`` mounts
    ``sub/data``, and ``../up`` climbs to the project root."""
    _write(
        tmp_path / "sub" / "compose.yml",
        "services:\n"
        "  api:\n"
        "    image: alpine:3.20\n"
        "    volumes:\n"
        "      - ./data:/data\n"
        "      - ../up:/up\n",
    )
    target = _project(tmp_path, "include:\n  - ./sub/compose.yml\n")
    volumes = load_compose_full(target).data["services"]["api"]["volumes"]

    root = "/" + "/".join(tmp_path.absolute().parts[1:])
    sources = [volume.rsplit(":", 1)[0] for volume in volumes]
    assert sources == [f"{root}/sub/data", f"{root}/up"]


def test_a_recursive_include_is_followed(tmp_path: Path) -> None:
    _write(
        tmp_path / "b" / "compose.yml",
        "include:\n  - ../a/compose.yml\nservices:\n  worker:\n    image: busybox:1\n",
    )
    _write(tmp_path / "a" / "compose.yml", DANGEROUS)
    target = _project(
        tmp_path,
        "include:\n  - ./b/compose.yml\nservices:\n  web:\n    image: nginx:1.27\n",
    )
    loaded = load_compose_full(target)

    assert sorted(loaded.data["services"]) == ["api", "web", "worker"]
    assert loaded.data["services"]["api"]["privileged"] is True


# --- The three orderings ---------------------------------------------------


def _two_apps(tmp_path: Path) -> None:
    _write(
        tmp_path / "one.yml",
        "services:\n"
        "  api:\n"
        "    image: alpine:3.20\n"
        '    user: "1000:1000"\n'
        "    cap_add: [NET_ADMIN]\n",
    )
    _write(
        tmp_path / "two.yml",
        "services:\n"
        "  api:\n"
        "    image: redis:7\n"
        '    user: "2000:2000"\n'
        "    cap_add: [SYS_TIME]\n",
    )


def test_an_earlier_include_entry_overrides_a_later_one(tmp_path: Path) -> None:
    """The reverse of ``-f a -f b``. Verified against Compose 5.5.0, which
    ships ``alpine:3.20`` — the *first* entry's image — and concatenates
    ``cap_add`` with the *later* file's entry first."""
    _two_apps(tmp_path)
    target = _project(tmp_path, "include:\n  - ./one.yml\n  - ./two.yml\n")
    api = load_compose_full(target).data["services"]["api"]

    assert api["image"] == "alpine:3.20"
    assert api["user"] == "1000:1000"
    assert api["cap_add"] == ["SYS_TIME", "NET_ADMIN"]


def test_later_wins_inside_one_object_form_path_list(tmp_path: Path) -> None:
    """The same two files under one entry fold the *other* way, because a
    ``path:`` list is one project assembled from several files. Verified
    against Compose 5.5.0, which ships ``redis:7`` here and ``alpine:3.20``
    for the test above — the same files, the opposite answer."""
    _two_apps(tmp_path)
    target = _project(
        tmp_path, "include:\n  - path:\n      - ./one.yml\n      - ./two.yml\n"
    )
    api = load_compose_full(target).data["services"]["api"]

    assert api["image"] == "redis:7"
    assert api["user"] == "2000:2000"
    assert api["cap_add"] == ["NET_ADMIN", "SYS_TIME"]


def test_the_including_document_overrides_what_it_includes(tmp_path: Path) -> None:
    """Verified against Compose 5.5.0: the primary's ``image`` wins, while keys
    only the included file declares are added rather than dropped."""
    _two_apps(tmp_path)
    target = _project(
        tmp_path,
        "include:\n  - ./one.yml\n"
        "services:\n  api:\n    image: primary:1\n    hostname: fromprimary\n",
    )
    api = load_compose_full(target).data["services"]["api"]

    assert api["image"] == "primary:1"
    assert api["hostname"] == "fromprimary"
    assert api["user"] == "1000:1000"
    assert api["cap_add"] == ["NET_ADMIN"]


# --- Interpolation layering ------------------------------------------------


def test_the_projects_env_wins_over_the_included_files_own(tmp_path: Path) -> None:
    """An included file's own ``.env`` is read — unlike an ``extends:`` base's,
    which is ignored entirely — but the project's wins where both define a
    name. Both halves verified against Compose 5.5.0 on one fixture."""
    _write(
        tmp_path / "sub" / "compose.yml",
        "services:\n"
        "  api:\n"
        "    image: nginx:${TAG:-none}\n"
        "    hostname: ${EXTRA:-noextra}\n",
    )
    _write(tmp_path / ".env", "TAG=fromproject\n")
    _write(tmp_path / "sub" / ".env", "TAG=fromsub\nEXTRA=onlyinsub\n")
    target = _project(tmp_path, "include:\n  - ./sub/compose.yml\n")
    api = load_compose_full(target).data["services"]["api"]

    assert api["image"] == "nginx:fromproject"  # project wins the shared name
    assert api["hostname"] == "onlyinsub"  # own .env supplies what it does not


def test_no_env_ignores_both(tmp_path: Path) -> None:
    """``--no-env``'s promise is that no ``.env`` beside a document is read.
    Widening to the included file's is ADR-027 §8's pattern."""
    _write(
        tmp_path / "sub" / "compose.yml",
        "services:\n  api:\n    image: nginx:${TAG:-none}\n",
    )
    _write(tmp_path / ".env", "TAG=fromproject\n")
    _write(tmp_path / "sub" / ".env", "TAG=fromsub\n")
    target = _project(tmp_path, "include:\n  - ./sub/compose.yml\n")

    assert (
        load_compose_full(target, use_env=False).data["services"]["api"]["image"]
        == "nginx:none"
    )


def test_an_override_beside_an_included_file_is_not_merged(tmp_path: Path) -> None:
    """Override discovery stays a property of the file the run was pointed at.
    Compose does not merge a ``compose.override.yml`` sitting beside an
    included file, and neither should the report."""
    _write(
        tmp_path / "sub" / "compose.yml",
        "services:\n  api:\n    image: alpine:3.20\n",
    )
    _write(
        tmp_path / "sub" / "compose.override.yml",
        "services:\n  api:\n    privileged: true\n",
    )
    target = _project(tmp_path, "include:\n  - ./sub/compose.yml\n")

    assert "privileged" not in load_compose_full(target).data["services"]["api"]


# --- What stays a coverage gap ---------------------------------------------


@pytest.mark.parametrize(
    ("reference", "reason"),
    [
        ("../outside/base.yml", "outside the project directory"),
        ("/etc/compose/base.yml", "outside the project directory"),
        ("~/base.yml", "outside the project directory"),
        ("${BASE}/base.yml", "interpolated"),
        ("nope.yml", "was not found"),
    ],
)
def test_a_reference_that_cannot_be_followed_stays_a_gap(
    tmp_path: Path, reference: str, reason: str
) -> None:
    target = _project(
        tmp_path,
        f"include:\n  - {reference}\nservices:\n  web:\n    image: nginx:1.27\n",
    )
    gaps = load_compose_full(target).gaps

    assert len(gaps) == 1
    assert reason in gaps[0]
    assert reference in gaps[0]


def test_a_symlink_out_of_the_project_is_refused(tmp_path: Path) -> None:
    """The filesystem gate: a committed symlink is spelled like a file inside
    the project while pointing anywhere."""
    outside = tmp_path.parent / "outside-include.yml"
    outside.write_text(DANGEROUS, encoding="utf-8")
    target = _project(
        tmp_path,
        "include:\n  - ./linked.yml\nservices:\n  web:\n    image: nginx:1.27\n",
    )
    (tmp_path / "linked.yml").symlink_to(outside)

    loaded = load_compose_full(target)
    assert any("outside the project directory" in gap for gap in loaded.gaps)
    assert "api" not in loaded.data["services"]


def test_a_cycle_ends_as_a_gap_rather_than_a_hang(tmp_path: Path) -> None:
    """Compose exits 1 on ``include cycle detected``; the linter reports the
    part it could read and calls the rest a gap."""
    _write(
        tmp_path / "two.yml",
        "include:\n  - ./compose.yml\nservices:\n  worker:\n    image: busybox:1\n",
    )
    target = _project(
        tmp_path,
        "include:\n  - ./two.yml\nservices:\n  web:\n    image: nginx:1.27\n",
    )
    loaded = load_compose_full(target)

    assert any("already pulled in" in gap for gap in loaded.gaps)
    assert sorted(loaded.data["services"]) == ["web", "worker"]


def test_a_fan_out_past_the_file_cap_ends_as_a_gap(tmp_path: Path) -> None:
    references = []
    for index in range(MAX_REFERENCE_FILES + 2):
        _write(
            tmp_path / f"app{index}.yml",
            f"services:\n  s{index}:\n    image: nginx:1.2{index % 10}\n",
        )
        references.append(f"  - ./app{index}.yml\n")
    target = _project(
        tmp_path,
        "include:\n"
        + "".join(references)
        + "services:\n  web:\n    image: nginx:1.27\n",
    )
    gaps = load_compose_full(target).gaps

    assert gaps
    assert all(f"more than {MAX_REFERENCE_FILES} files" in gap for gap in gaps)


def test_an_unreadable_included_file_is_a_gap_not_a_crash(tmp_path: Path) -> None:
    _write(tmp_path / "bad.yml", "services: [not, a, mapping]\n")
    target = _project(
        tmp_path,
        "include:\n  - ./bad.yml\nservices:\n  web:\n    image: nginx:1.27\n",
    )
    gaps = load_compose_full(target).gaps

    assert len(gaps) == 1
    assert "bad.yml" in gaps[0]


def test_an_include_only_root_that_resolves_nothing_is_still_refused(
    tmp_path: Path,
) -> None:
    """#516's rule survives ADR-036 intact. Nothing at all was linted, so a
    verdict over it would be the false pass that rule exists to prevent — and
    the refusal is a parse error rather than a downgradable gap, so
    ``--allow-partial-coverage`` cannot turn it into a clean run."""
    target = _project(tmp_path, "include:\n  - ./nope.yml\n")

    with pytest.raises(ComposeError, match="services all come from 'include:'"):
        load_compose_full(target)

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--allow-partial-coverage", str(target)])
    assert exc.value.code == 2


def test_an_include_only_root_that_resolves_some_entries_lints_those(
    tmp_path: Path,
) -> None:
    """Partial is not nothing: what was read is graded, and the rest is an
    ordinary coverage gap the flag can accept."""
    _write(tmp_path / "apps" / "api.yml", DANGEROUS)
    target = _project(tmp_path, "include:\n  - ./apps/api.yml\n  - ./nope.yml\n")
    loaded = load_compose_full(target)

    assert loaded.data["services"]["api"]["privileged"] is True
    assert any("was not found" in gap for gap in loaded.gaps)


# --- Exit codes and the report ---------------------------------------------


def test_a_resolved_include_exits_on_findings_not_on_coverage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(tmp_path / "apps" / "api.yml", DANGEROUS)
    target = _project(
        tmp_path,
        "include:\n  - ./apps/api.yml\nservices:\n  web:\n    image: nginx:1.27\n",
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--format", "json", str(target)])
    assert exc.value.code == 1

    doc = json.loads(capsys.readouterr().out)
    assert doc["errors"] == []
    assert "CL-0002" in {f["rule_id"] for f in doc["findings"]}


def test_a_resolved_include_reports_executionsuccessful(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(tmp_path / "apps" / "api.yml", DANGEROUS)
    target = _project(tmp_path, "include:\n  - ./apps/api.yml\n")

    with pytest.raises(SystemExit):
        cli.main(["check", "--format", "sarif", str(target)])

    invocation = json.loads(capsys.readouterr().out)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True


def test_a_finding_written_in_an_included_file_names_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(tmp_path / "apps" / "api.yml", DANGEROUS)
    target = _project(
        tmp_path,
        "include:\n  - ./apps/api.yml\nservices:\n  web:\n    image: nginx:1.27\n",
    )

    with pytest.raises(SystemExit):
        cli.main(["check", "--format", "json", str(target)])

    findings = json.loads(capsys.readouterr().out)["findings"]
    privileged = next(f for f in findings if f["rule_id"] == "CL-0002")
    assert privileged["source_file"].replace("\\", "/").endswith("apps/api.yml")


def test_fix_rewrites_only_the_file_it_was_pointed_at(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An included file is another document. ``fix`` defers its findings by
    name and leaves it byte-identical."""
    included = _write(tmp_path / "apps" / "api.yml", DANGEROUS)
    before = included.read_text(encoding="utf-8")
    target = _project(
        tmp_path,
        "include:\n  - ./apps/api.yml\nservices:\n  web:\n    image: nginx:1.27\n",
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", "--apply", str(target)])
    assert exc.value.code == 0
    assert included.read_text(encoding="utf-8") == before
    assert (
        "apps/api.yml and need manual review there"
        in capsys.readouterr().err.replace("\\", "/")
    )


def test_a_config_beside_an_included_file_does_not_widen_suppression(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``.compose-lint.yml`` is read once, from the primary's directory. An
    included file must not be able to narrow the gate's scope — ADR-026 §4's
    principle, and the reason a document never chooses its own policy."""
    _write(tmp_path / "apps" / "api.yml", DANGEROUS)
    _write(
        tmp_path / "apps" / ".compose-lint.yml",
        "rules:\n  CL-0002:\n    enabled: false\n    reason: not from here\n",
    )
    target = _project(tmp_path, "include:\n  - ./apps/api.yml\n")

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--format", "json", str(target)])
    assert exc.value.code == 1

    findings = json.loads(capsys.readouterr().out)["findings"]
    privileged = next(f for f in findings if f["rule_id"] == "CL-0002")
    assert privileged["suppressed"] is False


# --- Where `extends:` sits in the resolution order --------------------------


def test_an_included_files_contribution_reaches_an_in_file_extends(
    tmp_path: Path,
) -> None:
    """`include:` folds in before `extends:` resolves, so the base is complete.

    Measured against Compose 5.5.0. The order is not the one a reading of the
    documentation suggests, and it is not symmetric — the overriding document
    below is on the other side of the same boundary:

        include: -> extends: -> `-f` / compose.override merge

    Getting it backwards was silent. A service extending one that an included
    file hardens inherited the *unincluded* version, so the absence rules
    reported hardening the deployed container has and the presence rules
    missed configuration it has.
    """
    _write(
        tmp_path / "parts" / "a.yml",
        "services:\n  api:\n    user: root\n    cap_add: [SYS_ADMIN]\n",
    )
    target = _project(
        tmp_path,
        "include:\n"
        "  - ./parts/a.yml\n"
        "services:\n"
        "  api:\n"
        "    image: nginx:1.27\n"
        "  derived:\n"
        "    extends:\n"
        "      service: api\n",
    )

    derived = load_compose_full(target).data["services"]["derived"]
    assert derived["user"] == "root"
    assert derived["cap_add"] == ["SYS_ADMIN"]


def test_an_included_files_contribution_reaches_a_cross_file_extends(
    tmp_path: Path,
) -> None:
    """Same boundary, the other `extends:` spelling.

    The included file's `user: root` reaches `web` before the cross-file base
    is merged under it, so the base's `user` loses — Compose 5.5.0 ships
    ``root``. Resolving the base first inverted it and reported ``1000``, a
    user the deployed container never runs as.
    """
    _write(tmp_path / "parts" / "a.yml", "services:\n  web:\n    user: root\n")
    _write(
        tmp_path / "base" / "common.yml",
        "services:\n  common:\n    user: '1000'\n    read_only: true\n",
    )
    target = _project(
        tmp_path,
        "include:\n"
        "  - ./parts/a.yml\n"
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27\n"
        "    extends:\n"
        "      file: ./base/common.yml\n"
        "      service: common\n",
    )

    web = load_compose_full(target).data["services"]["web"]
    assert web["user"] == "root"
    # Everything the base contributes that the merged service does not have
    # still arrives.
    assert web["read_only"] is True


def test_an_overriding_documents_contribution_does_not_reach_an_extends(
    tmp_path: Path,
) -> None:
    """The other side of the boundary, and the reason it is a boundary at all.

    `compose.override.yml` merges *after* `extends:` has resolved, so a value
    it adds to a base service is not inherited by the service extending it.
    Verified against Compose 5.5.0, whose `derived` carries neither key.
    """
    _write(
        tmp_path / "compose.override.yml",
        "services:\n  api:\n    user: root\n    cap_add: [SYS_ADMIN]\n",
    )
    target = _project(
        tmp_path,
        "services:\n"
        "  api:\n"
        "    image: nginx:1.27\n"
        "  derived:\n"
        "    extends:\n"
        "      service: api\n",
    )

    merged = load_merged([target, tmp_path / "compose.override.yml"])
    derived = merged.data["services"]["derived"]
    assert "user" not in derived
    assert "cap_add" not in derived


# --- An object-form entry is one sub-project --------------------------------


def _sub_project(tmp_path: Path, include_block: str) -> Path:
    """Two included files in different directories, one with relative paths."""
    _write(tmp_path / "parts" / "a.yml", "services:\n  api:\n    image: nginx:1.27\n")
    _write(
        tmp_path / "parts" / "nested.yml", "services:\n  from_parts:\n    image: a:1\n"
    )
    _write(tmp_path / "sub" / "nested.yml", "services:\n  from_sub:\n    image: a:1\n")
    _write(
        tmp_path / "sub" / "compose.yml",
        "include:\n"
        "  - ./nested.yml\n"
        "services:\n"
        "  sidecar:\n"
        "    image: nginx:1.27\n"
        '    volumes: ["./local:/local"]\n',
    )
    return _project(tmp_path, include_block)


def test_an_object_form_entry_resolves_against_its_first_path(
    tmp_path: Path,
) -> None:
    """An entry is a project, not a file list, and the first path names its root.

    Measured against Compose 5.5.0. `./local` written in `sub/compose.yml`
    mounts ``parts/local`` when the entry lists ``parts/a.yml`` first, and the
    nested `include: ./nested.yml` reads ``parts/nested.yml``. Resolving each
    file against its own directory instead mounted a host path the deployed
    container never sees, which is a wrong answer for the mount rules
    (CL-0013, CL-0017, CL-0025) with nothing in the output to say so.
    """
    target = _sub_project(
        tmp_path,
        "include:\n  - path:\n      - parts/a.yml\n      - sub/compose.yml\n",
    )
    data = load_compose_full(target).data

    # The suffix, not the whole path: the absolute prefix is a lint-host
    # detail whose spelling differs by platform (ADR-023 §1), and the segment
    # under test is the tail.
    (source,) = data["services"]["sidecar"]["volumes"]
    assert source.endswith("/parts/local:/local"), source
    assert "from_parts" in data["services"]
    assert "from_sub" not in data["services"]


def test_swapping_the_paths_moves_the_entrys_root(tmp_path: Path) -> None:
    """It really is the *first* path, not a preference for shallow directories."""
    target = _sub_project(
        tmp_path,
        "include:\n  - path:\n      - sub/compose.yml\n      - parts/a.yml\n",
    )
    data = load_compose_full(target).data

    (source,) = data["services"]["sidecar"]["volumes"]
    assert source.endswith("/sub/local:/local"), source
    assert "from_sub" in data["services"]


def test_each_list_form_entry_is_its_own_sub_project(tmp_path: Path) -> None:
    """The list form nests differently, and so resolves differently.

    Two bare entries are two sub-projects, each rooted at its own file — which
    is why the list form was never wrong, and why the fix has to distinguish
    the spellings rather than pick one directory for both.
    """
    target = _sub_project(tmp_path, "include:\n  - parts/a.yml\n  - sub/compose.yml\n")
    data = load_compose_full(target).data

    (source,) = data["services"]["sidecar"]["volumes"]
    assert source.endswith("/sub/local:/local"), source
    assert "from_sub" in data["services"]


def test_project_directory_names_the_entrys_root(tmp_path: Path) -> None:
    """`project_directory:` overrides the first path. Verified on Compose 5.5.0."""
    target = _sub_project(
        tmp_path,
        "include:\n"
        "  - path:\n"
        "      - parts/a.yml\n"
        "      - sub/compose.yml\n"
        "    project_directory: .\n",
    )
    data = load_compose_full(target).data

    (source,) = data["services"]["sidecar"]["volumes"]
    assert source.endswith("/local:/local"), source
    assert "/parts/" not in source
    assert "/sub/" not in source


def test_an_entrys_root_moves_which_env_an_included_file_reads(
    tmp_path: Path,
) -> None:
    """The entry's own `.env` comes from its project directory too.

    Measured against Compose 5.5.0 with `TAG` defined in both `parts/.env` and
    `sub/.env`: `nginx:${TAG:-fallback}` written in `sub/compose.yml` ships
    `nginx:from-parts` when the entry lists `parts/a.yml` first. Reading the
    file's own `.env` instead reported an image tag the deployed container
    never runs.
    """
    _write(tmp_path / "parts" / "a.yml", "services:\n  api:\n    image: nginx:1.27\n")
    _write(tmp_path / "parts" / ".env", "TAG=from-parts\n")
    _write(tmp_path / "sub" / ".env", "TAG=from-sub\n")
    _write(
        tmp_path / "sub" / "compose.yml",
        "services:\n  sidecar:\n    image: nginx:${TAG:-fallback}\n",
    )
    target = _project(
        tmp_path,
        "include:\n  - path:\n      - parts/a.yml\n      - sub/compose.yml\n",
    )

    data = load_compose_full(target).data
    assert data["services"]["sidecar"]["image"] == "nginx:from-parts"


def test_project_directory_moves_the_env_lookup_with_it(tmp_path: Path) -> None:
    """`project_directory: .` roots the entry where there is no `.env` at all.

    Same fixture, same measurement: Compose 5.5.0 ships the written default,
    because the entry's project directory is now the root and the root has no
    `.env`. This is the half that shows the `.env` follows the *entry*, not
    the including document — the including document's own `.env` would still
    be layered on top if it had one.
    """
    _write(tmp_path / "parts" / "a.yml", "services:\n  api:\n    image: nginx:1.27\n")
    _write(tmp_path / "sub" / ".env", "TAG=from-sub\n")
    _write(
        tmp_path / "sub" / "compose.yml",
        "services:\n  sidecar:\n    image: nginx:${TAG:-fallback}\n",
    )
    target = _project(
        tmp_path,
        "include:\n"
        "  - path:\n"
        "      - parts/a.yml\n"
        "      - sub/compose.yml\n"
        "    project_directory: .\n",
    )

    data = load_compose_full(target).data
    assert data["services"]["sidecar"]["image"] == "nginx:fallback"
