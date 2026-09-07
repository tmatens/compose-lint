"""Cross-file ``extends: {file: ...}`` is followed when it stays inside the project.

[ADR-036](../docs/adr/036-resolve-references-that-stay-inside-the-project.md)
applies the containment rule already shipped for ``env_file:`` to the reference
that was refused as a class: a base whose path resolves inside the project is
read and merged, one that leaves is still a coverage gap. Two things follow
from that and are pinned here.

**Which directory.** A base document is read from a place that is neither where
its paths resolve nor where its values come from, and the three differ. Both
were checked against Compose 5.5.0 on a fixture before being written down:
``./cfg`` inside ``shared/base.yml`` mounts ``shared/cfg``, while ``${TAG}``
inside the same file ships the *project's* ``.env`` value and never looks at a
``.env`` beside itself. Getting either backwards names a host path Compose does
not mount, which is the silent-wrong-claim failure ADR-023 exists to prevent.

**Which residuals stay gaps.** Decision 7 lists eight, and each states *which*
one it hit rather than the flat "is not resolved" every shape shared before.
The exit-code contract is unchanged: only references that now resolve move, and
they move from 2 to the ordinary findings verdict.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from compose_lint import cli
from compose_lint.parser import MAX_REFERENCE_FILES, load_compose_full

if TYPE_CHECKING:
    from pathlib import Path

# A base carrying full host control, so a run that misses it is unambiguously
# reporting on something other than what would be deployed.
DANGEROUS_BASE = (
    "services:\n"
    "  app:\n"
    "    image: nginx:1.27\n"
    "    privileged: true\n"
    "    network_mode: host\n"
)

CHILD = "services:\n  web:\n    extends:\n      file: {reference}\n      service: app\n"


def _project(tmp_path: Path, reference: str, *, base: str = DANGEROUS_BASE) -> Path:
    """A compose file extending ``reference``, with the base written at it."""
    target = tmp_path / "compose.yml"
    target.write_text(CHILD.format(reference=reference), encoding="utf-8")
    if base:
        base_path = tmp_path / reference
        base_path.parent.mkdir(parents=True, exist_ok=True)
        base_path.write_text(base, encoding="utf-8")
    return target


def _rule_ids(findings: list[dict[str, object]]) -> set[object]:
    return {f["rule_id"] for f in findings}


def _anchorless(path: Path) -> str:
    """``path`` spelled the way a resolved bind source is spelled.

    Resolution is lexical and ``/``-rooted on every platform (ADR-023 §1), so
    the drive or UNC anchor is dropped: the deploy-host-independent fact is
    "climbs to the root of the containing filesystem", and a Windows lint host
    must not stamp ``C:`` onto a path headed for a Linux server. Building the
    expectation with ``as_posix()`` keeps the anchor and passes only on POSIX.
    """
    return "/" + "/".join(path.absolute().parts[1:])


def _sources(volumes: list[str]) -> list[str]:
    """The host side of each short-syntax bind. Targets carry no colon."""
    return [volume.rsplit(":", 1)[0] for volume in volumes]


def _slashed(text: str) -> str:
    """``text`` with native separators normalised, for path assertions."""
    return text.replace("\\", "/")


# --- The reference is followed ---------------------------------------------


@pytest.mark.parametrize("reference", ["./base.yml", "base.yml", "shared/base.yml"])
def test_a_base_inside_the_project_is_merged(tmp_path: Path, reference: str) -> None:
    """Same directory and subdirectory both land inside, which is 98.3% of the
    corpus. The base's ``privileged: true`` is the whole point: before ADR-036
    the run exited 2 having graded ``web`` on its own two keys."""
    target = _project(tmp_path, reference)
    loaded = load_compose_full(target)

    assert loaded.gaps == ()
    assert loaded.data["services"]["web"]["privileged"] is True
    assert loaded.data["services"]["web"]["network_mode"] == "host"


def test_the_child_wins_over_the_base(tmp_path: Path) -> None:
    """The merge goes through the same field-strategy table as an overlay
    (ADR-025), rather than a second implementation that could drift from it."""
    target = tmp_path / "compose.yml"
    target.write_text(
        "services:\n"
        "  web:\n"
        "    extends:\n"
        "      file: base.yml\n"
        "      service: app\n"
        "    image: nginx:1.29\n"
        "    cap_add: [SYS_TIME]\n",
        encoding="utf-8",
    )
    (tmp_path / "base.yml").write_text(
        "services:\n  app:\n    image: nginx:1.27\n    cap_add: [NET_ADMIN]\n",
        encoding="utf-8",
    )
    web = load_compose_full(target).data["services"]["web"]

    assert web["image"] == "nginx:1.29"  # child scalar wins
    assert web["cap_add"] == ["NET_ADMIN", "SYS_TIME"]  # base first, then child


def test_a_relative_bind_source_resolves_against_the_base_file(
    tmp_path: Path,
) -> None:
    """Verified against Compose 5.5.0: ``./cfg`` in ``shared/base.yml`` mounts
    ``shared/cfg``. The spec's "relative to the location of the main Compose
    file" describes the ``file:`` value, not the paths inside what it names —
    a misreading that would claim a host path Compose never mounts."""
    target = _project(
        tmp_path,
        "shared/base.yml",
        base=(
            "services:\n"
            "  app:\n"
            "    image: nginx:1.27\n"
            "    volumes:\n"
            "      - ./cfg:/etc/nginx/conf.d\n"
            "      - ../up:/up\n"
        ),
    )
    volumes = load_compose_full(target).data["services"]["web"]["volumes"]

    root = _anchorless(tmp_path)
    assert _sources(volumes) == [f"{root}/shared/cfg", f"{root}/up"]


def test_interpolation_in_the_base_reads_the_projects_env(tmp_path: Path) -> None:
    """The mirror image of the test above, and the reason the two directories
    are separate parameters. Verified against Compose 5.5.0: with ``TAG`` set
    in the project's ``.env`` and set differently in ``shared/.env``, Compose
    ships the project's value."""
    target = _project(
        tmp_path,
        "shared/base.yml",
        base="services:\n  app:\n    image: nginx:${TAG:-none}\n",
    )
    (tmp_path / ".env").write_text("TAG=fromproject\n", encoding="utf-8")
    (tmp_path / "shared" / ".env").write_text("TAG=frombase\n", encoding="utf-8")

    assert load_compose_full(target).data["services"]["web"]["image"] == (
        "nginx:fromproject"
    )


def test_a_base_with_no_project_env_ships_its_default(tmp_path: Path) -> None:
    """The other half of the same behaviour: with no project ``.env`` Compose
    ships the ``${TAG:-none}`` default rather than falling back to a ``.env``
    beside the base."""
    target = _project(
        tmp_path,
        "shared/base.yml",
        base="services:\n  app:\n    image: nginx:${TAG:-none}\n",
    )
    (tmp_path / "shared" / ".env").write_text("TAG=frombase\n", encoding="utf-8")

    assert load_compose_full(target).data["services"]["web"]["image"] == "nginx:none"


def test_an_env_file_in_the_base_is_read_from_beside_the_base(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``env_file:`` is resolved after the parse, from the *primary* file's
    directory, so an inherited ``./app.env`` would be read from beside the
    extending file — a different file that may well exist there. The base's
    spelling is re-expressed against the project root instead, which keeps the
    whole path lexical (ADR-023 §1)."""
    target = _project(
        tmp_path,
        "shared/base.yml",
        base="services:\n  app:\n    image: nginx:1.27\n    env_file: ./app.env\n",
    )
    (tmp_path / "shared" / "app.env").write_text("DB_PASSWORD=hunter2\n", "utf-8")

    assert load_compose_full(target).data["services"]["web"]["env_file"] == (
        "shared/app.env"
    )
    with pytest.raises(SystemExit):
        cli.main(["check", "--format", "json", str(target)])
    findings = json.loads(capsys.readouterr().out)["findings"]
    # Read, not merely located: CL-0020 fires on a key name inside the file.
    assert "CL-0020" in _rule_ids(findings)


def test_a_chain_of_bases_across_files_is_followed(tmp_path: Path) -> None:
    """Compose follows the chain, so compose-lint does. Each hop is contained
    against the *project*, never against the previous hop's directory — a chain
    must not be able to walk outwards one ``../`` at a time."""
    target = _project(
        tmp_path,
        "one.yml",
        base=(
            "services:\n"
            "  app:\n"
            "    extends:\n"
            "      file: two.yml\n"
            "      service: root\n"
            "    cap_add: [SYS_TIME]\n"
        ),
    )
    (tmp_path / "two.yml").write_text(
        "services:\n  root:\n    image: nginx:1.27\n    privileged: true\n",
        encoding="utf-8",
    )
    web = load_compose_full(target).data["services"]["web"]

    assert web["privileged"] is True
    assert web["cap_add"] == ["SYS_TIME"]


def test_an_in_file_extends_inherits_what_its_target_pulled_in(
    tmp_path: Path,
) -> None:
    """Cross-file bases merge before the in-file pass, which is the order
    Compose resolves the two in."""
    target = tmp_path / "compose.yml"
    target.write_text(
        "services:\n"
        "  shared:\n"
        "    extends:\n"
        "      file: base.yml\n"
        "      service: app\n"
        "  web:\n"
        "    extends: shared\n",
        encoding="utf-8",
    )
    (tmp_path / "base.yml").write_text(DANGEROUS_BASE, encoding="utf-8")

    assert load_compose_full(target).data["services"]["web"]["privileged"] is True


def test_a_nested_reference_is_written_relative_to_its_own_file(
    tmp_path: Path,
) -> None:
    """A base in a subdirectory writes its own references relative to itself,
    not to the project root — the two questions the ``prefix`` separates.

    Both halves were wrong at once and both are silent. Measuring ``../`` from
    the project root reported a climb out of a *subdirectory* as leaving the
    project, so a base Compose merges became a coverage gap and its
    ``privileged: true`` was never graded — a false negative, which is the
    worst failure a security linter has. Verified against Compose 5.5.0: it
    resolves the chain and ships the privileged service.
    """
    (tmp_path / "shared").mkdir()
    (tmp_path / "other").mkdir()
    (tmp_path / "compose.yml").write_text(
        CHILD.format(reference="./shared/base.yml"), encoding="utf-8"
    )
    (tmp_path / "shared" / "base.yml").write_text(
        "services:\n"
        "  app:\n"
        "    extends:\n"
        "      file: ../other/base2.yml\n"
        "      service: app\n",
        encoding="utf-8",
    )
    (tmp_path / "other" / "base2.yml").write_text(DANGEROUS_BASE, encoding="utf-8")

    loaded = load_compose_full(tmp_path / "compose.yml")
    assert loaded.gaps == ()
    assert loaded.data["services"]["web"]["privileged"] is True


def test_a_nested_reference_does_not_read_a_like_named_file_at_the_root(
    tmp_path: Path,
) -> None:
    """The other half, and the more dangerous one: it is not a gap at all but a
    *different file read as if it were the right one*.

    ``./decoy.yml`` written in ``shared/mid.yml`` means ``shared/decoy.yml``.
    Resolved against the project root it found the root's copy, which exists,
    so nothing looked wrong — the run simply graded the wrong document.
    Verified against Compose 5.5.0, which reads the sibling.
    """
    (tmp_path / "shared").mkdir()
    (tmp_path / "compose.yml").write_text(
        CHILD.format(reference="./shared/mid.yml"), encoding="utf-8"
    )
    (tmp_path / "shared" / "mid.yml").write_text(
        "services:\n"
        "  app:\n"
        "    extends:\n"
        "      file: ./decoy.yml\n"
        "      service: app\n",
        encoding="utf-8",
    )
    (tmp_path / "shared" / "decoy.yml").write_text(
        "services:\n  app:\n    image: correct:1\n", encoding="utf-8"
    )
    (tmp_path / "decoy.yml").write_text(
        "services:\n  app:\n    image: wrong-file:1\n", encoding="utf-8"
    )

    loaded = load_compose_full(tmp_path / "compose.yml")
    assert loaded.gaps == ()
    assert loaded.data["services"]["web"]["image"] == "correct:1"


def test_a_chain_cannot_walk_out_of_the_project_one_hop_at_a_time(
    tmp_path: Path,
) -> None:
    """Containment is still measured against the project, not against the
    previous hop — otherwise each ``../`` would buy another level."""
    project = tmp_path / "project"
    (project / "shared").mkdir(parents=True)
    (tmp_path / "outside.yml").write_text(DANGEROUS_BASE, encoding="utf-8")
    (project / "compose.yml").write_text(
        CHILD.format(reference="./shared/base.yml"), encoding="utf-8"
    )
    (project / "shared" / "base.yml").write_text(
        "services:\n"
        "  app:\n"
        "    extends:\n"
        "      file: ../../outside.yml\n"
        "      service: app\n",
        encoding="utf-8",
    )
    loaded = load_compose_full(project / "compose.yml")

    assert any("outside the project directory" in gap for gap in loaded.gaps)
    assert "privileged" not in loaded.data["services"]["web"]


# --- What stays a coverage gap (ADR-036 decision 7) ------------------------


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
    """Each residual names itself. "outside the project directory" and "was not
    found" call for different edits from the reader, and the single "is not
    resolved" sentence they shared before told them neither."""
    target = _project(tmp_path, reference, base="")
    gaps = load_compose_full(target).gaps

    assert len(gaps) == 1
    assert reason in gaps[0]
    assert "'web'" in gaps[0]


def test_one_message_per_reference_and_reason_not_per_service(
    tmp_path: Path,
) -> None:
    """A monorepo root where several services extend the same absent file has
    one thing wrong with it. Two services failing for *different* reasons still
    get a line each — that distinction is what the grouping has to keep, and it
    is the whole reason the message names a reason at all."""
    target = tmp_path / "compose.yml"
    target.write_text(
        "services:\n"
        + "".join(
            f"  {name}:\n    extends:\n      file: {reference}\n      service: app\n"
            for name, reference in (
                ("a", "nope.yml"),
                ("b", "nope.yml"),
                ("c", "../outside.yml"),
            )
        ),
        encoding="utf-8",
    )
    gaps = load_compose_full(target).gaps

    assert len(gaps) == 2
    missing = next(g for g in gaps if "was not found" in g)
    assert "'a', 'b'" in missing
    assert "were graded" in missing
    outside = next(g for g in gaps if "outside the project directory" in g)
    assert "'c' was graded" in outside


def test_a_symlink_out_of_the_project_is_refused(tmp_path: Path) -> None:
    """The filesystem gate, which is the half the lexical test cannot answer: a
    committed symlink is an ordinary tracked object that survives clone, and
    ``base.yml`` is spelled like a file beside the document while pointing
    anywhere."""
    outside = tmp_path.parent / "outside-base.yml"
    outside.write_text(DANGEROUS_BASE, encoding="utf-8")
    target = _project(tmp_path, "base.yml", base="")
    (tmp_path / "base.yml").symlink_to(outside)

    loaded = load_compose_full(target)
    assert len(loaded.gaps) == 1
    assert "outside the project directory" in loaded.gaps[0]
    assert "privileged" not in loaded.data["services"]["web"]


def test_a_cycle_ends_as_a_gap_rather_than_a_hang(tmp_path: Path) -> None:
    target = _project(
        tmp_path,
        "one.yml",
        base=(
            "services:\n"
            "  app:\n"
            "    extends:\n"
            "      file: compose.yml\n"
            "      service: web\n"
        ),
    )
    gaps = load_compose_full(target).gaps

    assert any("already inherited" in gap for gap in gaps)


def test_a_fan_out_past_the_file_cap_ends_as_a_gap(tmp_path: Path) -> None:
    """The cap bounds one document's whole expansion, not each branch, so a
    wide fan-out cannot spend an allowance per service."""
    services = []
    for index in range(MAX_REFERENCE_FILES + 2):
        (tmp_path / f"base{index}.yml").write_text(
            f"services:\n  app:\n    image: nginx:1.2{index % 10}\n", encoding="utf-8"
        )
        services.append(
            f"  web{index}:\n"
            f"    extends:\n"
            f"      file: base{index}.yml\n"
            f"      service: app\n"
        )
    target = tmp_path / "compose.yml"
    target.write_text("services:\n" + "".join(services), encoding="utf-8")

    gaps = load_compose_full(target).gaps
    assert gaps
    assert all(f"more than {MAX_REFERENCE_FILES} files" in gap for gap in gaps)


def test_a_base_without_the_named_service_is_a_gap(tmp_path: Path) -> None:
    target = _project(
        tmp_path, "base.yml", base="services:\n  other:\n    image: nginx:1.27\n"
    )
    gaps = load_compose_full(target).gaps

    assert len(gaps) == 1
    assert "declares no service 'app'" in gaps[0]


def test_an_unreadable_base_is_a_gap_not_a_crash(tmp_path: Path) -> None:
    target = _project(tmp_path, "base.yml", base="services: [not, a, mapping]\n")
    gaps = load_compose_full(target).gaps

    assert len(gaps) == 1
    assert "'web'" in gaps[0]


# --- The exit-code contract ------------------------------------------------


def test_a_resolved_reference_exits_on_findings_not_on_coverage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The one row that moves: 2 becomes the ordinary findings verdict, and the
    machine channels stop reporting a partial view. The base's ``privileged:
    true`` is now *found* rather than merely warned about."""
    target = _project(tmp_path, "base.yml")

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--format", "json", str(target)])
    assert exc.value.code == 1

    doc = json.loads(capsys.readouterr().out)
    assert doc["errors"] == []
    assert "CL-0002" in _rule_ids(doc["findings"])  # privileged: true


def test_a_resolved_reference_reports_executionsuccessful(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = _project(tmp_path, "base.yml")

    with pytest.raises(SystemExit):
        cli.main(["check", "--format", "sarif", str(target)])

    invocation = json.loads(capsys.readouterr().out)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert invocation.get("toolExecutionNotifications", []) == []


def test_a_clean_base_leaves_the_run_at_zero(tmp_path: Path) -> None:
    """Resolving is not a way to fail: a base that adds nothing dangerous
    leaves the verdict exactly where the child's own keys put it."""
    target = _project(
        tmp_path,
        "base.yml",
        base=(
            "services:\n"
            "  app:\n"
            "    image: nginx@sha256:" + "ab" * 32 + "\n"
            "    read_only: true\n"
            "    cap_drop: [ALL]\n"
            '    security_opt: ["no-new-privileges:true"]\n'
            '    user: "1000:1000"\n'
            "    deploy:\n"
            "      resources:\n"
            "        limits:\n"
            "          memory: 512M\n"
            "          cpus: '0.50'\n"
        ),
    )
    with pytest.raises(SystemExit) as exc:
        cli.main(["check", str(target)])
    assert exc.value.code == 0


def test_allow_partial_coverage_still_accepts_a_residual(tmp_path: Path) -> None:
    """The flag's meaning is unchanged: it accepts the gaps that are left."""
    target = _project(tmp_path, "nope.yml", base="")

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--allow-partial-coverage", str(target)])
    assert exc.value.code == 0


def test_fix_defers_a_finding_written_in_the_base_and_names_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``fix`` rewrites only the file it was pointed at, so a finding whose
    evidence is written in the base is deferred — and the sentence has to name
    the base. It named the *overlay* list before, which is empty for an
    ``extends:`` reference, so the file was a blank in the message."""
    target = _project(tmp_path, "shared/base.yml")
    base_before = (tmp_path / "shared" / "base.yml").read_text(encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", "--apply", str(target)])
    assert exc.value.code == 0

    err = _slashed(capsys.readouterr().err)
    assert "come from" in err
    assert "shared/base.yml and need manual review there" in err
    # The base is another file's document. `fix` does not touch it.
    assert (tmp_path / "shared" / "base.yml").read_text(encoding="utf-8") == (
        base_before
    )


# --- Provenance ------------------------------------------------------------


def test_a_finding_written_in_the_base_names_the_base(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The report is headed by the primary file, so a finding whose evidence
    lives in another document has to say so — otherwise the reader edits a line
    number that belongs to a file they are not looking at."""
    target = _project(tmp_path, "shared/base.yml")

    with pytest.raises(SystemExit):
        cli.main(["check", "--format", "json", str(target)])

    findings = json.loads(capsys.readouterr().out)["findings"]
    privileged = next(f for f in findings if f["rule_id"] == "CL-0002")
    assert _slashed(privileged["source_file"]).endswith("shared/base.yml")
    assert privileged["line"] == 4  # `privileged: true` in the base, not the child
