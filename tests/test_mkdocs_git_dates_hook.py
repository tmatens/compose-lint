"""scripts/mkdocs_git_dates_hook.py — sitemap lastmod, derived from git.

The hook exists because mkdocs stamps every page with the build date, which
makes `<lastmod>` a field that says the same false thing about all 95 pages on
every deploy. Its value therefore rests entirely on two behaviours these tests
pin: that a tracked page gets *its own* last-commit date, and that a source git
cannot answer for is declined rather than guessed at.

The second half matters more than it looks. A shallow clone answers every query
happily and wrongly — every path resolves to the tip commit — so the failure
mode being guarded is not an exception, it is a plausible-looking uniform date
that would reintroduce exactly the defect the hook removes. `actions/checkout`
is shallow by default, so that is one forgotten `fetch-depth: 0` away at all
times, which is why it is tested against a real `--depth 1` clone rather than a
mocked one.
"""

from __future__ import annotations

import importlib.util
import logging
import pathlib
import subprocess
import sys
from types import SimpleNamespace

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "mkdocs_git_dates_hook",
    pathlib.Path(__file__).resolve().parent.parent
    / "scripts"
    / "mkdocs_git_dates_hook.py",
)
assert _SPEC is not None and _SPEC.loader is not None
hook = importlib.util.module_from_spec(_SPEC)
sys.modules["mkdocs_git_dates_hook"] = hook
_SPEC.loader.exec_module(hook)

# The hook has to import with no mkdocs installed — it runs inside mkdocs, but
# the dev environment that runs these tests does not carry the docs toolchain.
# Its mkdocs imports are therefore under TYPE_CHECKING; this asserts that stays
# true, because a stray runtime import would make the whole suite uncollectable.
assert "mkdocs" not in sys.modules


def _run(repo: pathlib.Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )


def _commit(repo: pathlib.Path, message: str, date: str) -> None:
    """Commit staged changes at a fixed date, independent of ambient git config.

    Signing and identity are forced off/explicit: the suite must not depend on
    the developer's `commit.gpgsign` or on a CI runner having `user.email` set.
    """
    stamp = f"{date}T12:00:00+00:00"
    _run(
        repo,
        "-c",
        "commit.gpgsign=false",
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "--no-verify",
        "-m",
        message,
        "--date",
        stamp,
        "--no-gpg-sign",
    )


def _tracked(repo: pathlib.Path) -> list[pathlib.Path]:
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [repo / line for line in out.splitlines() if line]


def _write(repo: pathlib.Path, rel: str, text: str = "x\n") -> pathlib.Path:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def repo(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    """A repo with two docs pages on different days, plus a file outside docs/.

    The out-of-tree README is load-bearing: without a committed file outside
    ``docs/``, a hook that walked the *whole* repo would produce an identical
    map and the scoping test would pass vacuously.
    """
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    _run(root, "init", "-b", "main")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-04-07T12:00:00+00:00")
    _write(root, "docs/old.md")
    _write(root, "README.md")
    _run(root, "add", "-A")
    _commit(root, "Add old page and README", "2026-04-07")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-09-06T12:00:00+00:00")
    _write(root, "docs/new.md")
    _run(root, "add", "-A")
    _commit(root, "Add new page", "2026-09-06")
    return root


class TestCommitDates:
    def test_each_file_gets_its_own_commit_date(self, repo: pathlib.Path) -> None:
        dates = hook._commit_dates(repo / "docs")
        assert dates is not None
        assert dates[repo / "docs" / "old.md"] == "2026-04-07"
        assert dates[repo / "docs" / "new.md"] == "2026-09-06"

    def test_newest_commit_wins(
        self, repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """git log is newest-first, so the *first* date seen must be kept."""
        monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-09-07T12:00:00+00:00")
        _write(repo, "docs/old.md", "edited\n")
        _run(repo, "add", "-A")
        _commit(repo, "Edit old page", "2026-09-07")

        dates = hook._commit_dates(repo / "docs")
        assert dates is not None
        assert dates[repo / "docs" / "old.md"] == "2026-09-07"

    def test_non_ascii_paths_are_matched(
        self, repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without core.quotePath=false git escapes these and nothing matches."""
        monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-05-01T12:00:00+00:00")
        _write(repo, "docs/pörtainer.md")
        _run(repo, "add", "-A")
        _commit(repo, "Add a non-ASCII page", "2026-05-01")

        dates = hook._commit_dates(repo / "docs")
        assert dates is not None
        assert dates[repo / "docs" / "pörtainer.md"] == "2026-05-01"

    def test_git_output_is_decoded_as_utf8_not_the_locale(
        self, repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """git emits UTF-8 paths everywhere; `text=True` alone decodes as cp1252
        on Windows, so a non-ASCII page silently keeps the build date.

        `test_non_ascii_paths_are_matched` only catches this on a non-UTF-8
        runner — it passed on Linux and failed on windows-2025. This pins the
        decode itself so the regression fails on every platform.
        """
        seen: list[dict[str, object]] = []
        real = subprocess.run

        def spy(*args, **kwargs):
            seen.append(kwargs)
            return real(*args, **kwargs)

        monkeypatch.setattr(hook.subprocess, "run", spy)
        hook._commit_dates(repo / "docs")

        assert seen, "no git call was made; the spy proved nothing"
        assert all(kw.get("encoding") == "utf-8" for kw in seen)
        assert all(kw.get("errors") == "replace" for kw in seen)

    def test_files_outside_docs_dir_are_not_mapped(self, repo: pathlib.Path) -> None:
        """The log walk is pathspec-scoped; a tracked README must not appear."""
        dates = hook._commit_dates(repo / "docs")
        assert dates is not None
        assert (repo / "README.md") in set(_tracked(repo)), (
            "fixture regression: nothing outside docs/ is committed"
        )
        assert (repo / "README.md") not in dates
        assert all(p.parent == repo / "docs" for p in dates)


class TestDeclinesRatherThanGuesses:
    def test_shallow_clone_declines_and_warns(
        self,
        repo: pathlib.Path,
        tmp_path: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The forgotten-fetch-depth case: answerable, but uniformly wrong."""
        clone = (tmp_path / "shallow").resolve()
        subprocess.run(
            ["git", "clone", "--depth", "1", repo.as_uri(), str(clone)],
            check=True,
            capture_output=True,
        )
        assert (
            subprocess.run(
                ["git", "-C", str(clone), "rev-parse", "--is-shallow-repository"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            == "true"
        ), "clone was not shallow; the test is not exercising the guard"

        with caplog.at_level(logging.WARNING, logger="mkdocs.hooks.git_dates"):
            assert hook._commit_dates(clone / "docs") is None
        assert "shallow" in caplog.text
        assert "fetch-depth" in caplog.text, "the warning must name the remedy"

    def test_outside_a_git_repo_declines(self, tmp_path: pathlib.Path) -> None:
        loose = tmp_path / "loose"
        loose.mkdir()
        assert hook._commit_dates(loose) is None

    def test_missing_git_binary_declines(
        self, repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*args: object, **kwargs: object) -> None:
            raise FileNotFoundError("git")

        monkeypatch.setattr(hook.subprocess, "run", boom)
        assert hook._commit_dates(repo / "docs") is None

    def test_git_failure_declines(
        self, repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fail(*args: object, **kwargs: object) -> None:
            raise subprocess.CalledProcessError(128, "git")

        monkeypatch.setattr(hook.subprocess, "run", fail)
        assert hook._commit_dates(repo / "docs") is None


def _page(abs_src_path: pathlib.Path | None, update_date: str) -> SimpleNamespace:
    return SimpleNamespace(
        page=SimpleNamespace(update_date=update_date),
        abs_src_path=str(abs_src_path) if abs_src_path else None,
    )


def _files(*entries: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(documentation_pages=lambda: list(entries))


class TestOnEnv:
    def test_stamps_tracked_pages(self, repo: pathlib.Path) -> None:
        old = _page(repo / "docs" / "old.md", "2026-09-07")
        new = _page(repo / "docs" / "new.md", "2026-09-07")
        config = SimpleNamespace(docs_dir=str(repo / "docs"))

        env = object()
        assert hook.on_env(env, config, _files(old, new)) is env
        assert old.page.update_date == "2026-04-07"
        assert new.page.update_date == "2026-09-06"

    def test_untracked_page_keeps_the_build_date(self, repo: pathlib.Path) -> None:
        """A page git has never seen really did change now — leave it alone."""
        _write(repo, "docs/draft.md")
        draft = _page(repo / "docs" / "draft.md", "2026-09-07")
        config = SimpleNamespace(docs_dir=str(repo / "docs"))

        hook.on_env(object(), config, _files(draft))
        assert draft.page.update_date == "2026-09-07"

    def test_page_without_a_source_path_is_skipped(self, repo: pathlib.Path) -> None:
        generated = _page(None, "2026-09-07")
        config = SimpleNamespace(docs_dir=str(repo / "docs"))

        hook.on_env(object(), config, _files(generated))
        assert generated.page.update_date == "2026-09-07"

    def test_leaves_every_date_alone_when_git_cannot_answer(
        self, tmp_path: pathlib.Path
    ) -> None:
        loose = tmp_path / "loose"
        (loose / "docs").mkdir(parents=True)
        page = _page(loose / "docs" / "index.md", "2026-09-07")
        config = SimpleNamespace(docs_dir=str(loose / "docs"))

        env = object()
        assert hook.on_env(env, config, _files(page)) is env
        assert page.page.update_date == "2026-09-07"
