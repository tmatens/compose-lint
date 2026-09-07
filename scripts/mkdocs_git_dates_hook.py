"""Sitemap `<lastmod>` from each page's last git commit, not the build date.

mkdocs sets `Page.update_date` to today for every page (`get_build_date()` in
`mkdocs/structure/pages.py`), and its built-in `sitemap.xml` template renders
that verbatim. Every rebuild therefore claims all ~95 pages changed today, which
is the one thing `<lastmod>` is not allowed to say: search engines that spot a
sitemap stamping uniform build dates discount the field entirely, so a page that
really did change loses the signal along with the ones that didn't.

No supported option gets git dates into the sitemap.
`mkdocs-git-revision-date-localized-plugin` — the obvious candidate — only writes
`page.meta["git_revision_date_localized_*"]`; it never touches `update_date`, so
it changes footers and leaves the sitemap exactly as wrong. Reading those meta
keys from the sitemap would mean overriding the template via `theme.custom_dir`,
which is worse than this hook: an override pins a private copy of mkdocs'
template that silently stops tracking upstream fixes.

`on_env` is the last event before `_build_theme_template` renders the sitemap
(`mkdocs/commands/build.py`) and the first at which every `Page` exists, so it is
the only point where setting `update_date` still reaches the output. The two
consumers of that attribute are the sitemap and the mtime of its `.gz` twin, so
the blast radius stays inside sitemap generation.

Degrades to mkdocs' build date whenever git cannot answer: no git binary, not a
work tree, or an untracked page (for which "now" is in fact the right answer).
A shallow clone can answer but answers wrongly — every path resolves to the tip
commit — so that case warns rather than passing off a uniform date as real.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jinja2 import Environment
    from mkdocs.config.defaults import MkDocsConfig
    from mkdocs.structure.files import Files

log = logging.getLogger("mkdocs.hooks.git_dates")

_DATE_PREFIX = "D "

# %cs is the committer date as bare YYYY-MM-DD, which is already the format the
# sitemap wants — no parsing, no timezone to get wrong. quotePath=false stops
# git escaping non-ASCII paths into a form that would not match the page path.
_LOG_ARGS = (
    "-c",
    "core.quotePath=false",
    "log",
    f"--pretty=format:{_DATE_PREFIX}%cs",
    "--name-only",
    "--no-renames",
)


def _git(repo_root: Path, *args: str) -> str | None:
    """Run git and decode its output as UTF-8, not as the ambient locale.

    `text=True` alone decodes with `locale.getencoding()`, which is UTF-8 on
    Linux and the ANSI codepage (cp1252) on Windows -- while git, with
    quotePath disabled, emits UTF-8 path bytes on every platform. The mismatch
    is invisible until a page has a non-ASCII name, at which point its map key
    becomes mojibake, no page matches it, and that page quietly keeps the build
    date. `errors="replace"` keeps a genuinely undecodable path from raising
    through the docs build: an unmatched key costs one page its real date,
    where an exception would cost the whole site its sitemap.
    """
    try:
        result = subprocess.run(
            ("git", "-C", str(repo_root), *args),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout


def _commit_dates(docs_dir: Path) -> dict[Path, str] | None:
    """Map every tracked file under docs_dir to its newest commit date."""
    toplevel = _git(docs_dir, "rev-parse", "--show-toplevel")
    if not toplevel:
        return None
    repo_root = Path(toplevel.strip())

    shallow = _git(repo_root, "rev-parse", "--is-shallow-repository")
    if shallow is not None and shallow.strip() == "true":
        log.warning(
            "git_dates: shallow clone — every page would resolve to the tip commit, "
            "so sitemap lastmod is left at the build date. Check out with full "
            "history (actions/checkout fetch-depth: 0) to get real dates."
        )
        return None

    # One walk of the log rather than a subprocess per page. Output is
    # newest-first, so the first date seen for a path is its latest change.
    output = _git(repo_root, *_LOG_ARGS, "--", str(docs_dir))
    if output is None:
        return None

    dates: dict[Path, str] = {}
    date = ""
    for line in output.splitlines():
        if line.startswith(_DATE_PREFIX):
            date = line[len(_DATE_PREFIX) :].strip()
        elif line.strip() and date:
            dates.setdefault(repo_root / line, date)
    return dates


def on_env(
    env: Environment, config: MkDocsConfig, files: Files, **kwargs: object
) -> Environment:
    docs_dir = Path(config.docs_dir).resolve()
    dates = _commit_dates(docs_dir)
    if not dates:
        return env

    stamped = 0
    for file in files.documentation_pages():
        page = file.page
        if page is None or not file.abs_src_path:
            continue
        date = dates.get(Path(file.abs_src_path).resolve())
        if date:
            page.update_date = date
            stamped += 1

    log.info("git_dates: sitemap lastmod set from git for %d pages", stamped)
    return env
