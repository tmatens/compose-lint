"""Per-page <title> and meta description for the docs site, derived at build time.

Both values are computed from content that already exists — the nav title and the
page's own prose — because the markdown under docs/ is the same text `--explain`
prints raw, so it cannot carry YAML front matter, and mkdocs.yml's rule against
duplicating content rules out a hand-maintained table of titles and blurbs here.

What it fixes:

- **Title order.** The nav label leads with the rule code ("CL-0007 read_only —
  Read-only file system errors"), which is what mkdocs-material puts first in
  <title>. Nobody searches "CL-0007"; they search the symptom. The code moves to
  the end so the searchable half leads, while the sidebar label stays short.
- **Descriptions.** Without this, all ~45 pages inherit the single
  `site_description` from mkdocs.yml, so every search snippet describes the tool
  rather than the page.

mkdocs-material reads `page.meta.title` and `page.meta.description` ahead of its
own defaults, so setting them here is enough; no template override is needed.
"""

from __future__ import annotations

import re

# "CL-0007 read_only — Read-only file system errors" -> code, remainder.
_RULE_TITLE = re.compile(r"^(CL-\d{4})\s+(.*)$")

_MAX_DESCRIPTION = 155

# Rule pages open with a severity/derivation/references block before any prose, so
# the first paragraph is metadata. "Why it matters" states the risk in prose and
# makes the better snippet; "What it detects" is the fallback.
_PREFERRED_SECTIONS = ("why it matters", "what it detects")

_FENCE = re.compile(r"^\s*(```|~~~)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_SKIP_LINE = re.compile(
    r"""^\s*(
        [-*+]\s          # bullet list
      | \d+\.\s          # ordered list
      | >                # blockquote
      | \|               # table row
      | !\[              # image
      | \*\*[A-Za-z /]+:\*\*   # **Severity:** and friends — label, not prose
    )""",
    re.VERBOSE,
)

# Inline markdown that should not reach a search snippet. Emphasis markers are
# unwrapped pair-by-pair rather than stripped blindly: a blind strip turns
# `read_only` into "readonly", which is exactly the term the page is about.
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_STRONG = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC_STAR = re.compile(r"(?<!\w)\*([^*]+)\*(?!\w)")
_ITALIC_UNDERSCORE = re.compile(r"(?<!\w)_([^_]+)_(?!\w)")


def _clean(text: str) -> str:
    text = _LINK.sub(r"\1", text)
    text = _STRONG.sub(r"\1", text)
    text = _ITALIC_STAR.sub(r"\1", text)
    text = _ITALIC_UNDERSCORE.sub(r"\1", text)
    text = text.replace("`", "")
    return re.sub(r"\s+", " ", text).strip()


def _truncate(text: str) -> str:
    if len(text) <= _MAX_DESCRIPTION:
        return text
    clipped = text[:_MAX_DESCRIPTION].rsplit(" ", 1)[0].rstrip(" ,;:—-")
    return f"{clipped}…"


def _paragraphs(markdown: str):
    """Yield (section_title, paragraph) for each prose paragraph, fences skipped."""
    section = ""
    buffer: list[str] = []
    in_fence = False

    def flush():
        if buffer:
            joined = " ".join(buffer)
            buffer.clear()
            return joined
        return None

    for line in markdown.splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
            paragraph = flush()
            if paragraph:
                yield section, paragraph
            continue
        if in_fence:
            continue

        heading = _HEADING.match(line)
        if heading:
            paragraph = flush()
            if paragraph:
                yield section, paragraph
            section = heading.group(2).strip().lower()
            continue

        if not line.strip() or _SKIP_LINE.match(line):
            paragraph = flush()
            if paragraph:
                yield section, paragraph
            continue

        buffer.append(line.strip())

    paragraph = flush()
    if paragraph:
        yield section, paragraph


def _usable(paragraph: str) -> str | None:
    """A snippet has to stand alone: no list lead-ins, no fragments."""
    cleaned = _clean(paragraph)
    if len(cleaned) < 60 or cleaned.endswith(":"):
        return None
    return cleaned


def _description(markdown: str) -> str | None:
    candidates = list(_paragraphs(markdown))
    for wanted in _PREFERRED_SECTIONS:
        for section, paragraph in candidates:
            if section.startswith(wanted):
                usable = _usable(paragraph)
                if usable:
                    return _truncate(usable)
    for _, paragraph in candidates:
        usable = _usable(paragraph)
        if usable:
            return _truncate(usable)
    return None


def _title(page_title: str | None) -> str | None:
    """Move a leading rule code to the end: search terms belong first."""
    if not page_title:
        return None
    match = _RULE_TITLE.match(page_title.strip())
    if not match:
        return None
    code, remainder = match.group(1), match.group(2).strip(" :—-")
    if not remainder:
        return None
    return f"{remainder} ({code})"


def on_page_markdown(markdown, page, config, files):  # noqa: ARG001 - mkdocs signature
    meta = page.meta if page.meta is not None else {}

    if "title" not in meta:
        retitled = _title(page.title)
        if retitled:
            meta["title"] = retitled

    if "description" not in meta:
        description = _description(markdown)
        if description:
            meta["description"] = description

    page.meta = meta
    return markdown
