#!/usr/bin/env python3
"""Move the Forgejo smoke harness to the newest Forgejo and runner releases.

Codeberg garbage-collects a superseded Forgejo patch tag — pinned digest
included — within days of the next patch shipping, so a pin nobody moves
404s and the weekly forgejo-smoke run goes red (#746). Renovate was meant
to open that bump (#748), but the hosted runner cannot look up either
registry (Dependency Dashboard: "Failed to look up docker package
codeberg.org/forgejo/forgejo: no-result"), and even a working Renovate PR
would fail the smoke: docs/forgejo.md's "Verified on Forgejo X, runner Y"
line is asserted against the live instance, and Renovate cannot move it.

So the bump is two files or nothing. This script:

1. reads both image pins from the harness compose file and the claim
   from docs/forgejo.md — and FAILS (exit 2) if either anchor is not
   exactly where it expects, because a watcher that silently watches
   nothing reads as "covered" (the eol_watch.py lesson);
2. asks each registry for its tags and keeps the newest plain X.Y.Z
   release — pre-releases, `-rootless` variants and floating `16`/`16.0`
   tags are never candidates;
3. resolves that tag to its manifest-list (OCI index) digest via the
   registry's own Docker-Content-Digest header — a per-architecture
   manifest digest would pin one platform and is refused;
4. rewrites the pin and the claim together, in place.

Policy: the newest stable release of each image, not the pinned minor.
The claim in the guide is "verified on Forgejo X", and a claim about a
line Codeberg has stopped serving is not worth keeping; a major that
breaks the snippet surfaces as a red smoke on the bump PR, which is the
review. Merging stays manual (forgejo-smoke-bump.yml opens the PR).

Exit codes: 0 = nothing to do, both pins current. 1 = files rewritten
(summary on stdout, ready for a commit). 2 = the script could not produce
a trustworthy answer (network, parse, stale anchor, a digest that is not a
manifest list). The workflow turns 1 into a PR and 2 into a failure.

Offline by design in tests: everything except ``fetch()`` and ``main()``
takes its inputs as parameters; ``Registry`` accepts a fetch callable.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping

REPO = pathlib.Path(__file__).resolve().parent.parent
COMPOSE_FILE = REPO / "scripts" / "forgejo_smoke" / "compose-forgejo-smoke.yml"
DOCS_FILE = REPO / "docs" / "forgejo.md"

# The two images the harness runs, keyed by the registry repository the
# compose file names. Anything else in the file is a stale-anchor failure.
IMAGES: dict[str, str] = {
    "forgejo/forgejo": "forgejo",
    "forgejo/runner": "runner",
}

IMAGE_RE = re.compile(
    r"^(?P<prefix>\s*image: )"
    r"(?P<registry>[a-z0-9.-]+)/(?P<repo>[a-z0-9_./-]+):"
    r"(?P<tag>[0-9][A-Za-z0-9._-]*)@(?P<digest>sha256:[0-9a-f]{64})[ \t]*$",
    re.MULTILINE,
)
# Kept in step with scripts/forgejo_smoke.py, which asserts the same line
# against the live instance.
VERIFIED_RE = re.compile(r"Verified on Forgejo ([0-9.]+), runner ([0-9.]+)")
STABLE_TAG_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")

INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
USER_AGENT = (
    "compose-lint-forgejo-smoke-bump (+https://github.com/tmatens/compose-lint)"
)
MAX_TAG_PAGES = 50

Response = tuple[int, Mapping[str, str], bytes]
Fetch = Callable[[str, str, Mapping[str, str]], Response]


class CannotAnswer(RuntimeError):
    """The script cannot produce a trustworthy result (exit 2)."""


@dataclasses.dataclass(frozen=True)
class Pin:
    registry: str
    repo: str
    tag: str
    digest: str

    @property
    def name(self) -> str:
        return IMAGES[self.repo]


# --- Pure: reading and rewriting the two files ----------------------------


def read_pins(compose_text: str) -> dict[str, Pin]:
    """Return the harness pins keyed by image name, or raise CannotAnswer."""
    found: dict[str, Pin] = {}
    for m in IMAGE_RE.finditer(compose_text):
        repo = m.group("repo")
        if repo not in IMAGES:
            raise CannotAnswer(f"unexpected image {m.group('registry')}/{repo}")
        name = IMAGES[repo]
        if name in found:
            raise CannotAnswer(f"{repo} is pinned more than once")
        found[name] = Pin(m.group("registry"), repo, m.group("tag"), m.group("digest"))
    missing = sorted(set(IMAGES.values()) - set(found))
    if missing:
        raise CannotAnswer(
            f"compose file does not pin {', '.join(missing)} as "
            "image: <registry>/<repo>:<tag>@sha256:<digest>"
        )
    return found


def read_claim(docs_text: str) -> tuple[str, str]:
    """Return (forgejo, runner) from the guide's verified-on line."""
    matches = VERIFIED_RE.findall(docs_text)
    if len(matches) != 1:
        raise CannotAnswer(
            "expected exactly one 'Verified on Forgejo X, runner Y' line in "
            f"docs/forgejo.md, found {len(matches)}"
        )
    forgejo, runner = matches[0]
    return forgejo, runner


def newest_stable(tags: list[str]) -> str | None:
    """The highest plain X.Y.Z tag, or None when there is none."""
    best: tuple[tuple[int, int, int], str] | None = None
    for tag in tags:
        m = STABLE_TAG_RE.match(tag)
        if not m:
            continue
        key = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if best is None or key > best[0]:
            best = (key, tag)
    return best[1] if best else None


def rewrite(
    compose_text: str,
    docs_text: str,
    pins: dict[str, Pin],
    targets: dict[str, Pin],
) -> tuple[str, str]:
    """Return the two files with every pin and the claim moved to ``targets``."""
    for name, new in targets.items():
        old = pins[name]
        old_ref = f"{old.registry}/{old.repo}:{old.tag}@{old.digest}"
        new_ref = f"{new.registry}/{new.repo}:{new.tag}@{new.digest}"
        if compose_text.count(old_ref) != 1:
            raise CannotAnswer(f"{old_ref} does not occur exactly once")
        compose_text = compose_text.replace(old_ref, new_ref)
    forgejo, runner = targets["forgejo"].tag, targets["runner"].tag
    claim = f"Verified on Forgejo {forgejo}, runner {runner}"
    docs_text, n = VERIFIED_RE.subn(claim, docs_text)
    if n != 1:
        raise CannotAnswer(f"verified-on line replaced {n} times, expected 1")
    return compose_text, docs_text


def branch_name(targets: dict[str, Pin]) -> str:
    forgejo, runner = targets["forgejo"].tag, targets["runner"].tag
    return f"forgejo-smoke/forgejo-{forgejo}-runner-{runner}"


# --- Registry client (token dance, pagination, digest) -------------------


def fetch(url: str, method: str, headers: Mapping[str, str]) -> Response:
    """One HTTP round trip. 4xx/5xx come back as a status, not an exception."""
    req = urllib.request.Request(url, method=method, headers=dict(headers))
    req.add_header("User-Agent", USER_AGENT)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CannotAnswer(f"{method} {url}: {exc}") from exc


_CHALLENGE_RE = re.compile(r'(\w+)="([^"]*)"')


class Registry:
    """Anonymous pull-scope client for one OCI distribution registry.

    Codeberg challenges every ``/v2/`` request and issues anonymous tokens
    from the realm it names; data.forgejo.org serves public repositories
    with no challenge at all. Both shapes are handled by answering a 401
    with the token the challenge asks for, once.
    """

    def __init__(self, host: str, fetch_fn: Fetch = fetch) -> None:
        self.host = host
        self._fetch = fetch_fn
        self._tokens: dict[str, str] = {}

    def _url(self, path: str) -> str:
        return f"https://{self.host}{path}"

    def _token(self, repo: str, challenge: str) -> str:
        params = dict(_CHALLENGE_RE.findall(challenge))
        realm = params.get("realm")
        if not challenge.startswith("Bearer") or not realm:
            raise CannotAnswer(f"{self.host}: unsupported challenge {challenge!r}")
        query = {"scope": f"repository:{repo}:pull"}
        if "service" in params:
            query["service"] = params["service"]
        status, _, body = self._fetch(
            f"{realm}?{urllib.parse.urlencode(query)}", "GET", {}
        )
        if status != 200:
            raise CannotAnswer(f"{self.host}: token request returned {status}")
        try:
            token = json.loads(body)["token"]
        except (ValueError, KeyError, TypeError) as exc:
            raise CannotAnswer(f"{self.host}: token response unreadable") from exc
        return str(token)

    def request(
        self, repo: str, path: str, method: str = "GET", accept: str | None = None
    ) -> Response:
        headers: dict[str, str] = {}
        if accept:
            headers["Accept"] = accept
        if repo in self._tokens:
            headers["Authorization"] = f"Bearer {self._tokens[repo]}"
        status, resp_headers, body = self._fetch(self._url(path), method, headers)
        if status == 401 and repo not in self._tokens:
            challenge = _header(resp_headers, "WWW-Authenticate")
            if not challenge:
                raise CannotAnswer(f"{self.host}{path}: 401 without a challenge")
            self._tokens[repo] = self._token(repo, challenge)
            headers["Authorization"] = f"Bearer {self._tokens[repo]}"
            status, resp_headers, body = self._fetch(self._url(path), method, headers)
        return status, resp_headers, body

    def tags(self, repo: str) -> list[str]:
        """Every tag of ``repo``, following ``Link: rel="next"`` pagination."""
        path: str | None = f"/v2/{repo}/tags/list?n=1000"
        tags: list[str] = []
        for _ in range(MAX_TAG_PAGES):
            if path is None:
                return tags
            status, headers, body = self.request(repo, path)
            if status != 200:
                raise CannotAnswer(f"{self.host}{path}: {status}")
            try:
                page = json.loads(body)["tags"] or []
            except (ValueError, KeyError, TypeError) as exc:
                raise CannotAnswer(f"{self.host}{path}: tags unreadable") from exc
            tags.extend(str(t) for t in page)
            path = _next_link(_header(headers, "Link"))
        raise CannotAnswer(f"{self.host}/{repo}: more than {MAX_TAG_PAGES} tag pages")

    def index_digest(self, repo: str, tag: str) -> str:
        """The manifest-list digest for ``tag`` — never a per-arch manifest."""
        status, headers, _ = self.request(
            repo,
            f"/v2/{repo}/manifests/{tag}",
            method="HEAD",
            accept=", ".join(INDEX_TYPES),
        )
        if status != 200:
            raise CannotAnswer(f"{self.host}/{repo}:{tag}: manifest HEAD {status}")
        ctype = _header(headers, "Content-Type").split(";")[0].strip()
        if ctype not in INDEX_TYPES:
            raise CannotAnswer(
                f"{self.host}/{repo}:{tag} resolves to {ctype or 'no content type'}, "
                "not a manifest list — refusing to pin one architecture"
            )
        digest = _header(headers, "Docker-Content-Digest")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise CannotAnswer(f"{self.host}/{repo}:{tag}: no usable digest header")
        return digest


def _header(headers: Mapping[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def _next_link(link: str) -> str | None:
    """Path of the ``rel="next"`` target, absolute URLs reduced to their path."""
    for part in link.split(","):
        m = re.match(r'\s*<([^>]+)>\s*;\s*rel="?next"?', part)
        if m:
            target = m.group(1)
            parsed = urllib.parse.urlsplit(target)
            return parsed.path + (f"?{parsed.query}" if parsed.query else "")
    return None


# --- Orchestration ---------------------------------------------------------


def resolve_targets(
    pins: dict[str, Pin], registries: Mapping[str, Registry]
) -> dict[str, Pin]:
    """The newest stable pin for each image, as the registry reports it."""
    targets: dict[str, Pin] = {}
    for name, pin in pins.items():
        registry = registries[pin.registry]
        tag = newest_stable(registry.tags(pin.repo))
        if tag is None:
            raise CannotAnswer(f"{pin.registry}/{pin.repo} lists no X.Y.Z tag")
        if tag == pin.tag:
            # Same tag: keep the digest we have rather than trusting a
            # re-push; a moved digest under an unchanged tag is a different
            # conversation than a version bump.
            targets[name] = pin
            continue
        digest = registry.index_digest(pin.repo, tag)
        targets[name] = Pin(pin.registry, pin.repo, tag, digest)
    return targets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="report what would change without rewriting any file",
    )
    parser.add_argument(
        "--github-output",
        type=pathlib.Path,
        help="append branch=/title=/forgejo=/runner= lines to this file",
    )
    args = parser.parse_args(argv)

    compose_text = COMPOSE_FILE.read_text(encoding="utf-8")
    docs_text = DOCS_FILE.read_text(encoding="utf-8")
    pins = read_pins(compose_text)
    claim = read_claim(docs_text)
    pinned = (pins["forgejo"].tag, pins["runner"].tag)
    if claim != pinned:
        raise CannotAnswer(
            f"docs/forgejo.md claims {claim} but the harness pins {pinned}; "
            "fix that by hand first"
        )

    registries = {
        host: Registry(host) for host in {pin.registry for pin in pins.values()}
    }
    targets = resolve_targets(pins, registries)
    moved = [name for name in ("forgejo", "runner") if targets[name] != pins[name]]
    if not moved:
        print(f"up to date: Forgejo {pinned[0]}, runner {pinned[1]}")
        return 0

    new_compose, new_docs = rewrite(compose_text, docs_text, pins, targets)
    for name in moved:
        new = targets[name]
        print(f"{name}: {pins[name].tag} -> {new.tag} ({new.digest})")
    if args.check:
        return 1

    COMPOSE_FILE.write_text(new_compose, encoding="utf-8")
    DOCS_FILE.write_text(new_docs, encoding="utf-8")
    title = "Bump the Forgejo smoke harness to " + ", ".join(
        f"{'Forgejo' if n == 'forgejo' else 'runner'} {targets[n].tag}" for n in moved
    )
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as out:
            out.write(f"branch={branch_name(targets)}\n")
            out.write(f"title={title}\n")
            out.write(f"forgejo={targets['forgejo'].tag}\n")
            out.write(f"runner={targets['runner'].tag}\n")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CannotAnswer as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
