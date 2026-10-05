"""Generate a whole Compose *project*, seeded and enumerated.

``tests/test_merge_fuzz.py`` generates one overlay pair. That reaches the merge
table and nothing else: a pair has no ``include:``, no ``extends:``, no
``.env``, no ``env_file:``, and no second directory — which is precisely the
area whose semantics are grounded by a comment rather than by a test. This
module generates the directory instead of the file:

    root/
      compose.yaml            base, always
      compose.override.yaml   0-1
      .env                    0-1, the project's interpolation source
      app.env, db.env         0-2 `env_file:` targets
      base/common.yaml        0-1 `extends:` target (own .env 0-1, to prove A7)
      base/.env
      parts/a.yaml            0-2 `include:` targets (own .env 0-1, to prove A8)
      parts/b.yaml
      parts/.env
      sub/compose.yaml        0-1 included document in a subdirectory

Seeded and enumerated rather than sampled per run, for the reason the pair
fuzzer's docstring gives: a fuzzer that generates different inputs on every
invocation reports failures nobody can reproduce.

Two deliberate limits on what a seed may build, both so that a Compose
rejection stays *meaningful*:

* Every generated project resolves, except the ones built to be unresolvable
  (``expects_gap``). The suite asserts acceptance rather than skipping on it,
  because "Compose rejects this" is exactly the claim that rotted in the
  merge fuzzer's ``_EXCLUSIVE`` comment (#798).
* A value is never emitted twice for the same service and field. Compose
  validates some list fields for uniqueness *after* merging and reports the
  duplicate against the overlay file — ``security_opt items at 0 and 1 are
  equal`` for a one-item overlay — so a repeat is a rejection rather than the
  deduplicating merge it looks like. Deduplication is pinned by
  ``test_merge_semantics.test_append_fields_match_compose_shape``.

Value *spellings* (short and long port syntax, mount flags, capability casing,
YAML 1.1 booleans, octal) are deliberately not varied here. They are the shape
comparator's rows, and shape is not compared until phase 3; a findings-only
comparison would take the cost of generating them and detect almost none of
it.

**Layout seeds.** Seeds from ``LAYOUT_SEED_BASE`` up build a second family of
projects, aimed at *where* files sit rather than what they say: symlinked
documents, dotenvs and directories, ``include:`` entries with
``project_directory:``, a ``COMPOSE_FILE`` list selecting an overlay in a
subdirectory, and an included document with no ``services:``. They are a
separate range rather than more steps on the builder above because every one
of them would consume the seed, and an existing seed must keep building the
bytes it always has — a replay of an old failure proves nothing otherwise. See
:class:`_LayoutBuilder` for the tree they build.
"""

from __future__ import annotations

import posixpath
import random
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

# Small enough that two documents naming services independently collide, which
# is what makes duplicate service names across included files reachable (A4).
SERVICE_NAMES = ("web", "api", "db")

# Interpolation references always carry a default. A `${VAR}` that no document
# defines is a real divergence — Compose substitutes empty, compose-lint leaves
# the reference as written (ADR-026) — but it is a *policy* divergence, and it
# belongs in the registry phase 4 adds rather than in every seed that happens
# to place a definition out of scope. With a default present, "defined here"
# and "not visible from here" differ in the resolved value, which is what makes
# A7 (a `.env` beside an `extends:` base is never read) and A8 (an included
# file's own `.env` supplies what the project's does not) observable at all.
VARIABLES = {
    "APPTAG": ("2.0", "1.0"),  # (definition, default written into the document)
    "HOSTPORT": ("9091", "8080"),
    "MOUNTSRC": ("./defined", "./fallback"),
}

# Field -> value spellings. Each pool mixes a dangerous value, a hardening
# value and a neutral one, so an override can move a finding in either
# direction rather than only adding one.
FIELD_POOL: dict[str, list[str]] = {
    "volumes": [
        '["/var/run/docker.sock:/var/run/docker.sock"]',
        '["/etc:/host-etc:ro"]',
        '["/:/host"]',
        '["./data:/data"]',
        '["${MOUNTSRC:-./fallback}:/data"]',
    ],
    "devices": ['["/dev/mem:/dev/probe"]', '["/dev/null:/dev/probe"]'],
    "ports": [
        '["8080:80"]',
        '["127.0.0.1:8081:80"]',
        '["${HOSTPORT:-8080}:80"]',
        '["53:53/udp"]',
    ],
    "cap_add": ["[SYS_ADMIN]", "[NET_ADMIN]", "[SYS_PTRACE]"],
    "cap_drop": ["[ALL]", "[NET_RAW]"],
    "security_opt": [
        '["no-new-privileges:true"]',
        '["seccomp:unconfined"]',
        '["apparmor:unconfined"]',
    ],
    "read_only": ["true", "false"],
    "privileged": ["true", "false"],
    "user": ['"1000:1000"', '"root"', '"0"'],
    "tmpfs": ['["/tmp"]', '["/run"]'],
    "logging": ['{driver: "json-file"}', '{driver: "none"}'],
    "mem_limit": ['"512m"', '"1g"'],
    "cpus": ["0.5", "1.5"],
    "pid": ['"host"'],
    "ipc": ['"host"'],
    "environment": [
        '{AWS_SECRET_ACCESS_KEY: "AKIAIOSFODNN7EXAMPLE"}',
        '["AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"]',
        '{DATABASE_URL: "postgres://admin:hunter2@db:5432/app"}',
        '{HARMLESS: "1"}',
    ],
    "labels": ['{tier: "edge"}', '["role=web"]'],
    "depends_on": ["[db]", "{db: {condition: service_healthy}}"],
    "command": ['["sh", "-c", "sleep 1"]', '"sleep 2"'],
}

# `depends_on: [db]` needs `db` to exist; the generator only draws it for a
# project that already has that service.
_NEEDS_DB = frozenset({"depends_on"})

# `network_mode` is excluded from the pool entirely: Compose refuses it
# alongside the service-level `networks:` an included file may contribute, and
# the pair fuzzer already crosses it with `ports:`.

IMAGES = ["myapp:${APPTAG:-1.0}", "myapp:1.0", "myapp", "nginx:1.27"]

DIRECTIVES = ["", "", "", "", "!override ", "!reset "]

# Credential-shaped keys so `env_file:` targets reach CL-0020 and CL-0021
# rather than only proving the file was opened.
ENV_FILE_BODIES = {
    "app.env": (
        "APP_MODE=production\nAPI_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwx\n"
    ),
    "db.env": "POSTGRES_PASSWORD=hunter2\nPGDATA=/var/lib/postgresql/data\n",
}

ENV_FILE_SPELLINGS = [
    "app.env",
    "[app.env]",
    "[app.env, db.env]",
    "[{path: app.env, required: false}]",
]

# Seeds at or above this build a layout project (see `_LayoutBuilder`). Far
# enough above the original range that growing it never reaches here.
LAYOUT_SEED_BASE = 100_000

# What the layout projects define in a dotenv, as (definition, default written
# into the reference). The names are split by scope so that a disagreement
# says which dotenv was read: `PRIV`, `CAP` and `INCTAG` belong to an included
# entry's project directory, `DEVTAG` and `DEVCAP` to the project dotenv that
# selects an overlay with `COMPOSE_FILE`. Each definition differs from its
# default, and `PRIV` and `CAP` move a finding as well as the shape.
LAYOUT_VARIABLES = {
    "PRIV": ("true", "false"),
    "CAP": ("SYS_ADMIN", "NET_BIND_SERVICE"),
    "INCTAG": ("2.0", "1.0"),
    "DEVTAG": ("2.0", "1.0"),
    "DEVCAP": ("SYS_PTRACE", "NET_BIND_SERVICE"),
}

# Written into a dotenv Compose does not read for the document beside it: the
# included file's own directory when `project_directory:` names another, and
# an overlay's subdirectory. A value distinct from both the definition and the
# default, so a loader that reads the file anyway ships something neither side
# of a correct answer can produce.
LAYOUT_DECOYS = {
    "PRIV": "true",
    "CAP": "NET_ADMIN",
    "INCTAG": "from-file-dir",
    "DEVTAG": "from-overlay-dir",
    "DEVCAP": "NET_ADMIN",
}


@dataclass(frozen=True)
class GeneratedProject:
    """One project directory, plus what the seed meant it to exercise."""

    seed: int
    files: dict[str, str]
    primary: str = "compose.yaml"
    # Built with a reference that cannot be followed: Compose refuses it and
    # compose-lint must report a coverage gap rather than grading a partial
    # stack (A10).
    expects_gap: bool = False
    notes: tuple[str, ...] = field(default=())
    # Symbolic links, relative path -> target spelled relative to the link's
    # own directory, the way `ln -s` would be given it. Every target stays
    # inside the generated tree, which the harness writes as a repository: one
    # leaving it is a fact about the machine the run happens on, which is
    # registered policy rather than a case (ADR-038).
    links: dict[str, str] = field(default_factory=dict)

    def write(self, root: Path) -> Path:
        """Materialise the project under ``root`` and return the primary file."""
        for relative, text in self.files.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        # After the files, so a directory link can be told from a file link by
        # looking at what it points at.
        for relative, pointee in self.links.items():
            link = root / relative
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(
                pointee, target_is_directory=(link.parent / pointee).is_dir()
            )
        return root / self.primary

    def render(self) -> str:
        """Every file, in a form that can be pasted into a bug report."""
        blocks = [f"# seed {self.seed}: {', '.join(self.notes) or 'plain'}"]
        for relative in sorted(self.files):
            blocks.append(f"--- {relative} ---\n{self.files[relative]}")
        for relative in sorted(self.links):
            blocks.append(f"--- {relative} -> {self.links[relative]} ---")
        return "\n".join(blocks)


class _Picker:
    """Draws field values, never repeating one for the same service and field.

    A repeat is not a duplicate the merge deduplicates — for the list fields
    Compose validates for uniqueness it is a project it refuses outright.
    """

    def __init__(self, rng: random.Random) -> None:
        self._rng = rng
        self._used: dict[tuple[str, str], set[str]] = {}

    def value(self, service: str, field_name: str) -> str | None:
        used = self._used.setdefault((service, field_name), set())
        choices = [v for v in FIELD_POOL[field_name] if v not in used]
        if not choices:
            return None
        chosen = self._rng.choice(choices)
        used.add(chosen)
        return chosen


def _service_block(name: str, lines: list[str]) -> str:
    body = f"  {name}:\n"
    for line in lines:
        body += f"    {line}\n"
    return body


def _document(services: str, *, prelude: str = "", epilogue: str = "") -> str:
    return f"{prelude}services:\n{services}{epilogue}"


def _fields_for(
    rng: random.Random,
    picker: _Picker,
    service: str,
    *,
    available: list[str],
    count: int,
    directives: bool,
) -> list[str]:
    """``count`` distinct fields for one service, rendered as YAML lines."""
    lines: list[str] = []
    for field_name in rng.sample(available, min(count, len(available))):
        directive = rng.choice(DIRECTIVES) if directives else ""
        if directive.startswith("!reset"):
            # `!reset` deletes the key; a typed value is schema-invalid.
            lines.append(f"{field_name}: !reset null")
            continue
        value = picker.value(service, field_name)
        if value is None:
            continue
        lines.append(f"{field_name}: {directive}{value}")
    return lines


class _Builder:
    """One seed's decisions, taken in the order the documents are written.

    A class rather than one long function so each structural choice — which
    files exist, where a variable is defined, which document names a service —
    is a named step that reads on its own. The seed is consumed strictly in
    method order, so adding a step at the end leaves every earlier seed's
    project byte-identical.
    """

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.rng = random.Random(seed)  # noqa: S311 - fixtures, not security
        self.picker = _Picker(self.rng)
        self.files: dict[str, str] = {}
        self.notes: list[str] = []
        self.expects_gap = False
        self.names = self.rng.sample(
            SERVICE_NAMES, self.rng.randint(1, len(SERVICE_NAMES))
        )
        self.has_db = "db" in self.names

    # -- helpers ----------------------------------------------------------

    def _pool_for(self, service: str) -> list[str]:
        """The fields drawable for one service.

        ``depends_on: [db]`` needs ``db`` to exist, and a service must not
        depend on itself — Compose refuses the project outright with
        ``dependency cycle detected: db -> db``.
        """
        usable = self.has_db and service != "db"
        return [f for f in FIELD_POOL if f not in _NEEDS_DB or usable]

    def _fields(
        self, service: str, *, count: int, directives: bool, skip: str = ""
    ) -> list[str]:
        available = [f for f in self._pool_for(service) if f != skip]
        return _fields_for(
            self.rng,
            self.picker,
            service,
            available=available,
            count=count,
            directives=directives,
        )

    # -- the documents reached by reference --------------------------------

    def include_targets(self) -> list[str]:
        """The files ``include:`` will point at, written as a side effect."""
        paths: list[str] = []
        if self.rng.random() < 0.55:
            self.notes.append("include")
            for part in ("a", "b")[: self.rng.randint(1, 2)]:
                # Services sharing a name with the base document's, so
                # duplicates across documents are merged rather than rejected
                # (A4), and a relative bind that must resolve against
                # `parts/` rather than the project root (A6).
                body = ""
                for name in self.rng.sample(
                    [*self.names, "cache"], self.rng.randint(1, 2)
                ):
                    body += _service_block(
                        name,
                        [
                            "image: myapp:1.0",
                            f'volumes: ["./{part}-data:/data"]',
                            # `volumes:` is written above; drawing it again
                            # would be a duplicate mapping key, which Compose
                            # refuses to parse.
                            *self._fields(
                                name, count=1, directives=False, skip="volumes"
                            ),
                        ],
                    )
                self.files[f"parts/{part}.yaml"] = _document(body)
                paths.append(f"parts/{part}.yaml")

        if self.rng.random() < 0.3:
            # A document one directory down. Its `./` and `../` references
            # resolve against `sub/`, which is the shape the prefix bug fixed
            # in #788 got wrong.
            self.notes.append("subdir-include")
            self.files["sub/compose.yaml"] = _document(
                _service_block(
                    "sidecar",
                    [
                        "image: myapp:1.0",
                        'volumes: ["./local:/local", "../shared:/shared"]',
                    ],
                )
            )
            paths.append("sub/compose.yaml")

        if paths and self.rng.random() < 0.4:
            # The included file's own `.env`: the project's layers over it, so
            # the project wins where both define a name and this supplies the
            # rest (A8).
            self.notes.append("include-own-env")
            self.files["parts/.env"] = "MOUNTSRC=./from-part\n"
        return paths

    def extends_target(self) -> list[str] | None:
        """The cross-file ``extends:`` base, and the lines that reach it."""
        if self.rng.random() >= 0.4:
            return None
        self.notes.append("extends")
        self.files["base/common.yaml"] = _document(
            _service_block(
                "common",
                [
                    "image: myapp:${APPTAG:-1.0}",
                    'volumes: ["./common-data:/common"]',
                    "cap_add: [SYS_ADMIN]",
                ],
            )
        )
        if self.rng.random() < 0.5:
            # Never read: `extends:` interpolates from the *project's* `.env`
            # only, so this definition must not reach the resolved document
            # (A7). The default written into the reference is what makes "read"
            # and "not read" produce different values, and so observable.
            self.notes.append("extends-own-env")
            self.files["base/.env"] = "APPTAG=from-base\n"
        return ["extends:", "  file: base/common.yaml", "  service: common"]

    # -- the project's own inputs ------------------------------------------

    def interpolation_source(self) -> None:
        if self.rng.random() >= 0.5:
            return
        self.notes.append("project-env")
        defined = self.rng.sample(
            sorted(VARIABLES), self.rng.randint(1, len(VARIABLES))
        )
        self.files[".env"] = "".join(f"{n}={VARIABLES[n][0]}\n" for n in defined)

    def env_file_spelling(self) -> str | None:
        if self.rng.random() >= 0.45:
            return None
        self.notes.append("env-file")
        spelling = self.rng.choice(ENV_FILE_SPELLINGS)
        for target, body in ENV_FILE_BODIES.items():
            if target in spelling:
                self.files[target] = body
        return spelling

    # -- the documents the run is pointed at --------------------------------

    def _prelude(self, include_paths: list[str]) -> str:
        if not include_paths:
            if self.rng.random() < 0.12:
                # Nothing to include, so this seed builds the unresolvable
                # case instead: Compose refuses the project, and compose-lint
                # owes a coverage gap rather than a grade of the part it could
                # see (A10).
                self.notes.append("missing-include")
                self.expects_gap = True
                return "include:\n  - parts/absent.yaml\n"
            return ""
        if self.rng.random() < 0.35:
            # Object form with a `path:` list: inside one entry later beats
            # earlier, the reverse of the list form's precedence (A1/A2).
            listed = "".join(f"      - {p}\n" for p in include_paths)
            return f"include:\n  - path:\n{listed}"
        return "include:\n" + "".join(f"  - {p}\n" for p in include_paths)

    def base_document(
        self,
        include_paths: list[str],
        extends_lines: list[str] | None,
        env_file: str | None,
    ) -> None:
        prelude = self._prelude(include_paths)
        body = ""
        for index, name in enumerate(self.names):
            lines: list[str] = []
            if extends_lines is not None and index == 0:
                lines += extends_lines
            else:
                lines.append(f"image: {self.rng.choice(IMAGES)}")
            if env_file is not None and index == 0:
                lines.append(f"env_file: {env_file}")
            lines += self._fields(name, count=self.rng.randint(1, 4), directives=False)
            body += _service_block(name, lines)

        if len(self.names) > 1 and self.rng.random() < 0.25:
            # In-file `extends:`, service to service in one document (A13).
            # This is the shape that surfaced #800: its base is only complete
            # after `include:` has folded in.
            self.notes.append("in-file-extends")
            body += _service_block(
                "derived", [f"extends:\n      service: {self.names[0]}"]
            )
        self.files["compose.yaml"] = _document(body, prelude=prelude)

    def overlay(self) -> None:
        if self.rng.random() >= 0.6:
            return
        self.notes.append("override")
        body = ""
        for name in self.rng.sample(self.names, self.rng.randint(1, len(self.names))):
            lines = self._fields(name, count=self.rng.randint(1, 3), directives=True)
            if lines:
                body += _service_block(name, lines)
        if body:
            self.files["compose.override.yaml"] = _document(body)

    def build(self) -> GeneratedProject:
        include_paths = self.include_targets()
        extends_lines = self.extends_target()
        self.interpolation_source()
        env_file = self.env_file_spelling()
        self.base_document(include_paths, extends_lines, env_file)
        self.overlay()
        return GeneratedProject(
            seed=self.seed,
            files=self.files,
            expects_gap=self.expects_gap,
            notes=tuple(self.notes),
        )


def _dotenv(values: dict[str, str]) -> str:
    return "".join(f"{name}={value}\n" for name, value in values.items())


class _LayoutBuilder(_Builder):
    """One layout seed: a small project whose interest is where its files sit.

    The tree it writes is a checkout, and the Compose project is either the
    whole of it or ``svc/`` inside it. The run starts at the top, the way CI
    starts in the workspace, so a link from ``svc/`` up into ``shared/`` stays
    inside the tree without staying inside the project directory — which is
    exactly the distinction a loader can get wrong::

        .env                     0-1, only as the target of `svc/.env -> ../.env`
        shared/                  link targets (outside the project when it is svc/)
        shared/incdir/.env       0-1, a `project_directory:` above the project
        svc/store/               link targets inside the project directory
        [svc/]compose.yaml       base, always; 0-1 a link to a document elsewhere
        [svc/].env               0-1, possibly a link; may set COMPOSE_FILE
        [svc/]ops/dev.yaml       0-1 overlay a COMPOSE_FILE list selects
        [svc/]ops/.env           0-1, beside the overlay; never read by Compose
        [svc/]ops/extra.yaml     0-1 link, a further COMPOSE_FILE entry
        [svc/]parts/inc.yaml     0-1 included with `project_directory:`
        [svc/]parts/.env         0-1, the included file's own directory
        [svc/]<chosen>/.env      the dotenv of that project directory
        [svc/]parts/volumes.yaml 0-1 included, declares no services
        [svc/]linked.yaml        0-1 link to an included document
        [svc/]lib                0-1 link to a directory holding one, or
                                 holding the dotenv of a `project_directory:`

    Every link target stays inside the tree, every reference carries a
    default, and no service name repeats across documents, so each seed is a
    project Compose resolves and each disagreement has one cause.
    """

    # Fields a layout document writes itself. Drawing one again for the same
    # service would be a duplicate mapping key or, for the list fields, a
    # repeat Compose validates away as a rejection.
    OWNED = frozenset({"volumes", "cap_add", "privileged"})

    def __init__(self, seed: int) -> None:
        super().__init__(seed)
        self.links: dict[str, str] = {}
        self.entries: list[str] = []
        self.project_env: dict[str, str] = {}
        self.first_volumes = ["./data:/data"]
        self.lib_real: str | None = None
        self.lib_is_project_directory = False
        self.project = self.rng.choice([".", "svc"])
        if self.project != ".":
            self.notes.append("project-in-subdir")

    # -- helpers ----------------------------------------------------------

    def _at(self, relative: str) -> str:
        """``relative`` inside the project directory, spelled from the tree."""
        return posixpath.normpath(posixpath.join(self.project, relative))

    def _store(self, name: str) -> str:
        """Where a link target lives: inside the project, or beside it."""
        if self.project != "." and self.rng.random() < 0.5:
            return f"{self.project}/store/{name}"
        if self.project != "." and "link-leaves-project" not in self.notes:
            self.notes.append("link-leaves-project")
        return f"shared/{name}"

    def _link(self, link: str, target: str) -> None:
        self.links[link] = posixpath.relpath(target, posixpath.dirname(link) or ".")

    def _extra_fields(self, service: str, *, included: bool) -> list[str]:
        """A few drawn fields, none of which the layout writes itself.

        An included document never draws ``depends_on:``: it names a service of
        the including project, which the included one does not declare.
        """
        available = [
            f
            for f in self._pool_for(service)
            if f not in self.OWNED and not (included and f in _NEEDS_DB)
        ]
        return _fields_for(
            self.rng,
            self.picker,
            service,
            available=available,
            count=self.rng.randint(0, 2),
            directives=False,
        )

    # -- the documents reached by reference --------------------------------

    def linked_directory(self) -> None:
        """A directory link: an included document behind it, or a dotenv.

        The second use hands the directory to ``include_with_project_directory``
        as its ``project_directory:``, and is kept apart from the first rather
        than combined with it: a loader that refuses the linked document
        reports a gap, and that gap would hide what it did with the directory.
        """
        if self.rng.random() >= 0.35:
            return
        self.notes.append("linked-dir")
        self.lib_real = self._store("lib")
        self._link(self._at("lib"), self.lib_real)
        if self.rng.random() < 0.4:
            self.lib_is_project_directory = True
            return
        self.files[f"{self.lib_real}/part.yaml"] = _document(
            _service_block(
                "libsvc",
                [
                    "image: myapp:1.0",
                    'volumes: ["./lib-data:/data"]',
                    *self._extra_fields("libsvc", included=True),
                ],
            )
        )
        self.entries.append("  - lib/part.yaml\n")

    def include_with_project_directory(self) -> None:
        """An ``include:`` entry whose relative paths and dotenv live elsewhere.

        Compose resolves every relative path in the entry, and reads the
        dotenv, from ``project_directory:`` — whether that is the included
        file's own directory, one below it, a sibling, the project root, a
        linked directory, or a directory above the project in the same tree.
        The chosen directory's dotenv defines what the service interpolates,
        and a decoy beside the included file defines something else, so
        reading the wrong one is visible.
        """
        if self.lib_is_project_directory:
            chosen = "lib"
        else:
            if self.rng.random() >= 0.5:
                return
            choices = ["parts", "parts/env", "conf", "."]
            if self.project != ".":
                choices.append("../shared/incdir")
            chosen = self.rng.choice(choices)
        inside = chosen in ("parts", "parts/env")
        self.notes.append(
            "include-project-dir-inside" if inside else "include-project-dir-outside"
        )
        defined = sorted(
            self.rng.sample(["PRIV", "CAP", "INCTAG"], self.rng.randint(1, 3))
        )
        values = {name: LAYOUT_VARIABLES[name][0] for name in defined}
        if chosen == ".":
            self.project_env.update(values)
        elif chosen == "lib" and self.lib_real is not None:
            self.notes.append("linked-project-dir")
            self.files[f"{self.lib_real}/.env"] = _dotenv(values)
        else:
            if chosen.startswith(".."):
                # Above the project directory, still inside the tree: the
                # layout a checkout with one shared config directory has. Once
                # a registered policy gap, followed since ADR-038.
                self.notes.append("include-project-dir-leaves-project")
            self.files[self._at(f"{chosen}/.env")] = _dotenv(values)
        if chosen != "parts" and self.rng.random() < 0.5:
            self.notes.append("include-file-dir-decoy")
            self.files[self._at("parts/.env")] = _dotenv(
                {name: LAYOUT_DECOYS[name] for name in ("PRIV", "CAP", "INCTAG")}
            )
        self.files[self._at("parts/inc.yaml")] = _document(
            _service_block(
                "inc",
                [
                    "image: myapp:${INCTAG:-1.0}",
                    "privileged: ${PRIV:-false}",
                    'cap_add: ["${CAP:-NET_BIND_SERVICE}"]',
                    'volumes: ["./inc-data:/data"]',
                    *self._extra_fields("inc", included=True),
                ],
            )
        )
        self.entries.append(
            f"  - path: parts/inc.yaml\n    project_directory: {chosen}\n"
        )

    def include_without_services(self) -> None:
        """An included document that contributes only a top-level key."""
        if self.rng.random() >= 0.35:
            return
        self.notes.append("include-no-services")
        self.files[self._at("parts/volumes.yaml")] = "volumes:\n  cache: {}\n"
        self.entries.append("  - parts/volumes.yaml\n")
        if self.rng.random() < 0.5:
            # The named volume is declared nowhere else, so the project only
            # resolves if the include was read.
            self.first_volumes.append("cache:/cache")

    def linked_include(self) -> None:
        """An ``include:`` target that is a link to a document elsewhere."""
        if self.rng.random() >= 0.35:
            return
        self.notes.append("linked-include")
        real = self._store("part.yaml")
        self.files[real] = _document(
            _service_block(
                "linked",
                [
                    "image: myapp:1.0",
                    'volumes: ["./linked-data:/data"]',
                    *self._extra_fields("linked", included=True),
                ],
            )
        )
        self._link(self._at("linked.yaml"), real)
        self.entries.append("  - linked.yaml\n")

    # -- the project's own inputs ------------------------------------------

    def compose_file_selection(self) -> None:
        """``COMPOSE_FILE`` naming the base and an overlay one directory down.

        Compose resolves every file in the list against the *first* file's
        project directory — its relative bind sources and its interpolation
        both — so the overlay's ``./dev-data`` mounts beside ``compose.yaml``
        and its ``${DEVTAG}`` comes from the project dotenv, not from one
        beside the overlay.
        """
        if self.rng.random() >= 0.45:
            return
        self.notes.append("compose-file")
        first = self.names[0]
        defined = sorted(self.rng.sample(["DEVTAG", "DEVCAP"], self.rng.randint(1, 2)))
        self.project_env.update({n: LAYOUT_VARIABLES[n][0] for n in defined})
        self.files[self._at("ops/dev.yaml")] = _document(
            _service_block(
                first,
                [
                    "image: myapp:${DEVTAG:-1.0}",
                    'cap_add: ["${DEVCAP:-NET_BIND_SERVICE}"]',
                    'volumes: ["./dev-data:/dev-data"]',
                ],
            )
        )
        selected = ["compose.yaml", "ops/dev.yaml"]
        if self.rng.random() < 0.5:
            self.notes.append("overlay-own-env")
            self.files[self._at("ops/.env")] = _dotenv(
                {name: LAYOUT_DECOYS[name] for name in ("DEVTAG", "DEVCAP")}
            )
        if self.rng.random() < 0.5:
            self.notes.append("linked-compose-file-entry")
            real = self._store("extra.yaml")
            self.files[real] = _document(
                _service_block(
                    first,
                    ["privileged: true", 'volumes: ["./extra-data:/extra-data"]'],
                )
            )
            self._link(self._at("ops/extra.yaml"), real)
            selected.append("ops/extra.yaml")
        # First in the file so a reader sees the selection before the values.
        self.project_env = {"COMPOSE_FILE": ":".join(selected), **self.project_env}

    def project_dotenv(self) -> None:
        """The project's dotenv, written in place or as a link to one elsewhere."""
        if self.rng.random() < 0.5:
            self.project_env["APPTAG"] = VARIABLES["APPTAG"][0]
        linked = self.rng.random() < 0.4
        if linked and not self.project_env:
            self.project_env["APPTAG"] = VARIABLES["APPTAG"][0]
        if not self.project_env:
            return
        text = _dotenv(self.project_env)
        where = self._at(".env")
        if not linked:
            self.files[where] = text
            return
        self.notes.append("linked-env")
        if self.project != "." and self.rng.random() < 0.5:
            # `svc/.env -> ../.env`: one dotenv at the top of a checkout,
            # shared into a service directory.
            real = ".env"
            if "link-leaves-project" not in self.notes:
                self.notes.append("link-leaves-project")
        else:
            real = self._store("project.env")
        self.files[real] = text
        self._link(where, real)

    # -- the document the run is pointed at ---------------------------------

    def layout_base(self) -> None:
        body = ""
        for index, name in enumerate(self.names):
            if index == 0:
                listed = ", ".join(f'"{v}"' for v in self.first_volumes)
                lines = ["image: myapp:${APPTAG:-1.0}", f"volumes: [{listed}]"]
            else:
                lines = [f"image: {self.rng.choice(IMAGES)}"]
            lines += self._extra_fields(name, included=False)
            body += _service_block(name, lines)
        self.rng.shuffle(self.entries)
        prelude = "include:\n" + "".join(self.entries) if self.entries else ""
        text = _document(body, prelude=prelude)
        where = self._at("compose.yaml")
        if self.rng.random() < 0.3:
            self.notes.append("linked-compose")
            real = self._store("stack.yaml")
            self.files[real] = text
            self._link(where, real)
        else:
            self.files[where] = text

    def build(self) -> GeneratedProject:
        self.linked_directory()
        self.include_with_project_directory()
        self.include_without_services()
        self.linked_include()
        self.compose_file_selection()
        self.project_dotenv()
        self.layout_base()
        return GeneratedProject(
            seed=self.seed,
            files=self.files,
            primary=self._at("compose.yaml"),
            notes=tuple(self.notes),
            links=self.links,
        )


# Seeds at or above this build the second layout family (`_ChainBuilder`).
LAYOUT2_SEED_BASE = 200_000


class _ChainBuilder(_LayoutBuilder):
    """The second layout family: chains and selections the first one never builds.

    A range of its own so every first-family seed keeps its bytes. Each step
    is drawn independently, and every shape was checked against Compose 5.5.0
    before it was encoded here::

        [svc/]parts/outer.yaml      0-1 included; itself includes inner/inner.yaml
        [svc/]parts/inner/.env      0-1, possibly a link; the inner file's own
        [svc/]bases/base.yaml       0-1, an `extends: {file:}` target, maybe a link
        [svc/]app.env               0-1 `env_file:` target, maybe a link
        [svc/]compose.override.yaml 0-1, beside a COMPOSE_FILE that skips it
        [svc/]gone.yaml / gone.env  0-1 dangling links

    A dangling `include:` or `extends:` target is refused by Compose, so the
    seed expects a gap; a dangling optional `env_file:` or project dotenv is
    accepted by both. A dangling *required* `env_file:` is not built: Compose
    refuses it while compose-lint reports a note, by design (J2/K8).
    """

    def __init__(self, seed: int) -> None:
        super().__init__(seed)
        self.first_lines: list[str] = []

    def nested_include(self) -> None:
        """An included file that includes another, whose own dotenv it reads."""
        if self.rng.random() >= 0.4:
            return
        self.notes.append("nested-include")
        values = {"INCTAG": LAYOUT_VARIABLES["INCTAG"][0]}
        if self.rng.random() < 0.5:
            values["CAP"] = LAYOUT_VARIABLES["CAP"][0]
        text = _dotenv(values)
        where = self._at("parts/inner/.env")
        if self.rng.random() < 0.4:
            self.notes.append("nested-include-linked-env")
            real = self._store("inner.env")
            self.files[real] = text
            self._link(where, real)
        else:
            self.files[where] = text
        self.files[self._at("parts/inner/inner.yaml")] = _document(
            _service_block(
                "inner",
                [
                    "image: myapp:${INCTAG:-1.0}",
                    'cap_add: ["${CAP:-NET_BIND_SERVICE}"]',
                    'volumes: ["./inner-data:/data"]',
                ],
            )
        )
        self.files[self._at("parts/outer.yaml")] = _document(
            _service_block("outer", ["image: myapp:1.0"]),
            prelude="include:\n  - inner/inner.yaml\n",
        )
        self.entries.append("  - parts/outer.yaml\n")

    def _has(self, key: str) -> bool:
        return any(line.startswith(f"{key}:") for line in self.first_lines)

    def linked_extends(self) -> None:
        """A cross-file ``extends:`` whose file is a link to a base elsewhere."""
        if self.rng.random() >= 0.4 or self._has("extends"):
            return
        self.notes.append("linked-extends")
        real = self._store("base.yaml")
        self.files[real] = _document(
            _service_block(
                "base",
                ["image: myapp:1.0", "privileged: true", 'volumes: ["./b:/b"]'],
            )
        )
        self._link(self._at("bases/base.yaml"), real)
        self.first_lines.append("extends: {file: bases/base.yaml, service: base}")

    def linked_env_file(self) -> None:
        """An ``env_file:`` target that is a link to a file elsewhere."""
        if self.rng.random() >= 0.4 or self._has("env_file"):
            return
        self.notes.append("linked-env-file")
        real = self._store("app.env")
        self.files[real] = "AWS_SECRET_ACCESS_KEY=placeholder-not-a-real-key\n"
        self._link(self._at("app.env"), real)
        self.first_lines.append("env_file: app.env")

    def separator_selection(self) -> None:
        """``COMPOSE_FILE`` split by ``COMPOSE_PATH_SEPARATOR``, override skipped.

        Compose applies ``compose.override.yaml`` only when no file list is
        given, so an override beside a ``COMPOSE_FILE`` that leaves it out
        contributes nothing; its ``privileged: true`` must not be graded.
        """
        if self.rng.random() >= 0.4:
            return
        self.notes.append("path-separator")
        first = self.names[0]
        separator = self.rng.choice([",", ";", "|"])
        self.files[self._at("ops/dev.yaml")] = _document(
            _service_block(first, ['cap_add: ["SYS_PTRACE"]'])
        )
        self.project_env = {
            "COMPOSE_PATH_SEPARATOR": separator,
            "COMPOSE_FILE": separator.join(["compose.yaml", "ops/dev.yaml"]),
            **self.project_env,
        }
        if self.rng.random() < 0.6:
            self.notes.append("override-not-selected")
            self.files[self._at("compose.override.yaml")] = _document(
                _service_block(first, ["privileged: true"])
            )

    def dangling_links(self) -> None:
        """A link with nothing behind it, in a place each side treats alike."""
        if self.rng.random() >= 0.3:
            return
        kind = self.rng.choice(["include", "extends", "optional-env-file"])
        self.notes.append(f"dangling-{kind}")
        if kind == "include":
            self._link(self._at("gone.yaml"), self._at("missing.yaml"))
            self.entries.append("  - gone.yaml\n")
            self.expects_gap = True
        elif kind == "extends":
            self._link(self._at("gone.yaml"), self._at("missing.yaml"))
            self.first_lines.append("extends: {file: gone.yaml, service: base}")
            self.expects_gap = True
        else:
            self._link(self._at("gone.env"), self._at("missing.env"))
            self.first_lines.append("env_file: [{path: gone.env, required: false}]")

    def layout_base(self) -> None:
        body = ""
        for index, name in enumerate(self.names):
            if index == 0:
                lines = [
                    "image: myapp:${APPTAG:-1.0}",
                    'volumes: ["./data:/data"]',
                    *self.first_lines,
                ]
            else:
                lines = [f"image: {self.rng.choice(IMAGES)}"]
            body += _service_block(name, lines)
        self.rng.shuffle(self.entries)
        prelude = "include:\n" + "".join(self.entries) if self.entries else ""
        self.files[self._at("compose.yaml")] = _document(body, prelude=prelude)

    def build(self) -> GeneratedProject:
        # Dangling first: it claims its key, so a later step cannot write a
        # second `extends:` or `env_file:` over the one the gap depends on.
        self.dangling_links()
        self.nested_include()
        self.linked_extends()
        self.linked_env_file()
        self.separator_selection()
        self.project_dotenv()
        self.layout_base()
        return GeneratedProject(
            seed=self.seed,
            files=self.files,
            primary=self._at("compose.yaml"),
            expects_gap=self.expects_gap,
            notes=tuple(self.notes),
            links=self.links,
        )


def generate(seed: int) -> GeneratedProject:
    """Build the project for ``seed``. Same seed, same bytes, always.

    Seeds from ``LAYOUT_SEED_BASE`` build the layout family, and from
    ``LAYOUT2_SEED_BASE`` the second one; every seed below each builds exactly
    what it always has.
    """
    if seed >= LAYOUT2_SEED_BASE:
        return _ChainBuilder(seed).build()
    if seed >= LAYOUT_SEED_BASE:
        return _LayoutBuilder(seed).build()
    return _Builder(seed).build()
