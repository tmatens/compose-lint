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
"""

from __future__ import annotations

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

    def write(self, root: Path) -> Path:
        """Materialise the project under ``root`` and return the primary file."""
        for relative, text in self.files.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        return root / self.primary

    def render(self) -> str:
        """Every file, in a form that can be pasted into a bug report."""
        blocks = [f"# seed {self.seed}: {', '.join(self.notes) or 'plain'}"]
        for relative in sorted(self.files):
            blocks.append(f"--- {relative} ---\n{self.files[relative]}")
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


def generate(seed: int) -> GeneratedProject:
    """Build the project for ``seed``. Same seed, same bytes, always."""
    return _Builder(seed).build()
