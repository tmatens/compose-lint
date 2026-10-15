"""CL-0020: Credential-shaped environment keys with literal values."""

from __future__ import annotations

import re
import shlex
from typing import TYPE_CHECKING, Any

from compose_lint._output import inline
from compose_lint._scalar import as_scalar_text
from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._interpolation import ships_no_literal

if TYPE_CHECKING:
    from collections.abc import Iterator

    from compose_lint._service_env import EnvFileKey

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-12-utilize-docker-secrets-for-sensitive-data-management"
)

COMPOSE_SECRETS_REF = "https://docs.docker.com/reference/compose-file/secrets/"

# Substring matches (case-insensitive on the upper-cased key).
# PASSPHRASE and ENCRYPTION_KEY are unambiguously secret material (issue #279
# R3). A *generic* `_KEY` suffix is deliberately not added: it false-positives on
# non-secret names like LICENSE_KEY / PUBLIC_KEY / IDEMPOTENCY_KEY, against this
# project's "no unactionable findings" principle. GPG_KEY is likewise omitted —
# it commonly names a key *id*/fingerprint (public), not key material.
_SUBSTRING_PATTERNS = (
    "PASSWORD",
    "PASSPHRASE",
    "TOKEN",
    "SECRET",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "SECRET_KEY",
    "ENCRYPTION_KEY",
    "CREDENTIAL",
)

# Suffix matches. Anchored as suffix to avoid noisy substring matches
# (e.g. raw "PASS" hits Passport.js naming like EGG_PASSPORT_GITHUB_CLIENT_ID).
_SUFFIX_PATTERNS = (
    "_PASS",
    "_PWD",
    "PASSWD",
    "_SALT",
    "_DSN",
)

# Exemption: keys whose name encodes a *file path to* a secret (the
# documented mitigation), not the secret itself.
_FILE_SUFFIX = "_FILE"

# Exemption: keys that contain a credential-shaped substring but are
# documented boolean toggles (image-startup behavior, not credentials).
_FLAG_KEY_FRAGMENTS = (
    "ALLOW_EMPTY_",
    "RANDOM_",
)

# Exemption: literal values that are clearly boolean / numeric toggles.
# Compared case-insensitively against the trimmed value.
_FLAG_VALUES = frozenset({"yes", "no", "true", "false", "0", "1", "on", "off"})

# Exemption: keys that carry a credential-shaped substring but name a
# *quantity* about the credential — a lifetime, size, limit or policy knob —
# rather than the credential itself (issue #561):
# `JWT_ACCESS_TOKEN_EXPIRE_MINUTES: 30` is a duration, not a token.
#
# Deliberately conjunctive with _QUANTITY_VALUE_RE below: a knob-shaped key is
# exempt only when its value is *also* a bare quantity. Exempting on the value
# alone would revert issue #277 F7 (`DB_PASSWORD: 12345678` must keep firing —
# a weak numeric password is the finding), and exempting on the key alone would
# skip `AUTH_TOKENS: your_token_here`. Fragments are corpus-derived: over the
# 5,417-file corpus this pair removes 30 findings, every one a knob, and keeps
# all 40 numeric-valued credentials.
_QUANTITY_KEY_FRAGMENTS = (
    # Lifetime / rotation.
    "TTL",
    "TIMEOUT",
    "EXPIRE",
    "EXPIRY",
    "EXPIRATION",
    "VALIDITY",
    "LIFETIME",
    "MAX_AGE",
    "MAXAGE",
    "ROTATION",
    "INTERVAL",
    "RETENTION",
    "DURATION",
    # Explicit time units.
    "_SECONDS",
    "_SECS",
    "_MINUTES",
    "_MINS",
    "_HOURS",
    "_DAYS",
    "_MS",
    # Size / length / limit / policy knobs.
    "MIN_LENGTH",
    "MINLENGTH",
    "MAX_LENGTH",
    "MAXLENGTH",
    "MIN_CHAR",
    "MINCHAR",
    "_LIMIT",
    "_SIZE",
    "REQUIREMENTS",
    "POLICY",
    "_BONUS",
    # Plural TOKENS counts an LLM's units of text, not credentials
    # (OPENAI_MAX_TOKENS, SUMMARY_MAX_TOKENS).
    "TOKENS",
    "ROUNDS",
    "ITERATIONS",
    "_HISTORY",
    "_ATTEMPTS",
    "_RETRIES",
    "_LENGTH",
    "_STRENGTH",
)

# Suffix-anchored so PASSPORT_SECRET is not read as a port number.
_QUANTITY_KEY_SUFFIXES = ("_PORT", "_COST")

# A bare number, optionally carrying a time unit (`30`, `1.5`, `900s`, `30m`,
# `500ms`). Anything else — a placeholder, a filename, a rate like `5/hour` —
# is not a quantity and the rule still fires.
_QUANTITY_VALUE_RE = re.compile(r"^\d+(\.\d+)?(ms|s|m|h|d)?$", re.IGNORECASE)

# ---- The argument-list surfaces (issue #1077) --------------------------------
#
# `command:`, `entrypoint:` and `healthcheck.test` reach the same metadata as
# the environment does: `docker inspect` returns `Config.Cmd`,
# `Config.Entrypoint` and `Config.Healthcheck` beside `Config.Env`, and
# `/proc/<pid>/cmdline` is readable by every uid in the container where
# `environ` is readable only by the process's own. The same key-shaped test is
# applied to each token that names a value: `--password hunter2`,
# `--admin-password=hunter2`, `PGPASSWORD=hunter2 psql`.

# Flag names the key list above does not reach. `--requirepass` is the single
# largest shape in the corpus (83 of 148 services) and has neither a PASSWORD
# substring nor a `_PASS` suffix; `--masterauth` is its replica-side twin.
_ARGV_FLAG_WORDS = ("REQUIREPASS", "MASTERAUTH")

# mysql-family clients take the password glued to `-p` (`-phunter2`); the
# port is `-P`. The shape is only read when one of these binaries is in the
# token list, because a bare `-p` means something else to every other program.
_MYSQL_BINARIES = frozenset(
    {
        "mysql",
        "mysqladmin",
        "mysqlcheck",
        "mysqldump",
        "mysqlsh",
        "mysqlshow",
        "mariadb",
        "mariadb-admin",
        "mariadb-check",
        "mariadb-dump",
    }
)

# Two value shapes that are literal under `environment:` but are not a shipped
# credential in an argument list. `$$VAR` is a literal dollar in the
# environment (`pa$$w0rd`, issue #502), but Compose hands `$$VAR` to the
# container as `$VAR`, which the shell expands at runtime from the environment
# -- a reference by another grammar. A value that is a path is the fix pattern
# (`--password-file /run/secrets/pw`), the `_FILE` exemption spelled as an
# argument. Measured over the corpus: 64 of 216 first-pass hits were one of
# these two, every one of them a file that had done the right thing.
_ARGV_PATH_PREFIXES = ("/", "./", "../", "~/")

# A token that assigns a variable in a shell payload: `PGPASSWORD=x psql`.
_ARGV_ASSIGNMENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
# A flag, with or without an inline `=value`. Single-dash long options
# (`-rpcpassword=x`) are included; a lone `-` or `--` is not.
_ARGV_FLAG_RE = re.compile(r"^-{1,2}([A-Za-z][A-Za-z0-9_.-]*)(?:=(.*))?$", re.DOTALL)
# mysql's glued password: `-p` followed by anything but another dash.
_ARGV_MYSQL_PASSWORD_RE = re.compile(r"^-p([^-\s].*)$", re.DOTALL)
# Tokens whose *next* token is a shell string to be split again.
_ARGV_SHELL_FLAGS = frozenset({"-c"})
_HEALTHCHECK_SHELL = "CMD-SHELL"


def _matches_credential_pattern(key_upper: str) -> bool:
    """Return True if the key name matches a credential-shaped pattern."""
    if any(substr in key_upper for substr in _SUBSTRING_PATTERNS):
        return True
    return any(key_upper.endswith(suffix) for suffix in _SUFFIX_PATTERNS)


def _is_exempt_key(key_upper: str) -> bool:
    """Return True if the key matches a structural exemption."""
    if key_upper.endswith(_FILE_SUFFIX):
        return True
    return any(fragment in key_upper for fragment in _FLAG_KEY_FRAGMENTS)


def _is_quantity_knob(key_upper: str, raw: Any) -> bool:
    """Return True for a quantity-shaped key holding a quantity-shaped value.

    Both halves are required: `PASSWORD_TTL: 900` is a lifetime, while
    `DB_PASSWORD: 12345678` (no knob word) and `AUTH_TOKENS: your_token_here`
    (not a quantity) are credentials and keep firing. See issue #561.
    """
    if isinstance(raw, bool):
        return False
    text = as_scalar_text(raw) if isinstance(raw, (int, float)) else raw
    if not isinstance(text, str):
        return False
    if not _QUANTITY_VALUE_RE.match(text.strip()):
        return False
    if any(fragment in key_upper for fragment in _QUANTITY_KEY_FRAGMENTS):
        return True
    return any(key_upper.endswith(suffix) for suffix in _QUANTITY_KEY_SUFFIXES)


def _is_literal_credential_value(raw: Any) -> bool:
    """Decide whether a value should be treated as a literal credential.

    Skips:
    - Booleans (a YAML `yes`/`no`/`true`/`false` toggle, not a credential)
    - Non-string, non-numeric, and empty-string values (env unset)
    - Boolean / numeric toggles like "yes", "true", "1"
    - Any value Compose ships as empty — one made only of references with
      no default (`${PW}`, `"${PW}"`). The credential is sourced from process
      env, the documented secure-ish pattern. A value that merely *contains* a
      reference is not skipped: `hunter2$X` ships the literal `hunter2`, and a
      *defaulted* reference ships its default, so `${PW:-hunter2}` is a
      hardcoded credential (the parser resolves it before this rule runs).
      Compose's escaped literal dollar (`$$`) is not a substitution, so
      `pa$$w0rd` still counts as literal (issue #502).

    An unquoted numeric value (`DB_PASSWORD: 12345678`) decodes to a Python
    int/float; it is coerced to its string form so a numeric literal secret is
    still flagged (issue #277 F7). Booleans subclass int, so they are checked
    first to preserve the toggle exemption.
    """
    if isinstance(raw, bool):
        return False
    if isinstance(raw, (int, float)):
        text = as_scalar_text(raw)
        if text is None:
            return False
        raw = text
    if not isinstance(raw, str):
        return False
    if raw == "":
        return False
    if raw.strip().lower() in _FLAG_VALUES:
        return False
    return not ships_no_literal(raw)


def _is_shell_reference_or_path(value: str) -> bool:
    """A value the shell will expand, or a path to where the secret lives."""
    return "$$" in value or value.startswith(_ARGV_PATH_PREFIXES)


def _is_credential_name(name_upper: str, value: str) -> bool:
    """The key-shaped test, as `check` applies it to an env key."""
    if name_upper in _ARGV_FLAG_WORDS:
        return True
    if not _matches_credential_pattern(name_upper):
        return False
    if _is_exempt_key(name_upper):
        return False
    return not _is_quantity_knob(name_upper, value)


def _split_shell(text: str) -> list[str]:
    """Split a shell string the way the shell would; fall back on bad quoting."""
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _argv_tokens(raw: Any, *, healthcheck: bool = False) -> list[str]:
    """Flatten a `command:`/`entrypoint:`/`healthcheck.test` value to tokens.

    A string is a shell line and is split as one. A list is taken as written,
    except that the payload after a `-c` (`sh -c "..."`) or after
    `CMD-SHELL` is itself a shell line and is split again, so the credential
    inside `sh -c "PGPASSWORD=x psql"` is reached either way.
    """
    items: list[str] = []
    if isinstance(raw, str):
        items = _split_shell(raw)
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, bool):
                continue
            text = as_scalar_text(item) if isinstance(item, (int, float)) else item
            if isinstance(text, str):
                items.append(text)
    else:
        return []
    tokens: list[str] = []
    for i, token in enumerate(items):
        previous = items[i - 1] if i else None
        is_payload = previous in _ARGV_SHELL_FLAGS or (
            healthcheck and i == 1 and previous == _HEALTHCHECK_SHELL
        )
        if is_payload:
            tokens.extend(_split_shell(token))
        else:
            tokens.append(token)
    return tokens


def _scan_argv(tokens: list[str]) -> Iterator[str]:
    """Yield the name, as written, of each credential-shaped literal argument.

    Three shapes: a `KEY=value` assignment, a flag taking a value inline or as
    the next token, and mysql's glued `-p<value>`. The value itself is never
    yielded -- only the name the finding reports.
    """
    binaries = {token.rsplit("/", 1)[-1] for token in tokens}
    mysql_present = bool(binaries & _MYSQL_BINARIES)
    for i, token in enumerate(tokens):
        assignment = _ARGV_ASSIGNMENT_RE.match(token)
        if assignment:
            key, assigned = assignment.groups()
            if _is_credential_name(key.upper(), assigned) and _is_literal_argument(
                assigned
            ):
                yield key
            continue
        glued = _ARGV_MYSQL_PASSWORD_RE.match(token)
        if glued and mysql_present:
            if _is_literal_argument(glued.group(1)):
                yield "-p"
            continue
        flag = _ARGV_FLAG_RE.match(token)
        if flag:
            name, inline_value = flag.groups()
            name_upper = name.upper().replace("-", "_").replace(".", "_")
            value: str | None = inline_value
            if value is None:
                following = tokens[i + 1] if i + 1 < len(tokens) else None
                if following and not following.startswith("-"):
                    value = following
            if value is None:
                continue
            if _is_credential_name(name_upper, value) and _is_literal_argument(value):
                yield token.split("=", 1)[0]
            continue


def _is_literal_argument(value: str) -> bool:
    """`_is_literal_credential_value`, minus what the shell or a path supplies."""
    if _is_shell_reference_or_path(value):
        return False
    return _is_literal_credential_value(value)


def _iter_argv(service_config: dict[str, Any]) -> Iterator[tuple[str, list[str]]]:
    """Yield (location, tokens) for each argument-list surface a service sets."""
    for key in ("command", "entrypoint"):
        if key in service_config:
            yield key, _argv_tokens(service_config[key])
    healthcheck = service_config.get("healthcheck")
    if (
        isinstance(healthcheck, dict)
        and healthcheck.get("disable") is not True
        and "test" in healthcheck
    ):
        yield "healthcheck.test", _argv_tokens(healthcheck["test"], healthcheck=True)


def _iter_env(env_block: Any) -> Iterator[tuple[str, Any, int | None]]:
    """Yield (key, raw_value, list_index_or_None) from a service's env block."""
    if isinstance(env_block, dict):
        for key, value in env_block.items():
            if isinstance(key, str):
                yield key, value, None
        return
    if isinstance(env_block, list):
        for i, item in enumerate(env_block):
            if isinstance(item, str):
                if "=" in item:
                    key, value = item.split("=", 1)
                    yield key, value, i
                # bare "KEY" form sources value from process env — skip
            elif isinstance(item, dict):
                for key, value in item.items():
                    if isinstance(key, str):
                        yield key, value, i


@register_rule
class CredentialEnvKeysRule(BaseRule):
    """Detects credential-shaped env keys with literal values."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0020",
            name="Credential-shaped env key with literal value",
            description=(
                "Environment variables whose key name matches a credential "
                "convention (PASSWORD, PASSPHRASE, TOKEN, SECRET, API_KEY, "
                "ACCESS_KEY, PRIVATE_KEY, ENCRYPTION_KEY, CREDENTIAL, *_PASS, "
                "*_PWD, PASSWD, *_SALT, *_DSN) and whose value is a non-empty "
                "literal string, in `environment:`, an `env_file:`, or as a "
                "flag or assignment in `command:`, `entrypoint:` or "
                "`healthcheck.test` (`--requirepass hunter2`, "
                "`PGPASSWORD=hunter2 psql`, mysql's `-phunter2`). The "
                "credential is exposed via `docker inspect`, "
                "`/proc/<pid>/environ` or `/proc/<pid>/cmdline`, `docker "
                "compose config`, process listings, and CI logs. Compose's "
                "`secrets:` primitive "
                "materializes credentials as files under /run/secrets/ and "
                "does not appear in any of those surfaces. A key naming a "
                "quantity about the credential (a lifetime, size, limit or "
                "policy knob) whose value is also a bare quantity is exempt: "
                "TOKEN_TTL_MINUTES: 30 is a duration, not a token. This rule "
                "is a naming-convention check, not a content scanner — it "
                "does not inspect the value for secret-like entropy or "
                "formats."
            ),
            severity=Severity.HIGH,
            references=[OWASP_REF, COMPOSE_SECRETS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        yield from self._check_argv(service_name, service_config, lines)

        env = service_config.get("environment")
        if env is None:
            return

        for key, raw, list_index in _iter_env(env):
            key_upper = key.upper()
            if not _matches_credential_pattern(key_upper):
                continue
            if _is_exempt_key(key_upper):
                continue
            if _is_quantity_knob(key_upper, raw):
                continue
            if not _is_literal_credential_value(raw):
                continue

            line = self._lookup_line(service_name, key, list_index, lines)
            yield Finding(
                rule_id="CL-0020",
                severity=Severity.HIGH,
                service=service_name,
                evidence=key,
                message=(
                    f"Service has credential-shaped env key '{key}' with a "
                    "literal value. Env vars are exposed via `docker inspect`, "
                    "`/proc/<pid>/environ`, `docker compose config`, process "
                    "listings, and CI logs — any process or operator with "
                    "daemon access can read them."
                ),
                line=line,
                fix=(
                    f"Move '{inline(key)}' to Compose's `secrets:` primitive. If the "
                    "image supports the `*_FILE` convention (Postgres, MySQL, "
                    "MariaDB, MinIO, etc.), set "
                    f"`{inline(key)}_FILE: /run/secrets/<name>` and declare the "
                    "secret under the top-level `secrets:` block sourced from "
                    "a gitignored file or `external: true`. Otherwise, have "
                    "the entrypoint read the secret file at startup and "
                    "export the value into the workload's environment."
                ),
                references=[OWASP_REF, COMPOSE_SECRETS_REF],
            )

    def _check_argv(
        self,
        service_name: str,
        service_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        """Grade `command:`, `entrypoint:` and `healthcheck.test` (issue #1077).

        The same key-shaped test as `check`, applied to the tokens that name a
        value in an argument list. One finding per name per location: a flag
        repeated on one line is one thing to move, not two.
        """
        for location, tokens in _iter_argv(service_config):
            seen: set[str] = set()
            for name in _scan_argv(tokens):
                if name in seen:
                    continue
                seen.add(name)
                yield Finding(
                    rule_id="CL-0020",
                    severity=Severity.HIGH,
                    service=service_name,
                    evidence=f"{location}:{name}",
                    message=(
                        f"Service passes credential-shaped argument '{name}' "
                        f"with a literal value in `{location}`. The argument "
                        "list is exposed via `docker inspect`, "
                        "`/proc/<pid>/cmdline` (readable by every user in the "
                        "container), `docker compose config`, process "
                        "listings, and CI logs — any process or operator with "
                        "daemon access can read it."
                    ),
                    line=lines.get(f"services.{service_name}.{location}"),
                    fix=(
                        f"Declare the value behind '{inline(name)}' under "
                        "Compose's `secrets:` primitive and read the file at "
                        "runtime instead of writing the literal into "
                        f"`{inline(location)}`: pass a path if the program takes one "
                        "(`--password-file /run/secrets/<name>`), or read it in "
                        "a shell line as `$$(cat /run/secrets/<name>)` — the "
                        "doubled `$` keeps Compose from interpolating it, so the "
                        "container's shell runs the substitution. Declare the "
                        "secret under the top-level `secrets:` block sourced "
                        "from a gitignored file or `external: true`."
                    ),
                    references=[OWASP_REF, COMPOSE_SECRETS_REF],
                )

    def check_env_file_keys(
        self,
        service_name: str,
        keys: tuple[EnvFileKey, ...],
        service_config: dict[str, Any],
    ) -> Iterator[Finding]:
        """Grade the keys an ``env_file:`` contributes, on the same tests.

        Every gate above applies unchanged, because the question is the same
        one: a credential-shaped key holding a literal value in a container's
        process environment. Only the route differs, and ADR-027's whole
        argument is that the route is not what the rule grades.

        The value never reaches the output. ``evidence`` is the key, the
        message names the key and the file, and ``source_is_document=False``
        stops the text formatter excerpting the line the key was written on --
        which is the one place a value could otherwise have been printed.
        """
        del service_config  # shadowed keys are removed before this is called
        for entry in keys:
            key_upper = entry.key.upper()
            if not _matches_credential_pattern(key_upper):
                continue
            if _is_exempt_key(key_upper):
                continue
            if _is_quantity_knob(key_upper, entry.value):
                continue
            if not _is_literal_credential_value(entry.value):
                continue

            yield Finding(
                rule_id="CL-0020",
                severity=Severity.HIGH,
                service=service_name,
                evidence=entry.key,
                message=(
                    f"Service reads credential-shaped env key '{entry.key}' "
                    f"with a literal value from '{entry.source_file}'. "
                    "Compose merges that file into the container's process "
                    "environment, where it is exposed via `docker inspect`, "
                    "`/proc/<pid>/environ`, `docker compose config`, process "
                    "listings, and CI logs — any process or operator with "
                    "daemon access can read them."
                ),
                line=entry.line or None,
                source_file=entry.path or entry.source_file,
                source_is_document=False,
                fix=(
                    f"Move '{inline(entry.key)}' out of "
                    f"'{inline(entry.source_file)}' and into "
                    "Compose's `secrets:` primitive. If the image supports the "
                    "`*_FILE` convention (Postgres, MySQL, MariaDB, MinIO, "
                    f"etc.), set `{inline(entry.key)}_FILE: /run/secrets/<name>` and "
                    "declare the secret under the top-level `secrets:` block "
                    "sourced from a gitignored file or `external: true`. "
                    "Otherwise, have the entrypoint read the secret file at "
                    "startup and export the value into the workload's "
                    "environment."
                ),
                references=[OWASP_REF, COMPOSE_SECRETS_REF],
            )

    @staticmethod
    def _lookup_line(
        service_name: str,
        key: str,
        list_index: int | None,
        lines: dict[str, int],
    ) -> int | None:
        env_path = f"services.{service_name}.environment"
        if list_index is not None:
            return lines.get(f"{env_path}[{list_index}]") or lines.get(env_path)
        return lines.get(f"{env_path}.{key}") or lines.get(env_path)
