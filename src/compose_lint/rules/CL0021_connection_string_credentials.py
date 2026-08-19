"""CL-0021: Credentials embedded in connection-string env values."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from compose_lint._limits import MAX_SCAN_LEN
from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._interpolation import ships_no_literal

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-12-utilize-docker-secrets-for-sensitive-data-management"
)

COMPOSE_SECRETS_REF = "https://docs.docker.com/reference/compose-file/secrets/"

RFC3986_REF = "https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.1"

# Match the `scheme://` prefix of a URL in any env value, per RFC 3986 §3.1
# (alpha + alnum/+/-/.). The quantifier is bounded: unbounded, the engine
# retries the scheme from each of n offsets and rescans the tail from each —
# O(n^2) on a value shaped like `scheme://<many>:<many>` (20 KB took 1.1 s,
# 40 KB took 4.1 s). The ceiling is far above any real scheme, which is a
# handful of characters.
_URI_SCHEME_RE = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]{0,63})://")

# Ceiling on either half of the userinfo. A userinfo half in the hundreds is
# already implausible, and the bound is what keeps the scan below linear in
# the length of a value that never terminates its userinfo.
_MAX_USERINFO_HALF = 512


def _split_userinfo(value: str, start: int) -> tuple[str, str] | None:
    """Split `user:password@` out of ``value[start:]``, ignoring ``${...}``.

    Returns the two halves, or ``None`` when what follows ``scheme://`` is not
    a userinfo at all — no ``:``, no terminating ``@``, or a ``/`` or
    whitespace reaching one of those first (both are structural separators
    that end the authority, so a credential cannot span them).

    Splitting on the first ``:`` with a regex splits *inside* the substitution,
    the same defect :func:`parser._split_short_volume` exists to avoid.
    ``postgresql://${DB_USER:?error}:${DB_PASSWORD:?error}@postgres/db`` has
    its first colon in the ``:?``, yielding a password of
    ``?error}:${HELLO_DB_PASSWORD:?error}`` — not wholly a reference, so
    :func:`ships_no_literal` called it a literal and the rule fired on a value
    that ships no credential at all (1 corpus instance, issue #561). Both
    halves are therefore delimited by scanning at substitution depth 0.

    ``$$`` is Compose's escape for a literal dollar, consumed before
    interpolation, so it never opens a substitution — ``pa$${x}w0rd`` is a
    literal password, not a reference (issue #502).
    """
    depth = 0
    colon = -1
    i = start
    # A userinfo cannot exceed both ceilings plus its ':' separator, so past
    # that point no '@' can produce a match. Bailing keeps the scan bounded on
    # a long value whose userinfo never terminates.
    limit = min(len(value), start + 2 * _MAX_USERINFO_HALF + 2)
    while i < limit:
        ch = value[i]
        if ch == "$" and i + 1 < len(value):
            following = value[i + 1]
            if following == "$":  # escaped literal dollar, not syntax
                i += 2
                continue
            if following == "{":
                depth += 1
                i += 2
                continue
        if depth:
            if ch == "}":
                depth -= 1
            i += 1
            continue
        if ch == "@":
            if colon < 0:
                return None  # no password half
            user = value[start:colon]
            password = value[colon + 1 : i]
            if len(user) > _MAX_USERINFO_HALF:
                return None
            if not 1 <= len(password) <= _MAX_USERINFO_HALF:
                return None
            return user, password
        if ch == "/" or ch.isspace():
            return None  # authority ended before any userinfo did
        if ch == ":" and colon < 0:
            colon = i
        i += 1
    return None


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
            elif isinstance(item, dict):
                for key, value in item.items():
                    if isinstance(key, str):
                        yield key, value, i


def _find_inline_credential(value: str) -> tuple[str, str, str] | None:
    """Return (scheme, user, password) for an inline credential, else None.

    Returns the first match whose *password* half is a literal. Only a
    password Compose ships as empty means the secret is parameterized;
    a substituted username with a literal password (e.g.
    `postgres://${DB_USER}:secret@db`) still leaks the credential, so it must
    not suppress the finding (issue #277 F6). The var-ref test is shared with
    CL-0020 so both rules classify a password identically — in particular,
    Compose's escaped literal dollar (`$$`) is data, not a substitution, so
    `pa$$w0rd` still fires (issue #502).

    An empty username is a match: RFC 3986 §3.2.1 permits one, and
    `redis://:password@host` — the standard Redis URL form — must still fire
    (issue #279 R2).
    """
    # A userinfo requires a terminating '@', so a value without one can never
    # match. Bail before the scan runs: without this guard a value shaped like
    # `scheme://<many chars>:<many chars>` with no '@' is walked from every
    # `scheme://` offset — O(n^2) on attacker-controlled env values, a cheap
    # DoS when sweeping untrusted compose files.
    if "@" not in value:
        return None
    if len(value) > MAX_SCAN_LEN:
        # The guard above is re-armed by a single trailing '@', so it does not
        # bound anything on its own. A scalar this long is not a connection
        # string; scanning it is pure cost.
        return None
    for m in _URI_SCHEME_RE.finditer(value):
        split = _split_userinfo(value, m.end())
        if split is None:
            continue
        user, password = split
        if ships_no_literal(password):
            continue
        return m.group("scheme"), user, password
    return None


@register_rule
class ConnectionStringCredentialsRule(BaseRule):
    """Detects credentials embedded in URL-shaped environment values."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0021",
            name="Credential embedded in connection-string env value",
            description=(
                "Environment variable values that contain a literal "
                "`scheme://user:password@host` userinfo. Common in "
                "`DATABASE_URL`, `MONGO_URL`, `REDIS_URL`, "
                "`AIRFLOW__DATABASE__SQL_ALCHEMY_CONN`, and similar "
                "connection-string env vars. The exposure surface is "
                "identical to CL-0020 — the credential propagates through "
                "`docker inspect`, `/proc/<pid>/environ`, `docker compose "
                "config`, process listings, and CI logs. Where CL-0020 "
                "matches credential-shaped *keys*, this rule matches "
                "credential-shaped *values* regardless of the key name. "
                "Skipped when the password half is a `${VAR}` "
                "substitution Compose resolves to nothing (the credential is "
                "parameterized); a default such as `${PW:-hunter2}` is the "
                "literal the file ships and still fires."
            ),
            severity=Severity.HIGH,
            references=[OWASP_REF, COMPOSE_SECRETS_REF, RFC3986_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        env = service_config.get("environment")
        if env is None:
            return

        for key, raw, list_index in _iter_env(env):
            if not isinstance(raw, str) or not raw:
                continue
            match = _find_inline_credential(raw)
            if match is None:
                continue
            scheme, _, _ = match

            line = self._lookup_line(service_name, key, list_index, lines)
            yield Finding(
                rule_id="CL-0021",
                severity=Severity.HIGH,
                service=service_name,
                evidence=key,
                message=(
                    f"Service has env var '{key}' containing an inline "
                    f"credential in a {scheme}:// connection string "
                    "(scheme://user:password@host). Env vars are exposed "
                    "via `docker inspect`, `/proc/<pid>/environ`, "
                    "`docker compose config`, process listings, and CI "
                    "logs — any process or operator with daemon access "
                    "can read them."
                ),
                line=line,
                fix=(
                    "Remove the literal password from the connection "
                    "string. Preferred: store the credential in Compose "
                    "`secrets:` and reassemble the URL in the workload's "
                    "entrypoint. Acceptable as an interim step: pull the "
                    "credential from process env via substitution, e.g. "
                    f"`{key}: {scheme}://user:" + "${DB_PASSWORD}@host/db`. "
                    "RFC 3986 §3.2.1 also deprecates passing passwords in "
                    "URI userinfo regardless of Docker context."
                ),
                references=[OWASP_REF, COMPOSE_SECRETS_REF, RFC3986_REF],
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
