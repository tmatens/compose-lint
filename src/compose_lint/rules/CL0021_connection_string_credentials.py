"""CL-0021: Credentials embedded in connection-string env values."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-11---use-secret-management-tools"
)

COMPOSE_SECRETS_REF = "https://docs.docker.com/reference/compose-file/secrets/"

RFC3986_REF = "https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.1"

# Match `scheme://user:password@` in any env value. The scheme follows
# RFC 3986 §3.1 (alpha + alnum/+/-/.); user and password halves stop at
# the structural separators (':', '/', '@', whitespace). The '$' guard
# below filters out variable substitutions in either half.
_URI_USERINFO_RE = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*)://"
    r"(?P<user>[^:/@\s]+):"
    r"(?P<password>[^@/\s]+)@"
)


def _is_var_ref(s: str) -> bool:
    """True if s contains a $VAR or ${VAR} substitution."""
    return "$" in s


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

    Returns the first match where neither userinfo half is a variable
    substitution. Substituted halves indicate the credential is
    parameterized — the secure-ish pattern, not an inline literal.
    """
    for m in _URI_USERINFO_RE.finditer(value):
        user = m.group("user")
        password = m.group("password")
        if _is_var_ref(user) or _is_var_ref(password):
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
                "Skipped when either userinfo half is a `${VAR}` "
                "substitution (the credential is parameterized)."
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
