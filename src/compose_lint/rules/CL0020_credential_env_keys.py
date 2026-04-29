"""CL-0020: Credential-shaped environment keys with literal values."""

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

# Substring matches (case-insensitive on the upper-cased key).
_SUBSTRING_PATTERNS = (
    "PASSWORD",
    "TOKEN",
    "SECRET",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "SECRET_KEY",
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

# A pure variable substitution ("${VAR}", "${VAR:-default}", "$VAR").
# Used to skip parameterized values entirely; the credential is sourced
# from process env, which is the documented secure-ish pattern.
_VAR_REF_RE = re.compile(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*")


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


def _is_literal_credential_value(raw: Any) -> bool:
    """Decide whether a value should be treated as a literal credential.

    Skips:
    - Non-string and empty-string values (env unset, not a credential)
    - Boolean / numeric toggles like "yes", "true", "1"
    - Any value containing a ${VAR} substitution (parameterized)

    Booleans and ints in YAML decode to Python bool/int and are skipped too.
    """
    if not isinstance(raw, str):
        return False
    if raw == "":
        return False
    if raw.strip().lower() in _FLAG_VALUES:
        return False
    return not _VAR_REF_RE.search(raw)


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
                "convention (PASSWORD, TOKEN, SECRET, API_KEY, ACCESS_KEY, "
                "PRIVATE_KEY, CREDENTIAL, *_PASS, *_PWD, PASSWD, *_SALT, "
                "*_DSN) and whose value is a non-empty literal string. The "
                "credential is exposed via `docker inspect`, "
                "`/proc/<pid>/environ`, `docker compose config`, process "
                "listings, and CI logs. Compose's `secrets:` primitive "
                "materializes credentials as files under /run/secrets/ and "
                "does not appear in any of those surfaces. This rule is a "
                "naming-convention check, not a content scanner — it does "
                "not inspect the value for secret-like entropy or formats."
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
        env = service_config.get("environment")
        if env is None:
            return

        for key, raw, list_index in _iter_env(env):
            key_upper = key.upper()
            if not _matches_credential_pattern(key_upper):
                continue
            if _is_exempt_key(key_upper):
                continue
            if not _is_literal_credential_value(raw):
                continue

            line = self._lookup_line(service_name, key, list_index, lines)
            yield Finding(
                rule_id="CL-0020",
                severity=Severity.HIGH,
                service=service_name,
                message=(
                    f"Service has credential-shaped env key '{key}' with a "
                    "literal value. Env vars are exposed via `docker inspect`, "
                    "`/proc/<pid>/environ`, `docker compose config`, process "
                    "listings, and CI logs — any process or operator with "
                    "daemon access can read them."
                ),
                line=line,
                fix=(
                    f"Move '{key}' to Compose's `secrets:` primitive. If the "
                    "image supports the `*_FILE` convention (Postgres, MySQL, "
                    "MariaDB, MinIO, etc.), set "
                    f"`{key}_FILE: /run/secrets/<name>` and declare the "
                    "secret under the top-level `secrets:` block sourced from "
                    "a gitignored file or `external: true`. Otherwise, have "
                    "the entrypoint read the secret file at startup and "
                    "export the value into the workload's environment."
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
