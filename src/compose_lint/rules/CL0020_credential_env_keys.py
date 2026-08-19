"""CL-0020: Credential-shaped environment keys with literal values."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from compose_lint._scalar import as_scalar_text
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
)

# Suffix-anchored so PASSPORT_SECRET is not read as a port number.
_QUANTITY_KEY_SUFFIXES = ("_PORT",)

# A bare number, optionally carrying a time unit (`30`, `1.5`, `900s`, `30m`,
# `500ms`). Anything else — a placeholder, a filename, a rate like `5/hour` —
# is not a quantity and the rule still fires.
_QUANTITY_VALUE_RE = re.compile(r"^\d+(\.\d+)?(ms|s|m|h|d)?$", re.IGNORECASE)


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
                "literal string. The "
                "credential is exposed via `docker inspect`, "
                "`/proc/<pid>/environ`, `docker compose config`, process "
                "listings, and CI logs. Compose's `secrets:` primitive "
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
