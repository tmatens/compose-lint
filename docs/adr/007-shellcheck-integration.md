# ADR-007: Shellcheck Integration

**Status:** Pending decision

**Context:** Docker Compose files can contain shell commands in `command` and `entrypoint` (string form) and in `healthcheck.test` entries using `CMD-SHELL`. These fields are passed through a shell at runtime, making them subject to the same class of bugs that shellcheck detects in Dockerfiles: unquoted variables (SC2086), legacy backtick substitution (SC2006), silent `cd` failures (SC2164), and others. No existing tool checks these fields.

**Proposed decision:** Integrate shellcheck as an optional external dependency, invoked via subprocess with `--format=json`. If shellcheck is not present in `PATH`, the rule skips silently. Shellcheck findings are remapped to compose file line numbers and reported under their original `SC` codes alongside native `CL-XXXX` rules. How shellcheck is delivered to the user's environment is the open question (see Alternatives).

**Alternatives:**

- **Linux system package (leading option):** shellcheck installed via `apk`/`apt`/etc., detected at runtime via `shutil.which("shellcheck")`. Zero new Python deps, no lockfile changes, works natively on Alpine. Users installing via `pip` must install shellcheck separately.
- **shellcheck-py:** Python package that bundles the shellcheck binary as a `pip install compose-lint[shellcheck]` optional extra. Simpler install for Python users, but the bundled binary is glibc-linked and does not run on Alpine without additional configuration. Conflicts with the PyYAML-only runtime dep policy (see CLAUDE.md) and requires lockfile regeneration.
- **Hybrid:** Detect shellcheck in `PATH` first, fall back to `shellcheck-py` if installed as an optional extra. Most flexible but adds two code paths to maintain and test.
- **Implement shell checks in pure Python:** Would require maintaining a shell parser and duplicating shellcheck's rule set. Not justified when shellcheck already exists.
- **Always-required shellcheck dep:** Makes the tool fail to run in environments without shellcheck, which is contrary to the optional nature of this feature.

**Rationale:**

- `command` and `entrypoint` in string form, and `healthcheck.test` with `CMD-SHELL`, are the only compose fields where the shell is actually invoked. Array form bypasses the shell; shellcheck findings there would be false positives.
- Compose performs `$VAR` interpolation before the shell sees the string. Variables resolved by compose must be masked before passing to shellcheck to suppress false SC2086 positives.
- The existing `LineLoader` (ADR-003) provides line numbers via the `lines` dict returned by `load_compose()`. Shellcheck findings are offset by the compose file line of the extracted shell string.
- `--format=json` produces structured output that maps cleanly to `Finding` dataclasses without fragile text parsing.
- Optional integration via `shutil.which` keeps the zero-dep install path intact and avoids breaking environments where shellcheck is unavailable.
