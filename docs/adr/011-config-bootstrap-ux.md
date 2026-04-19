# ADR-011: UX for Generating a Starter `.compose-lint.yml`

**Status:** Proposed

**Context:** Once a user runs compose-lint against a real file, they often want to convert the findings into a `.compose-lint.yml` so they can triage suppressions deliberately instead of hand-authoring the config from the schema docs. Hand-writing the config is the current friction point: users have to know the rule IDs, the `exclude_services` shape (ADR-010), and the mapping-vs-list forms. The intent of this ADR is to decide the shape of the *user-facing entry point* for generating that starter config, and the destination of its output. The content of the generated file (grouping strategy, placeholder reasons, severity warnings, header comment) is out of scope and will be specified when the feature is built.

**Decision:** Two decisions.

1. **CLI shape:** introduce a subcommand — `compose-lint init <file>`. Bare `compose-lint <file>` keeps working as an implicit alias for `compose-lint check <file>`; `check` is added as an explicit subcommand. No breaking change for existing users or CI pipelines.
2. **Output destination:** `init` writes `.compose-lint.yml` in the current working directory by default. It refuses to overwrite an existing file without `--force`. Status messages ("wrote .compose-lint.yml with N suppressions across M rules") go to stderr. A custom path is supported via `-o PATH`. Stdout emission is **deliberately out of scope for v1** and deferred until a user asks or `fix` forces the issue (see "Out of scope" below).

---

## Part 1 — CLI shape

### Option A — Subcommand (`compose-lint init <file>`) *(chosen)*

Pros:
- Clean separation of concerns. `init` and `check` are different operations with different output contracts. A subcommand makes that boundary explicit in the CLI surface, not just in documentation.
- Idiomatic. Matches `git init`, `terraform init`, `ruff check` / `ruff format`, `cargo new`.
- Leaves `--format` semantically pure: formatters produce finding output. No new value to document as "not really a format."
- Extensible for operations that clearly want subcommand shape (`fix` especially — destructive variant, own flag set).
- Discoverable. `compose-lint --help` lists subcommands; `compose-lint init --help` documents `init`-specific flags without polluting the top-level surface.

Cons:
- Largest implementation cost of the three options. Requires introducing `argparse` subparsers, refactoring `_build_parser` in `src/compose_lint/cli.py`, and keeping the bare `compose-lint <file>` form working as an implicit `check` alias via an argv shim.
- Two ways to invoke the default lint path (`compose-lint file` and `compose-lint check file`) for the v0.x series. Not deprecating the bare form preserves compatibility but leaves two spellings in the wild.
- Help-text surface grows: top-level help, `init --help`, `check --help`.
- Pathological edge case: a compose file literally named `check`, `init`, `fix`, `explain`, or `rules` (no extension) would collide with subcommand names. Workaround: `compose-lint ./init`. Worth a release-note line; not worth blocking on.

### Option B — New top-level flag (`--emit-config`)

Pros:
- Smallest diff. One `add_argument` call, one branch in `main()`. No subparser refactor.
- No change to existing invocations.

Cons:
- Flag soup risk. Each future mode becomes another top-level flag with documented "ignored in this mode" interactions.
- Mode-switching flags are an anti-pattern. `--emit-config` doesn't modify behavior, it replaces it — which is what subcommands exist for.
- Doesn't compose with future operations that clearly want subcommand shape (`fix` with its own flags).

### Option C — Overload `--format init` (original proposal)

Pros:
- Zero new CLI surface.
- Trivial to implement.

Cons:
- Semantically wrong. `--format` controls how findings are rendered. A config generator does not render findings — it emits a different artifact.
- Breaks the formatter contract from CLAUDE.md (`format(findings) -> str`). A config generator needs service names and rule metadata that formatters deliberately don't see.
- Confusing interaction surface (`--format init --skip-suppressed`? `--format init --fail-on critical`?).
- Hard to evolve (`init --minimal`, `init --only-critical` become `--format` siblings or more flag overload).

### Option D — Out-of-band tool (`compose-lint-init` script)

Pros:
- Zero impact on the main CLI.

Cons:
- Discoverability is terrible.
- Second entry point to package, document, and version-lock.
- Duplicates parsing and config-schema knowledge across two binaries.

### Rationale (CLI shape)

The generator is a distinct operation, not a rendering of findings. Subcommands model that honestly; flags and format overloads model it dishonestly. The one-time cost of introducing subparsers is paid back by `fix` alone — a destructive variant with its own flag set (`--in-place`, `--dry-run`, `--only CL-XXXX`) is a strong subcommand candidate on its own merits. `explain` and `rules list` are weaker cases and come along for consistency, not because they needed it.

Preserving bare `compose-lint <file>` as an alias means no CI pipeline breaks on upgrade. `check` is added as an explicit spelling so that CI configs can migrate when they're ready.

---

## Part 2 — Output destination

### Option A — Write `.compose-lint.yml` by default *(chosen)*

Pros:
- Matches newcomer expectations. `npm init`, `cargo init`, `git init`, `terraform init`, `eslint --init` all write files. The stdout-with-redirect pattern is for inspection tools (`kubectl get -o yaml`, `terraform show`), not bootstrap tools.
- No "did you remember to redirect?" failure mode. The common accident — running `compose-lint init docker-compose.yml` without a redirect and getting 200 lines of YAML dumped into the terminal with nothing saved — can't happen.
- Enables safer defaults. Refusing to overwrite an existing `.compose-lint.yml` without `--force` protects deliberate human suppression decisions from being silently clobbered. Pure stdout emission can't offer that guarantee.
- Simplifies the output contract for v1. Status messages go to stderr, the artifact lands on disk — no stdout/stderr collision with `check`'s banner.
- Sidesteps the question of how `check`'s text-mode banner should interact with a stdout-emitting mode. `cli.py:132` already gates the banner behind `output_format == "text"` so JSON/SARIF redirects cleanly today; extending that gate to future stdout modes is a handful of line edits, not a major refactor. Deferring that decision keeps `init` v1 narrow.

Cons:
- Docker users need a writable mount (`-v $(pwd):/src -w /src`) instead of relying on shell redirection. Standard pattern for artifact-producing CLIs, but one more thing to document.
- Preview-before-commit requires two commands (`compose-lint init -o /tmp/preview.yml && less /tmp/preview.yml`) instead of `compose-lint init | less`. Acceptable friction for a one-time operation.
- Chaining into other tools (`compose-lint init | yq ...`) becomes a two-step workflow. Rare enough not to design around.

### Option B — Emit to stdout, user redirects

Pros:
- Composable with shell pipelines.
- Works in Docker without a writable mount.
- Unix-y.

Cons:
- New users forget the redirect and lose the output. High-frequency papercut for a one-time command.
- Cannot refuse to overwrite — stdout doesn't know what the user will do with the bytes.
- Requires deciding now how `check`'s text-mode banner interacts with a stdout-emitting mode (extend the `output_format == "text"` gate, or move status lines to stderr). Tractable — it's a handful of line edits in `cli.py` — but it's design surface that `init` doesn't need to own.
- Mismatches the bootstrap-command mental model that users bring from `npm init` / `cargo init` / `git init`.

### Option C — Interactive prompt (like `eslint --init`)

Pros:
- Guides the user through decisions (which rules to suppress, which services to exclude).

Cons:
- PyYAML has no interactive-prompt story; adds a runtime dep (Prompt Toolkit, Questionary, etc.). CLAUDE.md forbids new runtime deps without discussion.
- Unusable in CI, Docker, and non-TTY contexts without a `--non-interactive` fallback — which is what Option A already is.
- Overkill for the actual problem (generate a starter file the user then edits).

### Rationale (output destination)

`init` is a bootstrap command for a well-known target filename. File-writing is the lower-friction default, fails safer, matches precedent, and lets us ship a narrower v1. The stdout-pipeline use case is real but uncommon, and deferring it costs nothing — it can be added later as `--stdout` (or `-o -`) without breaking anyone.

---

## Out of scope for this ADR

- **Stdout emission for `init`.** Deferred until a user requests it or until another operation (`fix`, `completion`) makes the stdout/stderr boundary decision unavoidable. At that point, adding `--stdout` / `-o -` to `init` is a small additive change.
- **Generalizing `check`'s stdout/stderr split.** Today, `cli.py:132` gates the text-mode banner so JSON/SARIF redirects cleanly; `stderr` is only used for errors and the stale-exclude warning. When a second stdout-emitting mode arrives, that gate either extends to cover it or status lines move to stderr. Either choice is small; calling it out here so the next ADR doesn't rediscover the question.
- **Output content of `init`** — grouping, placeholder reasons, severity-specific comments, header format.
- **Per-severity behavior** (e.g., refusing to auto-suppress CRITICAL without an explicit flag). Policy call, made at implementation time.
- **`--merge` mode** (re-run analysis and add new suppressions without disturbing existing entries). Useful follow-on, deferred.

## Implementation notes (non-binding)

- `cli.py`: convert `_build_parser` to use `add_subparsers(dest="command")`. Register `check` (current behavior) and `init`. An argv shim prepends `check` when the first non-flag token is neither a known subcommand nor starts with `-`, preserving bare-invocation compatibility.
- `--format`, `--fail-on`, `--config`, `--skip-suppressed` belong to `check` only. `--config` may later belong to `init` for merge support; deferred.
- `init` flags (v1): `-o PATH` (default `.compose-lint.yml`), `--force` (overwrite allowed), positional `FILE`.
- `init` shares `load_compose` and the engine with `check`, then hands findings to a config-emitter module. Place it under `src/compose_lint/config_emit.py` or similar; do **not** put it in `formatters/` — it does not satisfy the `format(findings) -> str` contract (it needs the full service list and rule metadata).
- Exit codes: `init` exits 0 on successful write, 2 on usage/parse error or overwrite-without-force, same as `check`. It does not exit 1 on findings — findings are the input, not the failure signal.
- Status messages ("wrote .compose-lint.yml with N suppressions") go to stderr so they don't interfere with any future `--stdout` mode.
- Tests must cover: bare invocation still works, `check` explicit form works, `init` writes a file that round-trips through `load_config`, overwrite refused without `--force`, `-o PATH` honored, compose file literally named `init`/`check`/etc. handled via `./init` workaround.
