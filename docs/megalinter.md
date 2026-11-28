# MegaLinter plugin

compose-lint runs inside [MegaLinter](https://megalinter.io/) as an external plugin. MegaLinter does not ship it in its image. Each run downloads the plugin's descriptor and installs the compose-lint release that descriptor pins.

## Enable it

Add this to `.mega-linter.yml`:

```yaml
PLUGINS:
  - https://raw.githubusercontent.com/tmatens/compose-lint/v1.8.2/mega-linter-plugin-compose-lint/compose-lint.megalinter-descriptor.yml
```

The URL names a release tag, and the descriptor at that tag installs the same release:

```dockerfile
RUN python3 -m venv /venvs/compose-lint && \
    /venvs/compose-lint/bin/pip install --no-cache-dir "compose-lint==1.8.2" && \
    ln -sf /venvs/compose-lint/bin/compose-lint /usr/local/bin/compose-lint
```

To move to a newer compose-lint, change the tag in the URL. Nothing changes until you do. MegaLinter's own note on plugins applies here too: using an external plugin means you trust its author.

The linter key is `COMPOSE_COMPOSE_LINT`. It is given every file named `compose.yml`, `compose.yaml`, `docker-compose.yml` or `docker-compose.yaml`, and dotted variants such as `docker-compose.prod.yml`.

## What a run does

MegaLinter calls `compose-lint check` once with the list of matching files. A `compose.override.yml` beside a file is merged before linting, as `docker compose` does, and `include:` and `extends:` are followed. [What a run reads](what-a-run-reads.md) has the detail.

When `.compose-lint.yml` is in the repository root, MegaLinter passes it with `--config`. [Configuration](configuration.md) covers what goes in it.

A `high` or `critical` finding fails the MegaLinter run. `medium` and `low` findings are reported and do not fail it.

## Change what fails the run

To fail on `critical` findings only:

```yaml
COMPOSE_COMPOSE_LINT_ARGUMENTS: ["--fail-on", "critical"]
```

To report findings without failing the run:

```yaml
COMPOSE_COMPOSE_LINT_DISABLE_ERRORS: true
```

## When part of the stack cannot be read

If a file points at another file that compose-lint cannot read, such as an `include:` whose target is missing, compose-lint exits with an error and MegaLinter fails the run. There is no finding to fix in that case. Correct the reference, or accept the gap:

```yaml
COMPOSE_COMPOSE_LINT_ARGUMENTS: ["--allow-partial-coverage"]
```

[Compatibility](compatibility.md) lists what counts as a gap.

## SARIF

With MegaLinter's SARIF reporter on, compose-lint writes SARIF 2.1.0:

```yaml
SARIF_REPORTER: true
```

`critical` and `high` findings map to `error`, `medium` to `warning` and `low` to `note`.

## What is not supported

- **Auto-fix.** MegaLinter's `APPLY_FIXES` does nothing for this linter. Some of compose-lint's fixes change how a container runs, so [`compose-lint fix`](fix.md) stays a command you run yourself and review.
- **Native mode.** MegaLinter does not run plugin installs when it runs without Docker.
