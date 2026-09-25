# GitHub Action

`tmatens/compose-lint` runs the linter in a job and, by default, uploads its
SARIF to GitHub Code Scanning so findings appear as PR annotations and
Security-tab alerts. The copy-paste workflow lives in the
[README](https://github.com/tmatens/compose-lint#github-actions), where release
automation keeps the `uses:` line pinned to the current release; this page is
the reference behind it.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `files` | `""` | Whitespace-separated list of Compose files to lint. Each entry is a literal path — `*` and `?` are not expanded; use `pattern` for globs. Takes precedence over `pattern` when both are set. Empty (with `pattern` also empty) lints whichever of `compose.yml`, `compose.yaml`, `docker-compose.yml`, `docker-compose.yaml` exist in the checkout root. Unlike a bare CLI run, that does **not** read `COMPOSE_FILE` from a `.env`; a repository that selects its documents that way should list them in `files`. |
| `pattern` | `""` | Glob matched against the file **name**, e.g. `'docker-compose*.yml'`, searched recursively under the checkout (`.git/` is skipped). It cannot contain `/` — the job fails before linting if it does — because a name glob never matches a path; use `files` for paths. |
| `fail-on` | `high` | Minimum severity that fails the job: `low`, `medium`, `high`, `critical`. |
| `config` | `""` | Path to a config file. Empty means the CLI's own discovery: `.compose-lint.yml`, then `.compose-lint.yaml`, in the checkout root. |
| `skip-suppressed` | `false` | Hide suppressed findings from the output. |
| `allow-partial-coverage` | `false` | Pass `--allow-partial-coverage`: a coverage gap — an `include:` or cross-file `extends:` the linter could not follow — becomes a warning instead of exit 2. See [coverage gaps are not findings](compatibility.md#coverage-gaps-are-not-findings). |
| `strict-config` | `false` | Pass `--strict-config`: config-file warnings (unknown rule id, unknown key, an inert `reason:` or `severity:`, a stale `exclude_services` name, both config spellings present) become a hard error. See [`--strict-config`](configuration.md#validation). |
| `quiet` | `false` | Text output: one line per finding. Mutually exclusive with `verbose`: setting both fails the job with `quiet and verbose are mutually exclusive` before anything is linted. |
| `verbose` | `false` | Text output: repeat the fix block and reference on every finding. Mutually exclusive with `quiet`, as above. |
| `sarif-file` | `""` | Path to write SARIF to. Setting it enables the Code Scanning upload. The path must stay inside the workspace; a parent directory that does not exist yet is created. |
| `upload-sarif` | `true` | Upload the written SARIF to Code Scanning. `"false"` only writes the file. |
| `version` | `""` | compose-lint version to install. Empty means the version this action was released with, so a SHA-pinned `uses:` is a reproducible check; `latest` tracks PyPI. |
| `allow-no-files` | `false` | Succeed when no Compose files are found. Off by default because a pattern that matches nothing is a misconfiguration, and the CLI itself exits 2 in that case. |

Boolean inputs are on only for the exact string `"true"`, which is what a YAML
`true` becomes; `"True"` or `"yes"` leave the input off.

One output, `sarif-written`, is `"true"` when the file requested via
`sarif-file` was written and non-empty, and empty otherwise. Use it to gate a
later `upload-artifact` step.

## Pin the SHA, or float on `v1`

The README's `uses:` line pins a commit SHA with the version in a trailing
comment. That is the supply-chain-rigorous form: it is what OpenSSF Scorecard
grades for, and Renovate or Dependabot keep the pin fresh. From 1.0 a floating
major tag also exists, `uses: tmatens/compose-lint@v1`, for setups that prefer
automatic updates. It is a mutable pointer moved by the release pipeline,
deliberately *not* part of the signed-tag guarantee that release tags carry —
the same trade this linter itself prices in CL-0004 and CL-0019. Pick the form
that matches your threat model; the SHA pin is the recommended default.

## Why the `permissions:` blocks are part of the recipe

Without them the job inherits the repository default, which on many
repositories is still read-write for every scope. A linting job that needs
only `contents: read` and `security-events: write` would then run holding a
token that can push code and edit releases. Denying everything at the workflow
level (`permissions: {}`) and granting the two scopes the job actually uses
keeps a compromised dependency in this job from reaching anything else.

Drop `security-events: write` if you are not uploading SARIF.

## SARIF without the Code Scanning upload

To write the SARIF file and skip the upload — for example to attach it as a
build artifact, or on a runner without Code Scanning — set
`upload-sarif: "false"` alongside `sarif-file`, and drop the
`security-events: write` scope:

```yaml
      - uses: tmatens/compose-lint@<sha> # vX.Y.Z
        id: lint
        with:
          sarif-file: results.sarif
          upload-sarif: "false"
      - uses: actions/upload-artifact@<sha> # vX.Y.Z
        if: steps.lint.outputs.sarif-written == 'true'
        with:
          name: compose-lint-sarif
          path: results.sarif
```

## Without the action

The action is a thin wrapper over the PyPI package. Installing it directly
works in any job that has Python:

```yaml
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - run: pip install compose-lint
      - run: compose-lint --format sarif docker-compose.yml > results.sarif
```

Forgejo Actions runs the same action with two practical differences; see the
[Forgejo guide](forgejo.md).
