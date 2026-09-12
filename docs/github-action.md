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
| `files` | `""` | Space-separated list of Compose files to lint. Empty means CLI discovery in the checkout root. |
| `pattern` | `""` | Glob to find Compose files, e.g. `'**/docker-compose*.yml'`. |
| `fail-on` | `high` | Minimum severity that fails the job: `low`, `medium`, `high`, `critical`. |
| `config` | `""` | Path to a `.compose-lint.yml`. |
| `skip-suppressed` | `false` | Hide suppressed findings from the output. |
| `quiet` | `false` | Text output: one line per finding. |
| `verbose` | `false` | Text output: repeat the fix block and reference on every finding. |
| `sarif-file` | `""` | Path to write SARIF to. Setting it enables the Code Scanning upload. |
| `upload-sarif` | `true` | Upload the written SARIF to Code Scanning. `"false"` only writes the file. |
| `version` | `""` | compose-lint version to install. Empty means the version this action was released with, so a SHA-pinned `uses:` is a reproducible check; `latest` tracks PyPI. |
| `allow-no-files` | `false` | Succeed when no Compose files are found. Off by default because a pattern that matches nothing is a misconfiguration, and the CLI itself exits 2 in that case. |

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
