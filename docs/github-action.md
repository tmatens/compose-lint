# GitHub Action

The compose-lint GitHub Action lints Docker Compose files in CI and, by
default, uploads its SARIF to GitHub Code Scanning so findings appear as PR
annotations and Security-tab alerts. `tmatens/compose-lint` runs the linter in
a job; the copy-paste workflow lives in the
[README](https://github.com/tmatens/compose-lint#github-actions), where release
automation keeps the `uses:` line pinned to the current release; this page is
the reference behind it.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `files` | `""` | Whitespace-separated list of Compose files to lint. Each entry is a literal path — `*` and `?` are not expanded; use `pattern` for globs. Takes precedence over `pattern` when both are set. Empty (with `pattern` also empty) lints whichever of `compose.yml`, `compose.yaml`, `docker-compose.yml`, `docker-compose.yaml` exist in the checkout root. Each file found is passed to the CLI by name, and graded as the CLI grades a named file: when a `.env` beside it sets a `COMPOSE_FILE` list that includes it, the whole list is merged in that order. A repository whose `COMPOSE_FILE` names none of those four files should list its documents in `files`, because the default search looks for the four names only. |
| `pattern` | `""` | Glob matched against the file **name**, e.g. `'docker-compose*.yml'`, searched recursively under the checkout (`.git/` is skipped). It cannot contain `/` — the job fails before linting if it does — because a name glob never matches a path; use `files` for paths. |
| `fail-on` | `high` | Minimum severity that fails the job: `low`, `medium`, `high`, `critical`. |
| `config` | `""` | Path to a config file. Empty means the CLI's own discovery: `.compose-lint.yml`, then `.compose-lint.yaml`, in the checkout root. |
| `skip-suppressed` | `false` | Leave suppressed findings out of both the job log and the SARIF file, so their Code Scanning alerts close. See [Suppressed findings in Code Scanning](#suppressed-findings-in-code-scanning). |
| `allow-partial-coverage` | `false` | Pass `--allow-partial-coverage`: a coverage gap (part of the stack the linter could not see, such as an `include:` it could not follow or a `.env` it could not read) becomes a warning instead of exit 2, as long as something is left to grade. The full list of gaps is in [coverage gaps are not findings](compatibility.md#coverage-gaps-are-not-findings). |
| `strict-config` | `false` | Pass `--strict-config`: config-file warnings (unknown rule id, unknown key, an inert `reason:` or `severity:`, a stale `exclude_services` name, both config spellings present) become a hard error. See [`--strict-config`](configuration.md#validation). |
| `quiet` | `false` | Text output: one line per finding. Mutually exclusive with `verbose`: setting both fails the job with `quiet and verbose are mutually exclusive` before anything is linted. |
| `verbose` | `false` | Text output: repeat the fix block and reference on every finding. Mutually exclusive with `quiet`, as above. |
| `sarif-file` | `""` | Path to write SARIF to. Setting it enables the Code Scanning upload. The path must stay inside the workspace; a parent directory that does not exist yet is created. A path where a directory, a symbolic link or another non-regular file already exists is [refused](#what-sarif-file-refuses). |
| `upload-sarif` | `true` | Upload the written SARIF to Code Scanning. `"false"` only writes the file. |
| `version` | `""` | compose-lint version to install. Empty means the version this action was released with, installed with the dependency versions locked at that release (`requirements.lock`, hash-checked), so a SHA-pinned `uses:` is a reproducible check. `latest` tracks PyPI; an explicit version or `latest` resolves its dependencies from PyPI. |
| `allow-no-files` | `false` | Succeed when no Compose files are found. Off by default because a pattern that matches nothing is a misconfiguration, and the CLI itself exits 2 in that case. |

Boolean inputs are on only for the exact string `"true"`, which is what a YAML
`true` becomes; `"True"` or `"yes"` leave the input off.

One output, `sarif-written`, is `"true"` when this run wrote the file
requested via `sarif-file`, as a non-empty regular file at that path, and
empty otherwise. Use it to gate a later `upload-artifact` step.

## What `sarif-file` refuses

The workflow chooses the `sarif-file` path, but on a pull request the checkout
decides what is already at it. The action writes the file only when all of
these hold, and otherwise fails the step with exit 2, leaves `sarif-written`
empty and skips the upload:

- The path resolves inside the workspace, through any symbolic links in its
  directories, and not into `.git`.
- Nothing is at the path, or a regular file is, which is replaced. A
  directory, a symbolic link (whatever it points to) or any other non-regular
  file at the path is refused, not written into or through.
- The directory can be created and written to.

The write itself is done by `compose-lint check --output`
([CLI reference](cli.md#writing-the-report-to-a-file)), as one atomic
replacement. A `version:` older than 1.4.0 has no such option; for those the
action writes the file itself under the same checks.

A file that was at the path before the run is never reported as written: if
compose-lint did not replace it, the step fails.

## Pin the SHA, or float on `v1`

The README's `uses:` line pins a commit SHA with the version in a trailing
comment. That is the supply-chain-rigorous form: it is what OpenSSF Scorecard
grades for, and Renovate or Dependabot keep the pin fresh. Since 1.0 a floating
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

## Problem matchers still read the output

compose-lint's output quotes text from the files it grades, so the action
turns workflow-command processing off (`stop-commands`) before the first
compose-lint run and turns it back on as the last thing the lint step does.
Anything the step reports as an annotation after that is fixed text, plus the
`sarif-file` input as the workflow wrote it. That does not turn off
[problem matchers](https://github.com/actions/toolkit/blob/main/docs/problem-matchers.md).
A matcher registered earlier in the job still reads compose-lint's output,
and any line matching its pattern becomes an annotation. Some setup actions
register one without being asked: `actions/setup-python` adds a matcher for
Python tracebacks. A Compose file in a pull request can be written so its
quoted text matches such a pattern and adds an annotation of its own. The
verdict and the exit code are not affected.

If those annotations matter to you, run the action in a job with no matcher
registered, or remove the matcher in a step before it:

```yaml
      - run: echo "::remove-matcher owner=python::"
```

The owner is the `owner` field of the matcher's JSON file.

## Suppressed findings in Code Scanning

A finding suppressed in `.compose-lint.yml` is written to the SARIF file with
SARIF's `suppressions[]` property and its reason as the `justification`.
GitHub Code Scanning does not read that property, so by default the finding
is an **open** alert like any other, although it does not fail the job.

To keep suppressed findings out of Code Scanning, set `skip-suppressed: true`.
They are then left out of the upload, and GitHub closes their alerts as
fixed. The same input also drops them from the job log. If a suppression is
later removed, the finding returns with the same fingerprint.

The default is off because a suppression that `compose-lint init` wrote is a
placeholder, not a decision: turning the input on with an untriaged
`init` config closes every alert it covers. Replace each
`TODO: justify or fix` reason, or fix the finding, before turning it on.

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
