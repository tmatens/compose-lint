# Forgejo Actions

Forgejo Actions runs GitHub-Actions-compatible workflows via `act_runner`, with two practical differences: cross-instance action refs need full URLs (`https://code.forgejo.org/...`), and JS actions like `checkout` need `node` inside the job container ([act#107](https://github.com/nektos/act/issues/107)) — `container:` jobs run fine, but a node-less Python image fails at checkout, so install via `apt` + `pip` on the default image instead:

```yaml
# .forgejo/workflows/validate.yml
name: Validate
on:
  pull_request:
    branches: [main]
  workflow_dispatch:

jobs:
  compose-lint:
    runs-on: docker
    steps:
      - uses: https://code.forgejo.org/actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Install compose-lint
        run: |
          apt-get update -qq
          apt-get install -yqq --no-install-recommends python3-pip
          pip3 install --break-system-packages --no-cache-dir compose-lint==1.8.1
      - name: Run compose-lint
        run: compose-lint --fail-on high
```

Forgejo has no SARIF UI today — `--format sarif` still produces a valid document, but there's no security-tab equivalent to render it. Verified on Forgejo 17.0.2, runner 13.2.2 — this exact snippet is executed against a live Forgejo weekly by the [forgejo-smoke workflow](https://github.com/tmatens/compose-lint/blob/main/.github/workflows/forgejo-smoke.yml), which fails if this line and the versions it ran on disagree.
