# scripts/compare/

The measurement behind [docs/compare.md](../../docs/compare.md): the fixtures,
the script that runs every compared tool over them, and the script that turns
what the tools printed into the page's tables.

## Files

- `fixtures/same-file/`: sixteen services, one deliberate misconfiguration
  each, named for the compose-lint rule it targets.
- `fixtures/owasp/`: twenty-one services, one per violation of the OWASP
  Docker Security Cheat Sheet that a Compose file can express.
- `fixtures/multi/`: one directory per scenario where a setting reaches the
  service through `extends:`, `include:`, an override file, an anchor, a
  variable or `.env`, plus the scenarios that look dangerous and deploy
  safely.
- `run.sh`: runs the tools and keeps their output.
- `score.py`: reads that output and prints the tables.

None of the fixtures is meant to be started. A scenario that needs a `.env`
keeps it as `dot-env`, because the repository does not track `.env` files, and
`run.sh` renames it in the copy it works on.

## Running it

On a host with Docker and the Compose plugin:

```bash
scripts/compare/run.sh /tmp/compare-out
python scripts/compare/score.py /tmp/compare-out
```

`run.sh` runs each fixture twice, as written and with the obsolete
`version: "3.9"` key added at the top of every YAML file, because two of the
tools only match with it. The tools run with no network, except Semgrep and
Trivy, which download their rules. `versions.txt` in the output directory
records the image digest and the version each tool reported.

## How a cell is scored

A finding counts for a row only when it comes from the tool's own rule for
that setting and is reported on the service the row is about. The rule names
are in `RULES` at the top of `score.py`. A tool with no rule for a setting
gets "No rule", so a miss is only charged to a tool that has the check.

In the multi-file scenarios the service Compose deploys is `app`. A finding on
`base`, the service `app` extends, is scored as "Base only". The file
`compose-config.json` in each scenario's output is what `docker compose
config` rendered, which is the ground truth for what deploys.

## Measuring newer versions

The image tags at the top of `run.sh` are the versions the page reports. They
record a measurement, so Renovate does not manage them, and the fixtures'
images are excluded from Renovate for the same reason. To refresh the page:

1. Change the tags in `run.sh` to the versions to measure.
2. Run both scripts.
3. Update the tables, the version lists and the dates in `docs/compare.md`
   from the output. If a tool renamed a rule, update `RULES` first, or its
   column will read as misses.
4. Check the upstream issues the page cites, since a merged fix changes a
   column.
