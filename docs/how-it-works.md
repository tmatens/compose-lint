# How compose-lint works

compose-lint grades the configuration Compose would actually run, then turns the
result into an exit code. If it was meant to read part of the stack and could
not, the run fails. A pass always means everything was graded.

## A check run

```mermaid
flowchart TB
  subgraph project["Inside the repository (the checkout)"]
    direction LR
    compose["compose.yml"]
    overlay["compose.override.yml<br/>or COMPOSE_FILE"]
    env[".env"]
    refs["include: and<br/>extends: targets"]
    envfile["env_file:<br/>targets"]
    policyfile[".compose-lint.yml"]
  end
  parse["<b>Merge and parse</b><br/>overlays merged in Compose's order<br/>${VAR:-default} resolved from .env<br/>YAML loaded with line numbers"]
  rules["<b>Rules</b><br/>every rule runs on every service<br/>each finding: rule, severity, file:line, fix"]
  policy["<b>Policy</b><br/>disabled rules reported as suppressed<br/>severity overrides, excluded services"]
  report["<b>Report</b><br/>text, JSON or SARIF on stdout"]
  code{"exit code"}
  gap(["exit 2: coverage gap<br/>a referenced file is outside<br/>the repository or unreadable"])
  usage(["exit 2: usage error<br/>invalid Compose"])
  compose & overlay & env & refs & envfile -->|read| parse
  project -.-> gap
  parse -.-> usage
  parse -->|one merged document| rules
  rules -->|findings| policy
  policyfile -->|rule policy| policy
  policy --> report --> code
  code -->|"0: nothing at or above the threshold"| pass(["pass"])
  code -->|"1: findings at or above the threshold"| fail(["fail"])
  classDef stop stroke:#c2410c,stroke-width:2px
  class gap,usage stop
```

1. **Inputs.** The file you name, or the one found in the working directory, plus
   everything `docker compose up` would read with it: the sibling override, the
   sibling `.env`, `include:` and cross-file `extends:` targets, and `env_file:`
   targets. Each must resolve inside the project. No registry, Docker daemon or
   image is ever contacted. [What a run reads](what-a-run-reads.md) has the full
   list and the flags that switch each source off.
2. **Merge and parse.** Overlays are merged in the order Compose uses, and
   `${VAR:-default}` resolves to what Compose would deploy. Line numbers are
   kept so every finding points at the line to change.
3. **Rules.** Every rule runs against every service. A rule's severity is derived
   from a fixed model, not picked per rule; see [Severity levels](severity.md).
4. **Policy.** [`.compose-lint.yml`](configuration.md) can disable a rule, override
   its severity, or exclude a service. A disabled rule's findings are still
   reported, marked suppressed with your reason. There are no inline suppression
   comments.
5. **Report and exit.** Findings go to stdout as text, JSON or SARIF. The run
   exits `1` if any finding is at or above `--fail-on` (default `high`), `0`
   otherwise.

The dashed paths are what makes the result safe to gate on. A part of the stack
compose-lint could not read is a coverage gap, and a coverage gap exits `2`, the
same as a usage error. It is never reported as a pass. The exit codes are part of
the [compatibility contract](compatibility.md).

## Where fix branches off

```mermaid
flowchart LR
  findings["Unsuppressed findings"] --> q{"One correct value, in one place,<br/>with no anchors or ${VAR} there?"}
  q -->|no| manual["Reported for manual review"]
  q -->|yes| edit["Edit, then re-parse and<br/>re-lint the merged result"]
  edit -->|would not round-trip| refused["Refused, diff shown"]
  edit -->|clean| out["Dry run prints the diff<br/>apply mode writes it in place"]
```

`compose-lint fix` edits only findings with exactly one right answer, and checks
each edit by linting the merged result before anything is written. A dry run is
the default. `--apply` writes with an atomic swap, and every edit that changes
how the stack behaves is labelled. [Fixing findings](fix.md) is the full
contract.
