# ADR-035: Defer the Published Agent Skill Channel

**Status:** Deferred — revisit when someone asks for a published skill, or
when the channel can meet [the distribution contract](../DISTRIBUTION.md).

**Context:** [#763](https://github.com/tmatens/compose-lint/issues/763) asked
for three agent-facing deliverables. Two shipped in
[#764](https://github.com/tmatens/compose-lint/pull/764): the [Automation and
agent use](../cli.md#automation-and-agent-use) section in the CLI reference,
which writes down the five behaviours an agent driving this tool tends to get
wrong, and a README pointer aimed at the human wiring an agent. The third was a
published Claude Code skill — a thin distillation of that section, packaged so
it lands in an agent's context *before* the agent edits a Compose file in a repo
that has not wired the pre-commit hook or the Action. That repo is the case the
first two deliverables do not reach, and it is the whole argument for the skill.

**Deferral rationale:**

- **The reach argument does not survive contact with who installs what.** A
  skill is opt-in, installed by a human. That is the same human who could
  install the pre-commit hook or the Action, and those gates are strictly
  stronger: they need no cooperation from the agent, they cannot be ignored by
  an agent that never read its context, and they grade the file that was
  actually written rather than hoping guidance was recalled correctly. Where
  both are available, recommending the weaker one is a disservice.
- **The residual win is real but narrow.** Someone who runs an agent across
  many repositories and will not wire each one gets per-user, cross-repo
  coverage from a skill and gets nothing from the gates. That case exists. It
  is also the whole case, and nobody has asked for it: the only mention of a
  skill anywhere in this repository's issues is #763, filed by the maintainer.
- **The channel has no analog for the contract.** Every channel must have a
  staging target, automatic smoke tests against the staged artifact, an
  approval gate, and signing. A git-hosted skill has no registry, so it has no
  staging target and no meaningful smoke; the honest mapping is "the signed
  release tag *is* this channel's contract". That is a real answer, but it
  makes the first exception to a contract that currently has none, in exchange
  for a channel with no demand.
- **The cost is per-release and permanent.** Shipping it means a drift test (a
  skill that names flags is one more doc surface, and every doc surface here has
  a test behind it), a deliberate packaging decision (the wheel already excludes
  `.claude/` and the sdist `include` is a root-anchored allowlist, so a new
  top-level directory ships in neither by accident), a row in the channel table,
  and a step in the release checklist — carried at every release, forever,
  against speculative demand.
- **The roadmap rule already covers this.** Distribution beyond the shipped
  channels waits for a demand signal. That rule deferred the Linux packages
  ([ADR-008](008-linux-packages.md)) and moved the Homebrew tap to Milestone 5.
  A skill is a weaker case than either: both of those close a genuine "no
  Python toolchain" install gap for users who cannot reach the tool at all,
  where this one adds a second, weaker path for users who can already reach it.

**Decision:** No skill ships from this repository for now. The agent-facing
surface is the [Automation and agent use](../cli.md#automation-and-agent-use)
section, the README pointer at it, and — the part that does the actual work —
the pre-commit hook and the GitHub Action, which grade agent-authored Compose
on the same terms as anyone else's.

This declines *publishing and maintaining* a skill as a project distribution
channel. It does not discourage anyone, maintainer included, from keeping a
local skill that distils the section for their own use; that costs this project
nothing and is the cheapest way for the demand signal below to show up.

**What would change this decision** (any one of these is enough to reopen it):

- A concrete request for a packaged skill from someone who is not the
  maintainer.
- Evidence that the docs section is not enough — an agent misusing the tool in
  a way the section already covers, reported on an issue. That is a
  correctness failure, and correctness has never waited for a demand signal
  here.
- A skill/plugin registry that supports a staging channel and artifact signing,
  which would collapse most of the contract objection.

**Retained approach (for the revisit):** ship it as a top-level `skills/`
directory with a plugin marketplace manifest; add the directory to the sdist
`include` allowlist (and decide the wheel deliberately — the CLI does not read
it at runtime, so the likely answer is sdist only); add a test asserting every
flag, environment variable, and rule ID the skill names still exists in
`--help` and the rule registry, so it fails the way the other doc surfaces
fail; add the channel row and a `docs/RELEASING.md` step; and record the
"signed release tag is the contract" mapping as an amendment here rather than
as a silent exception to `DISTRIBUTION.md`. The skill content stays a
distillation of the CLI section with no rule-specific prose — `--explain`
remains the single source, offline and shipped in the wheel.

**Alternatives rejected:**

- **An MCP server.** Wrapping a fast, exit-code-driven CLI in a protocol server
  adds a process, a dependency surface, and a second contract to keep in sync
  with the JSON envelope. Teaching the CLI beats wrapping it.
- **A `docs/agents.md`.** A second agents-named file next to the
  contributor-facing root `AGENTS.md` invites exactly the confusion the split
  is meant to avoid, and `cli.md` already carries the adjacent material. #764
  put the section there for this reason; nothing here reopens it.
- **Shipping the skill as a quiet exception to `DISTRIBUTION.md`.** The
  contract is only worth having if adding a channel is visibly harder than not
  adding one. An unwritten exception is how that stops being true.

**Consequences:** The unwired-repo case stays uncovered, and that is the known
cost of this decision rather than an oversight — the README answers it by
telling the human to wire a gate, which is the better fix anyway. `AGENTS.md`
stays contributor-facing. #763's third deliverable closes as decided-and-
declined rather than lingering as an implicit maybe, which was the point of
recording it.
