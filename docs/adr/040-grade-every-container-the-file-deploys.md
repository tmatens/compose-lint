# ADR-040: Grade Every Container the File Deploys

**Status:** Proposed

**Context:** The engine grades one kind of unit, the mapping under
`services.<name>`, and hands each rule that mapping. Since late 2024 Compose
has added three other places where a file puts a container or a privileged
command, and every rule is silent on all of them (issue #1185):

- `pre_start:` (Compose 5.3.0): a list of init containers run to completion
  before the service starts. The schema makes each entry a full container
  spec and says attributes the hook does not set are inherited from the
  service, with collections completed by the hook's entries and scalars
  replaced. Measured on Compose 5.6.1: a hook inherited the parent's
  `user`, `read_only`, `cap_drop`, environment and bind mount, kept its own
  image and variables, and a hook that set `privileged: true` and a socket
  mount ran with every capability, the host's device nodes and the socket.
  Override files append hook lists, and compose-lint's merger already does
  the same.
- `post_start:` / `pre_stop:` (Compose 2.30.0): commands executed inside the
  running container, with `command`, `user`, `privileged`, `working_dir` and
  `environment` only. Measured: `user: root` ran the command as uid 0 with
  the container's default capabilities; `privileged: true` widened the
  capability bounding set to everything but left seccomp in filter mode and
  the device cgroup enforced, so it is a lesser grant than a privileged
  container; an `environment:` literal was visible to the exec process and
  not to the container.
- top-level `jobs:` (Compose 5.6.0): run-to-completion containers with a full
  container spec, started by `docker compose run <job>` rather than by `up`.
  Measured: a job with `privileged: true` ran as a fully privileged
  container. A file with only `jobs:` is valid Compose; compose-lint refuses
  it as "missing 'services' key".

On an 11,111-file corpus (snapshot 2026-08-27) the hooks carry 11 findings
under three existing rules that compose-lint reports nothing for: six
unpinned init images, three tag-only images, and two credential-shaped
literals in an init container's environment where the parent service has no
`environment:` at all. A tool that grades the service and stays silent on the
init container two lines below it is wrong in the way its users will notice
first. `jobs:` has no corpus population yet; the key is four weeks old.

Three facts about the code shape the design. The parser's line map already
indexes hook paths (`services.app.pre_start[0].image`). Every rule builds its
line path as `services.<name>.<key>` and reads the keys it grades from the
top of the mapping it is given. And a finding's identity (ADR-024) is its
rule, its service and its evidence, where several rules carry no evidence,
so identity alone cannot tell a hook's finding from its parent's.

**Decision:**

1. **The engine grades units, not services.** A unit is a container the
   file deploys, or a command it runs inside one. The units of a file are:
   every `services.<name>` whose `provider` is not a mapping (the #1186
   rule stays); every `services.<name>.pre_start[i]`;
   every `services.<name>.post_start[i]` and `pre_stop[i]`; every
   `jobs.<name>`. Rules are unchanged: each is called once per unit with a
   mapping and a name, exactly as today.

2. **A unit's name is its document path below `services.`**, and it is what
   the finding's `service` field carries: `app.pre_start[0]`,
   `app.post_start[1]`, `jobs.migrate`. The brackets make a hook name
   impossible to confuse with a service, since Compose does not allow them
   in service names. A service literally named `jobs.<x>` beside a job
   `<x>` would share a name; both are still reported. The name is what
   `exclude_services` matches, what the text report groups under, and what
   the SARIF fingerprint hashes, so a hook's finding and its parent's are
   distinct alerts.

3. **A hook is graded as what it deploys, attributed to what it wrote.**
   The mapping a rule sees for a `pre_start` unit is the parent's scalar
   keys overlaid by the hook's, plus the hook's own collections and mappings
   (`volumes`, `cap_add`, `environment`, `ports`, ...), not the parent's.
   Scalars are inherited so that a presence rule sees the real posture
   (a hook under a `privileged: true` parent is privileged); collections are
   the hook's own so that a parent's socket mount is reported once, on the
   parent, and the hook's additions are reported on the hook with correct
   line numbers. A finding on a hook unit is then dropped when its line is
   `None` or is the unit's own line: that is a finding about a key the hook
   did not write, an inherited scalar or an absence, and it belongs to the
   parent, which already reports it. No rule needs to know any of this.

4. **An exec hook is graded on `user` and `environment`, never
   `privileged`.** Its mapping is the parent's scalars overlaid by the
   hook's `user` and `working_dir`, with the hook's own `environment`. The
   hook's `privileged` is removed before grading: measured, it is not the
   grant CL-0002 describes, and no rule describes what it is. It is recorded
   as not graded (issue #1189) with the measurement. The same drop rule as
   (3) applies, so a parent's absence findings are not repeated on its execs.

5. **A job is graded as a service is**, with no parent and no drop rule. Its
   line paths live under `jobs.<name>`, so the engine gives the rules a line
   map in which `services.jobs.<name>.*` aliases them. A document with
   `jobs:` and no `services:` is a lintable Compose file; the parser's
   missing-`services` error applies only when both are absent.

6. **`fix` edits service units only.** A finding on a hook or job unit goes
   to the manual list with a note saying so. The fixers locate edits by
   `services.<name>` block spans that were designed for service blocks, and
   extending them to hook blocks is a change of its own (MINOR, later).

7. **`env_file:` on a hook is not read.** Compose 5.6.1 accepts the key and
   does not apply it, so there is nothing a rule could grade. If a later
   Compose applies it, the premise check below fails and the decision is
   revisited.

8. **The measurements become a premise check.** `scripts/validate_rule_premises.py`
   gains a check that proves, on the CI daemon, the hook inheritance, the
   exec `privileged` grant shape, the inert hook `env_file`, and the job
   container, skipping (not failing) where the Compose plugin predates 5.6.
   A spec-shape change surfaces there first.

9. **Nothing here is a coverage gap.** Every unit is graded; the gap list in
   `compatibility.md` is unchanged. The unknown-name coverage warning for
   `exclude_services` learns unit names so excluding a hook is not flagged.

**Consequences:**

- Files that graded clean gain findings on their hooks and jobs: MINOR under
  `compatibility.md`. On the corpus that is 11 findings in 7 files, and
  2 CL-0018 findings on `user: root` exec hooks. No existing finding changes
  identity, since service units keep their names and their evidence.
- `exclude_services` accepts unit names. A service exclusion does not cover
  the service's hooks: a hook is its own unit with its own name, the same
  way the hook's findings are its own. Documented in `configuration.md`.
- CL-0018's message says "Service explicitly runs as root"; on an exec hook
  the engine supplies a name that makes the sentence read as the hook's, and
  the rule page gains the exec case. No rule text changes in this ADR.
- `fix` reports hook and job findings as manual until the fixers are taught
  hook blocks. The CLI's verdict is unchanged.
- A later container slot in the spec lands on the unit traversal, not on
  silence; the round-trip test in issue #1187 asserts every container-shaped
  slot in the schema is a unit kind here.
- Rejected: grading hooks as the full merged mapping with identity-based
  dedup against the parent. Several rules carry no evidence, so identical
  identity does not mean identical finding (a hook's tag-only image under a
  tag-only parent image would vanish). Rejected: a new `unit` field beside
  `service`, with exclusions by service covering hooks. It changes the
  output schema and the fingerprint composition for no gain over a name.
- Rejected for now: grading `privileged` on an exec hook under any rule.
  The grant is real (every capability in the bounding set) but bounded by
  seccomp and the device cgroup, which no current rule's derivation covers;
  the corpus has zero instances. Recorded for a recount.
