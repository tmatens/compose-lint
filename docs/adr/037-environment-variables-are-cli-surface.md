# ADR-037: Environment Variables Are Part of the CLI Surface

**Status:** Accepted

**Context:** compose-lint reads five environment variables: `NO_COLOR` and
`FORCE_COLOR` for color, and `PAGER`, `NO_PAGER` and `TERM` for the
`--explain` pager ([ADR-034](034-explain-pages-on-a-tty.md)). `docs/cli.md`
documents them, but the stability policy in
[compatibility.md](../compatibility.md) froze "subcommands, flags, and their
documented behavior" and said nothing about the environment. Their edge
cases were in code comments only: `FORCE_COLOR=0` and `FORCE_COLOR=false` turn
color off, while `FORCE_COLOR=` (set, empty) turns it on; a blank `PAGER`
disables paging; an unset `TERM` counts as `dumb`.

Left unstated, whether changing one of those edges is a PATCH or a MAJOR would
be argued case by case after 1.0, which is the ambiguity
[ADR-030](030-the-policy-is-part-of-the-contract.md) exists to prevent. A CI
job that sets `FORCE_COLOR=0` to keep ANSI out of its logs relies on that edge
as much as on any flag.

Two clarifications of existing wording ride along, found in the same review:

- The deprecation lifecycle says a deprecated surface emits a one-line
  `warning:` on stderr, and quotes `warning: config: unknown rule id` as an
  example. Every config diagnostic, coverage-gap warning and `--only` warning
  has always printed `Warning:` with a capital W. The policy described a
  prefix the tool does not use.
- JSON's `source_file` has been a deprecated alias of `file` since 0.25.0.
  Removing an output field post-1.0 is a MAJOR, so the alias lives through all
  of 1.x. Nothing said so.

**Decision:**

- The five variables, with the semantics `docs/cli.md` states, are part of the
  stable CLI surface from 1.0. Adding a variable is additive; changing or
  removing a documented one follows the same rules as a flag.
- Deprecation warnings use the prefix the tool already prints, `Warning:`.
- `source_file` is removed no earlier than 2.0.

**Consequences:**

- Under ADR-030, adding the variables to the stable surface promises more than
  before, so it is a tightening and a MINOR. The other two are clarifications.
- `FORCE_COLOR`'s `0`/`false` handling and the empty-`PAGER` behavior cannot
  change in a 1.x release without the deprecation lifecycle.
- Nothing in the tool's behavior changes.

**Alternatives considered:**

- *Declare the environment explicitly unstable, like text output.* Rejected:
  these variables change what reaches a terminal or a CI log, not how prose is
  worded, and the conventions they follow (no-color.org, `supports-color`) are
  ones users set once in CI and forget.
- *Normalize the one lowercase `warning:` line instead.* That line, the note
  that an override was merged, is human text outside the contract; the policy
  sentence was the thing that was wrong.
