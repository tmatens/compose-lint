# ADR-023: Claims Are Deploy-Host-Independent

**Status:** Accepted

**Context:** A compose file is routinely linted on a machine that is not the
machine it deploys to — a Windows or macOS laptop editing files headed for a
Linux server, a CI runner linting a checkout that production deploys from a
different path. The deploy target is not present in the document, so any
lint-host context that leaks into a finding is an unstated guess about it.

The codebase already followed this principle in four places, each chosen
deliberately: `${VAR:-default}` interpolations resolve to the no-`.env`
shipped value and never read the linting machine's environment;
`include:`/cross-file `extends:` are refused loudly as coverage gaps rather
than resolved through the lint host's filesystem; bind-source resolution is
lexical, never following the lint host's symlinks (verified against Compose
29.4.3); and `~user` sources are left unclaimed rather than asserting a path
from the linting user's environment for another account's home.

One layer violated it: `_resolved_bind_source` did its relative and `~` math
through the host's path semantics (`os.path.join`/`normpath`/`expanduser`).
Issue #588 surfaced the consequence when the OS smoke first ran on Windows:
a `..`-climb resolved to `C:\` instead of `/`, so the climb-to-root claims
(CL-0001 whole-root, CL-0025 root-equivalent) — the linter's highest-severity
territory — silently failed to fire. Silent false negatives are the worst
failure mode a security linter has. The same host-semantics assumption was
also wrong in the mirror direction: Windows path math describes a deployment
that never happens when the file deploys to Linux.

**Decision:** A finding must be true of the *document* on any plausible
deploy host. Concretely:

1. **Resolution is lexical segment math in POSIX notation on every
   platform** (`_lexical_join`): `..` saturates at the anchor of whatever
   filesystem contains the compose file — `/` on a POSIX host, the drive or
   UNC share root on Windows — and the result is spelled `/`-rooted either
   way, because "climbs to the root of the containing filesystem" is the
   deploy-host-independent fact the rules grade. On POSIX lint hosts the
   output is byte-identical to the previous `normpath(join(...))` behavior
   (verified: zero findings changed over the 5,417-file corpus).
2. **Lint-host context may serve only as a *declared proxy*, never as an
   undeclared input.** One proxy remains, documented at its site: the
   compose file's position on the linting machine stands in for its deploy
   position (CL-0013's `/home` membership). Where a proxy has no sensible
   value, nothing is claimed rather than something wrong.

   *Amended (#602):* the second original proxy — expanding `~` against the
   linting user's home, POSIX lint hosts only — is retired. `~` sources are
   left as written on every platform and CL-0013 claims the *spelling*
   (`~/.ssh` is the deploying user's credential directory, whoever that
   is), which is strictly stronger: reports stop asserting a lint-host
   username, and the claims fire identically on every lint platform.
   Verified: zero findings changed across the 5,417-file corpus.
3. **Future rules inherit the test:** a rule that would read the lint
   host's environment, check whether a bind source exists on disk, or
   follow document references through the lint host's filesystem is
   claiming a deploy-host fact it cannot know. Such context is admissible
   only as a new declared proxy or an explicit opt-in flag.

**Consequences:** Windows lint hosts regain the climb-to-root claims and
produce the same `/`-rooted notation as every other platform (a visible
output change for relative sources on Windows, shipped pre-1.0 while the
machine-readable output contract is still open to change — ADR-015). Tilde
sources are claimed only on POSIX lint hosts. The `/home`-membership proxy
keeps its known imprecision (lint position ≠ deploy position) as an accepted,
documented trade-off. Out of scope: presentation and operational host context
(color env vars, SARIF artifact URIs, config discovery, `fix` writing files)
— the ADR governs claims, not I/O.
