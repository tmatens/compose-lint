# ADR-026: Read the Sibling `.env`, Because Compose Does

**Status:** Accepted (amends the scope paragraph of
[ADR-025](025-lint-the-merged-configuration.md)).

**Context:** A `.env` beside a Compose file changes what Compose deploys, in two
independent ways, and compose-lint reads neither.

**Interpolation.** `volumes: ["${MOUNT}:/data"]` with `.env` setting
`MOUNT=/var/run/docker.sock` deploys the host control socket. compose-lint
reports zero CL-0001 — its highest-severity rule, silent. Measured over the
corpus, **22.0% of the 4,834 parseable files** carry at least one defaultless
`${VAR}` in a value a rule consumes, and **2,042 volume-mount sources** carry
one: 495 entries across 157 files where the source is *entirely* a variable, and
1,547 across 703 files where it is a segment (`${DATA_PATH_HOST}/typesense:/data`,
graded today at a path that is not the deployed one).

The first group is worse than a missed finding. A whole-source `${VAR}` with no
`.env` is not a configuration Compose ships — it refuses to start:
`${MOUNT}:/data` yields `invalid spec: :/data: empty section between colons`. So
[ADR-023](023-deploy-host-independent-claims.md)'s framing — that interpolations
"resolve to the no-`.env` shipped value" — has no referent here. There is no
shipped value, and the document being reported clean cannot deploy.

**File selection.** `COMPOSE_FILE` replaces discovery entirely, and works from a
`.env` as well as from the shell. It also **suppresses the automatic
`compose.override.yml` merge**, which ADR-025 shipped as unconditional. The
consequence is live, not theoretical. With `compose.yml`, `compose.prod.yml`, an
override setting `privileged: true`, and `.env` containing
`COMPOSE_FILE=compose.yml:compose.prod.yml`:

```
$ docker compose config | grep -c privileged
0                                      # Compose does NOT load the override

$ compose-lint check
files: compose.yml + compose.override.yml
warning: compose.yml: merged compose.override.yml before linting,
         because Compose merges it automatically.        <- false in this project
  3  CRITICAL  CL-0002  Service runs in privileged mode.
     in: compose.override.yml (merged into this run)      <- a file Compose never loads
```

One CRITICAL invented against a document that never runs, the real socket mount
in `compose.prod.yml` still ungraded, and a warning line asserting something
untrue about the user's project. ADR-025 is correct *conditional on
`COMPOSE_FILE` being unset*, and compose-lint could not check that condition.

**The question ADR-025 deferred** was whether a file beside the compose file
counts as project state or host state under ADR-023. ADR-023 excludes `.env`
deliberately, reasoning about the *linting machine's environment*: a compose
file is routinely linted on a machine that is not the machine it deploys to, and
lint-host context leaking into a finding is an unstated guess about the deploy
target. The tension is that `.env` is frequently gitignored — 53.6% of sampled
repositories carrying a `.gitignore` exclude it — so reading it can make the same
commit lint differently on a laptop and in CI, the outcome ADR-023 exists to
prevent.

Four findings resolve it.

1. **ADR-025 already crossed this line, in writing, for the same class of file.**
   Its accepted limitation reads: *"a gitignored overlay is absent from a CI
   checkout, so nothing merges one there."* Divergence between a laptop and a CI
   run, for a conditionally-present sibling file, is shipped behaviour. And the
   overlay is the *rarer* file: sampling 298 repositories from the corpus index
   (GitHub contents API; directory listings and `.gitignore` only, no `.env`
   content was fetched), **6.7% commit a `.env` beside the compose file against
   2.0% committing `compose.override.yml`**.

2. **`.env` has the locality of a sibling, not of the environment.** Compose
   reads it from the *project directory* — the first compose file's parent — not
   the shell's working directory. Verified: a `.env` in the cwd was ignored when
   `-f` named a file elsewhere. ADR-023's four exemplars are all context the user
   cannot see and the tool cannot name. A sibling file is neither.

3. **ADR-023 clause 2 already permits it.** *"Lint-host context may serve only as
   a declared proxy, never as an undeclared input."* The prohibition is on
   *undeclared* inputs. A read announced in the run header is declared by
   construction, and §5 below requires it.

4. **The divergence fails safe.** No finding disappears from CI relative to
   today, because CI does not read `.env` today either. A committed `.env` is
   read on both machines — better, and consistent. A gitignored one leaves CI
   exactly as blind as it is now, while the laptop gets stricter.

**Prior art agrees, and it is not close.** TFLint auto-loads `terraform.tfvars`
and `*.auto.tfvars` and evaluates variables "just like in Terraform"; Checkov
evaluates `.tfvars` found in the scanned directory; kube-linter renders Helm
charts using the `values.yaml` beside `Chart.yaml` by default, with overriding
those values filed as a *feature request*. Each mirrors what its own runtime
auto-loads, and `terraform.tfvars` is gitignored as routinely as `.env` for the
same reason. ShellCheck is the sole refuser — `source` is not followed without
`-x` — and its own documentation attributes that to its origin as a web service
checking scripts pasted by strangers, noting the setting "can safely be enabled
for normal development". That is a hosted-service threat model, not a position on
lint-host independence.

TFLint also converged on §2 below independently: it reads the variable file in
full and then declines to evaluate variables marked `sensitive`, *"to avoid
unintended disclosure"*.

---

**Decision:** compose-lint reads the `.env` beside the Compose file, under one
governing principle:

> **compose-lint uses files as Docker Compose would, when run in that file's
> directory.** If Compose would pull `.env`, so does compose-lint.

The trailing clause is load-bearing. `docker compose -f compose.yml config` does
**not** merge the sibling override; a bare run does, and ADR-025 already chose the
bare-run reading. Naming a file tells compose-lint *which project to look at*, not
that `-f` is being passed. With that clause three behaviours stop being separate
judgement calls and become one rule: the sibling override merge, `.env` read from
the compose file's own directory, and `COMPOSE_FILE` honoured for explicitly named
files.

The principle governs **file selection and resolution**. It does not govern what a
finding claims or what appears in output, and both already have owners — ADR-023's
scope note says so in terms: *"the ADR governs claims, not I/O."*

| layer | rule | owner |
| --- | --- | --- |
| which files are read, what values resolve | do what Compose does | this ADR |
| what a finding claims | true of the document on any plausible deploy host | ADR-023 |
| what appears in output | never echo a `.env`-supplied value | §2 below |

That layering is why §2 and §3 below are not exceptions to the principle. They sit
at a different layer.

1. **`COMPOSE_FILE` and `COMPOSE_PATH_SEPARATOR` select the documents, and
   suppress the override merge.** A `.env` naming a file set replaces discovery as
   Compose replaces it, the named documents merge left to right through the
   existing `merge_documents` fold, and the automatic `compose.override.yml` pair
   is not applied — because Compose does not apply it. Precedence follows Compose:
   an explicit path argument wins, then the shell, then `.env`. The shell form
   stays unread (§6).

2. **Credential rules classify on the written spelling.** A `.env` value never
   turns CL-0020 or CL-0021 on. Without this the tool contradicts itself: CL-0021's
   own fix text offers `DATABASE_URL: postgres://user:${DB_PASSWORD}@host/db` as
   the remediation, so a user who follows it and puts `DB_PASSWORD` in `.env` would
   be flagged by the rule that gave the advice. `${VAR:-default}` defaults are
   unaffected — a default is written in the committed file and ships to every
   clone, so `${PW:-changeme}` keeps firing exactly as it does today. Compose has
   no `sensitive` marker to read, so the carve-out is heuristic (CL-0020's key
   patterns) and errs generous: a false "do not resolve" costs one finding, a false
   "resolve" is the disclosure TFLint's rule exists to prevent.

   *Amended (#646):* the mechanism named here was a `str` subclass carrying the
   written spelling, read by the credential rules and the formatters. It does not
   work, because a subclass does not survive string operations: CL-0021 splits a
   list-form `environment` entry on `=` and CL-0001 splits a volume on `:`, so the
   marker is gone in exactly the places that need it. What replaces it is
   positional and strictly stronger — **a `.env` value is never substituted into an
   `environment:` value at all.** That subtree is the one place in a Compose
   document whose values are payload rather than configuration, and the only rules
   that read one are CL-0020 and CL-0021 (verified: no other rule touches
   `environment` values). Nothing has to remember to unwrap anything, and the
   guarantee holds for the mapping and list spellings alike. It also strengthens
   §5: names referenced only from `environment:` are excluded from the wanted set,
   so a credential the file externalises is never read out of the `.env` at all.

   The output half of the original mechanism is narrowed by the same finding. A
   `.env` value can still reach a report through a rule that grades a deployment
   property — CL-0001 naming the mount source it resolved to — because that *is*
   the finding. What is guaranteed is that nothing under `environment:`, which is
   where secrets live, is ever resolved, so none of it can be printed.

3. **`.env` chains do not expand from the process environment.** Compose resolves
   `FROM_SHELL=${SOME_SHELL_VAR}/tail` against the shell; compose-lint leaves it
   unknowable, exactly as it leaves a defaultless `${VAR}` in the compose file. This
   is not an exception to the principle — the principle is about *files*, and the
   shell is not one. Without it, host state enters through the `.env`, which is the
   ADR-023 failure arriving by a route the "it is a file in the repository" framing
   does not cover. The cost is that such a value stays unresolved and its rule stays
   silent: the same conservative failure the tool already accepts.

4. **`.env` may expand what is graded; for an explicitly named file it may not
   shrink it.** A file named on the command line is always graded, even if
   `COMPOSE_FILE` omits it; `.env` may add documents to its merge, never remove it
   from the run. **In bare discovery `COMPOSE_FILE` replaces discovery exactly as
   Compose does**, with the header stating what it selected.

   This is the one real divergence, and it is narrow — it applies only where the
   user named a file, which is the case Compose has no opinion about, because the
   user asked the linter rather than the runtime. A runtime does what it is told; a
   gate must not let the artifact under inspection define its own scope. It is
   ShellCheck's reason for refusing to let a checked file enable `external-sources`
   for itself: *"the sandbox would be useless if the sandboxed script can disable it
   for itself."* It matters because both first-party integrations pass explicit file
   lists — pre-commit appends filenames, `action.yml` passes `TARGET_FILES` — so
   without it an untrusted contributor could shrink a CI gate's scope by adding one
   file. Entries resolving outside the project directory are refused for the same
   reason.

5. **The read is announced, and only the needed values are retained.** The run
   header names the file and the count (`env: .env (3 values)`), which is what makes
   a laptop-versus-CI difference a diff rather than a mystery, and what satisfies
   ADR-023 clause 2. Only three sets are kept: the fixed `COMPOSE_*` allowlist, the
   variables the Compose documents reference, and whatever those chain to inside the
   `.env`. Everything else is discarded rather than parsed into the run. The bytes
   are still scanned — there is no seeking to one key — so the claim is *"values it
   does not need are discarded"*, never *"we do not read your secrets"*. Filtering
   also permits leniency: a malformed entry nobody needs is skipped rather than
   failing the lint.

6. **`--no-env` opts out**, reproducing the previous behaviour exactly, and the
   flag count stops at two. When `.env` is present and unread, or absent while a
   defaultless `${VAR}` occupies a slot a rule would have consumed, that is stated
   on stderr without touching the exit code — the gap becomes loud instead of
   silent, which is the half of option B worth keeping.

**Out of scope, and deliberately so:** the ambient shell environment,
`COMPOSE_ENV_FILES`, and `--env-file`. A `COMPOSE_FILE` exported in someone's shell
and never written down is host state by any reading, and honouring it would make the
same checkout lint differently depending on who ran the command. `COMPOSE_ENV_FILES`
set *inside* `.env` is not honoured by Compose either (verified), which bounds the
bootstrap and is what makes this implementable at all. A project that genuinely runs
`docker compose --env-file prod.env up` is unreachable from the file; the right answer
there is an explicit key in `.compose-lint.yml`, which is project state the user
declares, not context the tool sniffs.

Also out of scope: **"there is a secret in your `.env`" as a finding.** The
actionable, machine-independent version of that claim is "a secret is committed to
git", which is gitleaks/trufflehog territory and would make compose-lint git-aware to
answer. The advice that *is* actionable already exists and already fires — CL-0020,
pointing at `secrets:` and the `*_FILE` convention.

Also out of scope: **`COMPOSE_PROFILES`.** A `.env` may set it, and doing so
activates a profile (verified), so it changes which services Compose starts — the
same shape of claim `COMPOSE_FILE` makes about which files it loads, from the same
file. It is left unread because compose-lint grades *every* service in a document
today, and skipping the ones whose profile is inactive would trade a false positive
for a silent false negative: 47 CRITICAL findings across the 4,834-file corpus sit on
profiled services, 29 of them CL-0001, in 153 files that would then report nothing at
all. Honouring it would need the treatment §4 gives `COMPOSE_FILE` — never narrowing
what a named file grades — and that has not been designed. Recorded here rather than
decided, because a reader of this ADR will reasonably ask what else was in that file;
the measurement is in [#659](https://github.com/tmatens/compose-lint/issues/659).

**Alternatives considered:**

- **Keep the current rule, document it.** The gap stays exactly as silent as it is,
  across 22% of files, and no documentation fixes the false positive above.

- **Report a coverage signal, read nothing.** ADR-025 already litigated this shape:
  *"an unresolved `include:` is a gap because compose-lint cannot read the file; a
  sibling overlay is a gap because it does not. Being loud about what you cannot do
  is honest; warning about something you could simply do is a placeholder."* It would
  also introduce an exit-2 condition this decision then removes — a pinned pipeline
  turning red, then green, for no net change. The part worth keeping survives as §6.

- **An opt-in flag.** ADR-023 clause 3 names an opt-in flag as the admissible form
  for lint-*host* context, so this was the entailed answer had `.env` been judged host
  state. It was not, and ADR-025 §5 governs instead: *"the default is the
  configuration that runs."* Practically, the one feature this project shipped opt-in
  — profile enrichment, `profiles.enabled` off by default — was withdrawn in ADR-019,
  whose own reasoning notes that being off by default meant a deprecation window
  "protects nobody".

- **A staged rollout, off for one release.** ADR-017 set that precedent and it is
  available. Rejected here: with §2 and §5 the no-disclosure claim is verifiable by
  reading the substitution site and the retention filter, and the one time the pattern
  was used the flag was never flipped. The effort belongs in release notes stating
  what is read, what is classified, and what can never appear in output.

**Consequences:**

- Files clean on a previous release may report findings, including CRITICAL ones —
  the documented MINOR behaviour ([compatibility.md](../compatibility.md)), with the
  documented escape hatches: pin the version, or gate on `--fail-on`.
- The change is bidirectional, as ADR-025's was. Resolving `.env` also *removes*
  findings: roughly 290 corpus CL-0004 "unpinned tag" reports are against
  `image: app:${TAG:-latest}` where a `.env` supplies a pinned tag.
- A shipped false positive is retired: an override merged into a project whose
  `.env` sets `COMPOSE_FILE`, reported under a warning asserting Compose merges it.
- `--no-env` reproduces previous behaviour exactly, including that false merge. That
  is the honest cost of an escape hatch defined as "what the last release did", and it
  belongs in the flag's help text rather than hidden.
- Divergence between a laptop with a gitignored `.env` and a CI checkout without one
  is accepted, on the same terms ADR-025 accepted it for the overlay, and made legible
  by §5's header line rather than argued away.
- `.env` parsing becomes a compatibility surface with Compose, as the merge table
  already is. It is godotenv-shaped — comments, `export` prefixes, quoting, and
  chained expansion (`export SOCK=${BASE}/docker.sock` resolves) — and the
  `COMPOSE_FILE` selection and override-suppression semantics are to be derived from
  the `docker compose` binary in CI the way `tests/test_merge_semantics.py` derives the
  merge table, so a Compose release that changes them fails there rather than silently
  mis-scoping a run.
- compose-lint appears to be the first Compose-specific linter to resolve `.env`; no
  prior art was found in KICS, Checkov or Trivy. That is an absence of evidence rather
  than proof, and it means the semantics above have no reference implementation to
  check against beyond Compose itself.

**Scope:** This ADR amends ADR-025's closing paragraph, which excluded `COMPOSE_FILE`
and `.env` pending this question. It leaves ADR-023 intact: clause 2's declared-proxy
rule is what §5 satisfies, and clause 3's opt-in-flag provision still governs anything
judged to be lint-host context — which, per the Context above, `.env` is not.
