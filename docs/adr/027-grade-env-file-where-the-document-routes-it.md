# ADR-027: Grade an `env_file:` Where the Document Routes It

**Status:** Accepted (narrows one paragraph of
[ADR-026](026-read-the-sibling-env-file.md); leaves ADR-023 intact).

**Context:** [#665](https://github.com/tmatens/compose-lint/issues/665) opened on
a silent false negative — a credential moved from `environment:` into an
`env_file:` reaches the identical container process environment and CL-0020 and
CL-0021 both go quiet. [#669](https://github.com/tmatens/compose-lint/pull/669)
shipped the half that needed no decision: a service naming an `env_file:` now
says so on stderr, in all three spellings, with no finding, exit-code or
machine-readable change. The gap is loud. It is not closed.

What is left is one question, and it is narrower than the issue title suggests.
Reading the file is not in dispute — `env_file:` is *named in the document under
lint*, which makes it the easiest of the three sibling-file cases to justify
under ADR-026's governing principle. The dispute is whether the credential rules
may fire on what is inside, because that collides with a decision ADR-026 made
six lines below its §2 passage:

> Also out of scope: **"there is a secret in your `.env`" as a finding.** The
> actionable, machine-independent version of that claim is "a secret is
> committed to git", which is gitleaks/trufflehog territory.

So this is a request to *move* a recorded boundary, not to fill a gap in one.

**The boundary is not adjacent to `env_file:`. It is the same file.** Over the
5,417-file corpus, 414 files (7.64%) name an `env_file:` across 867 services and
924 path references. **496 of those references — 53.7% — name `.env` itself**,
in 267 files, which is 64.5% of every file that uses the feature. The majority
case for this decision is a file compose-lint already opens, already parses with
`parse_env`, and already refuses to let the credential rules read.

---

## What Compose actually does

Derived from the binary (Compose 5.4.0, client-side, no daemon), because
`env_file:` shares godotenv's grammar with `.env` and diverges from it in ways
no prose says out loud:

| behaviour | Compose | same as `.env`? |
| --- | --- | --- |
| path anchor | the Compose file's own directory | yes |
| `${VAR}` inside the path | resolved, from `.env` | n/a |
| `../` and absolute paths | accepted | n/a |
| missing file, `required` (the default) | **the run is refused, exit 1** | no |
| missing file, `required: false` | skipped, exit 0 | n/a |
| grammar (quoting, `export`, comments, `$$`) | godotenv | yes |
| bare `KEY` with no `=` | sourced from the shell; **omitted when unset** | no — `.env` ships empty |
| `${VAR}` inside a value | earlier keys in the same file, then earlier `env_file:`s, then `.env`, then **the shell** | yes |
| forward reference | empty | yes |
| `format: raw` | no interpolation, no quote stripping | n/a |
| malformed line | the whole run is refused | yes |
| precedence | `environment:` beats every `env_file:`; a later file beats an earlier one | n/a |
| **where the values go** | **the container's process environment, and nowhere else** | **no** |

The last row is the load-bearing one and it was measured, not assumed. An
`env_file:` key does **not** resolve a `${VAR}` in the Compose document:
with `TAG=1.2.3` in `x.env` and `image: "alpine:${TAG}"` in the document,
`docker compose config` emits `image: 'alpine:'` and warns that `TAG` is not
set. The value reaches exactly one destination.

## Decision

CL-0020 and CL-0021 classify the contents of an `env_file:`, under one addition
to ADR-026's principle:

> **A value is graded where the document routes it.** `env_file:` is a
> declaration that every key in the named file becomes a literal in a named
> service's process environment. `.env` on its own declares nothing of the kind.

That sentence is what settles the gitleaks boundary, and it settles it without
contradicting ADR-026:

1. **§2 stays exactly as written.** A `.env` value is still never substituted
   into an `environment:` value. This decision substitutes nothing — it grades a
   file the document *routes* into the environment, at the site of the routing.

2. **The discriminator is destination, not filename**, and destination is a
   property of the document under lint rather than of the lint host. A `.env`
   value's destination is unknown, and by §2's own construction is provably not
   `environment:`. An `env_file:` value has one destination, verified above.

3. **The claim is not the one line 224 excluded.** Line 224 excluded "a secret
   is committed to git", which is a fact about a repository. CL-0020's claim is
   "this credential is a literal in the container's process environment,
   readable through `docker inspect`, `/proc/<pid>/environ`, `docker compose
   config`, process listings and CI logs" — a fact about the deployed
   configuration, true whether or not the file is in git, and already the
   verbatim grounding in the rule's own documentation.

**`env_file: .env` is the strongest case for this, not the awkward one.** ADR-026
§2 exists because CL-0021's fix text offers
`DATABASE_URL: postgres://user:${DB_PASSWORD}@host/db` as the remediation, so
firing on a `.env` that supplies `DB_PASSWORD` would flag the user for taking the
rule's own advice. Adding `env_file: .env` *undoes that advice* — the credential
is back in the process environment, by a different route, and `docker compose
config` prints it. §2 protects the fix; this ADR fires only where the fix was
cancelled. 267 corpus files are in that shape.

Neither CL-0020 nor CL-0021 names `env_file:` as a remediation — checked: no
mention in either rule doc, and the only `env_file` occurrences under `docs/` are
three unrelated ADRs and one example Compose file. So unlike the §2 case, nothing
here punishes a documented fix.

## The ADR-023 objection, answered

The objection recorded in #665 is the real one: `env_file:` targets are usually
absent from the repository, so the same checkout lints differently on a laptop
and in CI — and, unlike `.env`, there appeared to be no conservative middle
state, only *absent → nothing* versus *present → findings*.

There is one, and it is stronger than the state ADR-026 had to settle for.

**Absent and required — which is the default — means the configuration does not
deploy.** `docker compose config` exits 1: `env file .../nope.env not found`.
There is no shipped configuration to grade, which is precisely the reasoning
ADR-026 used about a whole-source `${VAR}` with no `.env`: *"There is no shipped
value, and the document being reported clean cannot deploy."* compose-lint says
so — the #669 note, narrowed to the case where the file was actually unreadable —
and grades nothing, which is what it does today. **CI loses nothing relative to
this release.**

That is not a corner case. Sampling 218 corpus files that name an `env_file:`
(GitHub contents API; directory listings and `.gitignore` only — **no env-file
content was fetched**, matching ADR-026's sampling for the same question):

| | targets | files |
| --- | --- | --- |
| committed beside the Compose file | 137 / 456 (30.0%) | 79 / 218 have at least one |
| absent from the repository | 319 / 456 (70.0%) | 127 / 218 have none present |
| of those absent, `required` | 306 / 319 (95.9%) | — |
| unresolvable or outside the project dir | 30 / 456 | — |

So for roughly seven named targets in ten, a fresh clone cannot `docker compose
up` at all, and the honest report is "this document is incomplete", not "this
document is clean". For the other three in ten the file is committed and the run
is *identical* on a laptop and in CI — strictly better than today's silence on
both machines.

ADR-026's fourth resolving finding transfers verbatim: **the divergence fails
safe.** No finding disappears from CI relative to today, because CI does not read
these files today either. A committed target is read on both machines. An absent
one leaves CI exactly as blind as it is now, while the laptop gets stricter and
says which file it read.

## What this means concretely

1. **Which files.** Every path in every spelling (bare string, list of strings,
   list of mappings with `path:`), resolved relative to the Compose file's own
   directory, with `${VAR}` in the path resolved from `.env` as Compose resolves
   it. A path that stays unresolved is not read and is noted.

2. **What is read.** `parse_env`, plus the three places `env_file:` diverges from
   `.env`: a bare `KEY` is Compose's *shell* lookup and is therefore left
   unresolved rather than treated as empty; `format: raw` disables interpolation
   and quote processing; a missing `required` file is the note above rather than
   a parse failure. No process-environment fallback, for ADR-023's reason and by
   ADR-026's divergence 1 — a value the tool cannot honestly build stays out of
   the rules' hands. `MAX_ENV_BYTES` and `_safe_read` apply unchanged.

3. **What consumes it.** CL-0020 and CL-0021 only, on keys not shadowed by the
   service's own `environment:` (Compose's precedence, so a key in both is graded
   once, at the spelling that wins). Nothing else — verified that no other rule
   reads `environment` values, and verified above that these keys never reach
   document interpolation.

4. **ADR-026 §5's retention filter does not apply, and the honest claim changes.**
   For `.env`, only the values a run needs are kept. Here every key is a graded
   key, because every key is deployed. The statement that must appear in the docs
   is "every key in an `env_file:` is examined", never "we do not read your
   secrets".

5. **No disclosure — and the mechanism is not the one #665 named.** That
   comment argued the rules are safe because there is no `evidence` field. There
   is: both rules set it (`CL0020_credential_env_keys.py:277`,
   `CL0021_connection_string_credentials.py:212`), and both set it to the **key
   name**. The guarantee is what the field holds, not that it is absent, and it
   is the stronger claim of the two because it is a property of the code rather
   than of a schema. No value has ever reached a message, JSON, SARIF or code
   scanning, and nothing here adds a path by which one could.

6. **Attribution.** A finding on an `env_file:` key carries `source_file` set to
   the file as written and `line` set to the line within it. That extends
   `source_file`, whose docstring currently scopes it to a run that merged more
   than one *document*; the extension is the same claim in both cases — the
   evidence is not in the file named in the report — and ADR-025 already verified
   that naming a file absent from the repository is safe for SARIF. `evidence`
   (the key) keeps the finding's identity stable under ADR-024, so the
   fingerprint does not move if the prose does.

7. **Paths outside the project directory are refused, and noted.** Compose reads
   them; compose-lint does not. ADR-026 §4 refuses out-of-project `COMPOSE_FILE`
   entries because a document must not redefine the gate's scope; the reason here
   is different but no weaker — an `env_file: /home/runner/.aws/credentials`
   added in a pull request would put lint-host key *names* into a report, which
   is the ADR-023 leak arriving through the one field these rules do emit
   (verified that Compose accepts both an absolute path and a `../` climb). 20
   corpus files name one.

8. **`--no-env` covers it, and widens.** ADR-026 §6 stopped the flag count at
   two and this does not move it. The flag's help text is currently specific —
   *"ignore a `.env` sitting beside the Compose file"* — and becomes "do not read
   the env files beside this one"; its §6 promise, that it reproduces the previous
   release's behaviour exactly, is what makes the widening obligatory rather than
   optional, since after this change the previous behaviour includes the
   `env_file:` read. A second flag was considered and rejected on ADR-026's own
   reasoning.

9. **`label_file:` is decided, not implemented.** It is the same file-reference
   shape and is entirely unknown to compose-lint (0 hits in `src/`, 0 in
   `tests/`). No rule reads `labels:`, so nothing is missed today. The principle
   above already says what happens when one does: a `label_file:` value is graded
   wherever a `labels:` value would be, by the same destination test, and until
   then it stays unread and unnoted because there is nothing it could silence.

## Alternatives considered

- **Keep the #669 note and close #665.** ADR-025 already ruled on this shape, in
  its own words: *"an unresolved `include:` is a gap because compose-lint cannot
  read the file; a sibling overlay is a gap because it does not. Being loud about
  what you cannot do is honest; warning about something you could simply do is a
  placeholder."* `env_file:` is the second kind. Choosing this means accepting a
  permanent silent false negative — ADR-023's worst failure mode — in a rule whose
  own documentation states the harm.

- **Read the files but classify nothing.** Nothing else consumes an `env_file:`
  value — verified, twice over — so this is a no-op with a header line.

- **Fire on named targets but exempt `.env`.** Filename-based, so it exempts
  64.5% of the population, and it exempts precisely the case where CL-0021's
  recommended fix has been undone. It also re-introduces the mistake §2's
  amendment fixed: a rule that depends on where a value came from rather than on
  where it goes.

- **An opt-in flag.** ADR-023 clause 3 names an opt-in flag as the admissible
  form for lint-*host* context. An `env_file:` is named in the document, so it is
  not that; ADR-026's own precedent (and ADR-019's withdrawal of the one opt-in
  feature this project shipped) applies unchanged.

- **Extend ADR-026 line 224 to cover `env_file:` explicitly.** Coherent, and it
  is the status quo made deliberate. Rejected because line 224's actual argument
  — that the actionable form of the claim is a git-hygiene one — is false for a
  file the document routes into a container.

## Consequences

- Files clean on a previous release may report new CL-0020 and CL-0021 findings,
  including on a `.env` compose-lint already reads. The documented MINOR
  behaviour ([compatibility.md](../compatibility.md)), with the documented escape
  hatches: pin the version, or gate on `--fail-on`.
- **The corpus cannot measure this, but a reconstruction can, and did.** The
  corpus is filename-filtered (`scripts/corpus/fetch.py:29`) so it holds no
  sibling files: a corpus run reports every target absent and produces notes
  rather than findings. What it can measure is the population that newly has a
  file opened — 414 files, 867 services, 924 references, 496 of them a `.env`
  already being read — and not the finding count.

  That was measured by rebuilding the projects instead: fetching each named
  target its repository actually commits, staging it beside the compose file,
  and running the rules twice against the same parsed document, with and without
  `env_files`. Of 163 projects whose env file could be read, **90 (55%) gained at
  least one finding, 538 in total — 491 CL-0020 and 47 CL-0021** across 127
  distinct key names. 83.6% of the values are opaque literals; most of the rest
  are placeholders (`changeme`, `your_*_here`), which fire by design —
  [#561](https://github.com/tmatens/compose-lint/issues/561) settled that
  `AUTH_TOKENS: your_token_here` is a finding.

  **The number is a floor on a biased sample.** Only 44% of named targets are
  committed to their repository at all; the rest are gitignored, which is where
  live credentials concentrate and where no measurement reaches. The placeholder
  rate is itself evidence of that bias — a project that commits an env file is
  likelier to be committing an example one. The reconstruction is a scratch
  measurement and is deliberately not part of `scripts/corpus/`: a fetcher that
  pulls credential-bearing files is not something this repository should ship.
- ADR-026 line 224 is narrowed, not deleted. "There is a secret in your `.env`"
  remains out of scope. "There is a credential your document routes into a
  container's process environment" is in scope, and always was — only its
  implementation stopped at the document boundary.
- The `env_file:` grammar becomes a second compatibility surface with Compose,
  including the three divergences from `.env` above. It belongs in
  `tests/test_env_semantics.py`, which already re-derives the `.env` grammar from
  the binary on every run, so a Compose release that changes either one fails
  there rather than silently mis-reading a user's stack.
- The `required:`/absent split becomes user-visible: an absent required target is
  a statement that the project does not deploy from this checkout, which is new
  information the note did not previously carry.
- A run's stderr gets longer on the 7.64% of files that use the feature: one line
  per file read, plus the existing note narrowed to the unread cases.

**Scope:** This ADR amends the "secret in your `.env`" paragraph of ADR-026 and
nothing else in it — §§1–6 stand, and §2 in particular is strengthened rather
than weakened. ADR-023 is untouched: clause 2's declared-proxy rule is what the
announced read satisfies, and clause 3 still governs anything judged to be
lint-host context, which a file named in the document is not. Out of scope, as in
ADR-026: the ambient shell environment, `COMPOSE_ENV_FILES`, `--env-file`, and
`--project-directory`.
