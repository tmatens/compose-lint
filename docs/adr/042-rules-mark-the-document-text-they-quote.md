# ADR-042: Rules Mark the Document Text They Quote

**Status:** Accepted

**Context:** A sibling `.env` is read so that a reference is graded as Compose
deploys it ([ADR-026](026-read-the-sibling-env-file.md)). Its values are often
secrets a CI job wrote, and the report is read by whoever opened the pull
request, so since 0.32.0 a finding shows `${NAME}` and not the value.

That was done by searching the finished message for the value. The search had
to be cautious, because a message is two kinds of text: what the rule quoted
from the document, and the rule's own guidance. A `.env` value of `true` must
not turn `no-new-privileges:true` in the guidance into
`no-new-privileges:${PRIV}`. So the search looked only for the whole value and
its parts split on `:`, `/`, `@`, `=`, `,`, `;` and white space, from 8
characters up, and only for values recorded against the strings of the
finding's own service.

Each of those limits let a value through:

- A rule quotes a piece of what it parsed, cut where its own grammar cuts.
  CL-0021 names a connection string's scheme, which it reads back to the last
  character a scheme cannot hold. A piece cut at `_` is not one the search
  looked for.
- The record was keyed by the substituted string. The parser rewrites a
  relative bind source to the absolute path it names after substituting, and
  the rewritten string was not in the record.
- An `env_file:` target's values are filled in by a second substitution step
  that recorded nothing.
- A note that formatted a path with `repr()` printed the value with its
  backslashes doubled, which is not the text the search looked for.

Four advisories in a row were gaps of this kind. Fixing each one where it was
found does not stop the next.

**Decision:**

1. **A rule marks what it quotes from the document.** Every value a rule puts
   into a finding's `message` or `fix` goes through `_output.quoted()` or
   `_output.inline()`. Both wrap the text in two private-use characters
   (`_doc_text.mark`). `inline()` also writes a line break as `\u000a`, as
   before.

2. **The marks never leave the rule.** `BaseRule` wraps `check` and
   `check_env_file_keys` in every subclass, strips the marks from each
   finding, and records where they were as `message_spans` and `fix_spans`.
   A caller of `rule.check` sees the message as it will be printed. The spans
   are bookkeeping: not serialized, and not part of a finding's equality.

3. **Inside a mark, any run of a value is replaced.** The engine replaces
   every run of 8 or more characters that the marked text shares with a value
   the service used, ignoring case, and in the spellings a formatter can give
   it (a doubled backslash, an escaped quote, a line break as `\u000a`). This
   is safe because marked text is never the rule's own words. `evidence` and
   `target` are document text from end to end and are treated the same way.

4. **Outside a mark, the cautious search stays.** The rule's own words are
   still searched for the whole value and its separated parts. That is the
   second line: a value a rule failed to mark is still replaced in the shapes
   the old search covered.

5. **The record is the substitution step's to keep.** A step that fills in a
   value records it, and a step that rewrites a substituted string records
   the rewritten one. `_resolve_bind_sources` carries the record across its
   rewrite, and the `env_file:` reader records what it filled in, per service
   (`ServiceEnvFiles.substituted`), and tells the diagnostic sinks.

6. **The scope stays per service, by recorded string.** A value is replaced in
   a service's findings when a string of that service, a top-level definition
   its mounts read, or one of its `env_file:` targets used it. A literal one
   service wrote is not rewritten because another service's variable holds
   the same text. Searching each string for values, in place of looking the
   string up, was tried and dropped for that reason: it rewrote the literal.

7. **The 8-character floor stays**, as documented: a shorter value is shown as
   written.

**Tests that hold it in place** (`tests/test_doc_text_marking.py`):

- Every value interpolated into a rule's `message=` is a call to `quoted()` or
  `inline()`, or is on a short list of the rule's own words kept in the test.
  `tests/test_guidance_inline_values.py` already holds `fix=` to `inline()`.
- For every fixture and every string in it, a marker put into that string
  appears in a finding only inside a mark.
- For every fixture and every string in it, a marker supplied through a
  `.env` appears in no output of a run, in text, JSON or SARIF, on stdout or
  stderr. A second marker carries a backslash and both quote characters.
- A control runs the same sweep with the replacement switched off and
  requires it to report a leak.

**Consequences:**

- A new rule that quotes the document without marking it fails the build.
- A SARIF fingerprint is built from `evidence` and `target`. Where those held
  a `.env` value, they now hold the reference, so the fingerprint of such a
  finding changes once on upgrade and no longer changes when the value does.
  A fingerprint built from the value also let a guess at a short secret be
  checked offline; that is closed.
- Inside quoted document text a shared run of 8 characters is enough. A
  service that uses `${DATA}` and also writes a literal path sharing a long
  prefix with its value sees `${DATA}` where the prefix was. That is the
  price of not printing a piece of a secret, and it is confined to the
  service that used the variable.

**Alternatives rejected:**

- **Build every message from the text as written.** A rule quotes pieces it
  parsed out of the resolved value, and a variable can supply the structure
  itself (`${VOL}` holding `/a:/b:ro`), so there is often no written piece to
  quote.
- **A string type that carries its origin.** Slicing, `re` groups and path
  functions return plain strings, so the origin is lost at the first parse.
- **Search more aggressively everywhere.** Without the marks this rewrites the
  guidance, which is why the search was cautious in the first place.
