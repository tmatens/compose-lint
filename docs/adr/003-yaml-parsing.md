# ADR-003: YAML Parsing Strategy

**Status:** Accepted

**Context:** The linter needs line numbers in output and must handle YAML anchors, merge keys, and environment variable interpolation. Three libraries were evaluated: PyYAML, ruamel.yaml, and StrictYAML.

**Decision:** PyYAML with a custom `LineLoader` that captures line numbers during construction.

**Alternatives rejected:**

- **ruamel.yaml:** Packaging instability (maintainer has flagged PyPI publication concerns), breaking API changes across versions, and `CommentedMap`/`CommentedSeq` types would leak into rule code.
- **StrictYAML:** Does not support flow-style mappings or anchors/aliases, which are valid in compose files.

**Rationale:**
- PyYAML is the most widely installed YAML library in the Python ecosystem with no packaging concerns.
- Compose files use YAML 1.1 in practice. PyYAML's YAML 1.1 support matches Docker's own parser behavior.
- Line numbers are captured via a `LineLoader(SafeLoader)` subclass (~30 lines). Parsed output is plain `dict`/`list`, so rules have no parser coupling.
- The parser can be swapped later without touching rule code since the interface is `load_compose(path) -> (data, lines)`.

**Known divergences from Compose's loader:**

Two documents Compose accepts are refused by this parser. Both were measured against
Docker Compose 5.4.0 and neither occurs in the 5,417-file corpus, so both are recorded
as boundaries rather than tracked as defects.

- **Multi-document streams.** Compose loads a `---`-separated stream and merges every
  document into one project — a service defined only in the second document is part of
  the deployment, in either document order. `LineLoader` uses `yaml.load`, so
  compose-lint refuses the file with `Invalid YAML: expected a single document in the
  stream` and exit 2. A leading `---` start marker and a trailing `...` end marker are
  both handled and unaffected. Corpus incidence: 0 of 5,417 — 127 files contain a `---`
  line, but every one of those markers sits inside a block scalar rather than opening a
  document.
- **Non-UTF-8 encodings.** A UTF-16-encoded Compose file parses cleanly for Compose and
  is refused here with `Invalid encoding: file is not valid UTF-8` and exit 2. A UTF-8
  BOM and CRLF line endings are both handled and produce unchanged findings; a file
  with an invalid UTF-8 byte is refused by *both* tools. Corpus incidence: 0 of 5,417.

Both fail loudly at exit 2 with an accurate message, which is what keeps them
boundaries: a stack in either shape is unlintable rather than mis-linted, so neither
can produce the silent false negative ADR-023 treats as the worst outcome. That is the
whole reason they are cheap to leave open — a reader is told, and a CI gate stops.
