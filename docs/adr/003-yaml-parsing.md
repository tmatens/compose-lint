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
