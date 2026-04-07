# ADR-001: Python as Implementation Language

**Status:** Accepted

**Context:** The tool could be written in Python, Go, Rust, or TypeScript.

**Decision:** Python.

**Rationale:**
- The primary audience (DevOps engineers, homelabbers, small teams) overwhelmingly has Python available. `pip install` is the lowest-friction install path.
- Docker Compose files are YAML. Python has mature YAML parsing libraries with full spec compliance.
- Python lowers the contribution barrier. Rules are readable functions, not Rego policies or Haskell AST transforms.

**Tradeoffs:** Slower than Go for large-scale scanning. Acceptable because compose files are small (typically <500 lines) and scan time will be <1 second regardless.
