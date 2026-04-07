# Contributing to compose-lint

Thanks for your interest in contributing. This guide covers setup, code standards, and how to add new rules.

## Development Setup

```bash
git clone https://github.com/tmatens/compose-lint.git
cd compose-lint
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Quality Checks

All four must pass before submitting a PR:

```bash
ruff check src/ tests/          # Linting
ruff format --check src/ tests/ # Formatting
mypy src/                       # Type checking (strict mode)
pytest                          # Tests
```

## Code Standards

- **Python 3.10+** required
- **Type annotations** on all public functions (`mypy --strict`)
- **PyYAML** is the only runtime dependency. Do not add others without discussion.
- **Rules receive plain Python types** (`dict`, `list`, `str`). Never leak parser-specific types into rule code.

## Adding a New Rule

1. Create `src/compose_lint/rules/CL{NNNN}_{snake_name}.py`
2. Inherit from `BaseRule`, use the `@register_rule` decorator
3. Set `id`, `name`, `severity`, `description`, `references`
4. Implement `check(service_name, service_config, global_config, lines)` yielding `Finding` objects
5. Add test file `tests/test_CL{NNNN}.py` with positive and negative cases
6. Add fixture YAML files in `tests/compose_files/`
7. Add rule documentation in `docs/rules/CL-{NNNN}.md`

### Rule requirements

- Every rule must reference OWASP Docker Security Cheat Sheet, CIS Docker Benchmark, or Docker official docs. No opinion-only rules.
- Every finding must be actionable with specific fix guidance.
- Severity must reflect real-world exploitability, not subjective importance.
- Rule IDs are permanent and never reused.

## Pull Requests

- One feature or fix per PR
- All quality checks must pass
- Include tests for any new behavior
- Commit messages should explain *why*, not just *what*

## Questions?

Open an issue if something is unclear.
