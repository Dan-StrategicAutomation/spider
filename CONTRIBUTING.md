# Contributing to SPIDER

Thank you for helping improve SPIDER. SPIDER is a DSPy-native penetration testing
framework, so contributions must preserve the project's safety controls as well
as its developer experience.

## Ground Rules

- Use SPIDER only for lawful, authorized security testing.
- Do not include secrets, real customer data, private target details, exploit
  output from unauthorized systems, or personally identifiable information in
  issues, pull requests, tests, fixtures, screenshots, or logs.
- Keep changes small and reviewable.
- Add or update tests for every behavior change.
- Unit tests must mock LLM calls and external tools.
- Integration tests may only target the local lab or systems where you have
  written authorization.

## Development Setup

SPIDER uses `uv` for project commands.

```bash
uv sync --all-extras
cp .env.example .env
uv run pre-commit install
```

Edit `.env` so that `SPIDER_ALLOWED_TARGETS` only contains lab targets or systems
you are authorized to assess.

## Required Checks

Run the narrowest relevant tests first, then broader checks before opening a PR.

```bash
uv run pytest tests/ -q
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
```

Focused suites:

```bash
uv run pytest tests/test_safety/ -q
uv run pytest tests/test_tools/ -q
uv run pytest tests/test_engine/ -q
uv run pytest tests/test_intelligence/ -q
```

Integration tests are lab-only:

```bash
uv run pytest tests/test_integration/ -q
```

## Architecture and Safety Requirements

Before changing design-sensitive code, read the relevant documentation in
`docs/` and the planning material in `plan/`.

- Keep shared schemas in `src/spider/schemas.py`.
- Use Pydantic models for structured DSPy inputs and outputs.
- Register tools through `src/spider/tools/adapter.py`.
- Every tool must return a JSON string, include complete type hints, and have a
  docstring explaining its JSON output.
- Every tool that accepts a target must enforce scope checking before execution.
- Recon and enumeration may run autonomously inside scope.
- Exploitation, payload delivery, and post-exploitation require HITL approval.
- Do not add fallback logic that hides topology, schema, prompt, or safety
  failures.

## Pull Request Checklist

Before requesting review, confirm:

- [ ] Tests were added or updated for the behavior change.
- [ ] `uv run pytest tests/ -q` passes, or any skipped suite is explained.
- [ ] `uv run ruff check src/ tests/` passes.
- [ ] `uv run ruff format --check src/ tests/` passes.
- [ ] No secrets, PII, real target data, or private engagement artifacts are
      included.
- [ ] Safety controls remain enforced for scope, sandboxing, HITL, and audit
      logging.
- [ ] Documentation was updated when user-facing behavior changed.

## Developer Certificate of Origin

By contributing, you certify that you have the right to submit the work under
this project's Apache-2.0 license. Prefer signed-off commits:

```bash
git commit -s
```
