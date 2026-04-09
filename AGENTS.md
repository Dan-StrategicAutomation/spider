# AGENTS.md — SPIDER

This file defines the mandatory operating rules for AI coding agents working on SPIDER.

SPIDER is a DSPy-native penetration testing framework. Prefer DSPy primitives, Pydantic schemas, audited tool wrappers, and explicit safety controls over ad hoc Python logic.

## How to work here

- Make the smallest correct change that satisfies the request.
- Preserve existing architecture unless the task explicitly requires a refactor.
- Read the relevant docs in `docs/` and `PLAN.md` before changing design-sensitive code.
- When requirements are unclear, ask a concise clarifying question before editing.
- Prefer small, reviewable diffs and focused commits.
- Use Python best practices: type hints, docstrings, f-strings, explicit imports, and module-level constants where appropriate.

## Core constraints

- Never use `from __future__ import annotations`.
- Never use raw `str`, `float`, `list`, `dict`, or `tuple` in DSPy signatures for structured outputs or inputs.
- Always use Pydantic `BaseModel` for structured DSPy `InputField` and `OutputField` data.
- Never post-process LLM output to “fix” bad structure.
- Use `dspy.Refine(module, N, reward_fn, threshold)` for retries, self-improvement, and quality gating.
- Never write Python retry loops such as `for attempt in range(...)` around model calls.
- Use f-strings only.
- Keep shared schemas in `src/spider/schemas.py`.
- Use `pydantic-settings` for configuration.
- All tools must return JSON strings.
- Every tool must have a docstring and complete type hints.
- Every tool that accepts a target must enforce scope checking before execution.
- All exploitation and post-exploitation require human approval via HITL.
- All tool execution must remain inside the sandbox.
- Audit every action immutably.
- Never mask bad topology or prompt design with fallback logic that hides root causes.

## Python development flow

1. Write or update the test that proves the expected behavior.
2. Implement the smallest code change needed.
3. Run the narrowest relevant checks first.
4. Fix failures at the source, not with wrappers or silent fallbacks.
5. Run the broader suite only after the targeted checks pass.
6. Keep the final diff minimal and readable.

## DSPy rules

- The first node with no dependencies must use `dspy.ReAct`.
- Non-tool nodes should use `dspy.Predict` or `dspy.ChainOfThought`.
- Wrap modules that need quality improvement with `dspy.Refine`.
- Use low temperature for planning and orchestration, higher temperature only for controlled exploration.
- Keep signature and topology names aligned across Weaver, Runner, nodes, and schemas.
- If a node fails, fix the signature, prompt, or topology rather than adding positional fallback logic.

## Schema rules

- Put all shared data models in `src/spider/schemas.py`.
- Keep node-specific topology models close to the node if they are not shared.
- Use explicit field types, validators, and clear model names.
- Prefer nested Pydantic models for structured findings, plans, and reports.
- Do not add ad hoc models inside random modules when a shared schema already exists.

## Tool rules

- Register tools through the central adapter in `src/spider/tools/adapter.py`.
- Enforce scope checks before the tool does any work.
- Log tool invocation, target, parameters, and outcome.
- Return JSON-serializable strings only.
- Include a concise docstring that explains what the tool does and what the JSON output contains.
- Avoid hidden side effects and environment-dependent behavior.

## Safety rules

- Recon and enumeration may run autonomously.
- Exploitation, payload delivery, and post-exploitation require explicit human approval.
- Assume all targets are out of scope until validated by the scope guard.
- Treat sandbox boundaries as mandatory, not optional.
- Never modify the host filesystem from a tool or agent action unless the task explicitly allows it.

## Testing rules

- Use `uv` for all project commands.
- Never commit code that has not been tested.
- Unit tests must mock LLM calls and external tools.
- Integration tests may only run against lab targets.
- Add or update tests for every behavior change.
- Prefer file-scoped or module-scoped tests first, then run the wider suite.

## Commands

```bash
uv sync --all-extras
uv run pytest tests/ -q
uv run pytest tests/test_scopes/ -q
uv run pytest tests/test_sandbox/ -q
uv run pytest tests/test_tools/ -q
uv run pytest tests/test_nodes/ -q
uv run pytest tests/test_integration/ -q
uv run ruff check src/ tests/
uv run ruff format src/ tests/
uv run spider
```

## GitHub flow

- Keep branches focused on one change.
- Use conventional commits when possible.
- Open small pull requests with a clear summary.
- Include tests in the same PR as the code change.
- Never force-push shared branches unless explicitly instructed.
- Before merging, ensure linting, tests, and formatting are green.
- Prefer commit messages that explain the user-visible effect or the architectural reason for the change.

## Code style

- Use explicit, readable code over clever code.
- Prefer small functions with one responsibility.
- Keep module boundaries clean.
- Avoid duplicated logic; extract helpers when the same pattern appears in multiple places.
- Use structured logging instead of print statements in production code.
- Preserve type safety and avoid casts unless there is no better option.
- Favor dataclasses or Pydantic models for structured state rather than loose dictionaries.

## Documentation map

- `docs/architecture.md` — system architecture and graph topology.
- `docs/dspy-engine.md` — Weaver, Runner, Refine, and self-evaluation.
- `docs/tools.md` — tool catalog and adapter patterns.
- `docs/parallelism.md` — wave-based execution and async behavior.
- `docs/advanced-dspy-design.md` — GEPA, MIPROv2, and optimization strategy.
- `docs/safety.md` — scope guards, HITL, sandboxing, and audit logging.
- `docs/testing.md` — testing methodology and lab setup.
- `docs/tui.md` — terminal UI specification.
- `docs/index.md` — documentation entry point.
- `PLAN.md` — architecture plan and implementation phases.
- `README.md` — public overview.

## Project layout

- `src/spider/engine/` — orchestration and DSPy control flow.
- `src/spider/nodes/` — node modules and signatures.
- `src/spider/tools/` — tool wrappers and adapter logic.
- `src/spider/sandbox/` — scope guard, HITL, audit, and Docker execution.
- `src/spider/intelligence/` — CVE and exploit intelligence.
- `src/spider/tui/` — terminal UI.
- `src/spider/testing/` — lab integration helpers.
- `tests/` — automated test suite.
- `lab/` — Docker Compose test lab.
- `docs/` — long-form documentation.

## When stuck

- Check the nearest doc first.
- Prefer the simplest safe implementation.
- If the design is unclear, propose a short plan and ask for confirmation.
- If you discover a bug unrelated to the request, report it briefly instead of expanding scope.

## Antigravity usage

- Treat this file as the primary project contract for agent behavior.
- Follow approval boundaries before destructive, exploitative, or environment-changing actions.
- Keep work isolated to the requested scope.
- Use documentation and tests as the source of truth.
- Do not invent fallback behavior when a rule, schema, or topology mismatch should be fixed directly.