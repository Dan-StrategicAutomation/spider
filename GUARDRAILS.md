# GUARDRAILS.md — SPIDER

This file defines the safety, quality, and execution boundaries that apply when working on SPIDER. It complements `AGENTS.md` by focusing on risk control, verification discipline, and failure handling.

## Purpose

- Protect the integrity of the codebase.
- Prevent unsafe, hidden, or unauditable changes.
- Keep agent behavior aligned with SPIDER’s DSPy-native architecture.
- Ensure all work is reviewable, testable, and traceable.

## Safety boundaries

- Never bypass scope checks.
- Never run exploitation or post-exploitation without explicit human approval.
- Never assume a target is in scope unless validated.
- Never weaken sandbox isolation.
- Never add hidden network access, background processes, or implicit side effects.
- Never write to host locations from tools or agent code unless explicitly required and approved.
- Never introduce fallback logic that masks schema, topology, or prompt mismatches.
- Never store secrets, tokens, or credentials in source control, logs, tests, or examples.

## Change discipline

- Make the smallest change that solves the problem.
- Do not expand scope beyond the requested task.
- Do not refactor unrelated code while fixing a bug.
- Prefer direct fixes to architecture or schema alignment instead of defensive wrappers.
- Preserve existing naming, contracts, and public interfaces unless a change is explicitly requested.
- If a change affects multiple layers, update them together rather than adding compatibility hacks.

## Verification rules

- Add or update tests for every behavior change.
- Verify the narrowest affected path first.
- Run targeted tests before broader suites.
- Do not mark work complete until the relevant checks pass.
- Never commit untested code.
- For failures, fix the root cause rather than suppressing errors or relaxing assertions.

## DSPy-specific guardrails

- Use `dspy.Refine` for retries and quality improvement.
- Do not implement manual retry loops around model calls.
- Do not post-process model output to force validity.
- Use Pydantic models for structured data in DSPy signatures.
- Keep shared schemas centralized in `src/spider/schemas.py`.
- Ensure node signatures, prompts, and topology are aligned before changing orchestration logic.
- If a result is malformed, fix the signature or prompt instead of adding normalization code.

## Tooling guardrails

- All tools must be registered through the central adapter.
- All tools that take a target must validate scope before execution.
- All tool output must be JSON-formatted strings.
- All tools must have docstrings and type hints.
- Tool execution must be logged with enough detail to audit the action.
- Tool behavior must be deterministic enough to test locally.
- Avoid shelling out in ways that hide commands, suppress errors, or obscure audit trails.

## Testing guardrails

- Unit tests must mock external services, model calls, and live tools.
- Integration tests must use only sanctioned lab targets.
- Do not rely on the public internet in tests.
- Do not add flaky timing-based assertions unless there is no alternative.
- Prefer explicit fixtures and deterministic inputs.
- Keep regression tests close to the behavior they protect.

## Git and review guardrails

- Keep pull requests small and focused.
- Include tests with the code change.
- Avoid noisy formatting-only changes unless requested.
- Write commit messages that explain the purpose of the change.
- Do not rewrite shared history without explicit instruction.
- Preserve auditability in diffs, commit messages, and test output.

## Failure handling

- If a rule conflicts with a requested change, stop and clarify.
- If a design issue is discovered, fix the source of the mismatch instead of layering workarounds.
- If a task cannot be completed safely, explain the blocker and propose the safest alternative.
- If there is uncertainty about scope or safety, default to the stricter interpretation.

## Escalation triggers

Escalate to a human reviewer when any of the following are true:
- A change could cause unintended network access.
- A change touches exploit execution, payload delivery, or post-exploitation.
- A change affects scope validation or sandbox boundaries.
- A change modifies retry behavior, output validation, or schema enforcement.
- A change could weaken audit logging or remove traceability.
- A change introduces a compatibility fallback that hides an underlying defect.

## Recommended workflow

1. Read `AGENTS.md` first.
2. Read the relevant design or safety doc.
3. Identify the minimal code change.
4. Add or update tests.
5. Implement the change.
6. Run targeted checks.
7. Expand to the broader suite if needed.
8. Review the diff for hidden side effects before finishing.

## Companion relationship

- `AGENTS.md` defines how agents should operate.
- `GUARDRAILS.md` defines what they must not cross.
- If the two files ever appear to conflict, treat the stricter safety interpretation as the default until a human resolves the ambiguity.