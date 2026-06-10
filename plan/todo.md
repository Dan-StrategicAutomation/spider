# SPIDER — TODO

Actionable tasks derived from the codebase review and PLAN.md. Grouped by priority.
Each task includes the exact files to modify, acceptance criteria, and test commands.

---

## Legend

- `[ ]` — Not started
- `[/]` — In progress
- `[x]` — Complete

---

## P0 — Critical Bugs (Blocks Execution)

- [x] **Fix ReporterModule.__init__ signature**
  - File: `src/spider/nodes/reporter.py`
  - Change: Add `tools: list[dspy.Tool]` parameter (even if unused by ChainOfThought, needed for orchestrator compatibility)
  - Accept: `uv run python -c "from spider.nodes.reporter import ReporterModule; ReporterModule(tools=[])"` succeeds
  - Test: `uv run pytest tests/test_nodes/test_reporter.py -q`

- [x] **Fix ExecutorModule.__init__ signature**
  - File: `src/spider/nodes/executor.py`
  - Change: Add `hitl_gate` parameter, store as `self.hitl_gate`
  - Accept: `uv run python -c "from spider.nodes.executor import ExecutorModule; ExecutorModule(tools=[], hitl_gate=None)"` succeeds
  - Test: `uv run pytest tests/test_nodes/test_executor.py -q`

- [x] **Fix ScopeGuard empty-scope logic**
  - File: `src/spider/sandbox/scope_guard.py`
  - Change: When `allowed=[]` and `excluded=[]`, return `(False, "No targets authorized")` instead of `(True, "Unrestricted")`
  - Accept: `test_empty_scope_rejects_all` passes
  - Test: `uv run pytest tests/test_safety/test_scope_guard.py -q`

- [x] **Fix test infrastructure**
  - Run: `uv sync --all-extras`
  - File: `tests/test_safety/test_scope_guard.py` — remove unused `import pytest`, fix import order
  - File: `pyproject.toml` — register `integration` mark: `markers = ["integration: integration tests against lab targets"]`
  - Accept: `uv run pytest tests/ -q` collects and runs without import errors
  - Test: `uv run pytest tests/ -q`

---

## P1 — Safety Violations

- [ ] **Enforce HITL gate in tool adapter**
  - File: `src/spider/tools/adapter.py`
  - Change: Add `hitl_gate` and `hitl_required` params to `make_tool()`. When `hitl_required=True` and `hitl_gate` is provided, call `hitl_gate.request()` before executing the wrapped function. If denied, return a JSON error.
  - Files affected: `src/spider/tools/exploitation.py`, `src/spider/tools/post_exploit_tools.py` — pass `hitl_gate` and `hitl_required=True` to `make_tool()` calls
  - Accept: Calling `sqlmap_run` via the adapter with a non-interactive `HITLGate` returns denial JSON
  - Test: `uv run pytest tests/test_tools/test_adapter_hitl.py -q`

- [ ] **Add target/scope to responder_run**
  - File: `src/spider/tools/post_exploit_tools.py`
  - Change: Add `target: str` as first parameter to `responder_run()` so scope guard can validate it
  - Accept: Calling `responder_run` with an out-of-scope target returns `OUT_OF_SCOPE` JSON
  - Test: `uv run pytest tests/test_tools/test_post_exploit.py -q`

---

## P2 — Code Quality

- [ ] **Consolidate intelligence modules with tool layer**
  - Files: `src/spider/tools/cve_intelligence.py`, `src/spider/intelligence/cve_db.py`, `src/spider/intelligence/epss.py`, `src/spider/intelligence/kev.py`
  - Change: Refactor `cve_intelligence.py` to import and use `NVDAPI`, `EPSSClient`, `KEVClient` from `intelligence/` instead of inline `_fetch_*` functions
  - Accept: `cve_intelligence()` returns identical output, intelligence modules are no longer orphaned
  - Test: `uv run pytest tests/test_tools/test_cve_intelligence.py -q`

- [x] **Remove dead code in attack_chain.py**
  - File: `src/spider/tools/attack_chain.py:43`
  - Change: Either assign the low-severity vulns list to `low_vulns` and use it, or remove the line
  - Accept: `uv run ruff check src/spider/tools/attack_chain.py` clean

- [x] **De-duplicate PLAN.md sections**
  - File: `PLAN.md`
  - Change: Remove the second copy of Section 13 (lines 625-660) and the dangling line 625
  - Accept: No duplicate section headings in PLAN.md

- [x] **Fix test file lint issues**
  - File: `tests/test_safety/test_scope_guard.py`
  - Change: Remove unused `import pytest`, fix import sort order
  - Accept: `uv run ruff check tests/` clean

---

## P3 — Test Coverage (New Tests)

All tests must mock LLM calls and external tools per AGENTS.md.

- [ ] **Add node module unit tests**
  - Create: `tests/test_nodes/__init__.py`
  - Create: `tests/test_nodes/test_recon.py` — test `ReconModule` with mocked LM, verify Refine wrapping
  - Create: `tests/test_nodes/test_vuln_analysis.py` — test `VulnerabilityAnalysisModule` signature compliance
  - Create: `tests/test_nodes/test_exploit_planner.py` — test `ExploitPlanningModule` signature compliance
  - Create: `tests/test_nodes/test_executor.py` — test `ExecutorModule` with hitl_gate, verify HITL enforcement
  - Create: `tests/test_nodes/test_reporter.py` — test `ReporterModule` accepts tools param
  - Create: `tests/test_nodes/test_post_exploit.py` — test `PostExploitationModule` signature compliance
  - Accept: `uv run pytest tests/test_nodes/ -q` all pass
  - Pattern: Mock `dspy.settings.configure(lm=DummyLM())` for all tests

- [ ] **Add tool wrapper unit tests**
  - Create: `tests/test_tools/__init__.py`
  - Create: `tests/test_tools/test_recon_tools.py` — mock subprocess, verify JSON output
  - Create: `tests/test_tools/test_enum_tools.py` — mock subprocess
  - Create: `tests/test_tools/test_vuln_scanners.py` — mock subprocess
  - Create: `tests/test_tools/test_exploitation.py` — mock subprocess, HITL enforcement
  - Create: `tests/test_tools/test_cve_intelligence.py` — mock httpx, verify JSON structure
  - Create: `tests/test_tools/test_adapter_hitl.py` — test scope + HITL enforcement in adapter
  - Accept: `uv run pytest tests/test_tools/ -q` all pass

- [ ] **Add sandbox unit tests**
  - Create: `tests/test_sandbox/__init__.py`
  - Create: `tests/test_sandbox/test_audit_logger.py` — test append-only, export, threading
  - Create: `tests/test_sandbox/test_hitl_gate.py` — test non-interactive denial, approval flow
  - Create: `tests/test_sandbox/test_docker_env.py` — mock docker client
  - Accept: `uv run pytest tests/test_sandbox/ -q` all pass

- [ ] **Add engine unit tests**
  - Create: `tests/test_engine/__init__.py`
  - Create: `tests/test_engine/test_weaver.py` — test default topology, DAG validation
  - Create: `tests/test_engine/test_runner.py` — test wave execution with mock modules
  - Create: `tests/test_engine/test_orchestrator.py` — test scope rejection, tool provisioning
  - Accept: `uv run pytest tests/test_engine/ -q` all pass

- [ ] **Add schema validation tests**
  - Create: `tests/test_schemas.py` — test all Pydantic models, field validators, edge cases
  - Accept: `uv run pytest tests/test_schemas.py -q` passes

---

## P4 — Remaining PLAN.md Phases

### Phase 5: TUI (from PLAN.md)

- [ ] Textual dashboard layout integration testing
- [ ] Live findings table with reactive data binding
- [ ] Attack chain visualization
- [ ] HITL approval dialogs wired to HITLGate
- [ ] Report viewer

### Phase 6: Testing Lab (from PLAN.md)

- [ ] docker-compose lab (DVWA, Juice Shop, Metasploitable2)
- [ ] Expected findings documentation
- [ ] Integration test suite against lab targets
- [ ] E2E tests against lab
- [ ] CI/CD pipeline (ruff → pytest → integration)

### Phase 7: Polish & Documentation (from PLAN.md)

- [ ] Complete user documentation
- [ ] Safety documentation
- [ ] Example runs against lab targets
- [ ] Langfuse observability verification

---

## Validation Commands

```bash
# Full suite
uv sync --all-extras
uv run ruff check src/ tests/
uv run ruff format src/ tests/
uv run pytest tests/ -q

# Targeted
uv run pytest tests/test_safety/ -q          # Safety tests
uv run pytest tests/test_nodes/ -q           # Node module tests
uv run pytest tests/test_tools/ -q           # Tool wrapper tests
uv run pytest tests/test_sandbox/ -q         # Sandbox tests
uv run pytest tests/test_engine/ -q          # Engine tests
uv run pytest tests/test_integration/ -q     # Lab integration tests
```
