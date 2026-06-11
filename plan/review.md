# SPIDER Codebase Review

**Date:** 2026-04-09
**Branch:** `fix/dspy-node-signatures` (27 uncommitted modified files)
**Commit:** `da3d30b`

---

## Executive Summary

SPIDER is a DSPy-native pentesting framework at ~70% implementation. The core DSPy architecture (Weaver, Runner, Refine loops, Pydantic schemas) is well-designed and compliant with project rules. However, **2 critical runtime crashes**, a **ScopeGuard logic bug**, **broken test infrastructure**, and a **HITL enforcement gap** block real-world usage.

### Current State by Layer

| Layer | Files | Status |
|-------|-------|--------|
| Engine (weaver, runner, orchestrator, self_eval) | 4 | ⚠️ 2 crash bugs in orchestrator's node building |
| Nodes (recon, enum, vuln, exploit, executor, post, reporter) | 7 | ❌ Reporter and Executor have incompatible __init__ signatures |
| Tools (recon, enum, vuln, exploit, payload, chain, matcher, post) | 11 | ⚠️ HITL not enforced, responder skips scope |
| Sandbox (scope_guard, hitl_gate, audit_logger, docker_env) | 4 | ⚠️ ScopeGuard empty-scope logic bug |
| Intelligence (cve_db, epss, kev, exploit_db) | 4 | ⚠️ Orphaned — not used by any tool |
| CLI | 1 | ✅ Functional |
| TUI (app, dashboard, findings, attack_graph, hitl_dialog, report, session, theme) | 8 | ⚠️ Scaffolded but untested |
| Schemas | 1 | ✅ Well-organized |
| Config | 1 | ✅ Working |
| Tests | 2 | ❌ Broken infrastructure, 0% coverage |

---

## Bugs

### BUG-1: ReporterModule crashes orchestrator [CRITICAL]

**File:** `src/spider/nodes/reporter.py:29`
**Symptom:** `TypeError: ReporterModule.__init__() got an unexpected keyword argument 'tools'`

The orchestrator (`src/spider/engine/orchestrator.py:119`) passes `tools=node_tools` to every node module, but `ReporterModule.__init__()` only accepts `self` — no `tools` parameter.

**Fix:** Add `tools: list[dspy.Tool]` parameter to `ReporterModule.__init__()`, matching the pattern used by all other node modules.

---

### BUG-2: ExecutorModule crashes orchestrator [CRITICAL]

**File:** `src/spider/nodes/executor.py:29`
**Symptom:** `TypeError: ExecutorModule.__init__() got an unexpected keyword argument 'hitl_gate'`

The orchestrator (`src/spider/engine/orchestrator.py:129-132`) passes `hitl_gate=self.hitl_gate` to `ExecutorModule`, but the constructor only accepts `tools`.

**Fix:** Add `hitl_gate` parameter to `ExecutorModule.__init__()`. Store it and use it to gate tool execution in `forward()`.

---

### BUG-3: ScopeGuard allows everything when allowed list is empty [HIGH]

**File:** `src/spider/sandbox/scope_guard.py:53-55`

When `allowed=[]`, the guard returns `(True, "Unrestricted scope")`. The test at `tests/test_safety/test_scope_guard.py:47-50` expects `False`. AGENTS.md mandates: *"Assume all targets are out of scope until validated."*

**Fix:** Change the empty-scope behavior to reject. An empty allowed list means no targets are authorized.

---

### BUG-4: Test infrastructure broken [HIGH]

**File:** `tests/test_safety/test_scope_guard.py`
**Symptom:** `ModuleNotFoundError: No module named 'spider'`

Tests cannot import the package. Additional issues:
- Unused `import pytest` (F401)
- Unsorted imports (I001)
- Unregistered `integration` mark on `test_lab.py`

**Fix:** Run `uv sync --all-extras`, fix lint issues, register custom marks in `pyproject.toml`.

---

## Design Issues

### D-1: HITL gate not enforced at tool adapter level [SAFETY]

**Files:** `src/spider/tools/exploitation.py`, `src/spider/tools/post_exploit_tools.py`, `src/spider/tools/adapter.py`

Exploitation tools include `"hitl_required": True` in their JSON output, but this is only a response tag — nothing prevents the tool from executing. The `hitl_gate` parameter is accepted by `register_all()` but never passed to `make_tool()` or checked.

**Fix:** Extend `make_tool()` in `adapter.py` to accept an `hitl_gate` parameter and call `hitl_gate.request()` before executing any HITL-gated tool.

---

### D-2: Intelligence modules are orphaned [DUPLICATION]

**Files:** `src/spider/intelligence/cve_db.py`, `epss.py`, `kev.py`, `exploit_db.py`

These contain proper API clients (`NVDAPI`, `EPSSClient`, `KEVClient`, `ExploitDBClient`) but are never imported anywhere. The tool `src/spider/tools/cve_intelligence.py` reimplements the same logic with private functions (`_fetch_nvd`, `_fetch_kev`, `_fetch_epss`).

**Fix:** Refactor `cve_intelligence.py` to use the intelligence module clients, or consolidate.

---

### D-3: Dead code in attack_chain.py [MINOR]

**File:** `src/spider/tools/attack_chain.py:43`

Line 43: `[v for v in vulns if v.get("cvss", 0) < 4.0]` — result is discarded (not assigned).

---

### D-4: responder_run skips scope validation [SAFETY]

**File:** `src/spider/tools/post_exploit_tools.py:137-141`

`responder_run(interface, duration)` has no `target` parameter. The adapter looks for `target`/`domain`/`host` in kwargs — none exist, so scope validation is silently skipped.

---

### D-5: PLAN.md has duplicated sections [DOCS]

Section 13 "Tool Enhancement Strategy" appears twice (lines 591-624 and 626-660). The second copy also has mismatched subsection numbering.

---

## Lint Status

- **Source (`src/`):** ✅ All checks passed
- **Tests (`tests/`):** ⚠️ 2 issues (unused import, unsorted imports)

## Test Coverage

Effective coverage: **0%**. Only 1 test file with assertions exists and it cannot import the package. The following test directories referenced in AGENTS.md do not exist:
- `tests/test_nodes/`
- `tests/test_tools/`
- `tests/test_sandbox/`
- `tests/test_scopes/`
