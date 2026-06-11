# SPIDER — LLM Development Guide

This document is the authoritative step-by-step guide for an LLM coding agent working on SPIDER. It provides full context, architecture understanding, file locations, coding patterns, and execution order so that work can proceed without ambiguity.

**Before writing any code, read these files in order:**
1. This file (`plan/development-guide.md`)
2. `AGENTS.md` — mandatory project rules
3. `plan/review.md` — current bugs and issues
4. `plan/todo.md` — prioritized task checklist

---

## 1. Project Overview

SPIDER (Symbiotic Pentesting Investigation & DSPy Exploitation Runtime) is a DSPy-native penetration testing framework. It uses `dspy.Refine` for quality-driven self-improvement, Pydantic-validated schemas for all structured data, and a graph-based topology for multi-phase pentest execution.

### Key Differentiators
- **DSPy-native**: No raw LLM calls, no Python retry loops — all intelligence via `dspy.Refine`, `dspy.ReAct`, `dspy.ChainOfThought`
- **Pydantic everywhere**: Every DSPy InputField/OutputField is a Pydantic BaseModel
- **Safety-first**: ScopeGuard, HITL gate, audit logging, Docker sandbox
- **Self-improving**: Quality reward functions on every node enable automatic retry with feedback

---

## 2. Architecture Map

```
src/spider/
├── schemas.py              ← ALL Pydantic models (DO NOT add models elsewhere)
├── config.py               ← pydantic-settings SpiderConfig
├── models.py               ← DSPy LM configuration (Ollama/OpenRouter)
├── observability.py         ← Langfuse + OpenTelemetry setup
├── cli.py                  ← Entry point, interactive menus, SessionDB
├── banner.py               ← ASCII art
│
├── engine/                 ← DSPy orchestration core
│   ├── weaver.py           ← GraphWeaver: goal → validated DAG topology via Refine
│   ├── runner.py           ← GraphRunner: wave-based parallel execution
│   ├── orchestrator.py     ← Top-level: Weaver → Provision → Runner → Heal
│   └── self_eval.py        ← Quality reward functions per node type
│
├── nodes/                  ← DSPy node modules (signatures + Refine-wrapped modules)
│   ├── recon.py            ← Root ReAct node (reconnaissance)
│   ├── enum.py             ← WebEnumeration + ServiceEnumeration (ChainOfThought)
│   ├── vuln_analysis.py    ← CVE matching (ChainOfThought)
│   ├── exploit_planner.py  ← Attack chain planning (ChainOfThought)
│   ├── executor.py         ← HITL-gated exploitation (ReAct)
│   ├── post_exploit.py     ← Privilege escalation (ReAct, HITL-gated)
│   └── reporter.py         ← Report generation (ChainOfThought)
│
├── tools/                  ← Security tool wrappers (all return JSON strings)
│   ├── adapter.py          ← make_tool() — wraps functions with scope + audit
│   ├── recon_tools.py      ← nmap, masscan, whois, dns_enum, subdomain_enum
│   ├── enum_tools.py       ← gobuster, ffuf, nikto, enum4linux
│   ├── vuln_scanners.py    ← nuclei, nmap_nse, trivy
│   ├── cve_intelligence.py ← NVD + KEV + EPSS lookup (custom)
│   ├── exploit_matcher.py  ← Exploit-DB + Metasploit matching (custom)
│   ├── payload_gen.py      ← Adaptive payload generation (custom)
│   ├── attack_chain.py     ← Multi-step attack chain builder (custom)
│   ├── exploitation.py     ← sqlmap, hydra, metasploit (HITL-gated)
│   ├── post_exploit_tools.py ← bloodhound, crackmapexec, responder (HITL-gated)
│   └── diagnostics.py      ← Binary availability checker
│
├── sandbox/                ← Safety enforcement
│   ├── scope_guard.py      ← Target scope validation (CIDR + hostname matching)
│   ├── hitl_gate.py        ← Human-in-the-loop approval queue
│   ├── audit_logger.py     ← Immutable append-only action log
│   └── docker_env.py       ← Docker sandbox container management
│
├── intelligence/           ← Threat intelligence API clients (currently orphaned)
│   ├── cve_db.py           ← NVDAPI class
│   ├── epss.py             ← EPSSClient class
│   ├── kev.py              ← KEVClient class
│   └── exploit_db.py       ← ExploitDBClient class
│
├── tui/                    ← Textual terminal UI (scaffolded, incomplete)
│   ├── app.py              ← Main SpiderApp
│   ├── session.py          ← SessionStore + ScanSession dataclass
│   ├── dashboard.py        ← Live scan dashboard
│   ├── findings.py         ← Vulnerability findings panel
│   ├── attack_graph.py     ← Attack chain visualization
│   ├── hitl_dialog.py      ← HITL approval dialog
│   ├── report_view.py      ← Report viewer
│   └── theme.py            ← Theme constants
│
└── testing/                ← Lab integration helpers (placeholder)
```

---

## 3. Execution Pipeline

Understanding the runtime flow is essential before making changes:

```
CLI (cli.py)
  → SpiderOrchestrator.__init__(config, scope_guard, hitl_gate, audit_logger)
  → orchestrator.run(goal, target)
      1. scope_guard.authorize(target) → reject if out of scope
      2. weaver(goal, target) → GraphTopology (DAG of NodeDefs)
         └── dspy.Refine(ChainOfThought(GraphWeaverSignature), reward=topology_reward)
      3. _build_tools() → dict[str, dspy.Tool] (all tools registered via adapter)
      4. _build_node_modules(topology, tools) → dict[str, dspy.Module]
         └── Maps NodeRole → ReconModule/VulnAnalysisModule/etc with filtered tools
      5. GraphRunner(topology, modules, tools).forward()
         └── For each topological wave:
             └── asyncio.gather(run_one(node_id) for node_id in wave)
                 └── module(**inputs) → store output in all_results
      6. _heal_loop() → SelfEvaluator judges quality → re-weave if below threshold
```

---

## 4. Coding Patterns

### 4.1 Adding a New Node Module

Every node module follows the same pattern. Copy from `recon.py` or `vuln_analysis.py`:

```python
"""Description of what this node does."""

import dspy
from spider.schemas import InputSchema, OutputSchema


class MyNodeSignature(dspy.Signature):
    """Instruction prompt for the LLM. Be specific about output format."""

    input_data: InputSchema = dspy.InputField()
    output_data: OutputSchema = dspy.OutputField()


class MyNodeModule(dspy.Module):
    """Module description."""

    def __init__(self, tools: list[dspy.Tool]):
        super().__init__()
        # Use dspy.ReAct for tool-using nodes, dspy.ChainOfThought for reasoning-only
        base = dspy.ChainOfThought(MyNodeSignature)

        def reward_fn(args: dict, pred: dspy.Prediction) -> float:
            result = pred.output_data
            score = 0.0
            # Score based on completeness and quality
            if result.some_field:
                score += 0.5
            return min(1.0, score)

        self.module = dspy.Refine(
            module=base,
            N=3,
            reward_fn=reward_fn,
            threshold=0.7,
        )

    def forward(self, input_data: InputSchema) -> dspy.Prediction:
        with dspy.settings.context(temperature=0.1):
            return self.module(input_data=input_data)
```

**Rules:**
- `__init__` MUST accept `tools: list[dspy.Tool]` even if the node doesn't use tools
- All input/output types MUST be Pydantic BaseModel from `schemas.py`
- ALWAYS wrap with `dspy.Refine`
- ALWAYS use `dspy.settings.context(temperature=...)` in `forward()`
- Root reconnaissance node MUST use `dspy.ReAct` (not ChainOfThought)

### 4.2 Adding a New Tool

Every tool follows this pattern:

```python
"""Tool description."""

import json
import subprocess


def my_tool(target: str, option: str = "default", **kwargs) -> str:
    """Docstring explains what the tool does and the JSON output format.

    Returns JSON with success status and structured results.
    """
    cmd = ["binary", "--option", option, target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return json.dumps({
            "success": result.returncode == 0,
            "output": result.stdout[:10000],
            "errors": result.stderr[:2000],
        })
    except FileNotFoundError:
        return json.dumps({"success": False, "error": "binary not found in PATH"})
    except subprocess.TimeoutExpired:
        return json.dumps({"success": False, "error": "timed out"})
    except Exception as exc:
        return json.dumps({"success": False, "error": str(exc)})


def register_all(scope_guard=None, audit_logger=None):
    """Register tools via the adapter."""
    from spider.tools.adapter import make_tool

    return {
        "my_tool": make_tool(
            my_tool,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
        ),
    }
```

**Rules:**
- MUST return `json.dumps(...)` (JSON string)
- MUST accept `**kwargs` for forward-compatibility
- MUST include a docstring with type hints
- First parameter for target-operating tools MUST be `target: str`
- Handle `FileNotFoundError`, `TimeoutExpired`, and generic `Exception`
- Register via `make_tool()` from `adapter.py` — never create dspy.Tool directly
- HITL-gated tools MUST pass `hitl_required=True` to `make_tool()`

### 4.3 Adding a Test

```python
"""Tests for module_name."""

from unittest.mock import MagicMock, patch

import dspy

from spider.module import MyClass


class TestMyClass:
    """Test suite for MyClass."""

    def setup_method(self):
        # Mock DSPy LM for node tests
        dspy.configure(lm=dspy.LM("openai/gpt-4o-mini", api_key="test"))

    def test_basic_behavior(self):
        ...

    def test_edge_case(self):
        ...
```

**Rules:**
- Mock ALL LLM calls and external tools (subprocess, httpx, requests)
- Use `unittest.mock.patch` for subprocess calls
- Test files live in `tests/test_{component}/test_{module}.py`
- Each test directory needs an `__init__.py`
- Never make real network calls in unit tests

### 4.4 Schema Changes

All schemas live in `src/spider/schemas.py`. When adding a new model:

1. Add the Pydantic model to the appropriate section (marked by comment headers)
2. Use explicit `Field(default=..., description=...)` for all fields
3. Add `@field_validator` for fields with constrained values
4. Provide sensible defaults so `MyModel()` creates a valid empty instance
5. Never use raw `str`, `list`, `dict` for DSPy InputField/OutputField — always BaseModel

---

## 5. Development Workflow

For each task in `plan/todo.md`:

```
1. Read the task description, files, and acceptance criteria
2. Write/update the test that proves the expected behavior
3. Implement the smallest code change needed
4. Run the narrowest test: uv run pytest tests/test_specific.py -q
5. Fix failures at the source, not with wrappers
6. Run ruff: uv run ruff check src/ tests/
7. Run broader suite: uv run pytest tests/ -q
8. Mark the task as [x] in plan/todo.md
```

### Commands

```bash
# Project setup
uv sync --all-extras

# Run tests
uv run pytest tests/ -q                    # All tests
uv run pytest tests/test_safety/ -q        # Safety tests only
uv run pytest tests/test_nodes/ -q         # Node tests only

# Lint
uv run ruff check src/ tests/
uv run ruff format src/ tests/

# Import verification
uv run python -c "from spider.engine.orchestrator import SpiderOrchestrator; print('OK')"

# Run CLI
uv run spider
uv run spider --scan 192.168.1.100 --mode recon
```

---

## 6. Task Execution Order

Tasks MUST be executed in this exact order. Each group must pass all tests before moving to the next.

### Phase A: Fix Critical Bugs (P0)

Execute tasks in this order:
1. Fix `ReporterModule.__init__` signature
2. Fix `ExecutorModule.__init__` signature  
3. Fix `ScopeGuard` empty-scope logic
4. Fix test infrastructure (uv sync, lint fixes, mark registration)

**Gate:** `uv run pytest tests/test_safety/ -q` must pass with 7/7 tests.

### Phase B: Fix Safety Violations (P1)

5. Enforce HITL gate in `make_tool` adapter
6. Add target/scope to `responder_run`

**Gate:** `uv run pytest tests/test_tools/test_adapter_hitl.py -q` must pass.

### Phase C: Code Quality (P2)

7. Consolidate intelligence modules with tool layer
8. Remove dead code in `attack_chain.py`
9. De-duplicate PLAN.md sections
10. Fix remaining lint issues

**Gate:** `uv run ruff check src/ tests/` must show 0 errors.

### Phase D: Test Coverage (P3)

11. Add node module unit tests
12. Add tool wrapper unit tests
13. Add sandbox unit tests
14. Add engine unit tests
15. Add schema validation tests

**Gate:** `uv run pytest tests/ -q` must pass all tests.

### Phase E: TUI & Lab (P4 — from PLAN.md Phases 5-6)

16. Wire TUI to SessionStore and orchestrator
17. Build docker-compose lab
18. Integration tests against lab targets
19. E2E tests

**Gate:** Full pipeline runs against DVWA lab target.

---

## 7. Key Architectural Rules

These rules from `AGENTS.md` must NEVER be violated:

| Rule | Enforcement |
|------|-------------|
| No `from __future__ import annotations` | Ruff check |
| No raw `str`/`list`/`dict` in DSPy signatures | Code review |
| All schemas in `schemas.py` | Code review |
| `dspy.Refine` for retries (no Python loops) | Code review |
| Tools return JSON strings | Adapter validation |
| Tools enforce scope checking | `make_tool()` wrapper |
| Exploitation requires HITL approval | `make_tool()` wrapper |
| All actions audit-logged | `make_tool()` wrapper |
| f-strings only (no `.format()` or `%`) | Ruff check |
| No `from __future__ import annotations` | Ruff check |

---

## 8. File Cross-References

When modifying a file, check these dependencies:

| If you change... | Also check... |
|-------------------|---------------|
| `schemas.py` | All node modules, tools, self_eval.py |
| `adapter.py` | All tool `register_all()` functions |
| `scope_guard.py` | All tests in `test_safety/`, orchestrator.py |
| `config.py` | cli.py, orchestrator.py, models.py |
| Any node `__init__` | `orchestrator.py:_build_node_modules()` |
| `weaver.py` topology | `runner.py` I/O mapping |
| `runner.py` | orchestrator.py `_heal_loop()` |

---

## 9. Environment

- **Python:** 3.10+ (currently 3.13 in .venv)
- **Package manager:** `uv`
- **Linter:** `ruff` (config in pyproject.toml)
- **Test runner:** `pytest` with `pytest-asyncio`
- **LLM:** Ollama (Qwen3.5 abliterated) or OpenRouter fallback
- **Observability:** Langfuse v4 + OpenTelemetry
