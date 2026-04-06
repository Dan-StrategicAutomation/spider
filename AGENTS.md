# SPIDER - Development Guide

Instructions for AI coding assistants and agentic frameworks (Hermes, Codex,
Claude Code, Copilot) working on the SPIDER codebase.

SPIDER is a **DSPy-native penetration testing framework** -- every module,
signature, retry loop, and tool is built exclusively with DSPy 3.1+
primitives. There are zero Python workarounds, manual retry loops, or
post-processing hacks.

---

## Project Structure

```
spider/
├── pyproject.toml                 # Dependencies, ruff, pytest, build config
├── AGENTS.md                      # This file -- mandatory for all AI agents
├── PLAN.md                        # Architecture and design plan
├── src/spider/
│   ├── __init__.py
│   ├── config.py                  # Pydantic Settings (SpiderConfig)
│   ├── schemas.py                 # Centralized Pydantic models (ALL structured data)
│   │
│   ├── engine/                    # DSPy Core -- Weaver, Runner, Refine loops
│   │   ├── weaver.py              # GraphWeaver with dspy.Refine
│   │   ├── runner.py              # Wave-based parallel GraphRunner
│   │   ├── self_eval.py           # Pentest quality evaluator (dspy.Refine reward)
│   │   └── orchestrator.py        # Top-level pipeline: Weaver->Provision->Runner->Heal
│   │
│   ├── nodes/                     # DSPy Node Modules (signatures + modules)
│   │   ├── recon.py
│   │   ├── enum.py
│   │   ├── vuln_analysis.py
│   │   ├── exploit_planner.py
│   │   ├── executor.py
│   │   ├── post_exploit.py
│   │   └── reporter.py
│   │
│   ├── tools/                     # dspy.Tool wrappers for security tools
│   │   ├── recon_tools.py         # nmap, masscan, amass, whois, dig
│   │   ├── enum_tools.py          # gobuster, ffuf, nikto, enum4linux
│   │   ├── vuln_scanners.py       # nuclei, nmap NSE, trivy
│   │   ├── cve_intelligence.py    # CUSTOM: NVD + CISA KEV + EPSS
│   │   ├── exploit_matcher.py     # CUSTOM: Exploit-DB + Metasploit matcher
│   │   ├── payload_gen.py         # CUSTOM: Adaptive payload generation
│   │   ├── attack_chain.py        # CUSTOM: Multi-step attack chain builder
│   │   ├── exploitation.py        # sqlmap, hydra, metasploit (HITL-gated)
│   │   ├── post_exploit_tools.py  # bloodhound, crackmapexec, responder
│   │   └── adapter.py             # dspy.Tool registration adapter
│   │
│   ├── sandbox/                   # Safe execution environment
│   │   ├── docker_env.py          # Kali Docker sandbox management
│   │   ├── scope_guard.py         # Target scope validation
│   │   ├── hitl_gate.py           # Human-in-the-Loop approval
│   │   └── audit_logger.py        # Immutable audit log
│   │
│   ├── intelligence/              # Threat intelligence clients
│   │   ├── cve_db.py              # NVD API 2.0 with rate limiting + caching
│   │   ├── exploit_db.py          # Exploit-DB / searchsploit integration
│   │   ├── kev.py                 # CISA Known Exploited Vulnerabilities
│   │   └── epss.py                # EPSS exploit probability scoring
│   │
│   └── tui/                       # Textual terminal UI
│       ├── app.py
│       ├── dashboard.py
│       ├── findings.py
│       ├── attack_graph.py
│       ├── hitl_dialog.py
│       └── report_view.py
│
├── tests/                         # Pytest suite
├── lab/                           # Docker Compose test lab
│   └── docker-compose.yml         # DVWA + Juice Shop + Metasploitable2
└── docs/                          # Documentation
```

---

## CORE RULES (VIOLATIONS ARE REJECTED)

### 1. NEVER use `from __future__ import annotations`
Breaks DSPy type introspection and Pydantic forward reference resolution.
Use TYPE_CHECKING guards for forward refs if needed.

### 2. NEVER use `from __future__ import annotations`
It breaks DSPy signature introspection.

### 3. Always use Pydantic BaseModel in DSPy Signatures
Every `dspy.InputField()` and `dspy.OutputField()` carrying structured data
MUST use a typed Pydantic `BaseModel`. Never use raw types (`str`, `float`,
`list[dict]`) in signatures. DSPy serializes to JSON schema and parses
responses automatically.

```python
class ReconResults(BaseModel):
    hosts: list[str]
    ports: list[PortInfo]
    services: list[ServiceInfo]
    tech_stack: list[TechInfo]

class ReconSignature(dspy.Signature):
    target: str = dspy.InputField()
    findings: ReconResults = dspy.OutputField()
```

### 4. Use `dspy.Refine(module, N, reward_fn, threshold)` for ALL retry/self-improvement
NEVER write Python `for attempt in range(N): try/except` loops. DSPy's Refine
handles retries with different rollout IDs automatically.

```python
def quality_reward(args: dict, pred: dspy.Prediction) -> float:
    findings = pred.findings
    score = 0.0
    if findings.hosts: score += 0.3
    if findings.ports: score += 0.3
    if findings.tech_stack: score += 0.2
    if findings.services: score += 0.2
    return score

self.agent = dspy.Refine(
    module=dspy.ReAct(ReconSignature, tools=tools),
    N=3,
    reward_fn=quality_reward,
    threshold=0.7,
)
```

### 5. NEVER post-process LLM outputs
If the LLM generates invalid output, Pydantic rejects it and `dspy.Refine`
retries. Post-processing masks root cause prompting issues.

### 6. ALWAYS use f-strings
```python
f"Scan result: {len(findings.hosts)} hosts found"  # GOOD
"Scan result: {} hosts found".format(len(findings.hosts))  # BAD
```

### 7. Centralize ALL Pydantic schemas in `schemas.py`
No ad-hoc models scattered across modules. Topology schemas can stay in
`nodes/` if they're signature-specific, but all shared data models go in
`schemas.py`.

### 8. Use `pydantic-settings` for configuration
```python
from pydantic_settings import BaseSettings, SettingsConfigDict

class SpiderConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SPIDER_")
    openrouter_api_key: str
    ollama_base_url: str = "http://localhost:11434"
    model: str = "anthropic/claude-sonnet-4-5-20250929"
    lab_targets: list[str] = ["dvwa", "juice-shop", "metasploitable2"]
```

### 9. All tools MUST return JSON strings for DSPy compatibility
```python
def nmap_scan(target: str, ports: str = "-T4 -sV") -> str:
    result = _run_nmap(target, ports)
    return json.dumps({"success": True, "result": result})
```

### 10. Tools MUST have docstrings and type hints
DSPy's tool inspection reads docstrings and parameter types to build
schemas for the LLM. Vague docstrings break tool calling.

```python
def cve_intelligence(service: str, version: str, cpe: str = "") -> list[CVEFinding]:
    """Look up known CVEs for a service/version across NVD, CISA KEV, and EPSS.
    Returns prioritized vulnerability findings with exploit availability
    indicators and severity scores. Used for vulnerability analysis phase.
    """
```

---

## DSPy MODULE PATTERNS

### Root Node MUST be ReAct
The first node (no dependencies) must use `dspy.ReAct` for tool-use capability.

```python
class ReconModule(dspy.Module):
    def __init__(self, tools):
        super().__init__()
        # ReAct for tool use, wrapped with Refine for self-improvement
        base = dspy.ReAct(ReconSignature, tools=tools, max_iters=10)
        self.agent = dspy.Refine(module=base, N=3, reward_fn=recon_reward, threshold=0.7)

    def forward(self, target: str) -> dspy.Prediction:
        with dspy.settings.context(temperature=0.1):
            return self.agent(target=target)
```

### Non-Tool Nodes Use ChainOfThought or Predict
```python
class VulnAnalysisModule(dspy.Module):
    def __init__(self):
        super().__init__()
        self.analyzer = dspy.Refine(
            module=dspy.ChainOfThought(VulnAnalysisSignature),
            N=3,
            reward_fn=vuln_quality_reward,
            threshold=0.8,
        )
```

### Reward Function Signature
```python
def reward_fn(args: dict, pred: dspy.Prediction) -> float:
    # args: the input arguments dict passed to forward()
    # pred: the DSPy Prediction object with output fields
    # Returns: float 0.0 to 1.0
    return score
```

### Temperature Control
```python
# Weaving/planning: low temperature for precision
with dspy.settings.context(temperature=0.1):
    result = self.weave(goal=goal)

# Brainstorming/adapting: slightly higher
with dspy.settings.context(temperature=0.4):
    payload = self.generator(vuln_type=vuln_type)
```

---

## PYDANTIC SCHEMA PATTERNS

### Nested Models in OutputFields
```python
class AttackStep(BaseModel):
    step_number: int
    action: str
    tool: str
    cve_id: str | None = None
    expected_outcome: str
    hitl_required: bool
    risk_level: str

class AttackChain(BaseModel):
    name: str
    steps: list[AttackStep]
    final_objective: str
    overall_risk: str
    stealth_score: float = Field(ge=0.0, le=1.0)

class ExploitPlanSignature(dspy.Signature):
    vulnerability_findings: str = dspy.InputField()
    attack_chains: list[AttackChain] = dspy.OutputField()
```

### Field Validators
```python
class CVEFinding(BaseModel):
    cve_id: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    epss_score: float = Field(ge=0.0, le=1.0)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
        if v.upper() not in valid:
            raise ValueError(f"Severity must be one of {valid}")
        return v.upper()
```

### NEVER wrap dynamic node outputs in Pydantic models
When building DSPy signatures dynamically for pipeline nodes, use plain
`dspy.OutputField()`. Pydantic wrappers break data flow in dynamic signatures.

```python
# CORRECT for DYNAMIC signatures:
output_fields = {node.output: dspy.OutputField(desc=f"Output: {node.output}")}
signature = type(f"{node.name}Sig", (dspy.Signature,), {
    "__doc__": node.description, **input_fields, **output_fields,
})
```

---

## DSPy TOOL REGISTRATION

### Registering a tool with DSPy
```python
import dspy

def nmap_scan(target: str, ports: str = "-T4 -sV -p-", args: str = "-sC") -> str:
    """Run nmap scan against target. Returns ports, services, versions, and OS detection."""
    cmd = ["nmap", ports, args, target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return json.dumps({"success": True, "output": result.stdout, "errors": result.stderr})

# Wrap as DSPy tool
nmap_tool = dspy.Tool(nmap_scan)
```

### Tool adapter pattern (adapter.py)
All tools go through a central adapter that handles:
- Scope guard enforcement
- Audit logging
- JSON serialization
- Timeout management

```python
def make_tool(func, scope_guard=None, audit_logger=None):
    """Wrap a tool function with scope checking and audit logging."""
    @functools.wraps(func)
    def wrapped(**kwargs):
        if scope_guard and "target" in kwargs:
            if not scope_guard.authorize(kwargs["target"], func.__name__):
                return json.dumps({"error": f"Out of scope: {kwargs['target']}"})
        if audit_logger:
            audit_logger.log(action=func.__name__, target=kwargs.get("target"))
        return func(**kwargs)
    return dspy.Tool(wrapped)
```

---

## SAFETY MANDATES

### Scope Guard at EVERY tool invocation
Every tool that takes a target parameter must check scope before execution.
No exceptions. Not even in "test mode."

### HITL for ALL exploitation
Only Recon and Enum phases are fully autonomous. Every exploit execution,
payload delivery, and post-exploitation action requires explicit human
approval via `hitl_gate.py`.

### Sandbox-first
All tool execution happens inside an isolated Docker container:
- No access to host filesystem
- No privileged mode
- Resource limits enforced
- Internal network only during testing

### Audit-everything
Immutable append-only log of every action:
- Timestamp, action, target, parameters, result
- No deletion or modification of past entries
- Exportable for compliance reporting

---

## TESTING REQUIREMENTS

### ruff for linting/formatting
```bash
ruff check src/ tests/
ruff format src/ tests/
```

### pytest for testing
```bash
pytest tests/ -q                    # Full suite
pytest tests/test_scopes/ -q        # Scope guard tests (MUST PASS)
pytest tests/test_sandbox/ -q       # Sandbox isolation tests
pytest tests/test_tools/ -q         # Tool wrapper tests
pytest tests/test_nodes/ -q         # DSPy node module tests
pytest tests/test_integration/ -q   # Lab target integration tests
```

### NEVER commit untested code
1. Write the test first (TDD approach)
2. Implement the code
3. Run the tests
4. Only then commit

### Unit tests use mocks for LLM calls
No network calls in unit tests. Mock `dspy.LM` and tool responses.

### Integration tests against lab targets only
DVWA, Juice Shop, and Metasploitable2 in docker-compose. External internet
disabled on lab network.

---

## COMMON PITFALLS & FIXES

| Pitfall | Fix |
|---------|-----|
| `from __future__ import annotations` | NEVER. Breaks DSPy type introspection. Use `TYPE_CHECKING`. |
| `dspy.TypedPredictor` | DEPRECATED in 3.1+. Use `dspy.Predict(SignatureClass)` with Pydantic. |
| `dspy.Assert` / `dspy.Suggest` | REMOVED since 2.6. Use `dspy.Refine(module, N, reward_fn, threshold)`. |
| Python retry loops | NEVER. All retries via `dspy.Refine` with `reward_fn`. |
| Raw `str`/`float`/`list` in signatures | ALWAYS use Pydantic BaseModel for InputField/OutputField. |
| `.format()` or `%s` strings | ALWAYS use f-strings: `f"Found {n} hosts"`. |
| `dspy.JSONAdapter` with Ollama | NEVER. Throws serialization error. Use `dspy.settings.context(temperature=0.1)`. |
| Post-processing LLM outputs | NEVER. Let Pydantic validate + `dspy.Refine` retry on failure. |
| Mutable default in ContextVar | Use `None`, not `{}`. Handle None explicitly. |
| Missing tool docstrings | Tools MUST have docstrings with descriptions. DSPy reads them. |
| `lm` = uppercase `dspy.configure(LM=lm)` | LOWERCASE: `dspy.configure(lm=lm)`. |
| Ollama connection refused | Use `api_key=""` (empty string). `api_base="http://localhost:11434"`. |
| Out-of-scope tool calls | ScopeGuard checks at adapter level before tool execution. |
| Reward function missing `pred` param | Signature MUST be `(args: dict, pred: dspy.Prediction) -> float`. |

---

## LM CONFIGURATION

```python
# Primary: OpenRouter
import dspy
lm = dspy.LM(
    model="openrouter/anthropic/claude-sonnet-4-5-20250929",
    api_key=os.environ["SPIDER_OPENROUTER_API_KEY"]
)

# Local fallback: Ollama
if not os.environ.get("SPIDER_OPENROUTER_API_KEY"):
    lm = dspy.LM(
        model="qwen3:8b-instruct",
        api_base="http://localhost:11434",
        api_key="",  # empty for Ollama
    )

dspy.configure(lm=lm)
```

---

## LANGFUSE OBSERVABILITY

```python
# Set env vars before importing DSPy
import os
os.environ["LANGFUSE_PUBLIC_KEY"] = "pk-..."
os.environ["LANGFUSE_SECRET_KEY"] = "sk-..."
os.environ["LANGFUSE_HOST"] = "https://cloud.langfuse.com"

from langfuse import get_client
from openinference.instrumentation.dspy import DSPyInstrumentor

get_client()  # Registers global OTEL TracerProvider
DSPyInstrumentor().instrument()
```

---

## Documentation Structure

All project documentation lives in `docs/`. Reference these files during development:

| Document | Purpose |
|----------|---------|
| [docs/architecture.md](docs/architecture.md) | System architecture, DSPy graph topology, component relationships |
| [docs/dspy-engine.md](docs/dspy-engine.md) | DSPy engine internals: Weaver, Runner, Refine, self-evaluation |
| [docs/tools.md](docs/tools.md) | Security tool catalog, custom tools, adapter pattern, registration |
| [docs/parallelism.md](docs/parallelism.md) | Parallel execution: wave-based, async, multi-target parallelism |
| [docs/safety.md](docs/safety.md) | Safety architecture: scope guards, HITL, sandbox, audit logging |
| [docs/testing.md](docs/testing.md) | Testing methodology: lab setup, test targets, pipeline |
| [docs/tui.md](docs/tui.md) | Terminal UI specification (Textual TUI) |
| [docs/index.md](docs/index.md) | Documentation index |
| [PLAN.md](PLAN.md) | Architecture plan, implementation phases, roadmap |
| [README.md](README.md) | Public-facing project overview |
