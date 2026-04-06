# Architecture Overview

## Introduction

SPIDER (Symbiotic Pentesting Investigation & DSPy Exploitation Runtime) is a
**DSPy-native penetration testing framework** that combines traditional security
tools with LLM-driven reasoning, self-evaluation, and autonomous problem-solving.

Unlike existing pentesting MCP servers (HexStrike, Tengu, pentestMCP) which are
mere tool orchestrators exposing CLI commands as function calls, SPIDER uses
`dspy.Refine` for quality-driven retry loops, Pydantic-validated output schemas,
and attack chain reasoning. No other DSPy-native pentesting framework exists.

## What Sets SPIDER Apart

### Existing Solutions (Tool Orchestrators Only)
- **HexStrike AI**: 150+ tools, 12+ agents -- but raw LLM calls via MCP, no self-evaluation
- **Tengu**: 80 tools, PTES methodology -- no quality scoring, no reasoning loops
- **pentestMCP**: 20+ tools in Docker -- clean architecture but simple tool passthrough
- **LuaN1aoAgent**: Dual-graph reasoning, PER cycle -- custom orchestration, NOT DSPy

### SPIDER (DSPy-Native)
- `dspy.Refine(module, N=3, reward_fn, threshold)` for ALL self-improvement
- Attack chain reasoning with Pydantic-validated structured output
- Custom tools that solve their own problems via adaptive retry
- Reward-function scoring for recon completeness, vulnerability specificity, exploit feasibility
- Quality evaluation that knows: did the scan actually work or did the WAF block it?

## System Architecture

```
                    +---------------------------+
                    |      Terminal TUI          |
                    |    (Textual Framework)     |
                    +------------+---------------+
                                 |
                    +------------v---------------+
                    |        Orchestrator        |
                    |  Weaver -> Provision ->    |
                    |  Runner -> Heal loop       |
                    +------------+---------------+
                                 |
              +------------------+------------------+
              |                                     |
   +----------v----------+              +-----------v-----------+
   |   GraphWeaver       |              |   GraphRunner         |
   |   (dspy.Refine)     |              |   (wave-based async)  |
   |                     |              |                       |
   |   Builds topology   |              |   Executes nodes in   |
   |   from goal text    |              |   topological waves   |
   +----------+----------+              +-----------+-----------+
              |                                     |
              v                                     v
   +----------+----------+              +-----------v-----------+
   |   Node Modules      |              |   Reward Functions    |
   |                     |              |                       |
   |   Recon (ReAct)     |              |   Quality evaluation  |
   |   Vulnerability     |              |   0.0-1.0 scoring     |
   |   Exploit Planner   |              |   Self-improvement    |
   |   Executor (HITL)   |              +-----------+-----------+
   |   Reporter          |                          |
   +----------+----------+                          |
              |                                     |
              v                                     v
   +----------+----------+              +-----------v-----------+
   |   Security Tools    |              |   Intelligence        |
   |                     |              |                       |
   |   Recon: nmap, etc  |              |   NVD API 2.0         |
   |   Enum: gobuster    |              |   CISA KEV            |
   |   Vuln: nuclei      |              |   EPSS Scoring        |
   |   Exploit: metasploit|              |   Exploit-DB          |
   +----------+----------+              +-----------+-----------+
              |                                     |
              v                                     v
   +----------+----------+              +-----------v-----------+
   |   Scope Guard       |              |   Sandbox (Docker)    |
   |   HITL Gate         |              |   Audit Logger        |
   |   Resource Limits   |              |   Network Isolation   |
   +----------+----------+              +-----------------------+
```

## DSPy Graph Topology (Default)

SPIDER executes pentests as a **directed acyclic graph (DAG)** of DSPy modules,
processed in parallel waves:

```
WAVE 0  [Recon - ReAct]  -->  Root node. Autonomous tool use.
  recon: discover hosts, ports, services, technologies
    tools: nmap, whois, dns_enum, subdomain_enum
    output: ReconResults

WAVE 1  [Parallel - ChainOfThought]
  web_enum: directory discovery, web tech detection, parameter identification
    depends_on: [recon]
    tools: gobuster, ffuf, nikto, tech_detect
    output: WebFindings

  service_enum: service version probing, default credential checks
    depends_on: [recon]
    tools: nmap_nse, service_probe, banner_grab
    output: ServiceDetails

WAVE 2  [ChainOfThought with dspy.Refine]
  vuln_analysis: CVE matching, exploit availability, severity scoring
    depends_on: [web_enum, service_enum]
    tools: cve_intelligence, exploit_matcher, nuclei_scan
    output: VulnerabilityList

WAVE 3  [ChainOfThought with dspy.Refine]
  exploit_planner: attack chain construction, prioritization
    depends_on: [vuln_analysis]
    tools: attack_chain_builder, payload_generator
    output: AttackPlan

WAVE 4  [ReAct with HITL gating]
  executor: exploitation attempts (human approved)
    depends_on: [exploit_planner]
    tools: sqlmap_run, hydra_run, metasploit_run
    output: ExploitResult

WAVE 5  [ChainOfThought]
  reporter: structured pentest report generation
    depends_on: [recon, vuln_analysis, executor]
    tools: None (synthesis only)
    output: PentestReport
```

**Key property**: If Wave 1 produces incomplete output, `dspy.Refine` on the
recon node automatically retries with different rollout IDs before Wave 2
executes. Quality scoring is deterministic and configurable.

## Component Details

### Engine Layer (`src/spider/engine/`)

| Module | Role |
|--------|------|
| `weaver.py` | GraphWeaver with dspy.Refine |
| `runner.py` | Wave-based parallel GraphRunner |
| `self_eval.py` | Pentest quality evaluator |
| `orchestrator.py` | Top-level pipeline |
| `provision.py` | Runtime tool provisioning and LM configuration |

See [DSPy Engine](dspy-engine.md) for details.

### Node Layer (`src/spider/nodes/`)

Each node is a `dspy.Module` with:
- A `dspy.Signature` class with Pydantic InputField/OutputField types
- A `forward(self, ...) -> dspy.Prediction` method
- Wrapping with `dspy.Refine` for self-improvement (except ProgramOfThought nodes)

See [DSPy Engine](dspy-engine.md) for module implementation patterns.

### Tool Layer (`src/spider/tools/`)

Tools are registered via the adapter pattern in `adapter.py`:
- Automatic scope guard enforcement
- Audit logging on every invocation
- JSON serialization of outputs
- Timeout management

**Existing tool wrappers** (wrappers for CLI tools):
- `recon_tools.py`: nmap, masscan, amass, whois, dig
- `enum_tools.py`: gobuster, ffuf, nikto, enum4linux
- `vuln_scanners.py`: nuclei, nmap NSE, trivy
- `exploitation.py`: sqlmap, hydra, metasploit (HITL-gated)
- `post_exploit_tools.py`: bloodhound, crackmapexec, responder

**Custom-built tools** (our unique differentiators):
- `cve_intelligence.py`: NVD + CISA KEV + EPSS cross-reference
- `exploit_matcher.py`: Exploit-DB + Metasploit module matcher
- `payload_gen.py`: Adaptive payload generation
- `attack_chain.py`: Multi-step attack chain builder

See [Security Tools](tools.md) for the full catalog and integration guide.

### Intelligence Layer (`src/spider/intelligence/`)

Threat intelligence clients with rate limiting and caching:
- `cve_db.py`: NVD API 2.0 (0.6 req/sec rate limit, batch caching)
- `kev.py`: CISA Known Exploited Vulnerabilities feed
- `epss.py`: FIRST EPSS exploit probability scoring
- `exploit_db.py`: Exploit-DB / searchsploit integration

See [Threat Intelligence](intelligence.md) for details.

### Safety Layer (`src/spider/sandbox/`)

Non-negotiable safety infrastructure:
- `scope_guard.py`: Target scope validation at EVERY tool invocation
- `hitl_gate.py`: Human-in-the-Loop approval for all exploitation
- `docker_env.py`: Isolated Kali Docker sandbox
- `audit_logger.py`: Immutable append-only audit log

See [Safety Architecture](safety.md) for details.

### UI Layer (`src/spider/tui/`)

Textual (textualize.io) terminal UI:
- Dashboard: target map, live findings, phase progress
- Findings: deep-dive CVE details with exploit options
- HITL: approval dialogs for exploit authorization
- Report viewer: generated pentest report display

See [Terminal UI](tui.md) for screen layouts and navigation.

### Testing Lab (`lab/`)

Docker Compose environment with safe, deliberately vulnerable targets:
- DVWA (Damn Vulnerable Web Application)
- OWASP Juice Shop
- Metasploitable 2

All targets on internal bridge network. No external internet access.

See [Testing Methodology](testing.md) for setup and procedures.

## Configuration

```bash
# Environment variables (pydantic-settings)
SPIDER_OPENROUTER_API_KEY=sk-or-...
SPIDER_LANGFUSE_PUBLIC_KEY=pk-lf-...
SPIDER_LANGFUSE_SECRET_KEY=sk-lf-...
SPIDER_OLLAMA_BASE_URL=http://localhost:11434
SPIDER_DEFAULT_MODEL=anthropic/claude-sonnet-4-5-20250929
SPIDER_ALLOWED_TARGETS=192.168.1.0/24,10.0.0.0/8
SPIDER_SANDBOX_TIMEOUT=300
SPIDER_MAX_REFINE_RETRIES=3
```

## Dependency Chain

```
schemas.py (no deps -- imported by all modules)
       ↑
tools/*.py (import schemas, register with adapter)
       ↑
nodes/*.py (import tools, build DSPy signatures + modules)
       ↑
engine/*.py (import nodes, build weaver/runner/orchestrator)
       ↑
tui/*.py (import engine, orchestrate execution + display results)
```
