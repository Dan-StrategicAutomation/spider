---
name: SPIDER - Symbiotic Pentesting Investigation & DSPy Exploitation Runtime
version: 0.1.0
status: design
created: 2026-04-06
---

# SPIDER - Full Architecture & Design Plan

## 1. Vision

A DSPy-native penetration testing framework that combines traditional security tools
with LLM-driven reasoning, self-evaluation, and autonomous problem-solving. Unlike
existing MCP-based pentest servers (HexStrike, Tengu, pentestMCP) which are just
tool orchestrators, SPIDER uses `dspy.Refine` for quality-driven retry loops,
Pydantic-validated output schemas, and attack chain reasoning.

## 2. What Exists (Landscape Analysis)

### MCP Pentest Servers (Tool Providers Only)
| Project | Tools | Stars | Notes |
|---------|-------|-------|-------|
| Tengu (rfunix/tengu) | 80 | - | PTES methodology, safety controls, audit logging |
| HexStrike AI (0x4m4/hexstrike-ai) | 150+ | 1.5k | Multi-agent, but raw LLM calls, no self-eval |
| pentestMCP (ramkansal/pentestMCP) | 20+ | 51 | Clean Docker architecture, async execution |
| mcp-security-hub (FuzzingLabs) | Multiple | - | Individual MCP servers per tool (nmap, nuclei, sqlmap) |
| kali-docker MCP (weirdmachine64) | Kali tools | - | Sandboxed Kali in Docker |

### AI Pentest Agents (Full Frameworks)
| Project | Approach | Strengths | Gaps |
|---------|----------|-----------|------|
| LuaN1aoAgent (SanMuzZzZz) | PER cycle (Plan-Execute-Reflect) | 645 stars, XBOW 90%+, RAG knowledge base | NOT DSPy, custom orchestration, Chinese-first |
| xOffense | Multi-stage academic approach | Research paper, structured evaluation | Academic only, not production-ready |
| HexStrike Agents | Multi-agent via MCP | 12+ agents, 150+ tools | No self-evaluation, no quality scoring |

### What Nobody Has Built
- DSPy-native pentesting (zero projects found)
- `dspy.Refine` for exploit chain quality
- Attack path reasoning with Pydantic validation
- Adaptive payload generation with self-eval
- Self-improving vulnerability analysis

## 3. Architecture

```
spider/
├── pyproject.toml                # DSPy 3.1+, pydantic, pydantic-settings, ruff, pytest
├── AGENTS.md                     # Project context for AI agents
├── src/spider/
│   ├── __init__.py
│   │
│   ├── config.py                 # Pydantic Settings (SpiderConfig)
│   └── schemas.py                # Centralized Pydantic models (ALL structured data)
│   │
│   ├── engine/                   # DSPy Core - The Brains
│   │   ├── weaver.py             # GraphWeaver - builds pentest topology via dspy.Refine
│   │   ├── runner.py             # GraphRunner - wave-based parallel execution
│   │   ├── self_eval.py          # Pentest-specific quality evaluator
│   │   └── orchestrator.py       # Top-level: Weaver -> Provision -> Runner -> Heal loop
│   │
│   ├── nodes/                    # DSPy Node Modules (signatures + modules)
│   │   ├── recon.py              # ReconSignature + ReconModule (root ReAct node)
│   │   ├── enum.py               # EnumSignature + EnumModule
│   │   ├── vuln_analysis.py      # VulnAnalysisSignature + VulnAnalysisModule
│   │   ├── exploit_planner.py    # ExploitPlanSignature + ExploitPlanModule
│   │   ├── executor.py           # ExecutorSignature + ExecutorModule (HITL-gated)
│   │   ├── post_exploit.py       # PostExploitSignature + PostExploitModule
│   │   └── reporter.py           # ReportSignature + ReportModule
│   │
│   ├── tools/                    # Security Tools as dspy.Tool wrappers
│   │   ├── __init__.py           # register() all tools
│   │   ├── recon_tools.py        # nmap, masscan, amass, whois, dig
│   │   ├── enum_tools.py         # gobuster, ffuf, nikto, enum4linux
│   │   ├── vuln_scanners.py      # nuclei, nmap NSE, trivy
│   │   ├── cve_intelligence.py   # CUSTOM: NVD API + CISA KEV + EPSS lookup
│   │   ├── exploit_matcher.py    # CUSTOM: Exploit-DB + Metasploit module matcher
│   │   ├── payload_gen.py        # CUSTOM: Adaptive payload generator with validation
│   │   ├── attack_chain.py       # CUSTOM: Multi-step attack chain builder
│   │   ├── exploitation.py       # sqlmap, hydra, metasploit (HITL-gated)
│   │   ├── post_exploit_tools.py # bloodhound, crackmapexec, responder
│   │   └── adapter.py            # Tool adapter wrapper for dspy.Tool registration
│   │
│   ├── sandbox/                  # SAFE EXECUTION ENVIRONMENT
│   │   ├── docker_env.py         # Kali Linux Docker sandbox management
│   │   ├── scope_guard.py        # Target scope validation (never attack out-of-scope)
│   │   ├── hitl_gate.py          # Human-in-the-Loop approval gate
│   │   └── audit_logger.py       # Immutable audit log of all actions
│   │
│   ├── intelligence/             # CUSTOM: Threat Intelligence
│   │   ├── cve_db.py             # NVD API 2.0 client with rate limiting + caching
│   │   ├── exploit_db.py         # Exploit-DB / searchsploit integration
│   │   ├── kev.py                # CISA Known Exploited Vulnerabilities feed
│   │   └── epss.py               # EPSS exploit probability scoring
│   │
│   ├── tui/                      # Terminal UI (Textual framework)
│   │   ├── app.py                # Main TUI application
│   │   ├── dashboard.py          # Live scan results, target map
│   │   ├── findings.py           # Vulnerability findings panel
│   │   ├── attack_graph.py       # Visual attack chain display
│   │   ├── hitl_dialog.py        # Human approval dialogs
│   │   └── report_view.py        # Generated report viewer
│   │
│   └── testing/                  # Safe testing infrastructure
│       ├── vulnerable_targets.py # Local DVWA, metasploitable2, Juice Shop targets
│       ├── test_orchestrator.py  # Test runner against safe targets
│       ├── validation.py         # Result validation / scoring
│       └── docker_compose.py     # docker-compose for test lab
│
├── tests/                        # Pytest suite
│   ├── test_scopes/
│   ├── test_nodes/
│   ├── test_tools/
│   ├── test_sandbox/
│   └── test_integration/
│
├── lab/                          # Docker Compose test lab
│   ├── docker-compose.yml        # DVWA + Juice Shop + Metasploitable2
│   └── kali-tools/Dockerfile     # Custom Kali with pre-installed tools
│
└── docs/                         # Documentation
    ├── architecture.md
    ├── testing.md
    ├── safety.md
    └── tui.md
```

## 4. DSPy Node Topology (Default Graph)

```
WAVE 0 (Root - ReAct):
  recon (role: react, tools: [nmap_scan, whois_lookup, dns_enum, subdomain_enum])
    └── outputs: ReconResults (hosts, ports, services, technologies)

WAVE 1 (Parallel):
  web_enum (depends_on: [recon], role: chain_of_thought, tools: [gobuster, nikto, tech_detect])
    └── outputs: WebFindings (directories, params, tech, potential_vulns)
  service_enum (depends_on: [recon], role: chain_of_thought, tools: [nmap_nse, service_probe])
    └── outputs: ServiceDetails (versions, configs, default_creds)

WAVE 2:
  vuln_analysis (depends_on: [web_enum, service_enum], role: chain_of_thought,
                 tools: [cve_intelligence, exploit_matcher, nuclei_scan])
    └── outputs: VulnerabilityList (cves, severity, cvss, exploit_available)

WAVE 3:
  exploit_planner (depends_on: [vuln_analysis], role: chain_of_thought,
                   tools: [attack_chain_builder, payload_generator])
    └── outputs: AttackPlan (prioritized_paths, chains, hitl_required)

WAVE 4 (HITL-gated - ReAct):
  executor (depends_on: [exploit_planner], role: react,
            tools: [sqlmap_run, hydra_run, metasploit_run], hitl: true)
    └── outputs: ExploitResult (success, access_level, creds_found)

WAVE 5:
  reporter (depends_on: [recon, vuln_analysis, executor], role: chain_of_thought)
    └── outputs: PentestReport (exec_summary, technical_findings, remediation)
```

Each node is wrapped with `dspy.Refine(module, N=3, reward_fn, threshold=0.7)`
for self-improvement. The reward function is context-specific:
- Recon: rewards breadth (hosts found + ports + services + tech stack)
- Vuln Analysis: rewards specificity (CVEs matched + CVSS + exploit availability)
- Exploit Planning: rewards feasibility (chain completeness + stealth score)
- Reporter: rewards structure (all sections populated + actionable remediation)

## 5. Custom Tool Designs

### 5.1 cve_intelligence(service, version, cpe)
Lookups across 3 intelligence sources in parallel:
```python
from pydantic import BaseModel, Field

class CVEFinding(BaseModel):
    cve_id: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    epss_score: float = Field(ge=0.0, le=1.0)  # Exploit probability
    in_kev: bool  # Known exploited in the wild
    has_public_exploit: bool
    summary: str
    references: list[str]

def cve_intelligence(
    service: str,
    version: str,
    cpe: str = "",
    max_results: int = 20
) -> list[CVEFinding]:
    """Look up known CVEs for a service/version across NVD, CISA KEV, and EPSS.
    Returns prioritized vulnerabilities with exploit availability.

    Sources queried:
    - NVD API 2.0 (full CVE details + CVSS)
    - CISA Known Exploited Vulnerabilities (actively exploited)
    - EPSS (Exploit Prediction Scoring System)
    """
```

### 5.2 exploit_matcher(cve_id, target_context)
Maps CVEs to actual applicable exploits:
```python
class ExploitMatch(BaseModel):
    exploit_id: str
    source: str  # "exploit-db", "metasploit", "github-poc"
    title: str
    platform: str
    reliability: str  # "excellent", "good", "average", "manual"
    privileges_required: str
    success_probability: float = Field(ge=0.0, le=1.0)
    metasploit_module: str | None = None
    exploit_db_id: int | None = None
    notes: str

def exploit_matcher(
    cve_id: str,
    target_os: str,
    target_arch: str,
    mitigations: list[str] | None = None
) -> list[ExploitMatch]:
    """Find applicable exploits for a CVE against a specific target context.
    Checks Exploit-DB, Metasploit modules, and public PoC repositories.
    Filters by OS, architecture, and mitigations (ASLR, DEP, etc.).
    """
```

### 5.3 payload_generator(vuln_type, target_info, constraints)
Generates and validates custom payloads:
```python
class GeneratedPayload(BaseModel):
    payload: str
    encoding: str  # "raw", "url", "base64", "hex", "unicode"
    vuln_type: str
    expected_result: str
    waf_bypass_notes: str
    validation_status: str  # "valid", "needs_adjustment", "blocked"

def payload_generator(
    vuln_type: str,  # "sqli", "xss", "rce", "ssrf", "lfi", "command_injection"
    target_info: dict,
    constraints: dict | None = None
) -> GeneratedPayload:
    """Generate a custom payload for a specific vulnerability type against
    the target's technology stack. Adapts encoding and bypass techniques
    based on WAF/firewall detection patterns.
    """
```

### 5.4 attack_chain_builder(findings, goal)
Builds multi-step attack paths:
```python
class AttackStep(BaseModel):
    step_number: int
    action: str
    tool: str
    cve_id: str | None = None
    expected_outcome: str
    hitl_required: bool
    risk_level: str  # "low", "medium", "high", "critical"

class AttackChain(BaseModel):
    name: str
    steps: list[AttackStep]
    final_objective: str
    overall_risk: str
    stealth_score: float = Field(ge=0.0, le=1.0)
    feasibility_score: float = Field(ge=0.0, le=1.0)

def attack_chain_builder(
    vulnerabilities: list[CVEFinding],
    target_topology: dict,
    goal: str = "full system access"
) -> list[AttackChain]:
    """Build multi-step attack chains from discovered vulnerabilities.
    Chains may include: initial access -> privilege escalation ->
    lateral movement -> persistence. Prioritizes by stealth and feasibility.
    """
```

### 5.5 adaptive_tester(vulnerability, target)
The "solve its own problems" tool:
```python
class AdaptationResult(BaseModel):
    test_name: str
    initial_result: str
    adaptation_made: str
    new_result: str
    success: bool
    attempts: int

def adaptive_tester(
    test_type: str,
    target: str,
    previous_attempts: list[dict] | None = None
) -> AdaptationResult:
    """Run a security test and adapt if blocked. If the WAF blocks
    the initial payload, try different encodings. If timing-based
    detection fails, switch to blind techniques. The LLM reasons
    about WHY the test failed and adapts accordingly.
    """
```

## 6. GUI Design (Textual TUI)

### 6.1 Technology Choice: Textual (textualize.io)
- Modern Python TUI framework with Rich rendering
- Supports layouts, panels, tables, progress bars, dialogs
- Runs in any terminal (SSH-safe, tmux-compatible)
- CSS-like styling system for theming
- Async event loop compatible with dspy operations

### 6.2 Layout

```
+-------------------------------------------------------------------+
|  SPIDER v0.1.0  |  Target: 192.168.1.100  |  Mode: FULL_PENTEST   |
+-------------------------------------------------------------------+
|  TARGET MAP                    |  LIVE FINDINGS TABLE              |
|  (Network graph visualization) |  (scrollable table)              |
|                                |  | HOST | PORT | VULN  | CVSS |  |
|    [Internet]                  |  |------|------|-------|------|  |
|         |                      |  | .100 |  80  | CVE-X |  9.1 |  |
|      [Firewall]                |  | .100 |  443 | CVE-Y |  7.5 |  |
|     /       \                  |  | .100 | 3306 | ...   |  ... |  |
|   [Web]    [DB]               |  |------|------|-------|------|  |
|                                |                                   |
+--------------------------------+-----------------------------------+
|  PHASE PROGRESS                                               62%  |
|  Recon [##] Enum [##] VulnScan [--] Planning [--] Exec [--] Report |
+--------------------------------+-----------------------------------+
|  ATTACK CHAIN VISUALIZATION     |  LLM THINKING / REASONING        |
|  (step-by-step chain)          |  (streaming DSPy output)          |
|                                |                                   |
|  [1] Nmap -> 8 open ports     |  "The Apache version 2.4.49 is   |
|  [2] CVE-2021-41773 found     |   vulnerable to path traversal.   |
|  [3] [HITL] Approve exploit?  |   I will attempt to read /etc/..."|
|  [4] Post-exploit: www-data   |                                   |
+--------------------------------+-----------------------------------+
|  AUDIT LOG (append-only, timestamped)                             |
|  [2026-04-06 07:15:22] Recon started against 192.168.1.100        |
|  [2026-04-06 07:15:25] Nmap: 8 open ports discovered              |
|  [2026-04-06 07:15:30] CVE intelligence: 3 matches found          |
+-------------------------------------------------------------------+
|  STATUS BAR: dspy.Refine: retry 2/3 | EPSS: 0.91 | KEV: active    |
+-------------------------------------------------------------------+
```

### 6.3 Key UI Screens

1. **Dashboard** (default screen) - The layout above
2. **Findings Detail** - Deep dive into a single CVE with exploit options
3. **HITL Approval** - Modal dialog for exploit authorization:
   ```
   +----------------------------------------------------------+
   |  EXPLOIT AUTHORIZATION REQUIRED                          |
   |----------------------------------------------------------|
   |  Target:    192.168.1.100:80                             |
   |  CVE:       CVE-2021-41773 (Apache Path Traversal)       |
   |  CVSS:      9.8 (CRITICAL)                               |
   |  EPSS:      0.97 (97% probability of exploitation)       |
   |  In KEV:    YES - Actively exploited in the wild         |
   |                                                          |
   |  Action:    Attempt path traversal to read /etc/passwd   |
   |  Risk:      Service crash possible                       |
   |                                                          |
   |  [ APPROVE ]  [ DENY ]  [ APPROVE WITH CONSTRAINTS ]     |
   +----------------------------------------------------------+
   ```
4. **Report Viewer** - Generated pentest report with export options
5. **Configuration** - Target scope, rules of engagement, tool settings
6. **Test Lab** - Local vulnerable targets for safe testing

## 7. Safety Architecture

### 7.1 Scope Guard (NEVER attack out of scope)
```python
class ScopeGuard:
    def __init__(self, allowed_targets: list[str], excluded: list[str]):
        # All operations checked against these lists
        pass

    def authorize(self, target: str, action: str) -> bool:
        # Check target is in allowed scope
        # Check target is NOT in excluded list
        # Check action is allowed for this target
        # Return True/False with reason
        pass
```

### 7.2 Sandbox Execution (Kali Docker)
```yaml
# sandbox/Dockerfile
FROM kalilinux/kali-rolling
# Only install tools listed in ALLOWED_TOOLS
# No internet access from sandbox (air-gapped network)
# Resource limits: CPU 4 cores, RAM 8GB
# No access to host filesystem
# All actions logged to audit_logger
```

### 7.3 Human-in-the-Loop Gates
- ALL exploitation actions require explicit HITL approval
- Only recon and enumeration are fully autonomous
- HITL prompts show: CVE details, risk level, potential impact
- Approval can be constrained (e.g., "read-only only, no execution")
- Time-limited approvals (auto-expire after N minutes)

### 7.4 Audit Logging
- Immutable append-only log file
- Every tool invocation logged with timestamp, target, action, result
- Signed log entries for integrity
- Exportable for compliance reporting

## 8. Testing Infrastructure

### 8.1 Local Vulnerable Lab (docker-compose)

```yaml
# lab/docker-compose.yml
services:
  dvwa:          # Damn Vulnerable Web Application
    image: vulnerables/web-dvwa
    networks:
      - pentest_lab

  juice_shop:    # OWASP Juice Shop
    image: bkimminich/juice-shop
    networks:
      - pentest_lab

  metasploitable2:
    image: tleemcjr/metasploitable2
    networks:
      - pentest_lab

  # SPIDER runs in isolated container, connects only to lab network
  spider:
    build: ./kali-tools
    networks:
      - pentest_lab
    depends_on: [dvwa, juice_shop, metasploitable2]

networks:
  pentest_lab:
    driver: bridge
    internal: true  # No external internet
```

### 8.2 Test Methodology

1. **Unit Tests** (pytest against mocks)
   - Each dspy.Module tested with mocked LM
   - Tool wrappers tested against known inputs/outputs
   - Schema validation tested for all Pydantic models
   - No network calls

2. **Integration Tests** (pytest against lab targets)
   - Run against DVWA, Juice Shop, Metasploitable2
   - Verify recon finds expected hosts/ports
   - Verify vuln analysis finds known CVEs
   - Verify report generation produces valid output
   - Expected findings are pre-documented

3. **End-to-End Tests** (full graph execution)
   - `spider scan 192.168.x.x --mode recon-only` (safe)
   - `spider scan 192.168.x.x --mode full` (against lab only)
   - Compare actual findings against expected baseline
   - Score: % of known vulnerabilities discovered

4. **Safety Tests** (MUST PASS BEFORE ANYTHING ELSE)
   - Out-of-scope target rejection
   - HITL gate enforcement
   - Sandbox isolation verification
   - No tool execution against non-lab targets without explicit override
   - Audit log integrity

### 8.3 CI/CD Pipeline
```
pre-commit: ruff format -> ruff check -> mypy
tests/unit: mock-based unit tests
tests/safety: scope guard + sandbox + HITL tests
tests/integration: dvwa/juice-shop/metasploitable2 against lab
tests/e2e: full graph execution against lab (recon-only by default)
```

## 9. Dependencies

```python
# Core
dspy>=3.1.3,<4.0.0
pydantic>=2.0,<3.0
pydantic-settings>=2.0,<3.0

# TUI
textual>=0.50.0,<1.0.0
rich>=13.0,<15.0

# Security Tools Integration
python-libnmap>=0.7.3         # Nmap parsing
pyproject-registry            # Nuclei Python bindings (if available)
requests>=2.31,<3.0           # API calls (NVD, CISA, EPSS)

# Sandbox / Testing
docker>=7.0,<8.0
pytest>=8.0,<9.0

# Utilities
httpx>=0.27,<1.0              # Async HTTP for APIs
tenacity>=8.0,<9.0            # Rate limit retry for NVD API
questionary>=2.0,<3.0          # HITL CLI prompts
loguru>=0.7,<1.0               # Structured logging
```

## 10. Implementation Phases

### Phase 1: Foundation (Week 1-2)
- [x] Project scaffold (pyproject.toml, ruff, pytest config)
- [x] Pydantic schemas for all structured data
- [x] ScopeGuard + audit logger
- [x] Docker sandbox with Kali tools
- [x] Basic config via pydantic-settings

### Phase 2: Tool Layer (Week 2-3)
- [x] Recon tools (nmap, whois, dns_enum)
- [x] Enum tools (gobuster, ffuf, nikto)
- [x] Custom: cve_intelligence (NVD + KEV + EPSS)
- [x] Custom: exploit_matcher (Exploit-DB + Metasploit)
- [x] Tool adapter for dspy.Tool registration

### Phase 3: DSPy Core (Week 3-4)
- [x] Node signatures (Recon, VulnAnalysis, ExploitPlanner)
- [x] Graph Weaver with dspy.Refine
- [x] Graph Runner with wave-based parallel execution
- [x] Self-validator with pentest-specific reward functions
- [x] Orchestrator top-level pipeline
- [x] Real-time progress logging for all LLM phases

### Phase 4: HITL + Safety (Week 4-5)
- [x] HITL gate with approval dialogs
- [x] Custom payload generator with dspy.Refine
- [x] Attack chain builder
- [ ] Adaptive tester for self-solving
- [x] Comprehensive safety tests

### Phase 5: TUI (Week 5-6)
- [ ] Textual dashboard layout
- [ ] Live findings table
- [ ] Attack chain visualization
- [ ] HITL approval dialogs
- [ ] Report viewer

### Phase 6: Testing Lab (Week 6-7)
- [ ] docker-compose lab (DVWA, Juice Shop, Metasploitable2)
- [ ] Expected findings documentation
- [ ] Integration test suite
- [ ] E2E tests against lab
- [ ] CI/CD pipeline

### Phase 7: Polish & Documentation (Week 7-8)
- [ ] AGENTS.md for AI development
- [ ] User documentation
- [ ] Safety documentation
- [ ] Example runs against lab targets
- [ ] Langfuse observability integration

## 11. Key Design Decisions

1. **DSPy-native only** - No Python retry loops. All self-improvement via `dspy.Refine`.
2. **Pydantic for ALL structured data** - Every InputField/OutputField typed with BaseModel.
3. **Recon and enum are autonomous** - No HITL required for non-destructive ops.
4. **ALL exploitation requires HITL** - No exceptions. Even in test lab mode.
5. **Sandbox-first** - All tools run in isolated Docker containers.
6. **Audit-everything** - Every action logged, immutable, exportable.
7. **Scope-guarded** - Hard enforcement of target scope at the tool level.
8. **Textual TUI** - Modern terminal UI, SSH-safe, works everywhere.
9. **Modular tool registration** - Tools can be added as plugins without core changes.

## 12. Risks & Mitigations

|| Risk | Impact | Mitigation |
||------|--------|------------|
|| NVD API rate limits (0.6 req/s) | High | Local caching, batch requests, retry with backoff |
|| LLM hallucinates exploit success | Critical | HITL gate, tool output validation, no blind trust |
|| Tools break on target OS | Medium | Adaptive tester with fallback strategies |
|| False positive findings | Medium | Reward function penalizes unsubstantiated findings |
|| Sandbox escape | Critical | Docker security best practices, no privileged mode |
|| dspy.Refine too expensive | High | N=3 max, threshold tuned per node, local model fallback |
|| Out-of-scope targeting | Critical | ScopeGuard at EVERY tool invocation, audit trail |
|| Missing binary dependencies | Medium | Python-native alternatives for core functions, graceful degradation |

## 13. Tool Enhancement Strategy

To improve portability and reduce dependency issues, SPIDER will implement Python-native alternatives for core security tool functions where performance permits:

### 13.1 DNS Enumeration
- Replace `dig`/`nslookup` with `dnspython` library for A, AAAA, MX, TXT, NS records
- Maintains identical JSON output format for DSPy compatibility
- Optional fallback to system `dig` if available for advanced features (AXFR, etc.)

### 13.2 WHOIS Lookup
- Replace system `whois` with `python-whois` library
- Provides structured domain registration data
- Graceful fallback to binary if library unavailable

### 13.3 Basic Port Scanning
- TCP connect scanner using `socket` or `scapy` for quick checks
- Not intended to replace nmap/masscan for full scans
- Useful for cloud environments where raw sockets are restricted
- Returns same JSON structure as binary tools

### 13.4 Web Enumeration Supplement
- Simple `requests`-based directory/parameter fuzzing
- Wordlist iteration with timeout/retry handling
- Supplements gobuster/ffuf in constrained environments
- Identical output format for seamless integration

### 13.5 Implementation Approach
- **Adapter Enhancement**: Check for Python alternatives before falling back to binaries
- **Configuration Option**: Allow users to prefer Python tools via `.env` settings
- **Environment Detection**: Auto-select appropriate tools in restricted environments (containers, cloud)
- **Backward Compatibility**: All tools maintain identical JSON output signatures
- **Gradual Rollout**: Start with DNS/WHOIS, expand based on utility and performance

This approach ensures SPIDER remains functional in restricted environments while still leveraging the power of established security tools when available. The DSPy-native core remains unaffected - only the tool implementation layer gains enhanced portability.

