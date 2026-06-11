# Security Tools

SPIDER wraps security tools as `dspy.Tool` instances. Each tool is registered
through the adapter pattern which automatically enforces scope guards, audit
logging, JSON serialization, and timeout management.

## Tool Registration Pattern

All tools follow the same registration pattern:

```python
import dspy
import json
import subprocess

def nmap_scan(target: str, ports: str = "-T4 -sV -p-", args: str = "-sC") -> str:
    """Run nmap scan against target. Returns open ports, service versions,
    and OS detection results. Primary reconnaissance tool."""
    cmd = ["nmap", ports, args, "-oX", "-", target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return json.dumps({
        "success": result.returncode == 0,
        "output": result.stdout,
        "errors": result.stderr,
        "exit_code": result.returncode,
    })

# Register as DSPy tool (adapter adds scope guard + audit logging)
nmap_tool = make_tool(nmap_scan)
```

## Reconnaissance Tools

### nmap_scan(target, ports, args)
**Type**: Wrapper | **Phase**: Recon
Primary network scanner. Discovers hosts, open ports, service versions, OS detection.

### masscan_scan(target, ports, rate)
**Type**: Wrapper | **Phase**: Recon
Fast port scanner for large IP ranges. Finds open ports quickly, then hand off to nmap.

### whois_lookup(domain)
**Type**: Wrapper | **Phase**: Recon
WHOIS database queries for domain registration info, nameservers, contact details.

### dns_enum(domain)
**Type**: Wrapper | **Phase**: Recon
DNS enumeration -- A, AAAA, MX, TXT, NS records. Identifies mail servers, SPF records.

### subdomain_enum(domain)
**Type**: Wrapper | **Phase**: Recon
Subdomain discovery via certificate transparency logs, DNS brute-forcing, and search engines.

## Enumeration Tools

### gobuster_scan(target, mode, wordlist)
**Type**: Wrapper | **Phase**: Enumeration
Directory and file brute-forcing against web servers. Supports dir, dns, vhost modes.

### ffuf_scan(target, wordlist, extensions)
**Type**: Wrapper | **Phase**: Enumeration
Fast web fuzzer. Discovers hidden endpoints, parameters, and virtual hosts.

### nikto_scan(target)
**Type**: Wrapper | **Phase**: Enumeration
Web server scanner for outdated software, dangerous files, configuration issues.

### enum4linux(target)
**Type**: Wrapper | **Phase**: Enumeration
Windows/SMB enumeration -- users, shares, group memberships, password policies.

## Vulnerability Scanners

### nuclei_scan(target, templates, severity)
**Type**: Wrapper | **Phase**: Vulnerability Analysis
Template-based vulnerability scanner. Supports thousands of YAML-based detection templates.

### nmap_nse(target, scripts)
**Type**: Wrapper | **Phase**: Vulnerability Analysis
Nmap Scripting Engine -- vuln detection, default credential checks, exploit attempts.

## Custom Tools (Our Differentiators)

### cve_intelligence(service, version, cpe)
**Type**: CUSTOM | **Phase**: Vulnerability Analysis
Cross-references three intelligence sources in parallel:
- **NVD API 2.0**: Full CVE details with CVSS v3.1 scores
- **CISA KEV**: Known Exploited Vulnerabilities (actively exploited in the wild)
- **EPSS**: Exploit Prediction Scoring System (probability of exploitation in next 30 days)

Returns JSON string (deserializes to `list[CVEFinding]`). All tools return JSON for DSPy compatibility.

```python
class CVEFinding(BaseModel):
    cve_id: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    epss_score: float = Field(ge=0.0, le=1.0)
    in_kev: bool  # Known exploited in the wild
    has_public_exploit: bool
    summary: str
    references: list[str]
```

**Rate limiting**: NVD API is 0.6 req/sec. The tool implements:
- Local SQLite cache with 24h TTL
- Batch request bundling
- Exponential backoff on 429 responses

### exploit_matcher(cve_id, target_os, target_arch, mitigations)
**Type**: CUSTOM | **Phase**: Vulnerability Analysis
Maps CVEs to actual applicable exploits. Queries:
- Exploit-DB via searchsploit CLI
- Metasploit module database
- Public GitHub PoC repositories

Filters results by target context (OS, architecture, mitigations like ASLR/DEP).

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
```

### payload_generator(vuln_type, target_info, constraints)
**Type**: CUSTOM | **Phase**: Exploit Planning
Generates custom payloads using LLM reasoning, validated by Pydantic schemas:

```python
class GeneratedPayload(BaseModel):
    payload: str
    encoding: str  # "raw", "url", "base64", "hex", "unicode"
    vuln_type: str
    expected_result: str
    waf_bypass_notes: str
    validation_status: str  # "valid", "needs_adjustment", "blocked"
```

Supports: SQLi, XSS, RCE, SSRF, LFI, command injection, XXE, SSTI.

Uses `dspy.Refine` with a reward function that validates:
- Payload syntax correctness
- Expected vulnerability interaction
- Encoding/escaping consistency

### attack_chain_builder(vulnerabilities, target_topology, goal)
**Type**: CUSTOM | **Phase**: Exploit Planning
Constructs multi-step attack paths from discovered vulnerabilities:

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
```

Examples of chains it builds:
- Web RCE -> www-data access -> SUID binary -> root
- SQLi -> database credentials -> SSH login -> internal pivot -> domain controller
- XSS -> cookie theft -> admin session -> file upload -> reverse shell

### adaptive_tester(test_type, target, previous_attempts)
**Type**: CUSTOM | **Phase**: All phases
The "solve its own problems" tool. When a security test fails, this module:
1. Analyzes WHY the test failed (WAF block, wrong port, rate limit, etc.)
2. Adapts its approach (different encoding, different wordlist, different timing)
3. Retries with the adapted approach
4. Uses `dspy.Refine` internally for quality-driven improvement

```python
class AdaptationResult(BaseModel):
    test_name: str
    initial_result: str
    adaptation_made: str
    new_result: str
    success: bool
    attempts: int
```

## Exploitation Tools (HITL-Gated)

### sqlmap_run(target, options)
**Type**: Wrapper | **Phase**: Exploitation | **HITL**: Yes
SQL injection detection and exploitation. Requires human approval.

### hydra_run(target, service, wordlist)
**Type**: Wrapper | **Phase**: Exploitation | **HITL**: Yes
Brute-force authentication for various protocols (SSH, FTP, HTTP, SMB).

### metasploit_run(module, target, options)
**Type**: Wrapper | **Phase**: Exploitation | **HITL**: Yes
Metasploit Framework exploitation. Requires human approval for module selection.

## Post-Exploitation Tools (HITL-Gated)

### bloodhound_run(domain, credentials)
**Type**: Wrapper | **Phase**: Post-Exploitation | **HITL**: Yes
Active Directory attack path analysis. Maps trust relationships and abuse paths.

### crackmapexec_run(target, protocol, credentials)
**Type**: Wrapper | **Phase**: Post-Exploitation | **HITL**: Yes
Lateral movement and credential testing across Windows networks.

### responder_run(target, interface)
**Type**: Wrapper | **Phase**: Post-Exploitation | **HITL**: Yes
LLMNR/NBT-NS/MDNS poisoning for credential capture. The target is part of the public tool signature for scope authorization and audit correlation.

## Tool Adapter

The adapter (`adapter.py`) wraps every tool with safety infrastructure:

```python
def make_tool(func, scope_guard=None, audit_logger=None, timeout=300):
    """Wrap a tool function with scope checking, audit logging, and timeout."""
    @functools.wraps(func)
    def wrapped(**kwargs):
        # 1. Scope check
        if scope_guard and "target" in kwargs:
            authorized, reason = scope_guard.authorize(kwargs["target"], func.__name__)
            if not authorized:
                return json.dumps({"error": f"OUT_OF_SCOPE: {reason}"})

        # 2. Audit log
        if audit_logger:
            audit_logger.log(
                timestamp=datetime.utcnow(),
                action=func.__name__,
                target=kwargs.get("target", "unknown"),
                params={k: v for k, v in kwargs.items() if k != "target"},
                phase="pending",
            )

        # 3. Execute with timeout
        try:
            result = func(**kwargs)
            phase = "completed"
        except subprocess.TimeoutExpired:
            result = json.dumps({"error": "TIMEOUT", "limit": timeout})
            phase = "timeout"
        except Exception as e:
            result = json.dumps({"error": str(e)})
            phase = "error"

        # 4. Audit log result
        if audit_logger:
            audit_logger.update_phase(phase=phase, result=result[:500])

        return result

    return dspy.Tool(wrapped)
```

## Adding New Tools

1. Write the tool function in the appropriate `tools/` module
2. MUST have: clear docstring, type annotations, returns JSON string
3. Register via `make_tool()` in the adapter
4. Add the tool to `SpiderConfig.available_tools` list
5. Write tests: mock the underlying CLI, assert JSON output schema

## Tool Availability by Phase

| Phase | Tools Available | Autonomous? |
|-------|----------------|-------------|
| Recon | nmap, masscan, whois, dns_enum, subdomain_enum | Yes |
| Enumeration | gobuster, ffuf, nikto, enum4linux | Yes |
| Vuln Analysis | nuclei, nmap NSE, cve_intelligence, exploit_matcher | Yes |
| Exploit Planning | attack_chain_builder, payload_generator, adaptive_tester | Yes |
| Exploitation | sqlmap, hydra, metasploit | HITL Required |
| Post-Exploitation | bloodhound, crackmapexec, responder | HITL Required |
| Reporting | None (synthesis only) | Yes |

**Phase 4 (Exploit Planning) produces a plan with HITL flags.**
**Phase 5 (Exploitation) waits for explicit human approval before each step.**
