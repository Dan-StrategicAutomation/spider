# Safety Architecture

SPIDER enforces safety at multiple mandatory layers. No tool can execute without
passing through these checks.

## 1. ScopeGuard -- Target Authorization

Every tool invocation is checked against allowed and excluded targets **before
execution**. This happens at the adapter level (`tools/adapter.py`).

```python
# Before any tool runs:
authorized, reason = scope_guard.authorize(target, action_name)
if not authorized:
    return json.dumps({"error": f"OUT_OF_SCOPE: {reason}"})
```

**How it works:**
- Allowed targets are CIDR ranges or hostname patterns
- Excluded targets are explicitly blocked (0.0.0.0, 127.0.0.1, localhost)
- Lab network (172.20.0.0/24) is always authorized for testing
- Scope violations return immediately with an error -- tool never executes

## 2. HITL Gate -- Human Approval for Exploitation

**ALL exploitation actions require explicit human approval.** Only recon and
enumeration are fully autonomous.

```python
# In executor node (ReAct with HITL):
# Before running metasploit, sqlmap, hydra, etc.:
approved = hitl_gate.request(
    action="metasploit_exploit",
    target="192.168.1.100:80",
    risk_level="high",
    details="CVE-2021-41773 - Apache path traversal to read /etc/passwd",
    cve_id="CVE-2021-41773",
    timeout=300,  # Auto-expires after 5 minutes
)
if not approved:
    return json.dumps({"error": "HITL_DENIED: Human did not approve exploitation"})
```

**In non-interactive mode (CI/CD):** Default deny -- no exploitation occurs.

## 3. Sandbox -- Isolated Docker Execution

All tools run inside an isolated Docker container:

- **No privileged mode** -- container runs unprivileged
- **No host filesystem access** -- no volume mounts to host directories
- **Resource limits** -- CPU 4 cores max, 8GB RAM max
- **Internal network** -- lab targets only on isolated bridge network
- **No persistent access** -- container destroyed after each session

```python
# docker_env.py - security settings
kwargs = {
    "image": "kalilinux/kali-rolling",
    "privileged": False,           # NEVER use privileged mode
    "working_dir": "/tmp/spider",  # Isolated working directory
}
if "cpu_count" in self.resource_limits:
    kwargs["cpu_count"] = self.resource_limits["cpu_count"]
if "mem_limit" in self.resource_limits:
    kwargs["mem_limit"] = self.resource_limits["mem_limit"]
```

## 4. Audit Logger -- Immutable Append-Only Log

Every action is logged with:
- Timestamp (UTC)
- Action name (tool function)
- Target
- Phase (started, completed, timeout, error)
- Parameters (redacted if sensitive)
- Result (truncated to prevent log overflow)

```python
{
    "timestamp": "2026-04-06T07:15:22.123456+00:00",
    "action": "nmap_scan",
    "target": "192.168.1.100",
    "phase": "completed",
    "params": {"ports": "-T4 -sV -p-", "args": "-sC"},
    "result": "8 open ports discovered: 22, 80, 443, 3306..."
}
```

**Log integrity:** Logs are append-only. No existing entries can be modified or
deleted. Export capability for compliance reporting.

## 5. Rate Limiting -- Intelligence API Protection

- NVD API: 0.6 req/sec (without key), 5 req/sec (with key)
- EPSS API: Rate limited client-side
- Local caching with 24h TTL to reduce API calls
- Exponential backoff on 429 (Too Many Requests) responses

## 6. Tool Timeout Protection

Every tool invocation has a configurable timeout (default: 300 seconds). Tools
that exceed the timeout are terminated and logged:

```python
try:
    result = func(**kwargs)
except subprocess.TimeoutExpired:
    return json.dumps({"error": "TIMEOUT", "limit": timeout})
```

## Safety Checklist (MUST pass before ANY execution)

1. Target is in allowed scope
2. Target is not in excluded list
3. Sandbox container is running and isolated
4. Audit logger is initialized and writing
5. HITL gate is active for exploitation tools
6. Rate limiting is active for intelligence APIs
7. Timeouts are configured for all tools

## Rules of Engagement

Default RoE (configurable via `SPIDER_RULES_OF_ENGAGEMENT`):
- No destructive actions without human approval
- No production targets without explicit written authorization
- No credential exfiltration beyond what's needed to prove access
- No lateral movement beyond initially authorized scope
- All findings must be documented with proof of exploitation
