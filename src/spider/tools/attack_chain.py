"""attack_chain -- CUSTOM: Multi-step attack chain builder."""

import json


def attack_chain_builder(
    vulnerabilities: str = "",
    target_topology: str = "",
    goal: str = "full system access",
) -> str:
    """Build multi-step attack chains from discovered vulnerabilities.

    Chains may include: initial access -> privilege escalation ->
    lateral movement -> persistence. Prioritizes by stealth and feasibility.
    """
    vulns = []
    if vulnerabilities:
        try:
            vulns = json.loads(vulnerabilities)
        except json.JSONDecodeError:
            return json.dumps({
                "success": False,
                "error": "Invalid vulnerabilities JSON",
            })

    if not vulns:
        return json.dumps({
            "success": True,
            "chains": [],
            "total": 0,
            "note": "No vulnerabilities provided",
        })

    chains = []
    chain_id = 1

    high_vulns = [v for v in vulns if v.get("cvss", 0) >= 7.0]
    med_vulns = [v for v in vulns if 4.0 <= v.get("cvss", 0) < 7.0]
    [v for v in vulns if v.get("cvss", 0) < 4.0]

    if high_vulns:
        step_num = 1
        steps = []
        for v in high_vulns[:3]:
            steps.append({
                "step_number": step_num,
                "action": f"Exploit {v.get('cve_id', 'unknown')}",
                "tool": "metasploit",
                "cve_id": v.get("cve_id"),
                "expected_outcome": "Initial access via high-severity vulnerability",
                "hitl_required": True,
                "risk_level": "critical",
            })
            step_num += 1

        chain = {
            "id": chain_id,
            "name": "Direct Exploitation Chain",
            "steps": steps,
            "final_objective": goal,
            "overall_risk": "critical",
            "stealth_score": 0.3,
            "feasibility_score": 0.8,
        }
        chains.append(chain)
        chain_id += 1

    if med_vulns:
        step_num = 1
        steps = []
        for v in med_vulns[:3]:
            steps.append({
                "step_number": step_num,
                "action": f"Exploit {v.get('cve_id', 'unknown')}",
                "tool": "nuclei",
                "cve_id": v.get("cve_id"),
                "expected_outcome": "Access via medium-severity vulnerability",
                "hitl_required": True,
                "risk_level": "high",
            })
            step_num += 1

        chain = {
            "id": chain_id,
            "name": "Medium Severity Chain",
            "steps": steps,
            "final_objective": goal,
            "overall_risk": "high",
            "stealth_score": 0.6,
            "feasibility_score": 0.6,
        }
        chains.append(chain)
        chain_id += 1

    return json.dumps({
        "success": True,
        "chains": chains,
        "total": len(chains),
    })


def register_all(scope_guard=None, audit_logger=None):
    """Register attack chain builder with the adapter."""
    from spider.tools.adapter import make_tool
    return {
        "attack_chain_builder": make_tool(
            attack_chain_builder,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
        ),
    }
