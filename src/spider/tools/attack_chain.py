"""attack_chain -- CUSTOM: Multi-step attack chain builder."""

import json

from spider.schemas import VulnerabilityList


def attack_chain_builder(
    vulnerabilities: VulnerabilityList | str = "",
    target_topology: str = "",
    goal: str = "full system access",
    **kwargs,
) -> str:
    """Build multi-step attack chains from discovered vulnerabilities.

    Chains may include: initial access -> privilege escalation ->
    lateral movement -> persistence. Prioritizes by stealth and feasibility.
    """
    vulns = []

    if isinstance(vulnerabilities, VulnerabilityList):
        vulns = [
            v.model_dump() if hasattr(v, "model_dump") else dict(v)
            for v in vulnerabilities.vulnerabilities
        ]
    elif vulnerabilities:
        try:
            vulns = json.loads(vulnerabilities)
        except json.JSONDecodeError:
            return json.dumps(
                {
                    "success": False,
                    "error": "Invalid vulnerabilities JSON",
                }
            )

    if not vulns:
        return json.dumps(
            {
                "success": True,
                "chains": [],
                "total": 0,
                "note": "No vulnerabilities provided",
            }
        )

    def get_cvss(v: str | dict) -> float:
        if isinstance(v, str):
            return 0.0
        if isinstance(v, dict):
            return v.get("cvss", 0) or v.get("severity", 0)
        return 0

    def get_cve_id(v: str | dict) -> str:
        if isinstance(v, str):
            return v.split(":")[0] if ":" in v else v
        if isinstance(v, dict):
            cve = v.get("cve", {})
            if isinstance(cve, dict):
                return cve.get("cve_id", "unknown")
            return cve if cve else v.get("cve_id", "unknown")
        return "unknown"

    chains = []
    chain_id = 1

    high_vulns = [v for v in vulns if get_cvss(v) >= 7.0]
    med_vulns = [v for v in vulns if 4.0 <= get_cvss(v) < 7.0]

    if high_vulns:
        step_num = 1
        steps = []
        for v in high_vulns[:3]:
            cve = get_cve_id(v)
            steps.append(
                {
                    "step_number": step_num,
                    "action": f"Exploit {cve}",
                    "tool": "metasploit",
                    "cve_id": cve,
                    "expected_outcome": "Initial access via high-severity vulnerability",
                    "hitl_required": True,
                    "risk_level": "critical",
                }
            )
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
            cve = get_cve_id(v)
            steps.append(
                {
                    "step_number": step_num,
                    "action": f"Exploit {cve}",
                    "tool": "nuclei",
                    "cve_id": cve,
                    "expected_outcome": "Access via medium-severity vulnerability",
                    "hitl_required": True,
                    "risk_level": "high",
                }
            )
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

    return json.dumps(
        {
            "success": True,
            "chains": chains,
            "total": len(chains),
        }
    )


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
