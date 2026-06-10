"""Tool registration and catalog building, filtered by ScanMode.

Provides stateless functions for provisioning security tools and
building the ToolCatalog that the GraphWeaver uses to design topologies.
"""

from typing import Any

import dspy

from spider.sandbox.hitl_gate import HITLGate
from spider.sandbox.scope_guard import ScopeGuard
from spider.schemas import ScanMode, ToolCatalog

# ── Tool Category Constants ──────────────────────────────────────────────────

RECON_TOOLS = frozenset(
    {
        "dns_enum",
        "subdomain_enum",
        "whois_lookup",
        "tcp_port_scan",
        "nmap_scan",
        "masscan_scan",
    }
)

WEB_ENUM_TOOLS = frozenset(
    {
        "dirb_scan",
        "nikto_scan",
        "wapitizer",
        "param_spider",
        "webtech_scan",
    }
)

SVC_ENUM_TOOLS = frozenset(
    {
        "smb_enum",
        "mysql_enum",
        "postgres_enum",
        "ssh_enum",
        "ftp_enum",
    }
)

VULN_TOOLS = frozenset(
    {
        "nmap_nse",
        "nuclei_scan",
        "sqlmap_scan",
        "exploit_matcher",
    }
)

ATTACK_PLAN_TOOLS = frozenset(
    {
        "cve_intelligence",
        "exploit_matcher",
        "attack_chain_builder",
    }
)


# ── Public API ───────────────────────────────────────────────────────────────


def build_tools(
    mode: ScanMode,
    scope_guard: ScopeGuard | None = None,
    audit_logger: Any | None = None,
    hitl_gate: HITLGate | None = None,
) -> dict[str, dspy.Tool]:
    """Register security tools filtered by scan mode.

    In RECON mode, exploitation/post-exploitation/payload/attack-chain
    tool modules are never registered.  This is the first line of defense.

    Returns:
        Dictionary mapping tool name to dspy.Tool instance.
    """
    from spider.tools.cve_intelligence import register_all as cve_reg
    from spider.tools.enum_tools import register_all as enum_reg
    from spider.tools.recon_tools import register_all as recon_reg
    from spider.tools.vuln_scanners import register_all as vuln_reg

    kw: dict[str, Any] = {
        "scope_guard": scope_guard,
        "audit_logger": audit_logger,
    }

    tools: dict[str, dspy.Tool] = {}

    # Always available: recon, enumeration, vuln scanning, CVE intel
    tools.update(recon_reg(**kw))
    tools.update(enum_reg(**kw))
    tools.update(vuln_reg(**kw))
    tools.update(cve_reg(**kw))

    # Exploitation tools only in FULL and CUSTOM modes
    if mode in (ScanMode.FULL, ScanMode.CUSTOM):
        from spider.tools.attack_chain import register_all as chain_reg
        from spider.tools.exploit_matcher import register_all as match_reg
        from spider.tools.exploitation import register_all as exploit_reg
        from spider.tools.payload_gen import register_all as payload_reg
        from spider.tools.post_exploit_tools import register_all as post_reg

        tools.update(match_reg(**kw))
        tools.update(exploit_reg(**kw, hitl_gate=hitl_gate))
        tools.update(post_reg(**kw, hitl_gate=hitl_gate))
        tools.update(payload_reg(**kw))
        tools.update(chain_reg(**kw))

    # Filter out unavailable tools (None values from make_tool)
    return {k: v for k, v in tools.items() if v is not None}


def build_tool_catalog(tool_names: set[str], mode: ScanMode) -> ToolCatalog:
    """Build a ToolCatalog for the Weaver, filtered by mode.

    In RECON mode, exploit_tools and post_exploit_tools are empty lists.
    This prevents the Weaver LLM from seeing attack tools in the catalog.
    """
    if mode == ScanMode.RECON:
        return ToolCatalog(
            recon_tools=sorted(tool_names & RECON_TOOLS),
            web_enum_tools=sorted(tool_names & WEB_ENUM_TOOLS),
            service_enum_tools=sorted(tool_names & SVC_ENUM_TOOLS),
            vuln_tools=sorted(tool_names & VULN_TOOLS),
            exploit_tools=[],
            post_exploit_tools=[],
        )

    return ToolCatalog(
        recon_tools=sorted(tool_names & RECON_TOOLS),
        web_enum_tools=sorted(tool_names & WEB_ENUM_TOOLS),
        service_enum_tools=sorted(tool_names & SVC_ENUM_TOOLS),
        vuln_tools=sorted(tool_names & VULN_TOOLS),
        exploit_tools=sorted(tool_names & ATTACK_PLAN_TOOLS),
    )
