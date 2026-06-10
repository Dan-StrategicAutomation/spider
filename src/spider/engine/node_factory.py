"""Node module factory — maps topology nodes to DSPy modules.

Reads each node's canonical output name and instantiates the correct
module class with the appropriate tool subset and config.
"""

import os
from collections.abc import Callable
from typing import Any

import dspy

from spider.config import SpiderConfig
from spider.engine.tool_registry import (
    EXPLOIT_EXECUTION_TOOLS,
    EXPLOIT_PLANNING_TOOLS,
    POST_EXPLOIT_TOOLS,
    RECON_TOOLS,
    SVC_ENUM_TOOLS,
    VULN_TOOLS,
    WEB_ENUM_TOOLS,
)
from spider.sandbox.hitl_gate import HITLGate
from spider.schemas import GraphTopology, NodeRole

# ── Output-name → Module class registry ──────────────────────────────────────
#
# Each entry: (output_pattern, module_factory_name, needs_hitl)
# The first matching pattern wins.  Checked via `pattern in output_name`.

_REGISTRY: list[tuple[str, str, bool]] = [
    ("recon_results", "ReconModule", False),
    ("service_details", "ServiceEnumerationModule", False),
    ("web_findings", "WebEnumerationModule", False),
    ("vulnerabilities", "VulnerabilityAnalysisModule", False),
    ("attack_plan", "ExploitPlanningModule", False),
    ("exploit_result", "ExecutorModule", True),
    ("post_exploit_result", "PostExploitationModule", True),
    ("report", "ReporterModule", False),
]

# Maps output patterns to the tool category they should draw from.
_OUTPUT_TOOL_MAP: dict[str, frozenset[str]] = {
    "recon_results": RECON_TOOLS,
    "web_findings": WEB_ENUM_TOOLS,
    "service_details": SVC_ENUM_TOOLS,
    "vulnerabilities": VULN_TOOLS,
    "attack_plan": EXPLOIT_PLANNING_TOOLS,
    "exploit_result": EXPLOIT_EXECUTION_TOOLS,
    "post_exploit_result": POST_EXPLOIT_TOOLS,
}


def _get_module_classes() -> dict[str, type]:
    """Lazy-import all node module classes to avoid circular imports."""
    from spider.nodes.enum import ServiceEnumerationModule, WebEnumerationModule
    from spider.nodes.executor import ExecutorModule
    from spider.nodes.exploit_planner import ExploitPlanningModule
    from spider.nodes.post_exploit import PostExploitationModule
    from spider.nodes.recon import ReconModule
    from spider.nodes.reporter import ReporterModule
    from spider.nodes.vuln_analysis import VulnerabilityAnalysisModule

    return {
        "ReconModule": ReconModule,
        "ServiceEnumerationModule": ServiceEnumerationModule,
        "WebEnumerationModule": WebEnumerationModule,
        "VulnerabilityAnalysisModule": VulnerabilityAnalysisModule,
        "ExploitPlanningModule": ExploitPlanningModule,
        "ExecutorModule": ExecutorModule,
        "PostExploitationModule": PostExploitationModule,
        "ReporterModule": ReporterModule,
    }


def _select_tools_for_node(
    node_output: str,
    node_role: NodeRole,
    node_tools: list[Any],
    all_tools: dict[str, dspy.Tool],
) -> list[dspy.Tool]:
    """Select the tool subset appropriate for a given node.

    Uses the node's canonical output name to determine which tool
    category to filter from.  Falls back to all available tools
    if no category matches.
    """
    output_name = node_output.lower()

    # Check for ReAct root nodes (always recon)
    if node_role == NodeRole.REACT and "recon_results" not in output_name:
        allowed = RECON_TOOLS
    else:
        # Find the matching category
        allowed = None
        for pattern, tool_set in _OUTPUT_TOOL_MAP.items():
            if pattern in output_name:
                allowed = tool_set
                break

    if allowed:
        return [all_tools[t.name] for t in node_tools if t.name in all_tools and t.name in allowed]
    return [all_tools[t.name] for t in node_tools if t.name in all_tools]


def _resolve_module(
    output_name: str,
    node_role: NodeRole,
    node_tools: list[dspy.Tool],
    config: SpiderConfig,
    hitl_gate: HITLGate | None,
    classes: dict[str, type],
) -> dspy.Module:
    """Instantiate the correct DSPy module for a node's output name."""
    lower = output_name.lower()

    for pattern, class_name, needs_hitl in _REGISTRY:
        if pattern in lower:
            cls = classes[class_name]
            kwargs: dict[str, Any] = {"tools": node_tools, "config": config}
            if needs_hitl:
                kwargs["hitl_gate"] = hitl_gate
            return cls(**kwargs)

    # Fallback: ReAct root → ReconModule, otherwise VulnerabilityAnalysis
    if node_role == NodeRole.REACT:
        return classes["ReconModule"](tools=node_tools, config=config)
    return classes["VulnerabilityAnalysisModule"](tools=node_tools, config=config)


def load_compiled_module(
    module: dspy.Module,
    progress_fn: Callable[[str, str], None] | None = None,
) -> None:
    """Attempt to load BootstrapFewShot optimized weights for a module."""
    progress_fn = progress_fn or (lambda _s, _d="": None)
    module_name = module.__class__.__name__
    compiled_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "compiled")
    weights_path = os.path.join(compiled_dir, f"{module_name}.json")

    if os.path.exists(weights_path):
        try:
            module.load(weights_path)
            progress_fn("optimize_load", f"Loaded compiled weights for {module_name}")
        except Exception as e:
            progress_fn(
                "optimize_error",
                f"Failed to load weights for {module_name}: {str(e)}",
            )


def build_node_modules(
    topology: GraphTopology,
    tools: dict[str, dspy.Tool],
    config: SpiderConfig,
    hitl_gate: HITLGate | None = None,
    progress_fn: Callable[[str, str], None] | None = None,
) -> dict[str, dspy.Module]:
    """Build DSPy modules for each node in the topology.

    Maps each node to its module class via the canonical output name,
    selects the appropriate tool subset, and loads compiled weights
    if available.
    """
    classes = _get_module_classes()
    node_modules: dict[str, dspy.Module] = {}

    for node in topology.nodes:
        node_tools = _select_tools_for_node(
            node_output=node.output,
            node_role=node.role,
            node_tools=node.tools,
            all_tools=tools,
        )

        module = _resolve_module(
            output_name=node.output,
            node_role=node.role,
            node_tools=node_tools,
            config=config,
            hitl_gate=hitl_gate,
            classes=classes,
        )

        load_compiled_module(module, progress_fn)
        node_modules[node.id] = module

    return node_modules
