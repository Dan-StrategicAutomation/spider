"""Node module factory — maps topology nodes to DSPy modules.

Reads each node's explicit kind and instantiates the correct module class
with the appropriate tool subset and config.
"""

import os
from collections.abc import Callable
from typing import Any, NamedTuple

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
from spider.schemas import GraphTopology, NodeDef, NodeKind, ScanMode


class TopologyValidationError(ValueError):
    """Raised when a topology node cannot be mapped safely to a module."""

    pass


class RegistryEntry(NamedTuple):
    """Factory metadata for one supported explicit node kind."""

    module_class: str
    output: str
    allowed_tools: frozenset[str]
    tool_category: str
    needs_hitl: bool = False


# ── Node kind → Module class and tool category registry ──────────────────────

_REGISTRY: dict[NodeKind, RegistryEntry] = {
    NodeKind.RECON: RegistryEntry(
        module_class="ReconModule",
        output="recon_results",
        allowed_tools=RECON_TOOLS,
        tool_category="recon_tools",
    ),
    NodeKind.WEB_ENUM: RegistryEntry(
        module_class="WebEnumerationModule",
        output="web_findings",
        allowed_tools=WEB_ENUM_TOOLS,
        tool_category="web_enum_tools",
    ),
    NodeKind.SERVICE_ENUM: RegistryEntry(
        module_class="ServiceEnumerationModule",
        output="service_details",
        allowed_tools=SVC_ENUM_TOOLS,
        tool_category="service_enum_tools",
    ),
    NodeKind.VULNERABILITY_ANALYSIS: RegistryEntry(
        module_class="VulnerabilityAnalysisModule",
        output="vulnerabilities",
        allowed_tools=VULN_TOOLS,
        tool_category="vuln_tools",
    ),
    NodeKind.EXPLOIT_PLANNING: RegistryEntry(
        module_class="ExploitPlanningModule",
        output="attack_plan",
        allowed_tools=EXPLOIT_PLANNING_TOOLS,
        tool_category="exploit_tools",
    ),
    NodeKind.EXPLOIT_EXECUTION: RegistryEntry(
        module_class="ExecutorModule",
        output="exploit_result",
        allowed_tools=EXPLOIT_EXECUTION_TOOLS,
        tool_category="exploit_tools",
        needs_hitl=True,
    ),
    NodeKind.POST_EXPLOITATION: RegistryEntry(
        module_class="PostExploitationModule",
        output="post_exploit_result",
        allowed_tools=POST_EXPLOIT_TOOLS,
        tool_category="post_exploit_tools",
        needs_hitl=True,
    ),
    NodeKind.REPORTING: RegistryEntry(
        module_class="ReporterModule",
        output="report",
        allowed_tools=frozenset(),
        tool_category="no_tools",
    ),
}


def _get_module_classes() -> dict[str, type]:
    """Lazy-import all node module classes to avoid circular imports."""
    from spider.nodes.enum import ServiceEnumerationModule, WebEnumerationModule
    from spider.nodes.executor import ExecutorModule
    from spider.nodes.exploit_planner import ExploitPlanningModule
    from spider.nodes.post_exploit import PostExploitationModule
    from spider.nodes.recon import ReconModule
    from spider.nodes.reporter import ReconReporterModule, ReporterModule
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
        "ReconReporterModule": ReconReporterModule,
    }


def _registry_entry_for(node: NodeDef) -> RegistryEntry:
    """Return registry metadata for a node, or fail for unknown node kinds."""
    if node.kind not in _REGISTRY:
        supported = ", ".join(kind.value for kind in _REGISTRY)
        raise TopologyValidationError(
            f"Node '{node.id}' has unknown node kind '{node.kind}'. Supported kinds: {supported}."
        )
    return _REGISTRY[node.kind]


def _validate_node_output(node: NodeDef, entry: RegistryEntry) -> None:
    """Fail fast when a node kind declares an unsupported output field."""
    if node.output != entry.output:
        raise TopologyValidationError(
            f"Node '{node.id}' kind '{node.kind}' must output '{entry.output}', "
            f"got '{node.output}'."
        )


def _validate_node_tools(
    node: NodeDef,
    entry: RegistryEntry,
    all_tools: dict[str, dspy.Tool],
) -> None:
    """Fail fast when a node declares unavailable or wrong-category tools."""
    requested = {tool.name for tool in node.tools}
    unavailable = sorted(requested - set(all_tools))
    if unavailable:
        raise TopologyValidationError(
            f"Node '{node.id}' requested unavailable tool(s): {', '.join(unavailable)}."
        )

    unsupported = sorted(requested - entry.allowed_tools)
    if unsupported:
        allowed = ", ".join(sorted(entry.allowed_tools)) or "none"
        raise TopologyValidationError(
            f"Node '{node.id}' kind '{node.kind}' requested tool(s) from an unsupported "
            f"category: {', '.join(unsupported)}. Allowed {entry.tool_category}: {allowed}."
        )


def _validate_node(node: NodeDef, all_tools: dict[str, dspy.Tool]) -> RegistryEntry:
    """Validate kind, output, and tool category consistency for one node."""
    entry = _registry_entry_for(node)
    _validate_node_output(node, entry)
    _validate_node_tools(node, entry, all_tools)
    return entry


def _select_tools_for_node(
    node: NodeDef,
    entry: RegistryEntry,
    all_tools: dict[str, dspy.Tool],
) -> list[dspy.Tool]:
    """Select declared tools for a node after category validation."""
    return [all_tools[tool.name] for tool in node.tools if tool.name in entry.allowed_tools]


def _scan_mode_from_topology(topology: GraphTopology) -> ScanMode | None:
    """Return the scan mode declared in topology metadata, if present."""
    raw_mode = topology.metadata.get("scan_mode") or topology.metadata.get("mode")
    if raw_mode is None:
        return None
    try:
        return ScanMode(raw_mode)
    except (TypeError, ValueError):
        return None


def _node_contract_inputs(node: NodeDef, topology: GraphTopology) -> set[str]:
    """Return topology input names available to a node contract."""
    output_by_id = {candidate.id: candidate.output for candidate in topology.nodes}
    inputs = set(node.inputs)
    inputs.update(output_by_id[dep] for dep in node.depends_on if dep in output_by_id)
    return inputs


def _resolve_module(
    node: NodeDef,
    entry: RegistryEntry,
    node_inputs: set[str],
    scan_mode: ScanMode | None,
    node_tools: list[dspy.Tool],
    config: SpiderConfig,
    hitl_gate: HITLGate | None,
    classes: dict[str, type],
) -> dspy.Module:
    """Instantiate the correct DSPy module for a node's explicit kind."""
    if entry.module_class == "ReporterModule":
        if scan_mode == ScanMode.RECON:
            return classes["ReconReporterModule"](tools=node_tools, config=config)
        if scan_mode in (ScanMode.FULL, ScanMode.CUSTOM):
            return classes["ReporterModule"](tools=node_tools, config=config)
        if "attack_plan" not in node_inputs:
            return classes["ReconReporterModule"](tools=node_tools, config=config)
        return classes["ReporterModule"](tools=node_tools, config=config)

    cls = classes[entry.module_class]
    kwargs: dict[str, Any] = {"tools": node_tools, "config": config}
    if entry.needs_hitl:
        kwargs["hitl_gate"] = hitl_gate
    return cls(**kwargs)


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
    scan_mode: ScanMode | None = None,
) -> dict[str, dspy.Module]:
    """Build DSPy modules for each node in the topology.

    Maps each node to its module class via explicit node kind, validates
    the declared output and tool category, chooses reporter contracts from
    topology inputs or explicit scan mode, and loads compiled weights
    if available.
    """
    classes = _get_module_classes()
    node_modules: dict[str, dspy.Module] = {}
    resolved_scan_mode = scan_mode or _scan_mode_from_topology(topology)

    for node in topology.nodes:
        entry = _validate_node(node, tools)
        node_tools = _select_tools_for_node(
            node=node,
            entry=entry,
            all_tools=tools,
        )

        module = _resolve_module(
            node=node,
            entry=entry,
            node_inputs=_node_contract_inputs(node, topology),
            scan_mode=resolved_scan_mode,
            node_tools=node_tools,
            config=config,
            hitl_gate=hitl_gate,
            classes=classes,
        )

        load_compiled_module(module, progress_fn)
        node_modules[node.id] = module

    return node_modules
