"""Tests for explicit node kind factory validation."""

import dspy
import pytest
from pydantic import ValidationError

from spider.config import SpiderConfig
from spider.engine.node_factory import TopologyValidationError, build_node_modules
from spider.schemas import GraphTopology, NodeDef, NodeKind, NodeRole, ToolDef


def gobuster_scan(target: str) -> str:
    """Test web enumeration tool."""
    return "{}"


def nmap_scan(target: str) -> str:
    """Test recon tool."""
    return "{}"


def tcp_port_scan(target: str) -> str:
    """Test TCP port scan tool."""
    return "{}"


def _config() -> SpiderConfig:
    return SpiderConfig(
        ollama_base_url="http://localhost:11434",
        primary_model="test-model",
        eval_model="test-model",
        use_refine=False,
    )


def _topology(node: NodeDef) -> GraphTopology:
    return GraphTopology(
        name="factory_validation",
        objective="validate explicit node kinds",
        nodes=[node],
        edges=[],
        runtime_inputs=[
            "target_spec",
            "recon_results",
            "web_findings",
            "service_details",
            "vulnerabilities",
            "attack_plan",
        ],
    )


def test_build_node_modules_maps_explicit_kind_to_module_class_and_tools():
    """Factory should use node kind, not output substring fallback, for module mapping."""
    node = NodeDef(
        id="web_enum",
        kind=NodeKind.WEB_ENUM,
        role=NodeRole.CHAIN_OF_THOUGHT,
        name="Web Enumeration",
        description="Enumerate web targets.",
        inputs=["recon_results"],
        output="web_findings",
        tools=[ToolDef(name="gobuster_scan")],
    )
    modules = build_node_modules(
        topology=_topology(node),
        tools={"gobuster_scan": dspy.Tool(gobuster_scan)},
        config=_config(),
    )

    assert modules["web_enum"].__class__.__name__ == "WebEnumerationModule"


def test_node_def_rejects_unknown_node_kind():
    """Pydantic schema validation should reject topology nodes with unknown kinds."""
    with pytest.raises(ValidationError, match="kind"):
        NodeDef(
            id="unknown",
            kind="mystery",
            role=NodeRole.REACT,
            name="Unknown",
            description="Unknown node kind.",
            output="recon_results",
        )


def test_build_node_modules_rejects_unsupported_output_for_kind():
    """A known node kind may only produce its canonical output field."""
    node = NodeDef(
        id="web_enum",
        kind=NodeKind.WEB_ENUM,
        role=NodeRole.CHAIN_OF_THOUGHT,
        name="Web Enumeration",
        description="Bad output.",
        inputs=["recon_results"],
        output="vulnerabilities",
    )

    with pytest.raises(TopologyValidationError, match="must output 'web_findings'"):
        build_node_modules(topology=_topology(node), tools={}, config=_config())


def test_build_node_modules_rejects_mismatched_tool_category():
    """Nodes should fail fast if a declared tool belongs to another category."""
    node = NodeDef(
        id="web_enum",
        kind=NodeKind.WEB_ENUM,
        role=NodeRole.CHAIN_OF_THOUGHT,
        name="Web Enumeration",
        description="Wrong tool category.",
        inputs=["recon_results"],
        output="web_findings",
        tools=[ToolDef(name="nmap_scan")],
    )

    with pytest.raises(TopologyValidationError, match="unsupported category"):
        build_node_modules(
            topology=_topology(node),
            tools={"nmap_scan": dspy.Tool(nmap_scan)},
            config=_config(),
        )


def test_build_node_modules_allows_tcp_port_scan_for_service_enum():
    """Service enumeration should accept TCP scanning for local service discovery."""
    node = NodeDef(
        id="service_enum",
        kind=NodeKind.SERVICE_ENUM,
        role=NodeRole.CHAIN_OF_THOUGHT,
        name="Service Enumeration",
        description="Probe services.",
        inputs=["recon_results"],
        output="service_details",
        tools=[ToolDef(name="tcp_port_scan")],
    )

    modules = build_node_modules(
        topology=_topology(node),
        tools={"tcp_port_scan": dspy.Tool(tcp_port_scan)},
        config=_config(),
    )

    assert modules["service_enum"].__class__.__name__ == "ServiceEnumerationModule"


def test_build_node_modules_defaults_to_available_kind_tools_when_omitted():
    """Omitted node tools should not create a ReAct module with only finish available."""
    node = NodeDef(
        id="recon",
        kind=NodeKind.RECON,
        role=NodeRole.REACT,
        name="Recon",
        description="Discover the target.",
        inputs=["target_spec"],
        output="recon_results",
    )

    modules = build_node_modules(
        topology=_topology(node),
        tools={"nmap_scan": dspy.Tool(nmap_scan)},
        config=_config(),
    )

    react = modules["recon"].agent
    assert "nmap_scan" in react.tools


def test_build_node_modules_rejects_unavailable_declared_tool():
    """Nodes should fail fast when they name a tool that was not registered."""
    node = NodeDef(
        id="recon",
        kind=NodeKind.RECON,
        role=NodeRole.REACT,
        name="Recon",
        description="Missing tool.",
        inputs=["target_spec"],
        output="recon_results",
        tools=[ToolDef(name="nmap_scan")],
    )

    with pytest.raises(TopologyValidationError, match="unavailable tool"):
        build_node_modules(topology=_topology(node), tools={}, config=_config())
