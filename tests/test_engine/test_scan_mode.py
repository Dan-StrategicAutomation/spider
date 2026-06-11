"""Tests for ScanMode-aware tool filtering and topology shaping.

Verifies that:
- RECON mode excludes exploitation tools at every level.
- FULL and CUSTOM modes include the full tool set.
- Topology post-filtering removes attack nodes in RECON mode.
- build_default_topology respects mode.
"""

import pytest

from spider.config import SpiderConfig
from spider.engine.mode_filter import filter_topology_for_mode
from spider.engine.tool_registry import (
    EXPLOIT_EXECUTION_TOOLS,
    EXPLOIT_PLANNING_TOOLS,
    PAYLOAD_TOOLS,
    POST_EXPLOIT_TOOLS,
    build_tool_catalog,
    build_tools,
)
from spider.engine.weaver import build_default_topology
from spider.schemas import ScanMode

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def config():
    """Minimal SpiderConfig for testing."""
    return SpiderConfig(
        ollama_base_url="http://localhost:11434",
        primary_model="test-model",
        eval_model="test-model",
        use_refine=False,
    )


# ── Tool Registration Tests ───────────────────────────────────────────────────

EXPLOIT_TOOL_NAMES = (
    (EXPLOIT_PLANNING_TOOLS - {"cve_intelligence"})
    | PAYLOAD_TOOLS
    | EXPLOIT_EXECUTION_TOOLS
    | POST_EXPLOIT_TOOLS
)


def test_recon_mode_excludes_exploit_tools():
    """RECON mode must not register any exploitation/post-exploitation tools."""
    tools = build_tools(mode=ScanMode.RECON)
    registered = set(tools.keys())
    leaked = registered & EXPLOIT_TOOL_NAMES
    assert leaked == set(), f"Exploit tools leaked into recon mode: {leaked}"


def test_full_mode_includes_attack_chain_builder():
    """FULL mode must include attack_chain_builder."""
    tools = build_tools(mode=ScanMode.FULL)
    assert "attack_chain_builder" in tools


def test_custom_mode_includes_attack_chain_builder():
    """CUSTOM mode must include attack_chain_builder (LLM decides topology)."""
    tools = build_tools(mode=ScanMode.CUSTOM)
    assert "attack_chain_builder" in tools


def test_recon_mode_still_has_recon_tools():
    """RECON mode must still include basic recon tools."""
    tools = build_tools(mode=ScanMode.RECON)
    registered = set(tools.keys())
    # At least some recon tools should be present (even if binary not found,
    # make_tool may return None — so we check the tool registration paths ran)
    assert len(registered) > 0, "RECON mode registered zero tools"


def test_mode_switch_rebuilds_tools():
    """Switching mode must produce different tool sets."""
    recon_tools = build_tools(mode=ScanMode.RECON)
    full_tools = build_tools(mode=ScanMode.FULL)
    assert len(full_tools) >= len(recon_tools)
    assert set(recon_tools.keys()) != set(full_tools.keys()) or len(full_tools) > len(recon_tools)


# ── Tool Catalog Tests ────────────────────────────────────────────────────────


def test_recon_catalog_has_empty_exploit_list():
    """RECON catalog must have exploit_tools=[] and post_exploit_tools=[]."""
    tools = build_tools(mode=ScanMode.RECON)
    catalog = build_tool_catalog(set(tools.keys()), ScanMode.RECON)
    assert catalog.exploit_tools == []
    assert catalog.post_exploit_tools == []


def test_full_catalog_has_exploit_tools():
    """FULL catalog should populate exploit_tools."""
    tools = build_tools(mode=ScanMode.FULL)
    catalog = build_tool_catalog(set(tools.keys()), ScanMode.FULL)
    assert isinstance(catalog.exploit_tools, list)


def test_full_catalog_includes_available_execution_and_post_exploit_tools(monkeypatch):
    """FULL catalog lists registered execution and post-exploitation tools."""
    import shutil

    monkeypatch.setattr(shutil, "which", lambda binary: f"/usr/bin/{binary}")

    tools = build_tools(mode=ScanMode.FULL)
    catalog = build_tool_catalog(set(tools.keys()), ScanMode.FULL)

    assert set(catalog.exploit_tools) >= EXPLOIT_EXECUTION_TOOLS
    assert set(catalog.post_exploit_tools) >= POST_EXPLOIT_TOOLS


def test_custom_catalog_includes_available_execution_and_post_exploit_tools(monkeypatch):
    """CUSTOM catalog lists registered execution and post-exploitation tools."""
    import shutil

    monkeypatch.setattr(shutil, "which", lambda binary: f"/usr/bin/{binary}")

    tools = build_tools(mode=ScanMode.CUSTOM)
    catalog = build_tool_catalog(set(tools.keys()), ScanMode.CUSTOM)

    assert set(catalog.exploit_tools) >= EXPLOIT_EXECUTION_TOOLS
    assert set(catalog.post_exploit_tools) >= POST_EXPLOIT_TOOLS


# ── Default Topology Tests ────────────────────────────────────────────────────


def test_default_topology_recon_has_no_exploit_planner():
    """RECON default topology must not include exploit_planner node."""
    topo = build_default_topology(ScanMode.RECON)
    assert topo is not None
    node_ids = {n.id for n in topo.nodes}
    assert "exploit_planner" not in node_ids
    outputs = {n.output for n in topo.nodes}
    assert "attack_plan" not in outputs


def test_default_topology_full_has_exploit_planner():
    """FULL default topology must include exploit_planner node."""
    topo = build_default_topology(ScanMode.FULL)
    assert topo is not None
    node_ids = {n.id for n in topo.nodes}
    assert "exploit_planner" in node_ids


def test_default_topology_custom_returns_none():
    """CUSTOM mode default topology must return None to force Weaver usage."""
    topo = build_default_topology(ScanMode.CUSTOM)
    assert topo is None


def test_default_topology_recon_reporter_does_not_depend_on_exploit_planner():
    """RECON reporter must not depend on exploit_planner."""
    topo = build_default_topology(ScanMode.RECON)
    assert topo is not None
    reporter = next(n for n in topo.nodes if n.id == "reporter")
    assert "exploit_planner" not in reporter.depends_on
    assert "attack_plan" not in reporter.inputs


def test_default_topology_recon_has_reporting():
    """RECON mode should still include reporting."""
    topo = build_default_topology(ScanMode.RECON)
    assert topo is not None
    outputs = {n.output for n in topo.nodes}
    assert "report" in outputs


def test_reporter_signatures_have_mode_specific_inputs():
    """Reporter signatures must reflect RECON and FULL mode contracts."""
    from spider.nodes.reporter import ReconReporterSignature, ReporterSignature

    assert set(ReconReporterSignature.input_fields) == {"recon_results", "vulnerabilities"}
    assert set(ReporterSignature.input_fields) == {
        "recon_results",
        "vulnerabilities",
        "attack_plan",
    }


def test_node_factory_uses_recon_reporter_for_recon_contract(config):
    """Reporter node without attack_plan input uses the recon reporter module."""
    from spider.engine.node_factory import build_node_modules
    from spider.nodes.reporter import ReconReporterModule
    from spider.schemas import GraphTopology, NodeDef, NodeRole

    topology = GraphTopology(
        name="recon_report",
        objective="Recon report",
        nodes=[
            NodeDef(
                id="reporter",
                role=NodeRole.CHAIN_OF_THOUGHT,
                name="Reporter",
                description="Generate report",
                inputs=["recon_results", "vulnerabilities"],
                output="report",
            )
        ],
        edges=[],
        runtime_inputs=["recon_results", "vulnerabilities"],
    )

    modules = build_node_modules(topology=topology, tools={}, config=config)

    assert isinstance(modules["reporter"], ReconReporterModule)


def test_node_factory_uses_recon_reporter_for_explicit_recon_mode(config):
    """Explicit RECON mode uses the recon reporter even if stale inputs mention attack_plan."""
    from spider.engine.node_factory import build_node_modules
    from spider.nodes.reporter import ReconReporterModule
    from spider.schemas import GraphTopology, NodeDef, NodeRole

    topology = GraphTopology(
        name="filtered_recon_report",
        objective="Recon report",
        nodes=[
            NodeDef(
                id="reporter",
                role=NodeRole.CHAIN_OF_THOUGHT,
                name="Reporter",
                description="Generate report",
                inputs=["recon_results", "vulnerabilities", "attack_plan"],
                output="report",
            )
        ],
        edges=[],
        runtime_inputs=["recon_results", "vulnerabilities", "attack_plan"],
    )

    modules = build_node_modules(
        topology=topology,
        tools={},
        config=config,
        scan_mode=ScanMode.RECON,
    )

    assert isinstance(modules["reporter"], ReconReporterModule)


def test_node_factory_uses_full_reporter_for_attack_plan_contract(config):
    """Reporter node with attack_plan input uses the full reporter module."""
    from spider.engine.node_factory import build_node_modules
    from spider.nodes.reporter import ReporterModule
    from spider.schemas import GraphTopology, NodeDef, NodeRole

    topology = GraphTopology(
        name="full_report",
        objective="Full report",
        nodes=[
            NodeDef(
                id="reporter",
                role=NodeRole.CHAIN_OF_THOUGHT,
                name="Reporter",
                description="Generate report",
                inputs=["recon_results", "vulnerabilities", "attack_plan"],
                output="report",
            )
        ],
        edges=[],
        runtime_inputs=["recon_results", "vulnerabilities", "attack_plan"],
    )

    modules = build_node_modules(topology=topology, tools={}, config=config)

    assert isinstance(modules["reporter"], ReporterModule)


@pytest.mark.parametrize("mode", [ScanMode.FULL, ScanMode.CUSTOM])
def test_node_factory_preserves_full_reporter_for_full_modes_without_attack_plan_contract(
    config, mode
):
    """FULL/CUSTOM mode must not silently downgrade malformed reporter contracts."""
    from spider.engine.node_factory import build_node_modules
    from spider.nodes.reporter import ReporterModule
    from spider.schemas import GraphTopology, NodeDef, NodeRole

    topology = GraphTopology(
        name="malformed_full_report",
        objective="Full report",
        nodes=[
            NodeDef(
                id="exploit_planner",
                role=NodeRole.CHAIN_OF_THOUGHT,
                name="Exploit Planner",
                description="Build attack plan",
                inputs=["vulnerabilities"],
                output="attack_plan",
            ),
            NodeDef(
                id="reporter",
                role=NodeRole.CHAIN_OF_THOUGHT,
                name="Reporter",
                description="Generate report",
                inputs=["recon_results", "vulnerabilities"],
                output="report",
            ),
        ],
        edges=[],
        runtime_inputs=["recon_results", "vulnerabilities"],
    )

    modules = build_node_modules(
        topology=topology,
        tools={},
        config=config,
        scan_mode=mode,
    )

    assert isinstance(modules["reporter"], ReporterModule)


# ── Topology Post-Filter Tests ────────────────────────────────────────────────


def test_topology_post_filter_strips_exploit_nodes():
    """If Weaver produces exploit nodes in RECON mode, post-filter removes them."""
    from spider.schemas import GraphTopology, NodeDef, NodeRole

    nodes = [
        NodeDef(
            id="recon",
            role=NodeRole.REACT,
            name="Recon",
            description="Recon",
            output="recon_results",
            depends_on=[],
        ),
        NodeDef(
            id="vuln",
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="Vuln",
            description="Vuln",
            output="vulnerabilities",
            depends_on=["recon"],
        ),
        NodeDef(
            id="exploit",
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="Exploit",
            description="Exploit",
            output="attack_plan",
            depends_on=["vuln"],
        ),
        NodeDef(
            id="reporter",
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="Reporter",
            description="Report",
            output="report",
            depends_on=["recon", "vuln", "exploit"],
        ),
    ]

    topo = GraphTopology(name="test", objective="test", nodes=nodes, edges=[])
    filtered = filter_topology_for_mode(topo, ScanMode.RECON)

    node_ids = {n.id for n in filtered.nodes}
    assert "exploit" not in node_ids, "Exploit node should be stripped in RECON"
    assert "recon" in node_ids
    assert "vuln" in node_ids
    assert "reporter" in node_ids

    # Reporter's depends_on should no longer reference the removed node
    reporter = next(n for n in filtered.nodes if n.id == "reporter")
    assert "exploit" not in reporter.depends_on


def test_topology_post_filter_noop_for_full():
    """Post-filter should be a no-op for FULL mode."""
    from spider.schemas import GraphTopology, NodeDef, NodeRole

    nodes = [
        NodeDef(
            id="recon",
            role=NodeRole.REACT,
            name="R",
            description="R",
            output="recon_results",
            depends_on=[],
        ),
        NodeDef(
            id="exploit",
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="E",
            description="E",
            output="attack_plan",
            depends_on=["recon"],
        ),
    ]

    topo = GraphTopology(name="test", objective="test", nodes=nodes, edges=[])
    filtered = filter_topology_for_mode(topo, ScanMode.FULL)

    assert len(filtered.nodes) == 2
    assert {n.id for n in filtered.nodes} == {"recon", "exploit"}


def test_topology_post_filter_noop_for_custom():
    """Post-filter should be a no-op for CUSTOM mode."""
    from spider.schemas import GraphTopology, NodeDef, NodeRole

    nodes = [
        NodeDef(
            id="recon",
            role=NodeRole.REACT,
            name="R",
            description="R",
            output="recon_results",
            depends_on=[],
        ),
        NodeDef(
            id="exploit",
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="E",
            description="E",
            output="attack_plan",
            depends_on=["recon"],
        ),
    ]

    topo = GraphTopology(name="test", objective="test", nodes=nodes, edges=[])
    filtered = filter_topology_for_mode(topo, ScanMode.CUSTOM)

    assert len(filtered.nodes) == 2
