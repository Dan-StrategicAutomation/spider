"""Tests for topological wave generation and dependency grounding.
Verifies that GraphTopology correctly calculates waves based on NodeDef.depends_on.
"""

import pytest
from pydantic import ValidationError

from spider.engine.weaver import build_default_topology, validate_topology_contract
from spider.schemas import GraphTopology, NodeDef, NodeKind, NodeRole, ScanMode


def test_topological_waves_follows_depends_on():
    """Verify that waves are computed by depends_on, not just edges."""
    nodes = [
        NodeDef(
            id="recon",
            kind=NodeKind.RECON,
            role=NodeRole.REACT,
            name="Recon",
            description="Recon node",
            output="recon_output",
            depends_on=[],
        ),
        NodeDef(
            id="vuln",
            kind=NodeKind.VULNERABILITY_ANALYSIS,
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="Vuln",
            description="Vuln node",
            output="vuln_output",
            depends_on=["recon"],  # Explicit dependency
        ),
    ]

    # Topology with NO edges explicitly provided
    topo = GraphTopology(
        name="test_topo",
        objective="Test",
        nodes=nodes,
        edges=[],
    )

    # Validator should have synced edges
    assert len(topo.edges) == 1
    assert topo.edges[0].source == "recon"
    assert topo.edges[0].target == "vuln"

    waves = topo.topological_waves()
    assert waves == [["recon"], ["vuln"]]


def test_multistep_waves():
    """Verify deeper wave calculation."""
    nodes = [
        NodeDef(
            id="A",
            kind=NodeKind.RECON,
            role=NodeRole.REACT,
            name="A",
            description="A",
            output="oA",
            depends_on=[],
        ),
        NodeDef(
            id="B",
            kind=NodeKind.RECON,
            role=NodeRole.REACT,
            name="B",
            description="B",
            output="oB",
            depends_on=["A"],
        ),
        NodeDef(
            id="C",
            kind=NodeKind.RECON,
            role=NodeRole.REACT,
            name="C",
            description="C",
            output="oC",
            depends_on=["A"],
        ),
        NodeDef(
            id="D",
            kind=NodeKind.RECON,
            role=NodeRole.REACT,
            name="D",
            description="D",
            output="oD",
            depends_on=["B", "C"],
        ),
    ]

    topo = GraphTopology(name="test", objective="test", nodes=nodes, edges=[])
    waves = topo.topological_waves()

    assert waves[0] == ["A"]
    assert sorted(waves[1]) == ["B", "C"]
    assert waves[2] == ["D"]


def test_cycle_detection():
    """Verify cycle detection works with depends_on."""
    nodes = [
        NodeDef(
            id="A",
            kind=NodeKind.RECON,
            role=NodeRole.REACT,
            name="A",
            description="A",
            output="oA",
            depends_on=["B"],
        ),
        NodeDef(
            id="B",
            kind=NodeKind.RECON,
            role=NodeRole.REACT,
            name="B",
            description="B",
            output="oB",
            depends_on=["A"],
        ),
    ]

    topo = GraphTopology(name="cycle", objective="cycle", nodes=nodes, edges=[])

    with pytest.raises(ValueError, match="Cycle detected"):
        topo.topological_waves()


def test_orphan_handling():
    """Verify that nodes depending on non-existent internal nodes are handled."""
    nodes = [
        NodeDef(
            id="A",
            kind=NodeKind.RECON,
            role=NodeRole.REACT,
            name="A",
            description="A",
            output="oA",
            depends_on=["non_existent"],
        ),
    ]
    # 'non_existent' is not in id_set and not in runtime_inputs.
    # The validator ignores it, and waves() treats it as having
    # 0 satisfied dependencies (Wave 0).
    topo = GraphTopology(name="orphan", objective="orphan", nodes=nodes, edges=[])
    waves = topo.topological_waves()
    assert waves == [["A"]]


def test_topology_contract_rejects_missing_runtime_and_node_inputs():
    """Malformed LLM topologies should be rejected before runner execution."""
    nodes = [
        NodeDef(
            id="target_reconnaissance",
            kind=NodeKind.RECON,
            role=NodeRole.REACT,
            name="Target Reconnaissance",
            description="Discover target services.",
            output="recon_results",
            depends_on=[],
        ),
        NodeDef(
            id="final_reporting",
            kind=NodeKind.REPORTING,
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="Final Reporting",
            description="Generate a final report.",
            output="report",
            depends_on=[],
        ),
    ]
    with pytest.raises(ValidationError, match="runtime_inputs must include 'target_spec'"):
        GraphTopology(
            name="bad_llm_topology",
            objective="Bad topology from model",
            nodes=nodes,
            edges=[],
            runtime_inputs=[],
        )


def test_default_recon_topology_satisfies_contract():
    """Default recon topology should pass deterministic data-flow validation."""
    topo = build_default_topology(ScanMode.RECON)

    assert topo is not None
    assert validate_topology_contract(topo, ScanMode.RECON) == []
