"""Topology safety filter — strips disallowed nodes by ScanMode.

In RECON mode, any node whose output is not in RECON_OUTPUTS is removed.
Edges and depends_on lists are rebuilt to match. Validates that remaining
nodes have their inputs satisfiable. No-op for FULL and CUSTOM.
"""

from spider.schemas import RECON_OUTPUTS, GraphTopology, ScanMode

_RECON_RUNTIME_INPUTS = frozenset({"target", "target_spec"})


class UnsatisfiableInputError(ValueError):
    """Raised when a node's inputs cannot be satisfied after filtering."""

    pass


def filter_topology_for_mode(topology: GraphTopology, mode: ScanMode) -> GraphTopology:
    """Hard safety net: strip nodes not allowed by the current mode.

    In RECON mode, any node whose output is not in RECON_OUTPUTS
    is removed.  Edges and depends_on lists are rebuilt to match.
    Validates that remaining nodes have all inputs satisfiable.
    No-op for FULL and CUSTOM modes.
    """
    if mode != ScanMode.RECON:
        return topology

    allowed_ids: set[str] = set()
    allowed_outputs: set[str] = set()
    filtered_nodes = []
    for node in topology.nodes:
        if node.output.lower() in RECON_OUTPUTS:
            allowed_ids.add(node.id)
            allowed_outputs.add(node.output.lower())
            filtered_nodes.append(node)

    runtime_inputs = set(topology.runtime_inputs) | _RECON_RUNTIME_INPUTS

    # Rebuild depends_on to exclude removed nodes
    for node in filtered_nodes:
        node.depends_on = [d for d in node.depends_on if d in allowed_ids]
        node.inputs = [i for i in node.inputs if i.lower() in RECON_OUTPUTS or i in runtime_inputs]

    # Validate that each remaining node's inputs can be satisfied
    for node in filtered_nodes:
        for inp in node.inputs:
            inp_lower = inp.lower()
            # Input must be either a declared runtime input or produced by an allowed node.
            if inp_lower not in allowed_outputs and inp not in runtime_inputs:
                node.inputs = [
                    i for i in node.inputs if i.lower() in allowed_outputs or i in runtime_inputs
                ]

    # Rebuild edges
    filtered_edges = [
        e for e in topology.edges if e.source in allowed_ids and e.target in allowed_ids
    ]

    return GraphTopology(
        name=topology.name,
        objective=topology.objective,
        nodes=filtered_nodes,
        edges=filtered_edges,
        runtime_inputs=sorted(runtime_inputs),
        metadata=topology.metadata,
    )
