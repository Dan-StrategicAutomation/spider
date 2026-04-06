"""SpiderOrchestrator -- top-level pipeline: Weaver -> Provision -> Runner -> Heal.

Wires together the GraphWeaver, tool provisioning, GraphRunner, and
auto-healing loop for end-to-end pentest execution.
"""

import dspy
from datetime import datetime, timezone

from spider.schemas import GraphTopology
from spider.engine.weaver import GraphWeaver
from spider.engine.runner import GraphRunner
from spider.config import SpiderConfig


class SpiderOrchestrator(dspy.Module):
    """Top-level SPIDER orchestrator.

    Pipeline:
    1. Weaver generates topology from goal text
    2. Tools are provisioned for each node
    3. Runner executes topology in parallel waves
    4. Quality evaluator checks output quality
    5. If quality < threshold, re-weave with failure context
    """

    def __init__(self, config: SpiderConfig, hitl_gate=None, scope_guard=None, audit_logger=None):
        super().__init__()
        self.config = config
        self.weaver = GraphWeaver(max_nodes=config.max_graph_nodes)
        self.hitl_gate = hitl_gate
        self.scope_guard = scope_guard
        self.audit_logger = audit_logger
        self._session_id = None

    def _provision_tools(self, topology: GraphTopology) -> dict:
        """Provision and register tools for the topology."""
        all_tools = {}

        # Recon tools
        from spider.tools import recon_tools
        all_tools.update(recon_tools.register_all(
            scope_guard=self.scope_guard, audit_logger=self.audit_logger,
        ))

        # Enum tools
        from spider.tools import enum_tools
        all_tools.update(enum_tools.register_all(
            scope_guard=self.scope_guard, audit_logger=self.audit_logger,
        ))

        # TODO: Add vuln scanners, exploit tools, custom tools
        # from spider.tools import vuln_scanners, exploitation
        # from spider.tools import cve_intelligence, exploit_matcher

        return all_tools

    def _build_node_modules(self, topology: GraphTopology, tools: dict) -> dict[str, dspy.Module]:
        """Build DSPy modules for each node in the topology."""
        # TODO: Import node modules and instantiate per topology
        # For now, return placeholder
        return {}

    def forward(self, goal: str, target: str, **kwargs) -> dspy.Prediction:
        """Execute a pentest against the given target."""
        self._session_id = f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

        # Phase 1: Weave topology
        topology = self.weaver(
            goal=goal,
            target_info=target,
            constraints_text=self.config.rules_of_engagement,
            available_tools=", ".join(self.config.available_tools),
        ).topology

        if self.audit_logger:
            self.audit_logger.log(
                action="topology_generated",
                target=target,
                phase="completed",
                result=f"Topology: {topology.name} with {len(topology.nodes)} nodes",
            )

        # Phase 2: Provision tools
        tools = self._provision_tools(topology)

        # Phase 3: Build node modules
        node_modules = self._build_node_modules(topology, tools)

        # Phase 4: Execute
        runner = GraphRunner(topology=topology, node_modules=node_modules, goal=goal)
        result = runner(**kwargs)

        return result
