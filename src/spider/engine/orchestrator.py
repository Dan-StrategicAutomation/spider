"""SpiderOrchestrator -- top-level pipeline: Weaver -> Provision -> Runner -> Heal.

Wires together the GraphWeaver, tool provisioning, GraphRunner, and
auto-healing loop for end-to-end pentest execution.
"""

from datetime import datetime, timezone

import dspy

from spider.config import SpiderConfig
from spider.engine.runner import GraphRunner
from spider.engine.weaver import GraphTopology, GraphWeaver
from spider.sandbox.hitl_gate import HITLGate
from spider.sandbox.scope_guard import ScopeGuard
from spider.tui.session import SessionStore


class SpiderOrchestrator:
    """Top-level SPIDER orchestrator.

    Pipeline:
    1. Weaver generates topology from goal text
    2. Tools are provisioned for each node
    3. Runner executes topology in parallel waves
    4. Quality evaluator checks output quality
    5. If quality < threshold, re-weave with failure context
    """

    def __init__(
        self,
        config: SpiderConfig,
        scope_guard: ScopeGuard | None = None,
        hitl_gate: HITLGate | None = None,
        session_store: SessionStore | None = None,
        audit_logger=None,
    ) -> None:
        self.config = config
        self.weaver = GraphWeaver()
        self.scope_guard = scope_guard
        self.hitl_gate = hitl_gate
        self.session_store = session_store
        self.audit_logger = audit_logger
        self._all_tools: dict[str, dspy.Tool] = {}

    def _build_tools(
        self,
        scope_guard: ScopeGuard | None = None,
        audit_logger=None,
    ) -> dict[str, dspy.Tool]:
        """Build all security tools with scope guard and audit wrapper."""
        if self._all_tools:
            return self._all_tools

        from spider.tools.attack_chain import register_all as chain_reg
        from spider.tools.enum_tools import register_all as enum_reg
        from spider.tools.exploitation import register_all as exploit_reg
        from spider.tools.payload_gen import register_all as payload_reg
        from spider.tools.post_exploit_tools import register_all as post_reg
        from spider.tools.recon_tools import register_all as recon_reg
        from spider.tools.vuln_scanners import register_all as vuln_reg

        kw = {
            "scope_guard": scope_guard,
            "audit_logger": audit_logger,
        }

        self._all_tools.update(recon_reg(**kw))
        self._all_tools.update(enum_reg(**kw))
        self._all_tools.update(vuln_reg(**kw))
        self._all_tools.update(exploit_reg(**kw, hitl_gate=self.hitl_gate))
        self._all_tools.update(post_reg(**kw, hitl_gate=self.hitl_gate))
        self._all_tools.update(payload_reg(**kw))
        self._all_tools.update(chain_reg(**kw))

        return self._all_tools

    def _build_node_modules(
        self,
        topology: GraphTopology,
        tools: dict[str, dspy.Tool],
    ) -> dict[str, dspy.Module]:
        """Build DSPy modules for each node in the topology."""
        node_modules: dict[str, dspy.Module] = {}

        from spider.nodes.enum import EnumModule
        from spider.nodes.executor import ExecutorModule
        from spider.nodes.exploit_planner import ExploitPlannerModule
        from spider.nodes.post_exploit import PostExploitModule
        from spider.nodes.recon import ReconModule
        from spider.nodes.reporter import ReportingModule
        from spider.nodes.vuln_analysis import VulnAnalysisModule
        from spider.schemas import NodeRole

        for node in topology.nodes:
            node_role = node.role
            node_id = node.id

            if node_role == NodeRole.REACT:
                if "recon" in node_id.lower():
                    tools_list = [
                        tools["nmap_scan"],
                        tools["whois_lookup"],
                        tools["dns_enum"],
                        tools["subdomain_enum"],
                    ]
                    node_modules[node_id] = ReconModule(tools=tools_list)
                elif "enum" in node_id.lower():
                    tools_list = [
                        tools["gobuster_scan"],
                        tools["ffuf_scan"],
                        tools["nikto_scan"],
                    ]
                    node_modules[node_id] = EnumModule(tools=tools_list)
                else:
                    tools_list = list(tools.values())
                    node_modules[node_id] = ReconModule(tools=tools_list)
            elif node_role == NodeRole.CHAIN_OF_THOUGHT:
                if "vuln" in node_id.lower():
                    node_modules[node_id] = VulnAnalysisModule()
                elif "exploit" in node_id.lower() or "plan" in node_id.lower():
                    node_modules[node_id] = ExploitPlannerModule()
                elif "report" in node_id.lower():
                    node_modules[node_id] = ReportingModule()
                else:
                    node_modules[node_id] = VulnAnalysisModule()
            else:
                from spider.nodes.executor import ExecutorModule
                from spider.nodes.post_exploit import PostExploitModule

                if "post" in node_id.lower() or "elevate" in node_id.lower():
                    node_modules[node_id] = PostExploitModule()
                elif "exec" in node_id.lower():
                    node_modules[node_id] = ExecutorModule(
                        hitl_gate=self.hitl_gate,
                    )
                else:
                    node_modules[node_id] = VulnAnalysisModule()

        return node_modules

    def run(
        self,
        goal: str,
        target: str,
        **kwargs: str,
    ) -> dict[str, object]:
        """Execute a full pentest against the given target.

        Args:
            goal: Natural language description of the pentest objective.
            target: Target IP or hostname.
            **kwargs: Additional runtime inputs for the topology.

        Returns:
            Dictionary with topology, execution results, and session ID.
        """
        session_id = f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

        # Phase 1: Weave topology from goal and target
        with dspy.settings.context(temperature=0.1):
            topology = self.weaver.weave(
                goal=goal,
                target=target,
                constraints=self.config.rules_of_engagement,
            )

        # Phase 2: Provision tools
        tools = self._build_tools(
            scope_guard=self.scope_guard,
            audit_logger=self.audit_logger,
        )

        # Phase 3: Build node modules with topology + tools
        node_modules = self._build_node_modules(topology, tools)

        # Phase 4: Execute via GraphRunner
        runner = GraphRunner(
            topology=topology,
            node_modules=node_modules,
            goal=goal,
            target=target,
            tools=tools,
        )
        result = runner(**kwargs)

        # Phase 5: Quality evaluation + auto-healing loop
        healed = self._heal_loop(
            goal=goal,
            topology=topology,
            node_modules=node_modules,
            tools=tools,
            initial_result=result,
            **kwargs,
        )

        return {
            "session_id": session_id,
            "target": target,
            "goal": goal,
            "topology": topology,
            "result": healed,
        }

    def _heal_loop(
        self,
        goal: str,
        topology: GraphTopology,
        node_modules: dict[str, dspy.Module],
        tools: dict[str, dspy.Tool],
        initial_result: dict[str, object],
        max_rounds: int = 3,
        **kwargs: str,
    ) -> dict[str, object]:
        """Auto-healing: re-run waves with failure context if quality is low."""
        from spider.engine.self_eval import SelfEvaluator

        evaluator = SelfEvaluator()
        current_result = initial_result

        for _round_num in range(max_rounds):
            quality = evaluator.evaluate(
                goal=goal,
                result=current_result,
            )

            if quality >= self.config.refine_threshold:
                break

            # Re-weave with failure feedback
            feedback = (
                f"Previous run scored {quality:.2f} (threshold: "
                f"{self.config.refine_threshold}). "
                f"Improve coverage and detail."
            )

            with dspy.settings.context(temperature=0.4):
                new_topology = self.weaver.weave(
                    goal=goal,
                    target=kwargs.get("target", ""),
                    constraints=self.config.rules_of_engagement,
                    previous_result=str(current_result),
                    feedback=feedback,
                )
                new_modules = self._build_node_modules(new_topology, tools)
                runner = GraphRunner(
                    topology=new_topology,
                    node_modules=new_modules,
                    goal=goal,
                    target=kwargs.get("target", ""),
                    tools=tools,
                )
                current_result = runner(**kwargs)

        return current_result
