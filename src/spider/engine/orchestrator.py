"""SpiderOrchestrator -- top-level pipeline: Weaver -> Provision -> Runner -> Heal.

Wires together the GraphWeaver, tool provisioning, GraphRunner, and
auto-healing loop for end-to-end pentest execution.
"""

import os
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import dspy

from spider.config import SpiderConfig
from spider.engine.mode_filter import filter_topology_for_mode
from spider.engine.node_factory import build_node_modules
from spider.engine.runner import GraphRunner
from spider.engine.tool_registry import build_tool_catalog, build_tools
from spider.engine.weaver import GraphTopology, GraphWeaver
from spider.sandbox.hitl_gate import HITLGate
from spider.sandbox.scope_guard import ScopeGuard
from spider.schemas import ScanMode
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
        audit_logger: Any | None = None,
        progress_fn: Callable[[str, str], None] | None = None,
    ) -> None:
        self.config = config
        self.progress_fn = progress_fn or (lambda _s, _d="": None)
        self.weaver = GraphWeaver(config=config, progress_fn=self.progress_fn)
        self.scope_guard = scope_guard
        self.hitl_gate = hitl_gate
        self.session_store = session_store
        self.audit_logger = audit_logger
        self._all_tools: dict[str, dspy.Tool] = {}
        self._tools_by_mode: dict[ScanMode, dict[str, dspy.Tool]] = {}

    @property
    def tools(self) -> dict[str, dspy.Tool]:
        """Lazy-load and return all registered tools."""
        return self._build_tools(
            mode=ScanMode.FULL,
            scope_guard=self.scope_guard,
            audit_logger=self.audit_logger,
        )

    def _build_tools(
        self,
        mode: ScanMode = ScanMode.FULL,
        scope_guard: ScopeGuard | None = None,
        audit_logger: Any | None = None,
    ) -> dict[str, dspy.Tool]:
        """Build security tools with scope guard and scan-mode filtering."""
        if mode not in self._tools_by_mode:
            self._tools_by_mode[mode] = build_tools(
                mode=mode,
                scope_guard=scope_guard,
                audit_logger=audit_logger,
                hitl_gate=self.hitl_gate,
            )
        if mode == ScanMode.FULL:
            self._all_tools = self._tools_by_mode[mode]
        return self._tools_by_mode[mode]

    def _build_node_modules(
        self,
        topology: GraphTopology,
        tools: dict[str, dspy.Tool],
    ) -> dict[str, dspy.Module]:
        """Build DSPy modules for each node in the topology."""
        return build_node_modules(
            topology=topology,
            tools=tools,
            config=self.config,
            hitl_gate=self.hitl_gate,
            progress_fn=self.progress_fn,
        )

    def _load_compiled_module(self, module: dspy.Module) -> None:
        """Attempt to load BootstrapFewShot optimized weights for a module."""
        module_name = module.__class__.__name__
        compiled_dir = os.path.join(os.path.dirname(__file__), "..", "compiled")
        weights_path = os.path.join(compiled_dir, f"{module_name}.json")

        if os.path.exists(weights_path):
            try:
                module.load(weights_path)
                self.progress_fn("optimize_load", f"Loaded compiled weights for {module_name}")
            except Exception as e:
                self.progress_fn(
                    "optimize_error",
                    f"Failed to load weights for {module_name}: {str(e)}",
                )

    def run(
        self,
        goal: str,
        target: str,
        **kwargs: Any,
    ) -> dict[str, object]:
        """Execute a full pentest against the given target.

        Args:
            goal: Natural language description of the pentest objective.
            target: Target IP or hostname.
            **kwargs: Additional runtime inputs for the topology.

        Returns:
            Dictionary with topology, execution results, and session ID.
        """
        mode = kwargs.pop("mode", ScanMode.RECON)
        if isinstance(mode, str):
            mode = ScanMode(mode)
        session_id = f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

        # Phase 0: Scope Check
        if self.scope_guard:
            authorized, reason = self.scope_guard.authorize(target, "orchestrator_run")
            if not authorized:
                return {
                    "success": False,
                    "error": f"OUT_OF_SCOPE: {reason}",
                    "session_id": session_id,
                    "target": target,
                }

        # Phase 1: Weave topology from goal and target
        self.progress_fn("weave", "Generating attack topology with DSPy weaver...")
        tools = self._build_tools(
            mode=mode,
            scope_guard=self.scope_guard,
            audit_logger=self.audit_logger,
        )
        tool_catalog = build_tool_catalog(set(tools.keys()), mode)
        with dspy.settings.context(temperature=0.1):
            prediction = self.weaver(
                goal=goal,
                target_info=target,
                constraints_text=self.config.rules_of_engagement,
                tool_catalog=tool_catalog,
                progress_fn=self.progress_fn,
            )
            topology = filter_topology_for_mode(prediction.topology, mode)
        self.progress_fn(
            "weave_done",
            f"Topology woven: {len(topology.nodes)} nodes, {len(topology.edges)} edges",
        )

        # Phase 2: Provision tools
        self.progress_fn("provision", f"Provisioning {len(tools)} security tools...")
        self.progress_fn("provision_done", f"Tools ready: {', '.join(tools.keys())}")

        # Phase 3: Build node modules with topology + tools
        self.progress_fn("build", f"Building {len(topology.nodes)} DSPy node modules...")
        node_modules = self._build_node_modules(topology, tools)
        self.progress_fn("build_done", "Node modules ready")

        # Phase 4: Execute via GraphRunner
        node_names = [n.name for n in topology.nodes]
        self.progress_fn("execute", f"Running pipeline: {' -> '.join(node_names)}")
        runner = GraphRunner(
            topology=topology,
            node_modules=node_modules,
            goal=goal,
            target=target,
            tools=tools,
            progress_fn=self.progress_fn,
        )
        result = runner(**kwargs)
        self.progress_fn("execute_done", "All nodes executed")

        # Phase 5: Quality evaluation + auto-healing loop
        self.progress_fn("evaluate", "Evaluating output quality...")
        healed = self._heal_loop(
            goal=goal,
            target=target,
            topology=topology,
            node_modules=node_modules,
            tools=tools,
            initial_result=result,
            mode=mode,
            **kwargs,
        )
        self.progress_fn("done", "Scan complete")

        return {
            "session_id": session_id,
            "target": target,
            "goal": goal,
            "mode": mode.value,
            "topology": topology,
            "result": healed,
        }

    def _heal_loop(
        self,
        goal: str,
        target: str,
        topology: GraphTopology,
        node_modules: dict[str, dspy.Module],
        tools: dict[str, dspy.Tool],
        initial_result: dict[str, object],
        max_rounds: int = 3,
        mode: ScanMode = ScanMode.RECON,
        **kwargs: Any,
    ) -> dict[str, object]:
        """Auto-healing: re-run waves with failure context if quality is low."""
        from spider.engine.self_eval import SelfEvaluator

        evaluator = SelfEvaluator()
        current_result = initial_result

        if not self.config.use_refine:
            self.progress_fn("heal_skip", "Refinement disabled -- skipping healing loop")
            return current_result

        for round_num in range(max_rounds):
            self.progress_fn("heal_eval", f"Quality check round {round_num + 1}/{max_rounds}...")
            quality = evaluator.evaluate(
                goal=goal,
                result=current_result,
            )
            self.progress_fn(
                "heal_score",
                f"Quality score: {quality:.2f} (threshold: {self.config.refine_threshold})",
            )

            if quality >= self.config.refine_threshold:
                self.progress_fn(
                    "heal_done", f"Quality {quality:.2f} meets threshold -- no healing needed"
                )
                break

            self.progress_fn(
                "heal_reweave", "Quality below threshold -- re-weaving with feedback..."
            )

            # Re-weave with failure feedback
            feedback = (
                f"Previous run scored {quality:.2f} (threshold: "
                f"{self.config.refine_threshold}). "
                f"Improve coverage and detail."
            )

            with dspy.settings.context(temperature=0.4):
                tools = self._build_tools(
                    mode=mode,
                    scope_guard=self.scope_guard,
                    audit_logger=self.audit_logger,
                )
                tool_catalog = build_tool_catalog(set(tools.keys()), mode)
                new_prediction = self.weaver(
                    goal=goal,
                    target_info=target,
                    constraints_text=self.config.rules_of_engagement,
                    tool_catalog=tool_catalog,
                    previous_result=str(current_result),
                    feedback=feedback,
                    progress_fn=self.progress_fn,
                )
                new_topology = filter_topology_for_mode(new_prediction.topology, mode)
                new_modules = self._build_node_modules(new_topology, tools)
                runner = GraphRunner(
                    topology=new_topology,
                    node_modules=new_modules,
                    goal=goal,
                    target=target,
                    tools=tools,
                    progress_fn=self.progress_fn,
                )
                current_result = runner(**kwargs)

        return current_result
