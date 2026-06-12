"""SpiderOrchestrator -- top-level pipeline: Weaver -> Provision -> Runner -> Heal.

Wires together the GraphWeaver, tool provisioning, GraphRunner, and
auto-healing loop for end-to-end pentest execution.
"""

import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import dspy

from spider.config import SpiderConfig
from spider.engine.mode_filter import filter_topology_for_mode
from spider.engine.node_factory import build_node_modules
from spider.engine.runner import GraphRunner
from spider.engine.tool_registry import build_tool_catalog, build_tools
from spider.engine.topology_library import (
    TopologySelectionError,
    is_weaver_topology,
    load_saved_topology,
    normalize_topology_name,
    selected_prebuilt_mode,
)
from spider.engine.weaver import GraphWeaver, build_default_topology, validate_topology_contract
from spider.sandbox.hitl_gate import HITLGate
from spider.sandbox.scope_guard import ScopeGuard
from spider.schemas import (
    ExecutionConstraints,
    GraphTopology,
    PentestGoal,
    ScanMode,
    TargetSpec,
    ToolCatalog,
)
from spider.tui.session import SessionStore


class SpiderOrchestrator:
    """Top-level SPIDER orchestrator.

    Pipeline:
    1. Select a deterministic or DSPy-woven topology
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
        mode: ScanMode | None = None,
    ) -> dict[str, dspy.Module]:
        """Build DSPy modules for each node in the topology."""
        return build_node_modules(
            topology=topology,
            tools=tools,
            config=self.config,
            hitl_gate=self.hitl_gate,
            progress_fn=self.progress_fn,
            scan_mode=mode,
        )

    def _select_topology(
        self,
        mode: ScanMode,
        goal: PentestGoal,
        target_spec: TargetSpec,
        constraints: ExecutionConstraints,
        tool_catalog: ToolCatalog,
        topology_name: str | None = None,
    ) -> GraphTopology:
        """Select a prebuilt, saved, or DSPy-woven topology."""
        raw_selector = (topology_name or self.config.topology_name).strip()
        selected_name = normalize_topology_name(raw_selector)

        if is_weaver_topology(selected_name):
            return self._weave_topology(goal, target_spec, constraints, tool_catalog)

        prebuilt_mode = selected_prebuilt_mode(selected_name)
        if prebuilt_mode is not None:
            self.progress_fn(
                "topology_prebuilt",
                f"Using prebuilt {prebuilt_mode.value} topology",
            )
            topology = build_default_topology(prebuilt_mode)
            if topology is None:
                raise TopologySelectionError(
                    f"Prebuilt topology '{prebuilt_mode.value}' is not available."
                )
            return topology

        if selected_name != "auto":
            self.progress_fn(
                "topology_saved",
                f"Loading saved topology '{selected_name}'",
            )
            return load_saved_topology(raw_selector, self.config.topology_dir)

        default_topology = build_default_topology(mode)
        if default_topology is not None:
            self.progress_fn(
                "topology_default",
                f"Using deterministic {mode.value} topology",
            )
            return default_topology

        return self._weave_topology(goal, target_spec, constraints, tool_catalog)

    def _weave_topology(
        self,
        goal: PentestGoal,
        target_spec: TargetSpec,
        constraints: ExecutionConstraints,
        tool_catalog: ToolCatalog,
    ) -> GraphTopology:
        """Generate a topology with the DSPy weaver."""
        self.progress_fn("weave", "Generating custom attack topology with DSPy weaver...")
        with dspy.settings.context(temperature=0.1):
            prediction = self.weaver(
                goal=goal,
                target_spec=target_spec,
                constraints=constraints,
                tool_catalog=tool_catalog,
                progress_fn=self.progress_fn,
            )
        return prediction.topology

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
        goal: str | PentestGoal,
        target: str | TargetSpec,
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
        topology_name = kwargs.pop("topology_name", None)
        if isinstance(mode, str):
            mode = ScanMode(mode)
        session_id = f"run_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"
        goal_spec = goal if isinstance(goal, PentestGoal) else PentestGoal.from_text(goal)
        target_spec = (
            target
            if isinstance(target, TargetSpec)
            else TargetSpec.from_raw(
                target=target,
                scope=self.config.rules_of_engagement,
            )
        )
        constraints = ExecutionConstraints.from_text(
            rules_of_engagement=self.config.rules_of_engagement,
            scan_mode=mode,
            max_graph_nodes=self.config.max_graph_nodes,
        )

        # Phase 0: Scope Check
        if self.scope_guard:
            authorized, reason = self.scope_guard.authorize(target_spec.target, "orchestrator_run")
            if not authorized:
                return {
                    "success": False,
                    "error": f"OUT_OF_SCOPE: {reason}",
                    "session_id": session_id,
                    "target": target_spec.target,
                }

        # Phase 1: Select topology from deterministic defaults or custom DSPy weaving
        tools = self._build_tools(
            mode=mode,
            scope_guard=self.scope_guard,
            audit_logger=self.audit_logger,
        )
        tool_catalog = build_tool_catalog(set(tools.keys()), mode)
        try:
            topology = self._select_topology(
                mode=mode,
                goal=goal_spec,
                target_spec=target_spec,
                constraints=constraints,
                tool_catalog=tool_catalog,
                topology_name=topology_name,
            )
        except TopologySelectionError as exc:
            return {
                "success": False,
                "error": f"TOPOLOGY_SELECTION_ERROR: {exc}",
                "session_id": session_id,
                "target": target_spec.target,
            }
        topology = filter_topology_for_mode(topology, mode)
        topology_issues = validate_topology_contract(topology, mode)
        if topology_issues:
            return {
                "success": False,
                "error": f"INVALID_TOPOLOGY: {'; '.join(topology_issues)}",
                "session_id": session_id,
                "target": target_spec.target,
            }
        self.progress_fn(
            "topology_done",
            f"Topology ready: {len(topology.nodes)} nodes, {len(topology.edges)} edges",
        )

        # Phase 2: Provision tools
        self.progress_fn("provision", f"Provisioning {len(tools)} security tools...")
        self.progress_fn("provision_done", f"Tools ready: {', '.join(tools.keys())}")

        # Phase 3: Build node modules with topology + tools
        self.progress_fn("build", f"Building {len(topology.nodes)} DSPy node modules...")
        node_modules = self._build_node_modules(topology, tools, mode=mode)
        self.progress_fn("build_done", "Node modules ready")

        # Phase 4: Execute via GraphRunner
        node_names = [n.name for n in topology.nodes]
        self.progress_fn("execute", f"Running pipeline: {' -> '.join(node_names)}")
        runner = GraphRunner(
            topology=topology,
            node_modules=node_modules,
            goal=goal_spec,
            target_spec=target_spec,
            tools=tools,
            progress_fn=self.progress_fn,
        )
        result = runner(**kwargs)
        self.progress_fn("execute_done", "All nodes executed")

        # Phase 5: Quality evaluation + auto-healing loop
        self.progress_fn("evaluate", "Evaluating output quality...")
        healed = self._heal_loop(
            goal=goal_spec,
            target=target_spec,
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
            "target": target_spec.target,
            "goal": goal_spec.objective,
            "mode": mode.value,
            "topology": topology,
            "result": healed,
        }

    def _heal_loop(
        self,
        goal: PentestGoal,
        target: TargetSpec,
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
                    target_spec=target,
                    constraints=ExecutionConstraints.from_text(
                        rules_of_engagement=self.config.rules_of_engagement,
                        scan_mode=mode,
                        max_graph_nodes=self.config.max_graph_nodes,
                    ),
                    tool_catalog=tool_catalog,
                    previous_result=str(current_result),
                    feedback=feedback,
                    progress_fn=self.progress_fn,
                )
                new_topology = filter_topology_for_mode(new_prediction.topology, mode)
                topology_issues = validate_topology_contract(new_topology, mode)
                if topology_issues:
                    current_result = dspy.Prediction(
                        results=getattr(current_result, "results", {}),
                        error=f"INVALID_TOPOLOGY: {'; '.join(topology_issues)}",
                    )
                    continue
                new_modules = self._build_node_modules(new_topology, tools, mode=mode)
                runner = GraphRunner(
                    topology=new_topology,
                    node_modules=new_modules,
                    goal=goal,
                    target_spec=target,
                    tools=tools,
                    progress_fn=self.progress_fn,
                )
                current_result = runner(**kwargs)

        return current_result
