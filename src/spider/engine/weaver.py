"""GraphWeaver -- DSPy-native topology weaver with self-improving Refine loop.

Takes a pentest goal and produces a validated DAG of nodes.
Uses dspy.Refine with structural + quality reward for automatic retry.
"""

from collections.abc import Callable

import dspy

from spider.config import SpiderConfig
from spider.schemas import (
    EdgeDef,
    ExecutionConstraints,
    GraphTopology,
    NodeDef,
    NodeKind,
    NodeRole,
    PentestGoal,
    ScanMode,
    TargetSpec,
    ToolCatalog,
    TopologyScore,
)

_RECON_REPORT_INPUTS = frozenset({"recon_results", "vulnerabilities"})
_FULL_REPORT_INPUTS = frozenset({"recon_results", "vulnerabilities", "attack_plan"})

_REQUIRED_INPUTS_BY_KIND: dict[NodeKind, frozenset[str]] = {
    NodeKind.RECON: frozenset({"target_spec"}),
    NodeKind.WEB_ENUM: frozenset({"recon_results"}),
    NodeKind.SERVICE_ENUM: frozenset({"recon_results"}),
    NodeKind.VULNERABILITY_ANALYSIS: frozenset({"web_findings", "service_details"}),
    NodeKind.EXPLOIT_PLANNING: frozenset({"vulnerabilities"}),
    NodeKind.EXPLOIT_EXECUTION: frozenset({"attack_plan", "target_spec"}),
    NodeKind.POST_EXPLOITATION: frozenset({"exploit_result", "target_spec"}),
}


class TopologyEvalSignature(dspy.Signature):
    """Evaluate a woven pentest topology for quality and validity. Check:
    - Root node (no dependencies) MUST be ReAct for tool-use recon
    - No cycles in the graph -- pentest phases must flow forward only
    - Every node has inputs satisfied by upstream node outputs
      (e.g. if Node B wants 'web_findings', Node A must output
      'web_findings' AND Node B must depend on Node A)
    - At least 3 nodes for a meaningful pentest
    - HITL gate flags set on exploitation nodes
    - CANONICAL NAMING: You MUST enforce standard field names:
        recon -> recon_results, web_enum -> web_findings,
        svc_enum -> service_details, vuln_scan -> vulnerabilities,
        exploit_planner -> attack_plan, reporter -> report"""

    goal: PentestGoal = dspy.InputField()
    topology_json: str = dspy.InputField(desc="Serialized topology JSON to evaluate")
    evaluation: TopologyScore = dspy.OutputField()


class TopologyEvaluator(dspy.Module):
    """DSPy-native topology quality checker."""

    def __init__(self):
        super().__init__()
        self.judge = dspy.ChainOfThought(TopologyEvalSignature)

    def forward(self, goal: PentestGoal, topology_json: str) -> float:
        result = self.judge(goal=goal, topology_json=topology_json)
        return float(result.evaluation.score)


class GraphWeaverSignature(dspy.Signature):
    """Design a multi-agent pentest graph topology.
    The first node MUST be kind: recon and role: react. Recon always starts
    with active reconnaissance.

    CRITICAL: You MUST use CANONICAL field names for standard outputs:
    - recon kind -> recon_results (Node role: react)
    - web_enum kind -> web_findings
    - service_enum kind -> service_details
    - vulnerability_analysis kind -> vulnerabilities
    - exploit_planning kind -> attack_plan
    - exploit_execution kind -> exploit_result
    - post_exploitation kind -> post_exploit_result
    - reporting kind -> report

    DATA FLOW RULE: If Node B consumes 'web_findings', it MUST
    list Node A (the producer) in its 'depends_on' list.
    NO parallel waves for dependent data.
    Must be a DAG. NO cycles. Edges flow FORWARD only.
    Include HITL nodes for exploitation steps.

    REQUIRED INPUT DECLARATIONS:
    - topology.runtime_inputs MUST include "target_spec"
    - recon nodes MUST have inputs: ["target_spec"]
    - web_enum and service_enum nodes MUST consume "recon_results"
    - vulnerability_analysis nodes MUST consume both "web_findings" and "service_details"
    - recon reporting nodes MUST consume "recon_results" and "vulnerabilities"
    - full reporting nodes MUST also consume "attack_plan"

    NAMING RULE: Provide descriptive, user-friendly 'name' fields for each node
    (e.g., 'Target Reconnaissance' instead of 'react_node_1')."""

    goal: PentestGoal = dspy.InputField()
    target_spec: TargetSpec = dspy.InputField()
    constraints: ExecutionConstraints = dspy.InputField()
    tool_catalog: ToolCatalog = dspy.InputField(
        desc="Catalog of available tools organized by category"
    )
    topology: GraphTopology = dspy.OutputField()


class GraphWeaver(dspy.Module):
    """DSPy-native self-improving pentest topology weaver."""

    def __init__(self, config: SpiderConfig, progress_fn: Callable | None = None):
        super().__init__()
        self.config = config
        self.max_nodes = config.max_graph_nodes
        self.progress_fn = progress_fn or (lambda _s, _d="": None)
        # Optimized: Predict is faster for complex JSON topologies
        base_weave = dspy.Predict(GraphWeaverSignature)
        topology_eval = TopologyEvaluator()

        def topology_reward(args: dict, pred: dspy.Prediction) -> float:
            self.progress_fn("weave_attempt", "Evaluating topology draft...")
            topo = pred.topology
            if not topo or not topo.nodes:
                self.progress_fn("weave_attempt", "  Draft rejected: no nodes")
                return 0.0
            # Structural validation
            try:
                waves = topo.topological_waves()
                self.progress_fn(
                    "weave_attempt", f"  Draft valid: {len(waves)} waves, {len(topo.nodes)} nodes"
                )
            except ValueError:
                self.progress_fn("weave_attempt", "  Draft rejected: cycle detected")
                return 0.0

            issues = validate_topology_contract(topo)
            if issues:
                preview = "; ".join(issues[:3])
                self.progress_fn("weave_attempt", f"  Draft rejected: {preview}")
                return 0.0

            # Quality validation
            goal = args.get("goal", PentestGoal(objective="Evaluate pentest topology"))
            score = topology_eval(goal=goal, topology_json=topo.model_dump_json())
            self.progress_fn("weave_eval", f"  Draft topology quality score: {score:.2f}")
            return score

        if self.config.use_refine:
            self.weave = dspy.Refine(
                module=base_weave,
                N=self.config.max_refine_retries,
                reward_fn=topology_reward,
                threshold=0.8,
            )
        else:
            self.weave = base_weave

    def forward(
        self, goal: PentestGoal | str, progress_fn: Callable | None = None, **kwargs
    ) -> dspy.Prediction:
        if progress_fn:
            self.progress_fn = progress_fn
        goal_spec = goal if isinstance(goal, PentestGoal) else PentestGoal.from_text(goal)

        if "target_info" in kwargs and "target_spec" not in kwargs:
            kwargs["target_spec"] = TargetSpec.from_raw(str(kwargs.pop("target_info")))
        if "constraints_text" in kwargs and "constraints" not in kwargs:
            kwargs["constraints"] = ExecutionConstraints.from_text(
                rules_of_engagement=str(kwargs.pop("constraints_text")),
                scan_mode=kwargs.get("mode", ScanMode.RECON),
                max_graph_nodes=self.max_nodes,
            )

        with dspy.settings.context(temperature=0.1):
            return self.weave(goal=goal_spec, **kwargs)


def required_inputs_for_node(node: NodeDef, scan_mode: ScanMode | None = None) -> frozenset[str]:
    """Return the module signature inputs required by a topology node kind."""
    if node.kind == NodeKind.REPORTING:
        if scan_mode in (ScanMode.FULL, ScanMode.CUSTOM) or "attack_plan" in node.inputs:
            return _FULL_REPORT_INPUTS
        return _RECON_REPORT_INPUTS
    return _REQUIRED_INPUTS_BY_KIND.get(node.kind, frozenset())


def validate_topology_contract(
    topology: GraphTopology,
    scan_mode: ScanMode | None = None,
) -> list[str]:
    """Validate that node inputs can be sourced from runtime inputs or dependencies.

    The LLM quality judge can miss data-flow errors. This deterministic check
    mirrors the runner's strict input sourcing before a topology reaches execution.
    """
    issues: list[str] = []
    node_ids = {node.id for node in topology.nodes}
    output_by_id = {node.id: node.output for node in topology.nodes}
    producer_by_output = {node.output: node.id for node in topology.nodes}
    runtime_inputs = set(topology.runtime_inputs)

    if "target_spec" not in runtime_inputs:
        issues.append("Topology must declare runtime input 'target_spec'.")

    try:
        waves = topology.topological_waves()
    except ValueError as exc:
        return [str(exc)]

    first_wave = set(waves[0]) if waves else set()
    recon_roots = [
        node for node in topology.nodes if node.kind == NodeKind.RECON and node.id in first_wave
    ]
    if not recon_roots:
        issues.append("First wave must include a recon node.")
    if any(node.role != NodeRole.REACT for node in recon_roots):
        issues.append("First-wave recon nodes must use role 'react'.")

    for node in topology.nodes:
        missing_declared = sorted(required_inputs_for_node(node, scan_mode) - set(node.inputs))
        if missing_declared:
            issues.append(
                f"Node '{node.id}' kind '{node.kind}' must declare input(s): "
                f"{', '.join(missing_declared)}."
            )

        for dep in node.depends_on:
            if dep not in node_ids and dep not in runtime_inputs:
                issues.append(f"Node '{node.id}' depends on unknown node/input '{dep}'.")

        for input_name in node.inputs:
            if input_name in runtime_inputs:
                continue

            producer_id = producer_by_output.get(input_name)
            if producer_id is None:
                issues.append(
                    f"Node '{node.id}' input '{input_name}' has no runtime or node output source."
                )
                continue

            if producer_id not in node.depends_on:
                issues.append(
                    f"Node '{node.id}' input '{input_name}' must depend on producer "
                    f"'{producer_id}'."
                )

        for dep in node.depends_on:
            if dep in node_ids:
                dep_output = output_by_id[dep]
                if dep_output not in node.inputs:
                    issues.append(
                        f"Node '{node.id}' depends on '{dep}' but does not declare "
                        f"input '{dep_output}'."
                    )

    return issues


def build_default_topology(mode: ScanMode) -> GraphTopology | None:
    """Build a default pentest topology for the given scan mode.

    Returns None for CUSTOM mode — the Weaver must generate a topology
    from the user's natural language goal.
    """
    if mode == ScanMode.CUSTOM:
        return None

    nodes = [
        NodeDef(
            id="recon",
            kind=NodeKind.RECON,
            role=NodeRole.REACT,
            name="Reconnaissance",
            description="Discover all hosts, ports, services, and technologies on the target.",
            inputs=["target_spec"],
            output="recon_results",
            depends_on=[],
            tools=[],
        ),
        NodeDef(
            id="web_enum",
            kind=NodeKind.WEB_ENUM,
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="Web Enumeration",
            description="Enumerate web applications, directories, parameters, and technologies.",
            inputs=["recon_results"],
            output="web_findings",
            depends_on=["recon"],
            tools=[],
        ),
        NodeDef(
            id="service_enum",
            kind=NodeKind.SERVICE_ENUM,
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="Service Enumeration",
            description="Probe service versions, configurations, and default credentials.",
            inputs=["recon_results"],
            output="service_details",
            depends_on=["recon"],
            tools=[],
        ),
        NodeDef(
            id="vuln_analysis",
            kind=NodeKind.VULNERABILITY_ANALYSIS,
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="Vulnerability Analysis",
            description="Match discovered services to known CVEs. Check exploit availability.",
            inputs=["web_findings", "service_details"],
            output="vulnerabilities",
            depends_on=["web_enum", "service_enum"],
            tools=[],
        ),
    ]

    # Exploitation node only in FULL mode
    if mode == ScanMode.FULL:
        nodes.append(
            NodeDef(
                id="exploit_planner",
                kind=NodeKind.EXPLOIT_PLANNING,
                role=NodeRole.CHAIN_OF_THOUGHT,
                name="Exploit Planning",
                description="Build multi-step attack chains from discovered vulnerabilities.",
                inputs=["vulnerabilities"],
                output="attack_plan",
                depends_on=["vuln_analysis"],
                tools=[],
            )
        )

    # Reporter always included — inputs depend on mode
    if mode == ScanMode.FULL:
        reporter = NodeDef(
            id="reporter",
            kind=NodeKind.REPORTING,
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="Report Generation",
            description="Generate structured pentest report with findings and remediation.",
            inputs=["recon_results", "vulnerabilities", "attack_plan"],
            output="report",
            depends_on=["recon", "vuln_analysis", "exploit_planner"],
            tools=[],
        )
    else:
        reporter = NodeDef(
            id="reporter",
            kind=NodeKind.REPORTING,
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="Report Generation",
            description="Generate structured recon report with findings and remediation.",
            inputs=["recon_results", "vulnerabilities"],
            output="report",
            depends_on=["recon", "vuln_analysis"],
            tools=[],
        )
    nodes.append(reporter)

    edges = []
    for node in nodes:
        for dep in node.depends_on:
            edges.append(EdgeDef(source=dep, target=node.id, label=""))

    objective = "Full penetration test" if mode == ScanMode.FULL else "Reconnaissance scan"

    return GraphTopology(
        name="default_pentest",
        objective=objective,
        nodes=nodes,
        edges=edges,
        runtime_inputs=["target_spec"],
        metadata={"scan_mode": mode.value},
    )
