"""GraphWeaver -- DSPy-native topology weaver with self-improving Refine loop.

Takes a pentest goal and produces a validated DAG of nodes.
Uses dspy.Refine with structural + quality reward for automatic retry.
"""

from collections.abc import Callable

import dspy

from spider.config import SpiderConfig
from spider.schemas import (
    EdgeDef,
    GraphTopology,
    NodeDef,
    NodeRole,
    ScanMode,
    ToolCatalog,
    TopologyScore,
)


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

    goal: str = dspy.InputField()
    topology_json: str = dspy.InputField()
    evaluation: TopologyScore = dspy.OutputField()


class TopologyEvaluator(dspy.Module):
    """DSPy-native topology quality checker."""

    def __init__(self):
        super().__init__()
        self.judge = dspy.ChainOfThought(TopologyEvalSignature)

    def forward(self, goal: str, topology_json: str) -> float:
        result = self.judge(goal=goal, topology_json=topology_json)
        return float(result.evaluation.score)


class GraphWeaverSignature(dspy.Signature):
    """Design a multi-agent pentest graph topology.
    The first node MUST be role: react (recon always starts with active reconnaissance).

    CRITICAL: You MUST use CANONICAL field names for standard outputs:
    - reconnaissance outputs -> recon_results (Node role: react)
    - web app enumeration outputs -> web_findings
    - service probing/enumeration outputs -> service_details
    - vulnerability scanning outputs -> vulnerabilities
    - exploit planning outputs -> attack_plan
    - reporting outputs -> report

    DATA FLOW RULE: If Node B consumes 'web_findings', it MUST
    list Node A (the producer) in its 'depends_on' list.
    NO parallel waves for dependent data.
    Must be a DAG. NO cycles. Edges flow FORWARD only.
    Include HITL nodes for exploitation steps.

    NAMING RULE: Provide descriptive, user-friendly 'name' fields for each node
    (e.g., 'Target Reconnaissance' instead of 'react_node_1')."""

    goal: str = dspy.InputField()
    target_info: str = dspy.InputField()
    constraints_text: str = dspy.InputField()
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
            # Quality validation
            score = topology_eval(goal=args.get("goal", ""), topology_json=topo.model_dump_json())
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

    def forward(self, goal: str, progress_fn: Callable | None = None, **kwargs) -> dspy.Prediction:
        if progress_fn:
            self.progress_fn = progress_fn
        with dspy.settings.context(temperature=0.1):
            return self.weave(goal=goal, **kwargs)


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
            role=NodeRole.REACT,
            name="Reconnaissance",
            description="Discover all hosts, ports, services, and technologies on the target.",
            inputs=["target"],
            output="recon_results",
            depends_on=[],
            tools=[],
        ),
        NodeDef(
            id="web_enum",
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
        runtime_inputs=["target"],
        metadata={"scan_mode": mode.value},
    )
