"""GraphWeaver -- DSPy-native topology weaver with self-improving Refine loop.

Takes a pentest goal and produces a validated DAG of nodes.
Uses dspy.Refine with structural + quality reward for automatic retry.
"""

from collections.abc import Callable

import dspy

from spider.schemas import EdgeDef, GraphTopology, NodeDef, NodeRole, TopologyScore


class TopologyEvalSignature(dspy.Signature):
    """Evaluate a woven pentest topology for quality and validity. Check:
    - Root node (no dependencies) MUST be ReAct for tool-use reconnaissance
    - No cycles in the graph -- pentest phases must flow forward only
    - Every node has inputs satisfied by upstream node outputs
    - At least 3 nodes for a meaningful pentest
    - HITL gate flags set on exploitation nodes"""

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
    """Design a multi-agent pentest graph topology. The first node MUST be
    role: react (recon always starts with active tool-using reconnaissance).
    CRITICAL -- Must be a DAG. NO cycles. Edges flow FORWARD only.
    Include HITL nodes for exploitation steps."""

    goal: str = dspy.InputField()
    target_info: str = dspy.InputField()
    constraints_text: str = dspy.InputField()
    available_tools: str = dspy.InputField()
    topology: GraphTopology = dspy.OutputField()


class GraphWeaver(dspy.Module):
    """DSPy-native self-improving pentest topology weaver."""

    def __init__(self, max_nodes: int = 8, progress_fn: Callable | None = None):
        super().__init__()
        self.max_nodes = max_nodes
        self.progress_fn = progress_fn or (lambda _s, _d="": None)
        base_weave = dspy.ChainOfThought(GraphWeaverSignature)
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

        self.weave = dspy.Refine(
            module=base_weave,
            N=3,
            reward_fn=topology_reward,
            threshold=0.8,
        )

    def forward(self, goal: str, progress_fn: Callable | None = None, **kwargs) -> dspy.Prediction:
        if progress_fn:
            self.progress_fn = progress_fn
        with dspy.settings.context(temperature=0.1):
            return self.weave(goal=goal, **kwargs)



def build_default_topology() -> GraphTopology:
    """Build a default pentest topology when the Weaver is skipped."""
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
        NodeDef(
            id="exploit_planner",
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="Exploit Planning",
            description="Build multi-step attack chains from discovered vulnerabilities.",
            inputs=["vulnerabilities"],
            output="attack_plan",
            depends_on=["vuln_analysis"],
            tools=[],
        ),
        NodeDef(
            id="reporter",
            role=NodeRole.CHAIN_OF_THOUGHT,
            name="Report Generation",
            description="Generate structured pentest report with findings and remediation.",
            inputs=["recon_results", "vulnerabilities", "attack_plan"],
            output="report",
            depends_on=["recon", "vuln_analysis", "exploit_planner"],
            tools=[],
        ),
    ]

    edges = []
    for node in nodes:
        for dep in node.depends_on:
            edges.append(EdgeDef(source=dep, target=node.id, label=""))

    return GraphTopology(
        name="default_pentest",
        objective="Full penetration test",
        nodes=nodes,
        edges=edges,
        runtime_inputs=["target"],
    )
