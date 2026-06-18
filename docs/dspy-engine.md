# DSPy Engine

SPIDER's engine is the DSPy-native reasoning layer. Every module, retry loop,
and self-evaluation step uses DSPy 3.1+ primitives exclusively -- no Python
workarounds, no manual retry loops, no post-processing hacks.

## Core Primitives Used

| DSPy Primitive | Usage in SPIDER |
|---------------|-----------------|
| `dspy.Signature` | All node input/output contracts with Pydantic types |
| `dspy.ReAct` | Recon and Executor nodes (tool-using agents) |
| `dspy.ChainOfThought` | Analysis, planning, and reporting nodes |
| `dspy.Refine(module, N, reward_fn, threshold)` | Self-improvement for ALL nodes |
| `dspy.Tool` | Wrappers for all security tools |
| `dspy.asyncify()` | Parallel wave execution |
| `dspy.settings.context(temperature=X)` | Temperature control per node type |

## Topology Selection

SPIDER does not have to weave every graph. The orchestrator can select a
topology from selectable sources before execution:

1. `auto` uses prebuilt topologies for standard `recon` and `full` modes.
2. `recon` or `full` explicitly selects one of the prebuilt topologies.
3. A saved topology name/path loads a previously created `GraphTopology` JSON
   from `SPIDER_TOPOLOGY_DIR` or an explicit file path.
4. `weave` or `custom` invokes `GraphWeaver` for dynamic DSPy topology design.

Every selected topology still passes deterministic mode filtering and topology
contract validation before `GraphRunner` executes it.

## GraphWeaver

The Weaver is a DSPy module that takes a pentest goal and produces a
`GraphTopology` -- a validated DAG of nodes with dependency edges.

```python
class GraphWeaverSignature(dspy.Signature):
    """Design a multi-agent pentest graph. The first node MUST be role: react.
    CRITICAL -- Must be a DAG. NO cycles. Edges flow FORWARD only.
    Every node's inputs must be outputs or inputs of upstream nodes."""
    goal: str = dspy.InputField()
    target_info: str = dspy.InputField(desc="Known target information")
    constraints_text: str = dspy.InputField(desc="Rules of engagement, scope limits")
    available_tools: str = dspy.InputField(desc="Available security tools list")
    topology: GraphTopology = dspy.OutputField()

class TopologyEvalSignature(dspy.Signature):
    """Evaluate a woven topology for a pentest graph. Check:
    - Root node is ReAct (penetration testing always starts with reconnaissance)
    - No cycles in the graph (pentest phases must flow forward)
    - Every node's inputs are satisfied by upstream node outputs
    - Vulnerability analysis comes after enumeration
    - Exploit planning comes after vulnerability analysis
    - At least 3 nodes in the graph"""
    goal: str = dspy.InputField()
    topology_json: str = dspy.InputField()
    evaluation: TopologyScore = dspy.OutputField()

class TopologyEvaluator(dspy.Module):
    def __init__(self):
        super().__init__()
        self.judge = dspy.ChainOfThought(TopologyEvalSignature)

    def forward(self, goal: str, topology_json: str) -> float:
        result = self.judge(goal=goal, topology_json=topology_json)
        return float(result.evaluation.score)

class GraphWeaver(dspy.Module):
    def __init__(self, max_nodes=8):
        super().__init__()
        base_weave = dspy.ChainOfThought(GraphWeaverSignature)
        topology_eval = TopologyEvaluator()

        def topology_reward(args: dict, pred: dspy.Prediction) -> float:
            topo = pred.topology
            if not topo or not topo.nodes:
                return 0.0
            try:
                topo.topological_waves()  # Structural validation
            except ValueError:
                return 0.0  # Cycle detected
            return topology_eval(goal=args.get("goal", ""), topology_json=topo.model_dump_json())

        self.weave = dspy.Refine(
            module=base_weave, N=3,
            reward_fn=topology_reward, threshold=0.8
        )

    def forward(self, goal: str, **kwargs) -> dspy.Prediction:
        with dspy.settings.context(temperature=0.1):
            return self.weave(goal=goal, **kwargs)
```

### Topology Validation

`GraphTopology.topological_waves()` performs structural validation:
1. Computes in-degrees for all nodes
2. Iteratively peels zero-in-degree nodes into waves
3. If remaining nodes exist after peeling, a cycle is present --> ValueError

This is called in two places:
- Inside `topology_reward()` to validate Weaver output
- Inside `GraphRunner.forward()` before execution

## GraphRunner

Executes a validated topology in parallel waves. Each wave contains
nodes with all dependencies satisfied.

```python
class GraphRunner(dspy.Module):
    def __init__(self, topology: GraphTopology, tools: dict, goal: str = ""):
        super().__init__()
        self.topology = topology
        self.tools = tools
        self.goal = goal
        self._node_modules = {}
        self._build_node_modules()

    def _build_node_modules(self):
        for node in self.topology.nodes:
            module_class = self._resolve_module_class(node)
            node_tools = [self.tools[t] for t in node.tools if t in self.tools]
            self._node_modules[node.id] = module_class(tools=node_tools)

    def _wave_inputs(self, node_id: str, all_results: dict) -> dict:
        node_def = next(n for n in self.topology.nodes if n.id == node_id)
        return {inp: str(all_results.get(inp, "")) for inp in node_def.inputs}

    async def forward_async(self, **kwargs) -> dspy.Prediction:
        waves = self.topology.topological_waves()
        all_results: dict[str, Any] = {**kwargs}

        for wave in waves:
            async def run_one(nid):
                module = self._node_modules[nid]
                inputs = self._wave_inputs(nid, all_results)
                try:
                    result = await dspy.asyncify(module)(**inputs)
                    all_results[nid] = result
                    out_key = next(n for n in self.topology.nodes if n.id == nid).output
                    out_val = result.get(out_key) or getattr(result, out_key, None)
                    if out_val is not None:
                        all_results[out_key] = str(out_val)
                    return nid, None
                except Exception as e:
                    return nid, e

            outcomes = await asyncio.gather(*(run_one(nid) for nid in wave))
            if any(err for _, err in outcomes):
                break

        return dspy.Prediction(results=all_results)

    def forward(self, **kwargs):
        import asyncio
        return asyncio.run(self.forward_async(**kwargs))
```

## Self-Evaluation

Every node is wrapped with `dspy.Refine` for quality-driven retry.
The reward function is specific to each node type.

### Recon Reward
```python
def recon_reward(args: dict, pred: dspy.Prediction) -> float:
    findings = pred.findings
    score = 0.0
    if findings.hosts: score += 0.3
    if findings.ports: score += 0.3
    if findings.tech_stack: score += 0.2
    if findings.services: score += 0.2
    return score
```

### Vulnerability Analysis Reward
```python
def vuln_reward(args: dict, pred: dspy.Prediction) -> float:
    vulns = pred.vulnerabilities
    if not vulns: return 0.0
        score = min(0.7, len(vulns) * 0.1)
    # Bonus for CVSS scores
    if any(v.cvss_score > 7.0 for v in vulns): score += 0.2
    # Bonus for exploit availability
    if any(v.has_public_exploit for v in vulns): score += 0.2
    # Bonus for KEV entries
    if any(v.in_kev for v in vulns): score += 0.1
    return min(1.0, score)
```

### Exploit Planning Reward
```python
def exploit_plan_reward(args: dict, pred: dspy.Prediction) -> float:
    chains = pred.attack_chains
    if not chains: return 0.0
    score = 0.0
    for chain in chains:
        if chain.steps: score += 0.3
        if chain.stealth_score > 0.5: score += 0.2
        if chain.feasibility_score > 0.5: score += 0.2
    return min(1.0, score)
```

### Quality Evaluator (Self-Eval Module)
```python
class SelfEvalSignature(dspy.Signature):
    """Evaluate pentest output against the original goal.
    Check: completeness, accuracy, actionability."""
    goal: str = dspy.InputField()
    output: str = dspy.InputField()
    evaluation: QualityScore = dspy.OutputField()

class SelfEvaluator(dspy.Module):
    def __init__(self):
        super().__init__()
        self.judge = dspy.ChainOfThought(SelfEvalSignature)

    def forward(self, goal: str, pred: dspy.Prediction) -> float:
        output_val = str(pred.run_result) if hasattr(pred, "run_result") else str(pred)
        result = self.judge(goal=goal, output=output_val)
        return float(result.evaluation.score)
```

## Orchestrator

Top-level pipeline that wires Weaver --> Provision --> Runner --> Heal loop.

```python
class SpiderOrchestrator(dspy.Module):
    def __init__(self, config: SpiderConfig):
        super().__init__()
        self.config = config
        self.weaver = GraphWeaver(max_nodes=8)
        self._session_id = None

    def forward(self, goal: str, target: str, **kwargs) -> dspy.Prediction:
        # Phase 1: Weave or use provided topology
        topology = self.weaver(
            goal=goal,
            target_info=target,
            constraints_text=self.config.rules_of_engagement,
            available_tools=self.config.available_tools,
        ).topology

        # Phase 2: Provision tools
        tools = provision_tools(topology, self.config)

        # Phase 3: Execute
        runner = GraphRunner(topology=topology, tools=tools, goal=goal)
        result = runner(**kwargs)

        return result
```

## Pydantic Schema for Topology

```python
class NodeDef(BaseModel):
    id: str = Field(..., description="Unique snake_case ID")
    role: str  # "react", "chain_of_thought", "program_of_thought", "predict"
    name: str
    description: str
    inputs: list[str] = Field(default_factory=list)
    output: str
    depends_on: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)

class EdgeDef(BaseModel):
    source: str
    target: str
    label: str = ""

class GraphTopology(BaseModel):
    name: str
    objective: str
    nodes: list[NodeDef]
    edges: list[EdgeDef]
    runtime_inputs: list[str] = Field(default_factory=list)

    def topological_waves(self) -> list[list[str]]:
        id_set = {n.id for n in self.nodes}
        in_degree = {n.id: 0 for n in self.nodes}
        adj: dict[str, list[str]] = {n.id: [] for n in self.nodes}
        for e in self.edges:
            if e.source in id_set and e.target in id_set:
                in_degree[e.target] += 1
                adj[e.source].append(e.target)
        waves: list[list[str]] = []
        queue = sorted([k for k, d in in_degree.items() if d == 0])
        while queue:
            waves.append(list(queue))
            next_q = []
            for n in queue:
                for nb in adj[n]:
                    in_degree[nb] -= 1
                    if in_degree[nb] == 0:
                        next_q.append(nb)
            queue = sorted(next_q)
        if len(set().union(*(set(w) for w in waves), set())) != len(id_set):
            raise ValueError("Cycle detected in topology")
        return waves
```

## Temperature Guidelines

| Phase | Temperature | Reason |
|-------|-------------|--------|
| Weaving (topology generation) | 0.1 | Needs precise, valid DAG structure |
| Recon (ReAct) | 0.1 | Tool-calling requires precision |
| Vulnerability Analysis | 0.1 | CVE matching must be accurate |
| Exploit Planning | 0.2 | Some creativity for attack chains |
| Payload Generation | 0.4 | Needs variation for WAF bypass |
| Reporting | 0.1 | Structured output, no hallucination |

## Integration with Other Components

- **Tools**: Nodes receive tool references via the `tools` parameter in their
  constructor. Tools are provisioned by `provision_tools()` which handles
  scope guard wrapping, audit logging, and JSON serialization.
- **HITL Gate**: The Executor node's `dspy.Refine` loop pauses at HITL gates
  and waits for human approval before continuing.
- **Scope Guard**: Enforced at the tool adapter level before any execution.
- **Audit Logger**: Every tool invocation logs action, target, timestamp, result.
- **Langfuse**: DSPy instrumentation provides full trace visualization of
  every Refine attempt, tool call, and LLM reasoning step.
