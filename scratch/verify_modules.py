import dspy
from spider.engine.weaver import GraphTopology, NodeDef, NodeRole
from spider.engine.orchestrator import SpiderOrchestrator
from spider.config import SpiderConfig

# Mock topology with the problematic nodes
topology = GraphTopology(
    name="Test",
    objective="Test",
    nodes=[
        NodeDef(id="recon", role=NodeRole.REACT, name="Recon", description="Recon", output="recon_results"),
        NodeDef(id="reporter", role=NodeRole.CHAIN_OF_THOUGHT, name="Reporter", description="Reporter", output="report"),
        NodeDef(id="executor", role=NodeRole.REACT, name="Executor", description="Executor", output="exploit_result"),
    ],
    edges=[]
)

config = SpiderConfig()
orchestrator = SpiderOrchestrator(config)

# Mock tools
tools = {"test": dspy.Tool(lambda x: x)}

print("Starting node module building...")
try:
    modules = orchestrator._build_node_modules(topology, tools)
    print(f"Success! Built {len(modules)} modules.")
    for nid, mod in modules.items():
        print(f" - {nid}: {type(mod).__name__}")
except Exception as e:
    print(f"FAILED: {e}")
    import traceback
    traceback.print_exc()
