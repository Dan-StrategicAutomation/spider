import dspy
from spider.schemas import GraphTopology, NodeDef, NodeRole, EdgeDef
from spider.engine.runner import GraphRunner

# 1. Define a dummy module with specific input field names
class TargetModuleSig(dspy.Signature):
    recon_results: str = dspy.InputField()
    service_details: str = dspy.InputField()
    output: str = dspy.OutputField()

class TargetModule(dspy.Module):
    def __init__(self):
        super().__init__()
        self.p = dspy.Predict(TargetModuleSig)
    
    def forward(self, recon_results: str, service_details: str):
        return dspy.Prediction(output=f"Processed: {recon_results} and {service_details}")

# 2. Define a woven topology with DIFFERENT output/input names
def test_positional_mapping():
    nodes = [
        NodeDef(
            id="node1",
            role=NodeRole.PREDICT,
            name="Node 1",
            description="...",
            inputs=["initial"],
            output="data1" # Not 'recon_results'
        ),
        NodeDef(
            id="node2",
            role=NodeRole.PREDICT,
            name="Node 2",
            description="...",
            inputs=["initial"],
            output="data2" # Not 'service_details'
        ),
        NodeDef(
            id="target_node",
            role=NodeRole.PREDICT,
            name="Target",
            description="...",
            inputs=["data1", "data2"], # Maps to recon_results, service_details
            output="final_output"
        )
    ]
    edges = [
        EdgeDef(source="node1", target="target_node"),
        EdgeDef(source="node2", target="target_node")
    ]
    topo = GraphTopology(name="test", objective="test", nodes=nodes, edges=edges)

    # 3. Setup Runner
    node_modules = {
        "node1": dspy.Predict("initial -> data1"),
        "node2": dspy.Predict("initial -> data2"),
        "target_node": TargetModule()
    }

    runner = GraphRunner(topology=topo, node_modules=node_modules, initial="seed")
    
    # We simulate the first wave's results manually for speed in this test
    # or just run it via forward_async
    import asyncio
    
    async def run():
        # Mocking dspy.asyncify for the simple predictions for simplicity
        # but let's just use the actual runner.
        res = await runner.forward_async(initial="seed_value")
        print("\nResults keys in all_results:")
        for k in res.results.keys():
            print(f"  - {k}")
        
        if "final_output" in res.results:
            print(f"\nSUCCESS! final_output: {res.results['final_output']}")
        else:
            print("\nFAILED: final_output missing")

    try:
        asyncio.run(run())
    except Exception as e:
        print(f"\nCRASHED: {e}")

if __name__ == "__main__":
    test_positional_mapping()
