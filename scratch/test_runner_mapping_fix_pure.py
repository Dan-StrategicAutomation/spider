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
        # Use a dummy predictor that doesn't need an LM
    
    def forward(self, recon_results: str, service_details: str):
        return dspy.Prediction(output=f"Processed: {recon_results} and {service_details}")

class DummyPredictor(dspy.Module):
    def __init__(self, signature):
        super().__init__()
        self.signature = dspy.Signature(signature)
        # Extract output field name
        self.out_name = list(self.signature.output_fields.keys())[0]

    def forward(self, **kwargs):
        # Just echo the first input
        val = list(kwargs.values())[0]
        return dspy.Prediction(**{self.out_name: f"Echo: {val}"})

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
        "node1": DummyPredictor("initial -> data1"),
        "node2": DummyPredictor("initial -> data2"),
        "target_node": TargetModule()
    }

    runner = GraphRunner(topology=topo, node_modules=node_modules, initial="seed")
    
    import asyncio
    
    async def run():
        res = await runner.forward_async(initial="seed_value")
        print("\nResults keys in all_results:")
        for k in res.results.keys():
            print(f"  - {k}: {res.results[k]}")
        
        if "final_output" in res.results:
            print(f"\nSUCCESS! final_output: {res.results['final_output']}")
            expected = "Processed: Echo: seed_value and Echo: seed_value"
            if res.results['final_output'] == expected:
                print("Mapping Verified!")
            else:
                print(f"Mismatch: Expected '{expected}'")
        else:
            print("\nFAILED: final_output missing")

    try:
        asyncio.run(run())
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\nCRASHED: {e}")

if __name__ == "__main__":
    test_positional_mapping()
