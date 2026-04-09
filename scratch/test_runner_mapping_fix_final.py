import dspy
from spider.schemas import GraphTopology, NodeDef, NodeRole, EdgeDef
from spider.engine.runner import GraphRunner

# 1. Properly defined signatures for the runner to parse
class Node1Sig(dspy.Signature):
    initial: str = dspy.InputField()
    data1: str = dspy.OutputField()

class Node2Sig(dspy.Signature):
    initial: str = dspy.InputField()
    data2: str = dspy.OutputField()

class TargetModuleSig(dspy.Signature):
    recon_results: str = dspy.InputField()
    service_details: str = dspy.InputField()
    final_output: str = dspy.OutputField()

class DummyNode(dspy.Module):
    def __init__(self, sig):
        super().__init__()
        self.predictor = dspy.Predict(sig) # Just for runner to find the signature
    
    def forward(self, **kwargs):
        # Positionally access the first value
        val = list(kwargs.values())[0]
        return dspy.Prediction(**{list(self.predictor.signature.output_fields.keys())[0]: f"Echo: {val}"})

class TargetModule(dspy.Module):
    def __init__(self):
        super().__init__()
        self.predictor = dspy.Predict(TargetModuleSig)
    
    def forward(self, recon_results: str, service_details: str):
        return dspy.Prediction(final_output=f"Processed: {recon_results} and {service_details}")

# 2. Define a woven topology with DIFFERENT output/input names
def test_positional_mapping():
    nodes = [
        NodeDef(
            id="node1",
            role=NodeRole.PREDICT,
            name="Node 1",
            description="...",
            inputs=["initial"],
            output="woven_data1" # Mismatch with 'data1'
        ),
        NodeDef(
            id="node2",
            role=NodeRole.PREDICT,
            name="Node 2",
            description="...",
            inputs=["initial"],
            output="woven_data2" # Mismatch with 'data2'
        ),
        NodeDef(
            id="target_node",
            role=NodeRole.PREDICT,
            name="Target",
            description="...",
            inputs=["woven_data1", "woven_data2"], # Maps to recon_results, service_details
            output="final_output"
        )
    ]
    edges = [
        EdgeDef(source="node1", target="target_node"),
        EdgeDef(source="node2", target="target_node")
    ]
    topo = GraphTopology(name="test", objective="test", nodes=nodes, edges=edges)

    node_modules = {
        "node1": DummyNode(Node1Sig),
        "node2": DummyNode(Node2Sig),
        "target_node": TargetModule()
    }

    runner = GraphRunner(topology=topo, node_modules=node_modules)
    
    import asyncio
    
    async def run():
        # Setup dspy dummy LM to satisfy predictors if any are called
        lm = dspy.LM("openai/gpt-4o-mini", api_key="sk-...") # Won't be used
        dspy.configure(lm=lm)

        res = await runner.forward_async(initial="seed_value")
        print("\nResults keys in all_results:")
        for k in res.results.keys():
            v = str(res.results[k])
            print(f"  - {k}: {v[:50]}")
        
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

if __name__ == "__main__":
    test_positional_mapping()
