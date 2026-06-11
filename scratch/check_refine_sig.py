import dspy
from pydantic import BaseModel

class MyResult(BaseModel):
    data: str = ""

class MySig(dspy.Signature):
    input_text: str = dspy.InputField()
    output_result: MyResult = dspy.OutputField()

def my_reward(args, pred):
    return 1.0

cot = dspy.ChainOfThought(MySig)
refine = dspy.Refine(cot, N=3, threshold=0.8, reward_fn=my_reward)

print(f"Refine sig: {getattr(refine, 'signature', 'No signature')}")
if hasattr(refine, "signature"):
    sig = refine.signature
    print(f"Input fields: {list(sig.input_fields.keys())}")
    print(f"Output fields: {list(sig.output_fields.keys())}")
