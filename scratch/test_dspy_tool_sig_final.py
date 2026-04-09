import inspect
import dspy
from spider.tools.adapter import make_tool

def sample_tool(target: str, mode: str = "fast", **kwargs) -> str:
    """A sample tool for testing resiliency."""
    return f"Result: {target} ({mode})"

print("Testing Spider's make_tool resilient signature:")
tool = make_tool(sample_tool)

# Inspect signature
sig = inspect.signature(tool.func)
print(f"Signature of tool.func: {sig}")

# Verify that it allows extra arguments without crashing dspy.Tool
try:
    print("Calling tool with hallucinated 'unknown_arg'...")
    # dspy.Tool.__call__ will check args against signature
    res = tool(target="localhost", unknown_arg="hallucination")
    print(f"Success! Result: {res}")
except Exception as e:
    print(f"Failed: {e}")

# Verify filtering
def check_filtering(target: str, **kwargs):
    """Tool that expects ONLY target."""
    return f"OK: {target}"

tool_filtered = make_tool(check_filtering)
try:
    print("\nCalling tool_filtered with 'target' and 'extra'...")
    res = tool_filtered(target="127.0.0.1", extra="ignore_me")
    print(f"Success! Result: {res}")
except Exception as e:
    print(f"Failed: {e}")
