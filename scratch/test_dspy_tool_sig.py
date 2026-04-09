import inspect
import functools
import dspy

def my_tool(target: str, mode: str = "fast") -> str:
    """A sample tool."""
    return f"Result: {target} ({mode})"

def make_tool(func):
    # Original signature
    orig_sig = inspect.signature(func)
    
    # Create new parameters list: original params + **kwargs
    new_params = list(orig_sig.parameters.values())
    # Only add **kwargs if it's not already there
    if not any(p.kind == inspect.Parameter.VAR_KEYWORD for p in new_params):
        new_params.append(inspect.Parameter("kwargs", inspect.Parameter.VAR_KEYWORD))
    
    new_sig = orig_sig.replace(parameters=new_params)
    
    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        # Filter kwargs to only those in the original signature
        # unless the original function also accepted **kwargs
        has_orig_kwargs = any(
            p.kind == inspect.Parameter.VAR_KEYWORD 
            for p in orig_sig.parameters.values()
        )
        if not has_orig_kwargs:
            filtered_kwargs = {k: v for k, v in kwargs.items() if k in orig_sig.parameters}
        else:
            filtered_kwargs = kwargs
            
        print(f"Calling wrapped with filtered={filtered_kwargs}")
        return func(*args, **filtered_kwargs)
    
    # Overwrite the signature of the wrapped function
    wrapped.__signature__ = new_sig
    return dspy.Tool(wrapped)

print("Testing dspy.Tool signature inspection with functools.wraps:")
tool = make_tool(my_tool)

# Inspect signature
sig = inspect.signature(tool.func)
print(f"Signature of tool.func: {sig}")

# Try to call it like DSPy would
try:
    # Simulating what dspy might do internally
    print("Calling tool with target='localhost' and mode='slow'...")
    res = tool(target="localhost", mode="slow")
    print(f"Success: {res}")
except Exception as e:
    print(f"Error: {e}")

try:
    print("Calling tool with target='localhost' and unknown_arg='value'...")
    res = tool(target="localhost", unknown_arg="value")
    print(f"Success: {res}")
except Exception as e:
    print(f"Error: {e}")
