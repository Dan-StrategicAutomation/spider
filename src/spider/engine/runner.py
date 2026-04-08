"""GraphRunner -- wave-based parallel execution of a DSPy pentest topology.

Executes nodes in topological waves. Nodes in the same wave run in parallel
via dspy.asyncify + asyncio.gather. Fails fast if a wave has an error.
"""

import asyncio
import sys
from typing import Any

import dspy

from spider.schemas import GraphTopology


class GraphRunner(dspy.Module):
    """Executes a validated GraphTopology in parallel waves."""

    def __init__(
        self,
        topology: GraphTopology,
        node_modules: dict[str, dspy.Module],
        goal: str = "",
        **kwargs,
    ):
        super().__init__()
        self.topology = topology
        self.node_modules = node_modules
        self.goal = goal
        self.progress_fn = kwargs.pop("progress_fn", lambda _s, _d="": None)
        # Store initial inputs (target, etc.) for root nodes
        self._initial_inputs = {k: v for k, v in kwargs.items() if k != "progress_fn"}

    def _get_signature_fields(self, module: dspy.Module) -> tuple[list[str], list[str]]:
        """Extract InputField and OutputField names from a DSPy module's signature."""
        inner = None

        # Try common wrapper attributes
        for attr in ["predictor", "agent", "Judge", "module"]:
            val = getattr(module, attr, None)
            if val is not None:
                inner = val
                break
        
        if inner is None:
            inner = module

        sig = getattr(inner, "signature", None)
        if sig is None:
            # Maybe the module ITSELF is a Predictor/Signature holder
            sig = getattr(module, "signature", None)

        if sig:
            # Robust field extraction for DSPy 3.x
            # 1. Try input_fields/output_fields as dicts or callables
            inp_data = getattr(sig, "input_fields", {})
            out_data = getattr(sig, "output_fields", {})
            
            if callable(inp_data):
                inp_data = inp_data()
            if callable(out_data):
                out_data = out_data()

            def get_names(data):
                if isinstance(data, dict):
                    return list(data.keys())
                if isinstance(data, list | tuple):
                    names = []
                    for f in data:
                        if hasattr(f, "name"):
                            names.append(f.name)
                        elif isinstance(f, str):
                            names.append(f)
                    return names
                return []

            in_names = get_names(inp_data)
            out_names = get_names(out_data)

            if in_names or out_names:
                return in_names, out_names

        # Fallback: inspection of attributes if signature extraction failed
        # This is a last resort and should be rare with modern DSPy
        return [], []


    def _get_module_inputs(self, node_id: str, all_results: dict[str, Any]) -> dict[str, Any]:
        """Build input dict from signature's InputField definitions.
        
        Uses naming-based mapping first. If names don't match, falls back to 
        positional mapping based on the NodeDef.inputs list.
        """
        module = self.node_modules[node_id]
        input_fields, _ = self._get_signature_fields(module)
        node_def = next(n for n in self.topology.nodes if n.id == node_id)

        inputs = {}
        
        # Try direct naming match first
        for field in input_fields:
            if field in all_results:
                inputs[field] = all_results[field]

        # If we didn't fill all fields, try positional mapping from topology.inputs
        if len(inputs) < len(input_fields) and len(node_def.inputs) == len(input_fields):
            for i, field in enumerate(input_fields):
                topo_input_name = node_def.inputs[i]
                if topo_input_name in all_results:
                    inputs[field] = all_results[topo_input_name]

        return inputs

    async def forward_async(self, **kwargs) -> dspy.Prediction:
        waves = self.topology.topological_waves()
        # Merge initial inputs (target, etc.) with any additional kwargs
        all_results: dict[str, Any] = {**self._initial_inputs, **kwargs}

        for wave in waves:
            self.progress_fn("wave", f"Executing wave: {', '.join(wave)}")

            async def run_one(nid: str):
                self.progress_fn("node_running", f"  LLM running: {nid}")
                module = self.node_modules[nid]
                inputs = self._get_module_inputs(nid, all_results)
                
                try:
                    async def do_call():
                        ac = dspy.asyncify(module)
                        return await ac(**inputs)

                    result = await do_call()
                    all_results[nid] = result
                    node_def = next(n for n in self.topology.nodes if n.id == nid)
                    
                    # Robust output extraction
                    out_val = None
                    if isinstance(result, dict):
                        out_val = result.get(node_def.output)
                    else:
                        out_val = getattr(result, node_def.output, None)
                    
                    # Fallback to first output field if named lookup failed
                    if out_val is None:
                        _, output_fields = self._get_signature_fields(module)
                        if output_fields:
                            first_field = output_fields[0]
                            if isinstance(result, dict):
                                out_val = result.get(first_field)
                            else:
                                out_val = getattr(result, first_field, None)

                    if out_val is not None:
                        # Store in all_results using the topology's expected name.
                        all_results[node_def.output] = out_val
                    
                    self.progress_fn("node_done", f"  {nid} complete -> {node_def.output}")
                    return nid, None
                except Exception as e:
                    import traceback
                    self.progress_fn("node_failed", f"  {nid} FAILED: {e}")
                    print(f"[TRACEBACK] {traceback.format_exc()}", file=sys.stderr)
                    return nid, e

            outcomes = await asyncio.gather(*(run_one(nid) for nid in wave))
            if any(err for _, err in outcomes):
                failures = [f"{nid}: {err}" for nid, err in outcomes if err]
                return dspy.Prediction(
                    results=all_results,
                    error=f"Wave failed: {'; '.join(failures)}",
                    completed_waves=0,
                )

        return dspy.Prediction(results=all_results, completed=True)

    def forward(self, **kwargs):
        return asyncio.run(self.forward_async(**kwargs))
