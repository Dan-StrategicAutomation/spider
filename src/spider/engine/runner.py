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

        if hasattr(module, "predictor") and module.predictor:
            inner = module.predictor
        elif hasattr(module, "agent") and module.agent:
            # Handle dspy.Refine which wraps the module in .module attribute
            agent = module.agent
            inner = agent.module if hasattr(agent, "module") else agent
        elif hasattr(module, "Judge") and module.Judge:
            inner = module.Judge

        if inner and hasattr(inner, "signature"):
            sig = inner.signature

            # Robust field extraction for DSPy 3.x
            inp = getattr(sig, "input_fields", {})
            if callable(inp):
                inp = inp()

            out = getattr(sig, "output_fields", {})
            if callable(out):
                out = out()

            # Handle dict-based (name: Field) or list-based field storage
            if isinstance(inp, dict):
                in_names = list(inp.keys())
            else:
                in_names = [getattr(f, "name", str(f)) for f in (inp or [])]

            if isinstance(out, dict):
                out_names = list(out.keys())
            else:
                out_names = [getattr(f, "name", str(f)) for f in (out or [])]

            if in_names or out_names:
                return in_names, out_names

        # Fallback for simple signatures or custom attributes
        for attr_name in dir(module.__class__):
            if attr_name.startswith("_"):
                continue
            attr = getattr(module.__class__, attr_name, None)
            if attr is not None and hasattr(attr, "name"):
                inp_f = getattr(attr, "name", None)
                if inp_f:
                    return [inp_f], []

        return [], []


    def _get_module_inputs(self, node_id: str, all_results: dict[str, Any]) -> dict[str, Any]:
        """Build input dict from signature's InputField definitions."""
        module = self.node_modules[node_id]
        input_fields, _ = self._get_signature_fields(module)

        inputs = {}
        for field in input_fields:
            if field in all_results:
                inputs[field] = all_results[field]

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
                    out_val = (
                        result.get(node_def.output)
                        if isinstance(result, dict)
                        else getattr(result, node_def.output, None)
                    )
                    if out_val is not None:
                        all_results[node_def.output] = str(out_val)
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
