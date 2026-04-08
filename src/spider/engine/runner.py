"""GraphRunner -- wave-based parallel execution of a DSPy pentest topology.

Executes nodes in topological waves. Nodes in the same wave run in parallel
via dspy.asyncify + asyncio.gather. Fails fast if a wave has an error.
"""

import asyncio
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

    def _wave_inputs(self, node_id: str, all_results: dict[str, Any]) -> dict[str, Any]:
        """Build input dict for a node from upstream results."""
        node_def = next(n for n in self.topology.nodes if n.id == node_id)
        return {inp: str(all_results.get(inp, "")) for inp in node_def.inputs}

    async def forward_async(self, **kwargs) -> dspy.Prediction:
        waves = self.topology.topological_waves()
        all_results: dict[str, Any] = {**kwargs}

        for wave in waves:

            async def run_one(nid: str):
                module = self.node_modules[nid]
                inputs = self._wave_inputs(nid, all_results)
                try:
                    result = await dspy.asyncify(module)(**inputs)
                    all_results[nid] = result
                    node_def = next(n for n in self.topology.nodes if n.id == nid)
                    out_val = (
                        result.get(node_def.output)
                        if isinstance(result, dict)
                        else getattr(result, node_def.output, None)
                    )
                    if out_val is not None:
                        all_results[node_def.output] = str(out_val)
                    return nid, None
                except Exception as e:
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
