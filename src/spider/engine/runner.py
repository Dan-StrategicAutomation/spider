"""GraphRunner -- wave-based parallel execution of a DSPy pentest topology.

Executes nodes in topological waves. Nodes in the same wave run in parallel
via dspy.asyncify + asyncio.gather. Fails fast if a wave has an error.
"""

import asyncio
import sys
from typing import Any

import dspy
from pydantic import BaseModel

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

    def _get_signature_fields(self, module: dspy.Module) -> tuple[dict[str, Any], list[str]]:
        """Extract InputField and OutputField info from a DSPy module's signature.

        Recursively searches through wrappers (Refine, ReAct, CoT) to find the
        underlying signature definitions. Returns a mapping of input field names
         to their FieldInfo/annotations and a list of output field names.
        """

        def search_sig(mod):
            # 1. Direct attribute
            sig = getattr(mod, "signature", None)
            if sig:
                return sig

            # 2. Search common wrapper attributes
            for attr in ["predictor", "agent", "Judge", "module"]:
                val = getattr(mod, attr, None)
                if val:
                    found = search_sig(val)
                    if found:
                        return found

            # 3. Search named predictors fallback
            if hasattr(mod, "named_predictors"):
                try:
                    for _, m in mod.named_predictors():
                        found = search_sig(m)
                        if found:
                            return found
                except Exception:
                    pass
            return None

        sig = search_sig(module)

        if sig:
            # Robust field extraction for DSPy 3.1+ (Pydantic v2 based)
            inp_fields = getattr(sig, "input_fields", {})
            out_fields = getattr(sig, "output_fields", {})

            if callable(inp_fields):
                inp_fields = inp_fields()
            if callable(out_fields):
                out_fields = out_fields()

            # Ensure we have a dict of field names to FieldInfo/Objects
            if not isinstance(inp_fields, dict):
                # Fallback for older DSPy or unexpected structures
                inp_fields = {getattr(f, "name", str(f)): f for f in inp_fields}

            # Filter out internal DSPy fields that leak through wrappers (e.g. from dspy.ReAct)
            if "trajectory" in inp_fields:
                del inp_fields["trajectory"]

            out_names = []
            if isinstance(out_fields, dict):
                out_names = list(out_fields.keys())
            else:
                for f in out_fields:
                    out_names.append(getattr(f, "name", str(f)))

            return inp_fields, out_names

        return {}, []

    def _get_module_inputs(self, node_id: str, all_results: dict[str, Any]) -> dict[str, Any]:
        """Build input dict from signature's InputField definitions.

        Uses naming-based mapping first. If names don't match, falls back to
        positional mapping based on the NodeDef.inputs list.
        If a field is still missing, provides a default value based on type annotation.
        """
        module = self.node_modules[node_id]
        input_fields, _ = self._get_signature_fields(module)
        node_def = next(n for n in self.topology.nodes if n.id == node_id)

        inputs = {}

        # 1. Populate from results (direct name match or positional)
        for i, field_name in enumerate(input_fields.keys()):
            if field_name in all_results:
                inputs[field_name] = all_results[field_name]
            elif i < len(node_def.inputs):
                topo_input_name = node_def.inputs[i]
                if topo_input_name in all_results:
                    inputs[field_name] = all_results[topo_input_name]

        # 2. Safety: Provide defaults for missing required inputs
        for field_name, field_info in input_fields.items():
            if field_name not in inputs:
                # CHECK: Is this input expected from a node that hasn't run yet?
                upstream_nodes = [
                    n.id
                    for n in self.topology.nodes
                    if n.output == field_name or n.id == field_name
                ]
                pending = [uid for uid in upstream_nodes if uid not in all_results]

                warning_suffix = ""
                if pending:
                    warning_suffix = f" (Waiting for: {', '.join(pending)})"
                elif field_name not in ["target"]:  # 'target' is a root input
                    warning_suffix = " (No producer found in topology)"

                # Try to generate a default based on annotation
                annotation = getattr(field_info, "annotation", None)
                default_val = None

                if annotation:
                    try:
                        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
                            default_val = annotation()
                        elif annotation is str:
                            default_val = ""
                        elif annotation is int:
                            default_val = 0
                        elif annotation is list:
                            default_val = []
                        elif annotation is dict:
                            default_val = {}
                    except Exception:
                        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
                            default_val = annotation.model_construct()
                        else:
                            default_val = None

                if default_val is not None:
                    ann_name = (
                        annotation.__name__ if hasattr(annotation, "__name__") else str(annotation)
                    )
                    msg = (
                        f"  [!] Node {node_id} missing {field_name}, "
                        f"providing empty {ann_name}{warning_suffix}"
                    )
                    self.progress_fn("input_fallback", msg)
                    inputs[field_name] = default_val

        # 3. Filter inputs to only include keys that are in the signature
        # This prevents "unexpected keyword argument" errors when modules
        # have explicit parameter lists instead of **kwargs
        valid_input_names = set(input_fields.keys())
        filtered_inputs = {k: v for k, v in inputs.items() if k in valid_input_names}

        # 4. Filter against the actual 'forward' method signature to catch any
        # lingering artifacts from nested signature extraction (e.g., DSPy internals).
        import inspect
        try:
            # We inspect the unbound class method to avoid triggering DSPy's
            # instance-level __getattribute__ warnings for direct forward() access
            sig = inspect.signature(module.__class__.forward)
            has_kwargs = any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
            )
            if not has_kwargs:
                valid_forward_params = set(sig.parameters.keys())
                filtered_inputs = {
                    k: v for k, v in filtered_inputs.items() if k in valid_forward_params
                }
        except Exception:
            pass

        return filtered_inputs

    async def forward_async(self, **kwargs) -> dspy.Prediction:
        waves = self.topology.topological_waves()
        # Merge initial inputs (target, etc.) with any additional kwargs
        all_results: dict[str, Any] = {**self._initial_inputs, **kwargs}

        for wave in waves:
            # Map IDs to human names for cleaner logging
            wave_names = [
                next((n.name for n in self.topology.nodes if n.id == nid), nid) for nid in wave
            ]
            self.progress_fn("wave", f"Executing wave: {', '.join(wave_names)}")

            async def run_one(nid: str):
                node_def = next(n for n in self.topology.nodes if n.id == nid)
                self.progress_fn("node_running", f"  LLM running: {node_def.name}")
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
