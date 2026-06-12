"""GraphRunner -- wave-based parallel execution of a DSPy pentest topology.

Executes nodes in topological waves. Nodes in the same wave run in parallel
via dspy.asyncify + asyncio.gather. Fails fast if a wave has an error.
"""

import asyncio
import sys
from typing import Any

import dspy

from spider.schemas import ExecutionConstraints, GraphTopology, PentestGoal, ScanMode, TargetSpec


class GraphRunner(dspy.Module):
    """Executes a validated GraphTopology in parallel waves."""

    def __init__(
        self,
        topology: GraphTopology,
        node_modules: dict[str, dspy.Module],
        goal: str | PentestGoal = "",
        **kwargs,
    ):
        super().__init__()
        self.topology = topology
        self.node_modules = node_modules
        self.goal = self._normalize_goal(goal)
        self.progress_fn = kwargs.pop("progress_fn", lambda _s, _d="": None)

        # Precompute O(1) lookups to avoid O(n) or O(n^2) sweeps in hot paths
        self._node_by_id = {n.id: n for n in self.topology.nodes}
        self._producer_by_output = {n.output: n.id for n in self.topology.nodes}
        self._runtime_inputs_set = frozenset(self.topology.runtime_inputs)

        # Store normalized initial inputs (target_spec, constraints, etc.) for root nodes.
        self._initial_inputs = self._normalize_runtime_inputs(kwargs)

    @staticmethod
    def _normalize_goal(goal: str | PentestGoal) -> PentestGoal:
        """Convert legacy goal text into the shared PentestGoal model."""
        if isinstance(goal, PentestGoal):
            return goal
        if goal:
            return PentestGoal.from_text(goal)
        return PentestGoal(objective="Execute pentest topology")

    def _normalize_runtime_inputs(self, inputs: dict[str, Any]) -> dict[str, Any]:
        """Normalize runtime control inputs to shared Pydantic models."""
        normalized = dict(inputs)
        normalized["goal"] = self.goal

        if "target_spec" in normalized:
            target_spec = normalized["target_spec"]
            if isinstance(target_spec, str):
                target_spec = TargetSpec.from_raw(target_spec)
        elif "target" in normalized:
            target_value = normalized["target"]
            if isinstance(target_value, TargetSpec):
                target_spec = target_value
            else:
                target_spec = TargetSpec.from_raw(str(target_value))
        else:
            target_spec = None

        if target_spec is not None:
            normalized["target_spec"] = target_spec
            if "target" in normalized:
                normalized["target"] = target_spec

        if "constraints" in normalized:
            constraints = normalized["constraints"]
            if isinstance(constraints, str):
                normalized["constraints"] = ExecutionConstraints.from_text(constraints)
        elif "constraints_text" in normalized:
            constraints_text = normalized["constraints_text"]
            if isinstance(constraints_text, ExecutionConstraints):
                constraints = constraints_text
            else:
                constraints = ExecutionConstraints.from_text(str(constraints_text))
            normalized["constraints"] = constraints
            normalized["constraints_text"] = constraints
        elif "mode" in normalized:
            mode = normalized["mode"]
            scan_mode = ScanMode(mode) if isinstance(mode, str) else mode
            normalized["constraints"] = ExecutionConstraints(scan_mode=scan_mode)

        return normalized

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
        """Build input dict from required signature InputField definitions.

        Inputs may come only from explicitly declared runtime inputs or from
        upstream node outputs already present in the accumulated results.
        Missing required fields fail clearly instead of synthesizing empty
        placeholder models.
        """
        module = self.node_modules[node_id]
        input_fields, _ = self._get_signature_fields(module)
        node_def = self._node_by_id[node_id]

        inputs = {}

        def is_available_source(source_name: str) -> bool:
            if source_name not in all_results:
                return False
            if source_name in self._runtime_inputs_set:
                return True
            producer_id = self._producer_by_output.get(source_name)
            return producer_id is not None and producer_id in all_results

        # 1. Populate from explicit runtime inputs or completed upstream outputs.
        for i, field_name in enumerate(input_fields.keys()):
            if is_available_source(field_name):
                inputs[field_name] = all_results[field_name]
            elif i < len(node_def.inputs):
                topo_input_name = node_def.inputs[i]
                if is_available_source(topo_input_name):
                    inputs[field_name] = all_results[topo_input_name]

        # 2. Fail clearly for missing required inputs.
        for field_name in input_fields:
            if field_name not in inputs:
                raise ValueError(
                    f"Node '{node_id}' missing required signature input '{field_name}'. "
                    f"Cannot source it from runtime inputs or upstream node outputs. "
                    f"Declared topology inputs for node '{node_id}': {node_def.inputs}. "
                    f"Declared runtime inputs: {self.topology.runtime_inputs}."
                )

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
        all_results: dict[str, Any] = {
            **self._initial_inputs,
            **self._normalize_runtime_inputs(kwargs),
        }

        for wave in waves:
            # Map IDs to human names for cleaner logging
            wave_names = [
                self._node_by_id[nid].name if nid in self._node_by_id else nid for nid in wave
            ]
            self.progress_fn("wave", f"Executing wave: {', '.join(wave_names)}")

            async def run_one(nid: str):
                node_def = self._node_by_id[nid]
                self.progress_fn("node_running", f"  LLM running: {node_def.name}")
                module = self.node_modules[nid]

                try:
                    inputs = self._get_module_inputs(nid, all_results)

                    async def do_call():
                        ac = dspy.asyncify(module)
                        return await ac(**inputs)

                    result = await do_call()
                    all_results[nid] = result

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
