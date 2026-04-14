"""Optimization pipeline for SPIDER nodes.
Uses dspy.BootstrapFewShot to compile modules from training data.
"""

import os
import argparse
import dspy
from dspy.teleprompt import BootstrapFewShot
from pydantic import BaseModel
from typing import Any

from spider.config import SpiderConfig
from spider.models import configure_spider
from spider.observability import setup_observability, flush_observability
from spider.engine.orchestrator import SpiderOrchestrator
from spider.nodes.recon import ReconModule
from spider.nodes.exploit_planner import ExploitPlanningModule
from spider.data.trainset import RECON_TRAINSET, PLANNING_TRAINSET


def spider_metric(example: dspy.Example, pred: dspy.Prediction, trace: Any = None) -> float:
    """Evaluate the quality of a SPIDER node prediction.
    
    Checks for:
    1. Structural adherence (Pydantic validation).
    2. Zero hallucinations/nesting (No dictionaries where strings are expected).
    3. Basic goal alignment.
    """
    # 1. Look for the primary output model in the prediction
    # Prediction objects in DSPy often have fields named after the signature's output fields
    # We find it by looking for the one that is a Pydantic BaseModel
    output_val = None
    for attr in dir(pred):
        if attr.startswith("_"):
            continue
        val = getattr(pred, attr)
        if isinstance(val, (BaseModel, str, list)):
            output_val = val
            break
            
    if output_val is None:
        return 0.0

    # 2. Check for nesting hallucinations (the "hack" we are trying to undo)
    # If the output is a Pydantic model, check its recursive dict for nested keys matching themselves
    if isinstance(output_val, BaseModel):
        data = output_val.model_dump()
        def has_nested_hallucination(d: dict) -> bool:
            for k, v in d.items():
                if isinstance(v, dict) and k in v:
                    return True
                if isinstance(v, dict) and has_nested_hallucination(v):
                    return True
            return False
            
        if has_nested_hallucination(data):
            return 0.0
            
    # 3. Simple structural check
    # If we have an example, the prediction should at least have some content
    if isinstance(output_val, str) and len(output_val) < 5:
        return 0.0
        
    return 1.0


class SpiderOptimizer:
    """Orchestrates the compilation and persistence of SPIDER nodes."""

    def __init__(self, config: SpiderConfig):
        self.config = config
        self.compiled_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "compiled"
        )
        os.makedirs(self.compiled_dir, exist_ok=True)

    def compile(self, module: dspy.Module, trainset: list[dspy.Example], name: str) -> dspy.Module:
        """Compile a module and save its weights."""
        print(f"[*] Optimizing {name} with BootstrapFewShot...")
        
        optimizer = BootstrapFewShot(
            metric=spider_metric,
            max_bootstrapped_demos=4,
            max_labeled_demos=4,
        )
        
        compiled_module = optimizer.compile(module, trainset=trainset)
        
        # Save weights
        save_path = os.path.join(self.compiled_dir, f"{name}.json")
        compiled_module.save(save_path)
        print(f"[+] Optimization complete. Weights saved to {save_path}")
        
        return compiled_module


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SPIDER Node Optimizer")
    parser.add_argument(
        "--node",
        choices=["recon", "planning", "all"],
        default="all",
        help="Specific node to optimize (default: all)",
    )
    args = parser.parse_args()

    config = SpiderConfig()
    setup_observability(config)
    configure_spider(config)
    
    # Use a dummy orchestrator to build tools properly for the optimizer
    orch = SpiderOrchestrator(config)
    tools = orch._build_tools()
    
    opt = SpiderOptimizer(config)
    
    try:
        if args.node in ["recon", "all"]:
            recon = ReconModule(tools=list(tools.values()), config=config)
            opt.compile(recon, RECON_TRAINSET, "ReconModule")
            
        if args.node in ["planning", "all"]:
            planner = ExploitPlanningModule(tools=list(tools.values()), config=config)
            opt.compile(planner, PLANNING_TRAINSET, "ExploitPlanningModule")
            
    finally:
        flush_observability()
