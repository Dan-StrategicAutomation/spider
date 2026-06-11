"""DSPy engine: weaver, runner, self-evaluation, orchestrator."""

from spider.engine.mode_filter import filter_topology_for_mode
from spider.engine.node_factory import build_node_modules
from spider.engine.orchestrator import SpiderOrchestrator
from spider.engine.tool_registry import build_tool_catalog, build_tools

__all__ = [
    "SpiderOrchestrator",
    "build_node_modules",
    "build_tool_catalog",
    "build_tools",
    "filter_topology_for_mode",
]
