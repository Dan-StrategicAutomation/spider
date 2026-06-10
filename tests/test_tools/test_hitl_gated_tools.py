"""Tests for HITL enforcement in tool adapter registrations."""

import json
from collections.abc import Callable

import pytest

from spider.sandbox.hitl_gate import HITLGate
from spider.tools import adapter
from spider.tools.adapter import make_tool

EXPLOIT_AND_POST_EXPLOIT_TOOLS = (
    ("spider.tools.exploitation", "sqlmap_run", {"target": "example.com"}),
    ("spider.tools.exploitation", "hydra_run", {"target": "example.com"}),
    (
        "spider.tools.exploitation",
        "metasploit_run",
        {"module": "exploit/test/module", "target": "example.com"},
    ),
    ("spider.tools.post_exploit_tools", "bloodhound_run", {"target": "example.com"}),
    ("spider.tools.post_exploit_tools", "crackmapexec_run", {"target": "example.com"}),
    ("spider.tools.post_exploit_tools", "responder_run", {"interface": "eth0"}),
)


def _blocked_impl(tool_name: str, executed: dict[str, bool]) -> Callable[..., str]:
    def implementation(**kwargs) -> str:
        executed["called"] = True
        return json.dumps({"success": True, "kwargs": kwargs})

    implementation.__name__ = tool_name
    implementation.__doc__ = f"Blocked test implementation for {tool_name}."
    return implementation


@pytest.mark.parametrize(
    ("module_name", "tool_name", "call_kwargs"),
    EXPLOIT_AND_POST_EXPLOIT_TOOLS,
)
def test_exploitation_registrations_deny_without_executing_in_noninteractive_hitl(
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
    tool_name: str,
    call_kwargs: dict[str, str],
) -> None:
    """Registered exploitation and post-exploitation tools deny by default in CI."""
    module = pytest.importorskip(module_name)
    executed = {"called": False}

    monkeypatch.setattr(adapter.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(module, tool_name, _blocked_impl(tool_name, executed))

    tools = module.register_all(hitl_gate=HITLGate(interactive=False))
    result = json.loads(tools[tool_name](**call_kwargs))

    assert result["error"].startswith("HITL_DENIED")
    assert result["tool"] == tool_name
    assert result["approved"] is False
    assert result["hitl_required"] is True
    assert executed["called"] is False


def test_hitl_required_tool_denies_without_gate_before_executing() -> None:
    """A HITL-required adapter wrapper fails closed when no gate is configured."""
    executed = {"called": False}

    def dangerous_impl(target: str) -> str:
        executed["called"] = True
        return json.dumps({"success": True, "target": target})

    tool = make_tool(dangerous_impl, hitl_required=True)
    result = json.loads(tool(target="example.com"))

    assert result["error"] == "HITL_DENIED: approval gate is not configured"
    assert result["tool"] == "dangerous_impl"
    assert result["target"] == "example.com"
    assert result["approved"] is False
    assert result["hitl_required"] is True
    assert executed["called"] is False
