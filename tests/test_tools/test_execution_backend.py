"""Unit tests for external command execution backend wiring."""

import json
from collections.abc import Sequence

from spider.tools.adapter import make_tool, make_tool_from_cmd
from spider.tools.execution import ToolExecutionResult


class RecordingBackend:
    """Tool execution backend double that records commands."""

    def __init__(self, result: ToolExecutionResult | None = None) -> None:
        self.result = result or ToolExecutionResult(exit_code=0, stdout="ok", stderr="")
        self.calls: list[tuple[list[str], int]] = []

    def execute(
        self,
        command: Sequence[str],
        *,
        timeout: int = 300,
        workdir: str | None = None,
    ) -> ToolExecutionResult:
        self.calls.append((list(command), timeout))
        return self.result


def test_make_tool_injects_execution_backend_into_backend_aware_tool() -> None:
    backend = RecordingBackend()

    def backend_tool(target: str, backend=None) -> str:
        result = backend.execute(["echo", target], timeout=17)
        return json.dumps({"success": result.exit_code == 0, "output": result.stdout})

    tool = make_tool(backend_tool, execution_backend=backend)
    result = json.loads(tool(target="example.com"))

    assert result == {"success": True, "output": "ok"}
    assert backend.calls == [(["echo", "example.com"], 17)]


def test_make_tool_from_cmd_uses_execution_backend_only() -> None:
    backend = RecordingBackend(ToolExecutionResult(exit_code=3, stdout="", stderr="bad"))

    tool = make_tool_from_cmd(
        "demo_cmd",
        ["demo", "{target}"],
        "Run demo command.",
        execution_backend=backend,
    )
    result = json.loads(tool(target="example.com"))

    assert result == {"success": False, "stdout": "", "stderr": "bad", "exit_code": 3}
    assert backend.calls == [(["demo", "example.com"], 300)]
