"""Tests for the SPIDER CLI entry point."""

import sys

from spider import cli
from spider.schemas import ScanMode


class FakeSessionDB:
    """Minimal session store for non-interactive CLI tests."""

    def __init__(self):
        self.saved_results = []

    def find_by_target(self, target: str) -> list[dict]:
        return []

    def create_session(self, target: str) -> int:
        return 1

    def save_results(self, session_id: int, result: dict) -> None:
        self.saved_results.append((session_id, result))

    def update_status(self, session_id: int, status: str) -> None:
        raise AssertionError(f"Unexpected status update: {session_id=} {status=}")


class FakeOrchestrator:
    """Capture orchestrator.run calls without invoking DSPy."""

    def __init__(self):
        self.run_calls = []

    def run(
        self,
        *,
        goal: str,
        target: str,
        mode: ScanMode,
        topology_name: str | None = None,
    ) -> dict:
        run_call = {"goal": goal, "target": target, "mode": mode}
        if topology_name is not None:
            run_call["topology_name"] = topology_name
        self.run_calls.append(run_call)
        return {"ok": True}


def test_main_custom_mode_passes_goal_to_orchestrator(monkeypatch):
    """--mode custom --goal should reach orchestrator.run unchanged."""
    session_db = FakeSessionDB()
    orchestrator = FakeOrchestrator()
    goal = "Enumerate only SSH and web admin panels"
    target = "127.0.0.1"

    monkeypatch.setattr(cli, "SessionDB", lambda: session_db)
    monkeypatch.setattr(cli, "banner", lambda: None)
    monkeypatch.setattr(cli, "init_spider", lambda: (object(), orchestrator))
    monkeypatch.setattr(
        sys, "argv", ["spider", "--scan", target, "--mode", "custom", "--goal", goal]
    )

    cli.main()

    assert orchestrator.run_calls == [{"goal": goal, "target": target, "mode": ScanMode.CUSTOM}]


def test_main_passes_selected_topology_to_orchestrator(monkeypatch):
    """--topology should let users select a built-in or saved topology."""
    session_db = FakeSessionDB()
    orchestrator = FakeOrchestrator()
    target = "127.0.0.1"

    monkeypatch.setattr(cli, "SessionDB", lambda: session_db)
    monkeypatch.setattr(cli, "banner", lambda: None)
    monkeypatch.setattr(cli, "init_spider", lambda: (object(), orchestrator))
    monkeypatch.setattr(
        sys,
        "argv",
        ["spider", "--scan", target, "--mode", "full", "--topology", "full"],
    )

    cli.main()

    expected_goal = cli._build_goal(ScanMode.FULL, target)
    assert orchestrator.run_calls == [
        {
            "goal": expected_goal,
            "target": target,
            "mode": ScanMode.FULL,
            "topology_name": "full",
        }
    ]
