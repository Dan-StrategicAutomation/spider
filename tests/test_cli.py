"""Tests for the SPIDER CLI entry point."""

import sys

from spider import cli
from spider.schemas import ScanMode


class FakeSessionDB:
    """Minimal session store for non-interactive CLI tests."""

    def __init__(self):
        self.saved_results = []

    def close(self):
        pass

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

    def run(self, *, goal: str, target: str, mode: ScanMode) -> dict:
        self.run_calls.append({"goal": goal, "target": target, "mode": mode})
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


def test_main_help_includes_scan_examples_and_safety_note(monkeypatch, capsys):
    """CLI help should show actionable scan examples and safety context."""
    monkeypatch.setattr(sys, "argv", ["spider", "--help"])

    try:
        cli.main()
    except SystemExit as exc:
        assert exc.code == 0

    output = capsys.readouterr().out
    assert "spider --scan 127.0.0.1 --mode recon" in output
    assert "--mode=custom" in output
    assert "Scan modes" in output
    assert "SPIDER_ALLOWED_TARGETS" in output
    assert "SPIDER_EXCLUDED_TARGETS" in output
    assert "only scan systems you are authorized to test" in output
    assert "Full mode keeps exploitation behind human approval" in output


def test_parse_cli_args_supports_equals_style_options():
    """Manual parser should preserve argparse-compatible --option=value usage."""
    args = cli.parse_cli_args(
        [
            "--scan=127.0.0.1",
            "--mode=custom",
            "--goal=Enumerate SSH and web only",
        ]
    )

    assert args.scan == "127.0.0.1"
    assert args.mode == "custom"
    assert args.goal == "Enumerate SSH and web only"


def test_parse_cli_args_reports_missing_option_values(capsys):
    """Parser errors should remain actionable without loading the full app."""
    try:
        cli.parse_cli_args(["--scan"])
    except SystemExit as exc:
        assert exc.code == 2

    output = capsys.readouterr().out
    assert "ERROR --scan requires a value" in output
    assert "spider --help" in output
