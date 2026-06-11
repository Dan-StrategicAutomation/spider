"""Tests for TUI findings navigation."""

from types import SimpleNamespace

from spider.tui.findings import FindingsScreen


def test_findings_keyboard_actions_move_selection_within_bounds() -> None:
    """Arrow actions should navigate findings without wrapping unexpectedly."""
    screen = FindingsScreen()
    screen.update_session(
        SimpleNamespace(
            findings=[{"cve_id": f"CVE-2026-000{idx}", "severity": "medium"} for idx in range(3)]
        )
    )

    screen.action_select_next()
    screen.action_select_next()
    screen.action_select_next()
    assert screen._selected_index == 2
    assert "↑/↓ to select" in str(screen._render_findings_list().title)

    screen.action_select_previous()
    screen.action_select_previous()
    screen.action_select_previous()
    assert screen._selected_index == 0
