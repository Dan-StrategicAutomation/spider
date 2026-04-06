"""Spider TUI -- Interactive Textual-based dashboard."""

from spider.tui.attack_graph import AttackGraphScreen
from spider.tui.dashboard import DashboardScreen
from spider.tui.findings import FindingsScreen
from spider.tui.hitl_dialog import HITLDialog
from spider.tui.report_view import ReportScreen
from spider.tui.widgets import SpiderApp

__all__ = [
    "SpiderApp",
    "DashboardScreen",
    "FindingsScreen",
    "AttackGraphScreen",
    "HITLDialog",
    "ReportScreen",
]
