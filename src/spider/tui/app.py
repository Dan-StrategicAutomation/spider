"""Main Textual application for Spider TUI."""

from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header

from spider.tui.attack_graph import AttackGraphScreen
from spider.tui.dashboard import DashboardScreen
from spider.tui.findings import FindingsScreen
from spider.tui.hitl_dialog import HITLDialog
from spider.tui.report_view import ReportScreen

if TYPE_CHECKING:
    pass


class SpiderApp(App):
    """Main Spider TUI application.

    Provides dashboard, findings, attack graph visualization,
    HITL approval dialogs, and report viewing.
    """

    CSS = """
    Screen {
        background: $surface;
    }

    Header {
        dock: top;
        background: $surface-high;
        color: $text;
    }

    Footer {
        dock: bottom;
        background: $surface-high;
    }

    #status-bar {
        dock: bottom;
        height: 1;
        background: $panel;
        color: $primary;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("d", "push_screen('dashboard')", "Dashboard", show=True),
        Binding("f", "push_screen('findings')", "Findings", show=True),
        Binding("g", "push_screen('attack_graph')", "Attack Graph", show=True),
        Binding("r", "push_screen('report')", "Report", show=True),
        Binding("s", "toggle_dark", "Theme", show=True),
    ]

    def __init__(
        self,
        session_store=None,  # type: SessionStore | None
        orchestrator=None,
        dark=True,
    ):
        super().__init__()
        self.session_store = session_store
        self.orchestrator = orchestrator
        self._dark = dark

    def on_mount(self):
        """Initialize theme and push dashboard."""
        self.title = "SPIDER"
        self.sub_title = "DSPy Native Pentesting Framework"
        self.install_screen(DashboardScreen, name="dashboard")
        self.install_screen(FindingsScreen, name="findings")
        self.install_screen(AttackGraphScreen, name="attack_graph")
        self.install_screen(ReportScreen, name="report")
        self.push_screen("dashboard")

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()

    def action_toggle_dark(self):
        """Toggle dark/light theme."""
        self._dark = not self._dark
        if self._dark:
            self.theme = "textual-dark"
        else:
            self.theme = "textual-light"

    def show_hitl_dialog(
        self,
        cve_id="",
        target="",
        action="",
        risk="medium",
        callback=None,
    ):
        """Push the HITL approval modal."""
        dialog = HITLDialog(
            cve_id=cve_id,
            target=target,
            action=action,
            risk=risk,
            callback=callback,
        )
        self.push_screen(dialog, callback)
