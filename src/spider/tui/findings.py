"""Findings detail screen -- CVE deep-dive with exploit options."""

from typing import TYPE_CHECKING, Any

from rich.panel import Panel
from rich.table import Table
from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from spider.tui.theme import THEME

if TYPE_CHECKING:
    pass


SEVERITY_COLORS = {
    "CRITICAL": THEME.border_error,
    "HIGH": THEME.border_warning,
    "MEDIUM": THEME.border_primary,
    "LOW": THEME.border_success,
    "NONE": THEME.panel_border,
}


def style_for_severity(severity: str) -> str:
    """Return the theme border color for a severity level."""
    return SEVERITY_COLORS.get(severity.upper(), THEME.panel_border)


class FindingsScreen(Screen):
    """Detailed findings view with CVE info and exploit options."""

    BINDINGS = [
        ("escape", "app.push_screen('dashboard')", "Back"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._session = None  # type: ScanSession | None
        self._selected_index = 0  # Which finding is selected

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            VerticalScroll(
                Static(self._render_findings_list, id="findings-list"),
                Static(self._render_selected_detail, id="finding-detail"),
                id="findings-container",
            ),
        )
        yield Footer()

    def on_mount(self) -> None:
        """Load active session from the app."""
        if self.app.session_store:
            self._session = self.app.session_store.get_active()
        if self._session and self._session.findings:
            self._selected_index = min(self._selected_index, len(self._session.findings) - 1)

    def _render_findings_list(self) -> Panel:
        """Render a table of all findings."""
        if not self._session or not self._session.findings:
            return Panel(
                "No findings recorded.",
                title="Findings",
                border_style=THEME.border_primary,
            )

        table = Table(show_header=True, header_style="bold")
        table.add_column("#", style=THEME.border_primary, justify="right")
        table.add_column("CVE")
        table.add_column("CVSS", justify="right")
        table.add_column("Severity")
        table.add_column("EPSS", justify="right")
        table.add_column("KEV")
        table.add_column("Exploit")

        for idx, finding in enumerate(self._session.findings):
            cve_id = finding.get("cve_id", "Unknown")
            cvss = finding.get("cvss", 0.0)
            severity = finding.get("severity", "NONE").upper()
            epss = finding.get("epss", 0.0)
            kev = "YES" if finding.get("in_kev") else "No"
            exploit = "YES" if finding.get("has_public_exploit") else "No"
            style = f"bold {style_for_severity(severity)}"
            table.add_row(
                str(idx),
                cve_id,
                f"{cvss:.1f}",
                f"[{style}]{severity}[/{style}]",
                f"{epss:.2f}",
                kev,
                exploit,
            )

        return Panel(
            table,
            title=f"Findings ({len(self._session.findings)} total)",
            border_style=THEME.border_primary,
        )

    def _render_selected_detail(self) -> Panel:
        """Render detail view for the selected finding."""
        if not self._session or not self._session.findings:
            return Panel(
                "Select a finding to view details.",
                title="Finding Detail",
                border_style=THEME.border_primary,
            )

        if self._selected_index >= len(self._session.findings):
            self._selected_index = len(self._session.findings) - 1

        finding = self._session.findings[self._selected_index]
        severity = finding.get("severity", "NONE").upper()
        border_style = style_for_severity(severity)

        lines = [
            f"CVE ID: {finding.get('cve_id', 'Unknown')}",
            f"CVSS Score: {finding.get('cvss', 0.0):.1f}",
            f"Severity: {severity}",
            "",
            f"EPSS Score: {finding.get('epss', 0.0):.2f}",
            f"In CISA KEV: {'YES' if finding.get('in_kev') else 'No'}",
            f"Public Exploit: {'YES' if finding.get('has_public_exploit') else 'No'}",
            "",
            "Summary:",
            f"  {finding.get('summary', 'No summary available.')}",
        ]

        references = finding.get("references", [])
        if references:
            lines.append("")
            lines.append("References:")
            for ref in references:
                lines.append(f"  - {ref}")

        return Panel(
            "\n".join(lines),
            title=f"Finding #{self._selected_index}",
            border_style=border_style,
        )

    def select_finding(self, index: int) -> None:
        """Select a finding by index for detail view."""
        if self._session and 0 <= index < len(self._session.findings):
            self._selected_index = index
            self.query_one("#findings-list", Static).refresh()
            self.query_one("#finding-detail", Static).refresh()

    def update_session(self, session) -> None:
        """Update the session data."""
        self._session = session
        if self.is_mounted:
            self.query_one("#findings-list", Static).refresh()
            self.query_one("#finding-detail", Static).refresh()
