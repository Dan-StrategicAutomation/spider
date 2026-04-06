"""Attack graph visualization screen."""

from typing import TYPE_CHECKING, Any

from rich.panel import Panel
from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from spider.tui.theme import THEME

if TYPE_CHECKING:
    pass


RISK_COLORS = {
    "low": THEME.border_success,
    "medium": THEME.border_primary,
    "high": THEME.border_warning,
    "critical": THEME.border_error,
}


def style_for_risk(risk: str) -> str:
    """Return the theme border color for a risk level."""
    return RISK_COLORS.get(risk.lower(), THEME.panel_border)


class AttackGraphScreen(Screen):
    """Attack chain visualization with step-by-step progression."""

    BINDINGS = [
        ("escape", "app.push_screen('dashboard')", "Back"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._session = None  # type: ScanSession | None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            VerticalScroll(
                Static(self._render_chains, id="chains-view"),
                Static(self._render_graph_overview, id="graph-overview"),
                id="attack-graph-container",
            ),
        )
        yield Footer()

    def on_mount(self) -> None:
        """Load active session from the app."""
        if self.app.session_store:
            self._session = self.app.session_store.get_active()

    def _render_chains(self) -> Panel:
        """Render attack chain(s) as sequential steps."""
        if not self._session or not self._session.attack_chain:
            return Panel(
                "No attack chain discovered yet.",
                title="Attack Chain",
                border_style=THEME.border_primary,
            )

        lines = []
        for idx, chain in enumerate(self._session.attack_chain, 1):
            name = chain.get("name", f"Chain #{idx}")
            risk = chain.get("overall_risk", "medium").lower()
            feasibility = chain.get("feasibility_score", 0.0)
            stealth = chain.get("stealth_score", 0.0)
            border = style_for_risk(risk)

            lines.append(f"[bold {border}]{name}[/bold {border}]")
            lines.append(f"  Risk: {risk.upper()} | "
                         f"Feasibility: {feasibility:.2f} | "
                         f"Stealth: {stealth:.2f}")
            lines.append("")

            steps = chain.get("steps", [])
            for step in steps:
                num = step.get("step_number", "?")
                action = step.get("action", "Unknown")
                tool = step.get("tool", "")
                cve = step.get("cve_id")
                hitl = step.get("hitl_required", False)
                risk_val = step.get("risk_level", "medium").lower()
                risk_style = style_for_risk(risk_val)

                step_line = f"  [{num}] [bold]{action}[/bold]"
                if tool:
                    step_line += f" -- via [cyan]{tool}[/cyan]"
                if cve:
                    step_line += f" ({cve})"
                if hitl:
                    step_line += " [yellow][HITL][/yellow]"
                step_line += f" [{risk_style}]({risk_val.upper()})[/{risk_style}]"
                lines.append(step_line)

            lines.append("")

        return Panel(
            "\n".join(lines),
            title="Attack Chains",
            border_style=THEME.border_primary,
        )

    def _render_graph_overview(self) -> Panel:
        """Render a high-level attack graph overview."""
        if not self._session or not self._session.attack_chain:
            return Panel(
                "Run a scan to generate an attack graph.",
                title="Attack Graph Overview",
                border_style=THEME.border_primary,
            )

        total_steps = sum(
            len(chain.get("steps", []))
            for chain in self._session.attack_chain
        )
        hitl_count = sum(
            sum(
                1 for step in chain.get("steps", [])
                if step.get("hitl_required")
            )
            for chain in self._session.attack_chain
        )
        unique_cves = set()
        for chain in self._session.attack_chain:
            for step in chain.get("steps", []):
                cve = step.get("cve_id")
                if cve:
                    unique_cves.add(cve)

        lines = [
            f"Total attack chains: {len(self._session.attack_chain)}",
            f"Total steps: {total_steps}",
            f"HITL-gated steps: {hitl_count}",
            f"Unique CVEs referenced: {len(unique_cves)}",
        ]

        if unique_cves:
            lines.append("")
            lines.append("CVEs:")
            for cve in sorted(unique_cves):
                lines.append(f"  - {cve}")

        return Panel(
            "\n".join(lines),
            title="Attack Graph Overview",
            border_style=THEME.border_primary,
        )

    def update_session(self, session: Any) -> None:
        """Update the session data and refresh."""
        self._session = session
        if self.is_mounted:
            self.query_one("#chains-view", Static).refresh()
            self.query_one("#graph-overview", Static).refresh()
