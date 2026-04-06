from typing import TYPE_CHECKING, Any

from rich.panel import Panel
from rich.table import Table
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from spider.tui.theme import THEME

if TYPE_CHECKING:
    pass


class LiveStatusBar(Static):
    """Status bar showing scan phase, progress, and LLM state."""

    phase_text: str = reactive("IDLE")
    progress_val: float = reactive(0.0)
    refine_retry: str = reactive("")
    epss: str = reactive("")
    kev: str = reactive("")

    DEFAULT_CSS = """
    LiveStatusBar {
        dock: bottom;
        height: 1;
        background: $surface-high;
        color: $primary;
    }
    """

    def render(self) -> str:
        parts = [f"Phase: {self.phase_text}"]
        bar_len = int(self.progress_val * 20)
        bar = "#" * bar_len + "." * (20 - bar_len)
        parts.append(f"[{bar}] {self.progress_val * 100:.0f}%")
        if self.refine_retry:
            parts.append(f"dspy.Refine: {self.refine_retry}")
        if self.epss:
            parts.append(f"EPSS: {self.epss}")
        if self.kev:
            parts.append(f"KEV: {self.kev}")
        return " | ".join(parts)


class DashboardScreen(Screen):
    """Main dashboard showing scan overview."""

    DEFAULT_CSS = """
    Dashboard {
        layout: grid;
        grid-size: 2;
        grid-gutter: 1;
    }
    #target-panel { column-span: 2; }
    #audit-panel { column-span: 2; }
    """

    BINDINGS = [
        ("f", "app.push_screen('findings')", "Findings"),
        ("g", "app.push_screen('attack_graph')", "Attack Graph"),
        ("r", "app.push_screen('report')", "Report"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._session = None  # type: ScanSession | None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Static(self._render_target_panel, id="target-panel"),
            Horizontal(
                VerticalScroll(
                    Static(self._render_phase_panel, id="phase-panel"),
                    Static(self._render_findings_panel, id="findings-panel"),
                    id="left-col",
                ),
                VerticalScroll(
                    Static(self._render_attack_chain_panel, id="chain-panel"),
                    Static(
                        self._render_reasoning_panel, id="reasoning-panel"
                    ),
                    id="right-col",
                ),
            ),
            Static(self._render_audit_panel, id="audit-panel"),
            id="dashboard",
        )
        yield Footer()
        yield LiveStatusBar(id="status-bar")

    def on_mount(self) -> None:
        """Pull session from app and render."""
        if self.app.session_store:
            active = self.app.session_store.get_active()
            if active:
                self._session = active
                self.refresh_all()

    def refresh_all(self) -> None:
        """Force all panels to re-render."""
        for widget_id in [
            "target-panel",
            "phase-panel",
            "findings-panel",
            "chain-panel",
            "reasoning-panel",
            "audit-panel",
        ]:
            widget = self.query_one(f"#{widget_id}", Static)
            widget.refresh()
        status = self.query_one("#status-bar", LiveStatusBar)
        if self._session:
            status.phase_text = self._session.current_phase.value.upper()
            progress = self._session.phase_progress.get(
                self._session.current_phase.value, 0.0
            )
            status.progress_val = progress
            if self._session.llm_reasoning:
                count = len(self._session.llm_reasoning)
                status.refine_retry = f"retry {count}/3"

    def _render_target_panel(self) -> Panel:
        if not self._session:
            return Panel(
                "No active session",
                title="Target",
                border_style=THEME.border_primary,
            )
        s = self._session
        summary = s.summary()
        lines = [
            f"Target: {s.target}",
            f"Session: {s.session_id}",
            f"Status: {s.status.value.upper()}",
            f"Started: {s.started_at or 'N/A'}",
            f"Findings: {summary['findings_count']}",
            f"Errors: {summary['error_count']}",
        ]
        return Panel(
            "\n".join(lines),
            title="Target",
            border_style=THEME.border_primary,
        )

    def _render_phase_panel(self) -> Panel:
        if not self._session:
            return Panel(
                "No data",
                title="Phase Progress",
                border_style=THEME.border_primary,
            )
        s = self._session
        phases = [
            "recon",
            "enum",
            "vuln_scan",
            "planning",
            "execution",
            "post_exploit",
            "reporting",
        ]
        lines = []
        for phase in phases:
            progress = s.phase_progress.get(phase, 0.0)
            bar_len = int(progress * 15)
            bar = "#" * bar_len + "-" * (15 - bar_len)
            label = phase.upper() if phase == s.current_phase.value else phase.title()
            lines.append(f"{label:>12} [{bar}] {progress * 100:.0f}%")
        return Panel(
            "\n".join(lines),
            title="Phase Progress",
            border_style=THEME.border_primary,
        )

    def _render_findings_panel(self) -> Panel:
        if not self._session or not self._session.findings:
            return Panel(
                "No findings yet",
                title="Findings",
                border_style=THEME.border_primary,
            )
        table = Table(show_header=True, header_style="bold")
        table.add_column("CVE", style=THEME.border_primary)
        table.add_column("CVSS", justify="right")
        table.add_column("Severity")
        table.add_column("EPSS", justify="right")
        table.add_column("Exploit")
        by_severity = sorted(
            self._session.findings,
            key=lambda f: f.get("cvss", 0),
            reverse=True,
        )
        for finding in by_severity[:15]:
            sev = finding.get("severity", "LOW").upper()
            exploit = "YES" if finding.get("has_exploit") else "No"
            table.add_row(
                finding.get("cve_id", "?"),
                f"{finding.get('cvss', 0):.1f}",
                sev,
                f"{finding.get('epss', 0):.2f}",
                exploit,
            )
        return Panel(
            table,
            title="Findings",
            border_style=THEME.border_primary,
        )

    def _render_attack_chain_panel(self) -> Panel:
        if not self._session or not self._session.attack_chain:
            return Panel(
                "No attack chain",
                title="Attack Chain",
                border_style=THEME.border_primary,
            )
        lines = []
        for step in self._session.attack_chain:
            num = step.get("step_number", "?")
            action = step.get("action", "?")
            cve = step.get("cve_id")
            hitl = " [HITL]" if step.get("hitl_required") else ""
            line = f"[{num}] {action}"
            if cve:
                line += f" ({cve})"
            line += hitl
            lines.append(line)
        return Panel(
            "\n".join(lines),
            title="Attack Chain",
            border_style=THEME.border_primary,
        )

    def _render_reasoning_panel(self) -> Panel:
        if not self._session or not self._session.llm_reasoning:
            return Panel(
                "No LLM reasoning",
                title="LLM Thinking",
                border_style=THEME.border_primary,
            )
        last = self._session.llm_reasoning[-1]
        if len(last) > 500:
            last = last[:497] + "..."
        return Panel(
            last,
            title="LLM Thinking",
            border_style=THEME.border_primary,
        )

    def _render_audit_panel(self) -> Panel:
        if not self._session or not self._session.audit_log:
            return Panel(
                "No audit entries",
                title="Audit Log",
                border_style=THEME.border_primary,
            )
        entries = self._session.audit_log[-20:]
        lines = []
        for entry in entries:
            ts = entry.timestamp[:19] if hasattr(entry, "timestamp") else ""
            action = (
                entry.action
                if hasattr(entry, "action")
                else entry.get("action", "?")  # type: ignore[union-attr]
            )
            target = (
                entry.target
                if hasattr(entry, "target")
                else entry.get("target", "?")  # type: ignore[union-attr]
            )
            hitl_tag = " [HITL]" if entry.hitl_approved else ""
            lines.append(f"[{ts}] {action} -> {target}{hitl_tag}")
        return Panel(
            "\n".join(lines),
            title="Audit Log",
            border_style=THEME.border_primary,
        )

    def update_session(self, session) -> None:
        """Update the displayed session."""
        self._session = session
        self.refresh_all()
