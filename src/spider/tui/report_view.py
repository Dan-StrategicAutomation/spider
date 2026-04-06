"""Report viewer screen -- pentest report display and export."""

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


class ReportScreen(Screen):
    """View and export generated pentest reports."""

    DEFAULT_CSS = """
    #report-header { background: $surface-high; padding: 1; }
    #report-body { padding: 0 1; }
    """

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
                Static(self._render_report_header, id="report-header"),
                Static(self._render_executive_summary, id="report-summary"),
                Static(
                    self._render_findings_summary, id="report-findings"
                ),
                Static(self._render_attack_chains_summary, id="report-chains"),
                Static(self._render_recommendations, id="report-recommendations"),
                id="report-body",
            ),
        )
        yield Footer()

    def on_mount(self) -> None:
        """Load active session."""
        if self.app.session_store:
            self._session = self.app.session_store.get_active()

    def _render_report_header(self) -> Panel:
        if not self._session:
            return Panel(
                "No session data available.",
                title="Report",
                border_style=THEME.border_primary,
            )
        lines = [
            f"Target: {self._session.target}",
            f"Session ID: {self._session.session_id}",
            f"Generated: {self._session.completed_at or 'N/A'}",
            f"Status: {self._session.status.value.upper()}",
        ]
        return Panel(
            "\n".join(lines),
            title="Pentest Report",
            border_style=THEME.border_primary,
        )

    def _render_executive_summary(self) -> Panel:
        if not self._session:
            return Panel(
                "No session data.",
                title="Executive Summary",
                border_style=THEME.border_primary,
            )
        s = self._session
        total = len(s.findings)
        critical = sum(
            1 for f in s.findings
            if f.get("severity", "").upper() == "CRITICAL"
        )
        high = sum(
            1 for f in s.findings
            if f.get("severity", "").upper() == "HIGH"
        )
        medium = sum(
            1 for f in s.findings
            if f.get("severity", "").upper() == "MEDIUM"
        )
        chains = len(s.attack_chain)
        lines = [
            f"Total Findings: {total}",
            f"Critical: {critical}",
            f"High: {high}",
            f"Medium: {medium}",
            f"Attack Paths Discovered: {chains}",
        ]
        return Panel(
            "\n".join(lines),
            title="Executive Summary",
            border_style=THEME.border_primary,
        )

    def _render_findings_summary(self) -> Panel:
        if not self._session or not self._session.findings:
            return Panel(
                "No findings to report.",
                title="Findings Summary",
                border_style=THEME.border_primary,
            )
        table = Table(show_header=True, header_style="bold")
        table.add_column("#", style=THEME.border_primary, justify="right")
        table.add_column("CVE")
        table.add_column("Severity")
        table.add_column("CVSS", justify="right")
        table.add_column("Exploit Available")
        sorted_findings = sorted(
            self._session.findings,
            key=lambda f: f.get("cvss", 0),
            reverse=True,
        )
        for idx, finding in enumerate(sorted_findings, 1):
            table.add_row(
                str(idx),
                finding.get("cve_id", "Unknown"),
                finding.get("severity", "NONE").upper(),
                f"{finding.get('cvss', 0.0):.1f}",
                "Yes" if finding.get("has_public_exploit") else "No",
            )
        return Panel(
            table,
            title="Findings Summary",
            border_style=THEME.border_primary,
        )

    def _render_attack_chains_summary(self) -> Panel:
        if not self._session or not self._session.attack_chain:
            return Panel(
                "No attack chains discovered.",
                title="Attack Chains",
                border_style=THEME.border_primary,
            )
        lines = []
        for idx, chain in enumerate(self._session.attack_chain, 1):
            name = chain.get("name", f"Chain #{idx}")
            risk = chain.get("overall_risk", "medium").upper()
            lines.append(f"[bold]{name}[/bold]")
            lines.append(f"  Overall Risk: {risk}")
            steps = chain.get("steps", [])
            lines.append(f"  Steps: {len(steps)}")
            for step in steps:
                num = step.get("step_number", "?")
                action = step.get("action", "?")
                hitl = " [HITL Required]" if step.get("hitl_required") else ""
                lines.append(f"    {num}. {action}{hitl}")
            lines.append("")
        return Panel(
            "\n".join(lines),
            title="Attack Chains",
            border_style=THEME.border_primary,
        )

    def _render_recommendations(self) -> Panel:
        if not self._session or not self._session.findings:
            return Panel(
                "Run a scan to generate recommendations.",
                title="Recommendations",
                border_style=THEME.border_primary,
            )
        # Deduplicate remediation advice by CVE
        cves_seen = set()
        recs = []
        for finding in sorted(
            self._session.findings,
            key=lambda f: f.get("cvss", 0),
            reverse=True,
        ):
            cve = finding.get("cve_id", "")
            if cve in cves_seen:
                continue
            cves_seen.add(cve)
            severity = finding.get("severity", "LOW").upper()
            remediation = finding.get(
                "remediation", "Review and patch vulnerable component."
            )
            recs.append(f"[bold]{severity} -- {cve}[/bold]")
            recs.append(f"  {remediation}")
            recs.append("")
        return Panel(
            "\n".join(recs) if recs else "No actionable recommendations.",
            title="Recommendations",
            border_style=THEME.border_primary,
        )

    def export_report(self, format: str = "json") -> str | bytes:
        """Export the current report as a string or bytes."""
        import json

        if not self._session:
            return json.dumps({"error": "No session data"})

        report = {
            "target": self._session.target,
            "session_id": self._session.session_id,
            "status": self._session.status.value,
            "findings_count": len(self._session.findings),
            "findings": self._session.findings,
            "attack_chains": self._session.attack_chain,
            "audit_entries": len(self._session.audit_log),
        }

        if format == "json":
            return json.dumps(report, indent=2)
        elif format == "csv":
            lines = ["cve_id,cvss,severity,epss,has_exploit"]
            for f in self._session.findings:
                lines.append(
                    f"{f.get('cve_id', '')},{f.get('cvss', 0)},"
                    f"{f.get('severity', '')},{f.get('epss', 0)},"
                    f"{f.get('has_public_exploit', False)}"
                )
            return "\n".join(lines)
        else:
            return json.dumps(report, indent=2)
