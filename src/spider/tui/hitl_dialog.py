"""HITL (Human-in-the-Loop) approval dialog."""

from collections.abc import Callable
from typing import Any

from textual.app import ComposeResult
from textual.containers import Container, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

from spider.tui.theme import THEME

RISK_STYLES = {
    "low": THEME.border_success,
    "medium": THEME.border_primary,
    "high": THEME.border_warning,
    "critical": THEME.border_error,
}


def _risk_style(risk: str) -> str:
    """Return the theme border color for a risk level."""
    return RISK_STYLES.get(risk.lower(), THEME.panel_border)


class HITLDialog(ModalScreen):
    """Modal dialog for exploit authorization.

    Shows CVE details, risk assessment, and requires explicit
    user approval before any exploit execution.
    """

    DEFAULT_CSS = """
    HITLDialog {
        align: center middle;
    }

    #dialog-container {
        width: 80;
        background: $surface;
        border: thick $warning;
        padding: 1 2;
    }

    #hitl-title {
        text-align: center;
        text-style: bold;
        color: $warning;
        padding: 1 0 0 0;
    }

    #hitl-details {
        padding: 1 0;
        color: $text;
    }

    #hitl-actions {
        height: 3;
        layout: horizontal;
        align: center middle;
    }

    #hitl-actions Button {
        width: 1fr;
        margin: 0 1;
    }
    """

    def __init__(
        self,
        cve_id: str = "",
        target: str = "",
        action: str = "",
        risk: str = "medium",
        callback: Callable | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.cve_id = cve_id
        self.target = target
        self.action = action
        self.risk = risk
        self._callback = callback

    def compose(self) -> ComposeResult:
        _risk_style(self.risk)  # validates risk level
        yield Container(
            Label(
                "EXPLOIT AUTHORIZATION REQUIRED",
                id="hitl-title",
            ),
            Static(
                self._render_details(),
                id="hitl-details",
            ),
            Vertical(
                Button("APPROVE", id="btn-approve", variant="success"),
                Button(
                    "APPROVE WITH CONSTRAINTS",
                    id="btn-constrained",
                    variant="warning",
                ),
                Button("DENY", id="btn-deny", variant="error"),
                id="hitl-actions",
            ),
            id="dialog-container",
        )

    def _render_details(self) -> str:
        """Render the exploit authorization details panel."""
        lines = [
            f"Target:  {self.target}",
            f"CVE:     {self.cve_id}",
            f"Risk:    {self.risk.upper()}",
            "",
            f"Action:  {self.action}",
            "",
            "Requires explicit human approval before execution.",
        ]
        return "\n".join(lines)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        button_id = event.button.id
        if button_id == "btn-approve":
            self.dismiss({"approved": True, "constrained": False})
        elif button_id == "btn-constrained":
            self.dismiss({"approved": True, "constrained": True})
        elif button_id == "btn-deny":
            self.dismiss({"approved": False, "constrained": False})
