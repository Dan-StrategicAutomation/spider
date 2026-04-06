"""HITL Gate -- Human-in-the-Loop approval for exploitation actions.

All exploitation requires explicit human approval. Only recon and enumeration
are fully autonomous.
"""

import json
import time
import threading


class HITLApproval:
    """Represents a pending human approval request."""

    def __init__(
        self,
        action: str,
        target: str,
        risk_level: str,
        details: str = "",
        cve_id: str | None = None,
        timeout: int = 300,
    ):
        self.action = action
        self.target = target
        self.risk_level = risk_level
        self.details = details
        self.cve_id = cve_id
        self.timeout = timeout
        self.status = "pending"  # "pending", "approved", "denied", "expired"
        self._created = time.time()
        self._event = threading.Event()

    def is_expired(self) -> bool:
        return (time.time() - self._created) > self.timeout

    def approve(self) -> None:
        if not self.is_expired():
            self.status = "approved"
            self._event.set()

    def deny(self) -> None:
        self.status = "denied"
        self._event.set()

    def wait(self, timeout: int | None = None) -> bool:
        """Wait for human response. Returns True if approved."""
        t = timeout or self.timeout
        self._event.wait(timeout=t)
        if self.is_expired():
            self.status = "expired"
        return self.status == "approved"


class HITLGate:
    """Manages the queue of pending human approvals."""

    def __init__(self, interactive: bool = True):
        self.interactive = interactive
        self._queue: list[HITLApproval] = []
        self._lock = threading.Lock()

    def request(
        self,
        action: str,
        target: str,
        risk_level: str,
        details: str = "",
        cve_id: str | None = None,
        timeout: int = 300,
    ) -> bool:
        """Request human approval before executing an action.

        In interactive mode, prompts the user.
        In non-interactive mode, denies by default.
        """
        if not self.interactive:
            return False  # Default deny in non-interactive mode

        approval = HITLApproval(
            action=action,
            target=target,
            risk_level=risk_level,
            details=details,
            cve_id=cve_id,
            timeout=timeout,
        )

        with self._lock:
            self._queue.append(approval)

        # Use questionary for interactive prompt
        import questionary

        answer = questionary.confirm(
            f"EXECUTE: {action} -> {target} (risk: {risk_level})\n"
            f"{f'CVE: {cve_id}\n' if cve_id else ''}"
            f"{details}\n"
            f"Approve?",
            default=False,
        ).ask()

        if answer:
            approval.approve()
            return True
        else:
            approval.deny()
            return False

    def get_pending(self) -> list[HITLApproval]:
        with self._lock:
            return [a for a in self._queue if a.status == "pending"]
