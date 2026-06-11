"""Session management for Spider TUI.

Tracks scan runs, findings, and state across TUI sessions.
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from spider.schemas import ScanPhase


class ScanStatus(StrEnum):
    """Status of a scan session."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AuditEntry:
    """Single immutable audit log entry."""

    timestamp: str
    action: str
    target: str
    parameters: dict[str, Any] = field(default_factory=dict)
    result: str = ""
    hitl_approved: bool = False

    def to_json(self) -> str:
        return json.dumps(
            {
                "timestamp": self.timestamp,
                "action": self.action,
                "target": self.target,
                "parameters": self.parameters,
                "result": self.result,
                "hitl_approved": self.hitl_approved,
            }
        )


@dataclass
class ScanSession:
    """Represents a single scan session with full state tracking."""

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: str = ""
    status: ScanStatus = ScanStatus.PENDING
    started_at: str = ""
    completed_at: str = ""
    current_phase: ScanPhase = ScanPhase.RECON
    phase_progress: dict[str, float] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    attack_chain: list[dict[str, Any]] = field(default_factory=list)
    audit_log: list[AuditEntry] = field(default_factory=list)
    llm_reasoning: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.started_at and self.status == ScanStatus.RUNNING:
            self.started_at = datetime.now(UTC).isoformat()

    def start(self) -> None:
        """Mark session as running."""
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.now(UTC).isoformat()

    def complete(self) -> None:
        """Mark session as complete."""
        self.status = ScanStatus.COMPLETE
        self.completed_at = datetime.now(UTC).isoformat()

    def fail(self, reason: str) -> None:
        """Mark session as failed with reason."""
        self.status = ScanStatus.FAILED
        self.errors.append(reason)
        self.completed_at = datetime.now(UTC).isoformat()

    def pause(self) -> None:
        """Pause the session."""
        self.status = ScanStatus.PAUSED

    def resume(self) -> None:
        """Resume a paused session."""
        if self.status == ScanStatus.PAUSED:
            self.status = ScanStatus.RUNNING

    def cancel(self) -> None:
        """Cancel the session."""
        self.status = ScanStatus.CANCELLED
        self.completed_at = datetime.now(UTC).isoformat()

    def update_phase(self, phase: ScanPhase, progress: float = 0.0) -> None:
        """Update current phase and its progress."""
        self.current_phase = phase
        self.phase_progress[phase.value] = progress

    def add_finding(self, finding: dict[str, Any]) -> None:
        """Add a vulnerability finding."""
        self.findings.append(finding)

    def add_audit(
        self,
        action: str,
        target: str,
        parameters: dict[str, Any] | None = None,
        result: str = "",
        hitl_approved: bool = False,
    ) -> None:
        """Add immutable audit log entry."""
        entry = AuditEntry(
            timestamp=datetime.now(UTC).isoformat(),
            action=action,
            target=target,
            parameters=parameters or {},
            result=result,
            hitl_approved=hitl_approved,
        )
        self.audit_log.append(entry)

    def add_reasoning(self, thought: str) -> None:
        """Add LLM reasoning trace."""
        self.llm_reasoning.append(thought)

    def add_error(self, error: str) -> None:
        """Record an error."""
        self.errors.append(error)

    def summary(self) -> dict[str, Any]:
        """Return session summary."""
        return {
            "session_id": self.session_id,
            "target": self.target,
            "status": self.status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "current_phase": self.current_phase.value,
            "findings_count": len(self.findings),
            "audit_entries": len(self.audit_log),
            "error_count": len(self.errors),
        }


class SessionStore:
    """Persistent store for scan sessions."""

    def __init__(self, data_dir: str | None = None) -> None:
        if data_dir is None:
            data_dir = str(Path.home() / ".spider" / "sessions")
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, ScanSession] = {}
        self._active_session: str | None = None
        self._load_all()

    def _load_all(self) -> None:
        """Load existing sessions from disk."""
        for session_file in self._data_dir.glob("*.json"):
            try:
                data = json.loads(session_file.read_text())
                session = ScanSession(**data)
                self._sessions[session.session_id] = session
            except (json.JSONDecodeError, TypeError):
                continue

    def create(self, target: str) -> ScanSession:
        """Create a new scan session."""
        session = ScanSession(target=target)
        self._sessions[session.session_id] = session
        self._active_session = session.session_id
        self._save(session)
        return session

    def get(self, session_id: str) -> ScanSession | None:
        """Retrieve a session by ID."""
        return self._sessions.get(session_id)

    def get_active(self) -> ScanSession | None:
        """Get the currently active session."""
        if self._active_session:
            return self._sessions.get(self._active_session)
        return None

    def list_sessions(self) -> list[ScanSession]:
        """List all sessions, most recent first."""
        return sorted(
            self._sessions.values(),
            key=lambda s: s.started_at,
            reverse=True,
        )

    def save(self, session: ScanSession) -> None:
        """Persist a session to disk."""
        self._sessions[session.session_id] = session
        self._save(session)

    def _save(self, session: ScanSession) -> None:
        """Write session JSON to disk."""
        session_file = self._data_dir / f"{session.session_id}.json"
        data = {
            "session_id": session.session_id,
            "target": session.target,
            "status": session.status.value,
            "started_at": session.started_at,
            "completed_at": session.completed_at,
            "current_phase": session.current_phase.value,
            "phase_progress": session.phase_progress,
            "findings": session.findings,
            "attack_chain": session.attack_chain,
            "audit_log": [
                {
                    "timestamp": e.timestamp,
                    "action": e.action,
                    "target": e.target,
                    "parameters": e.parameters,
                    "result": e.result,
                    "hitl_approved": e.hitl_approved,
                }
                for e in session.audit_log
            ],
            "llm_reasoning": session.llm_reasoning,
            "errors": session.errors,
        }
        session_file.write_text(json.dumps(data, indent=2))
