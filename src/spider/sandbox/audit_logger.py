"""AuditLogger -- immutable append-only log of all actions.

Every tool invocation is logged with timestamp, action, target, params, result.
Log entries are never modified or deleted.
"""

import json
import threading
from datetime import UTC, datetime
from pathlib import Path


class AuditLogger:
    """Append-only audit log for penetration testing actions."""

    def __init__(self, log_path: str | Path | None = None):
        self._lock = threading.Lock()
        self._path = Path(log_path) if log_path else Path("audit.log")
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        action: str,
        target: str,
        phase: str = "pending",
        params: dict | None = None,
        result: str = "",
    ) -> None:
        """Append an audit log entry."""
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "action": action,
            "target": target,
            "phase": phase,
            "params": params or {},
            "result": result[:2000] if result else "",
        }
        with self._lock, open(self._path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def update_phase(self, phase: str, result: str = "") -> None:
        """Not implemented for audit integrity -- use a separate status tracker."""
        # Audit log is append-only; updates are new entries
        pass

    def export(self) -> list[dict]:
        """Export all log entries for compliance reporting."""
        entries = []
        with self._lock:
            if self._path.exists():
                with open(self._path) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            entries.append(json.loads(line))
        return entries
