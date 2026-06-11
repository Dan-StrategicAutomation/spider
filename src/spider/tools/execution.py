"""Execution backends for sandboxed external tool commands."""

import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from spider.sandbox.docker_env import DockerSandbox


@dataclass(frozen=True)
class ToolExecutionResult:
    """Normalized result returned by command execution backends."""

    exit_code: int
    stdout: str
    stderr: str


class ToolExecutionTimeoutError(Exception):
    """Raised when an execution backend times out running a command."""


class ToolExecutionBackend(Protocol):
    """Protocol for executing external commands inside an approved sandbox."""

    def execute(
        self,
        command: Sequence[str],
        *,
        timeout: int = 300,
        workdir: str | None = None,
    ) -> ToolExecutionResult:
        """Execute command and return exit code, stdout, and stderr."""


class DockerToolExecutionBackend:
    """Run external commands through DockerSandbox.exec."""

    def __init__(self, sandbox: DockerSandbox | None = None) -> None:
        self._sandbox = sandbox or DockerSandbox()

    def execute(
        self,
        command: Sequence[str],
        *,
        timeout: int = 300,
        workdir: str | None = None,
    ) -> ToolExecutionResult:
        """Execute command inside DockerSandbox and normalize the result."""
        if not self._sandbox.is_running:
            self._sandbox.start(workdir=workdir or "/tmp/spider")
        shell_command = shlex.join(command)
        exit_code, stdout, stderr = self._sandbox.exec(
            shell_command,
            timeout=timeout,
            workdir=workdir,
        )
        return ToolExecutionResult(exit_code=exit_code, stdout=stdout, stderr=stderr)


_default_backend: ToolExecutionBackend | None = None


def get_default_execution_backend() -> ToolExecutionBackend:
    """Return the process-wide default Docker-backed execution backend."""
    global _default_backend
    if _default_backend is None:
        _default_backend = DockerToolExecutionBackend()
    return _default_backend


def set_default_execution_backend(backend: ToolExecutionBackend | None) -> None:
    """Set or clear the process-wide default execution backend."""
    global _default_backend
    _default_backend = backend
