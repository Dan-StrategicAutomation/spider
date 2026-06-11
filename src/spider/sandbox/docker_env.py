"""DockerEnv -- sandboxed execution of security tools via isolated containers.

All tool execution happens inside an isolated Docker container with:
- No access to host filesystem
- No privileged mode
- Resource limits enforced
- Internal network during testing
"""

import docker
from docker.models.containers import Container


class DockerSandbox:
    """Manages a sandboxed Docker container for running security tools."""

    def __init__(
        self,
        image: str = "kalilinux/kali-rolling",
        network: str | None = None,
        resource_limits: dict | None = None,
    ):
        self.image = image
        self.network = network
        self.resource_limits = resource_limits or {"cpu_count": 4, "mem_limit": "8g"}
        self._client = docker.from_env()
        self._container: Container | None = None

    def start(self, workdir: str = "/tmp/spider") -> None:
        """Start the sandbox container."""
        kwargs = {
            "image": self.image,
            "detach": True,
            "tty": True,
            "entrypoint": "/bin/bash",
            "working_dir": workdir,
            "privileged": False,
        }
        if self.network:
            kwargs["network"] = self.network
        if "cpu_count" in self.resource_limits:
            kwargs["cpu_count"] = self.resource_limits["cpu_count"]
        if "mem_limit" in self.resource_limits:
            kwargs["mem_limit"] = self.resource_limits["mem_limit"]

        self._container = self._client.containers.run(**kwargs)

    def exec(
        self, command: str, timeout: int = 300, workdir: str | None = None
    ) -> tuple[int, str, str]:
        """Execute a command inside the sandbox.

        Returns (exit_code, stdout, stderr).
        """
        if not self._container:
            raise RuntimeError("Sandbox not started")

        cmd = ["bash", "-c", command]
        result = self._container.exec_run(cmd, demux=True)
        exit_code = result.exit_code or 0
        stdout = (result.output[0] or b"").decode("utf-8", errors="replace")
        stderr = (result.output[1] or b"").decode("utf-8", errors="replace")

        return exit_code, stdout, stderr

    def stop(self) -> None:
        """Stop and remove the sandbox container."""
        if self._container:
            try:
                self._container.stop(timeout=10)
                self._container.remove()
            except docker.errors.NotFound:
                pass
            finally:
                self._container = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    @property
    def is_running(self) -> bool:
        if not self._container:
            return False
        try:
            self._container.reload()
            return self._container.status == "running"
        except docker.errors.NotFound:
            return False
