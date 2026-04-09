"""Diagnostics utility to check for required security binaries in the PATH."""

import shutil
import subprocess
from typing import NamedTuple


class ToolCheck(NamedTuple):
    name: str
    binary: str
    description: str
    required: bool = True


REQUIRED_TOOLS = [
    ToolCheck("nmap", "nmap", "Port scanner and service discovery", required=True),
    ToolCheck("masscan", "masscan", "Mass IP port scanner", required=False),
    ToolCheck("gobuster", "gobuster", "Directory and DNS brute-forcer", required=True),
    ToolCheck("ffuf", "ffuf", "Fast web fuzzer", required=False),
    ToolCheck("nikto", "nikto", "Web server scanner", required=False),
    ToolCheck("nuclei", "nuclei", "Template-based vulnerability scanner", required=False),
    ToolCheck("sqlmap", "sqlmap", "Automatic SQL injection discovery", required=False),
    ToolCheck("hydra", "hydra", "Network logon cracker", required=False),
    ToolCheck("metasploit", "msfconsole", "Exploitation framework", required=False),
    ToolCheck("trivy", "trivy", "Vulnerability scanner for containers/FS", required=False),
]


def check_environment() -> list[dict]:
    """Check if required binaries are available in the system PATH.

    Returns a list of status dictionaries.
    """
    results = []
    for tool in REQUIRED_TOOLS:
        path = shutil.which(tool.binary)
        status = {
            "name": tool.name,
            "binary": tool.binary,
            "found": path is not None,
            "path": path,
            "required": tool.required,
            "description": tool.description,
        }

        # Additional check for version if found
        if path:
            try:
                # Most tools support --version or -h
                v_arg = "-v" if tool.name == "nikto" else "--version"
                proc = subprocess.run(
                    [tool.binary, v_arg], capture_output=True, text=True, timeout=2
                )
                stdout_first = proc.stdout.split("\n")[0].strip()
                stderr_first = proc.stderr.split("\n")[0].strip()
                status["version"] = stdout_first or stderr_first
            except Exception:
                status["version"] = "unknown"

        results.append(status)
    return results
