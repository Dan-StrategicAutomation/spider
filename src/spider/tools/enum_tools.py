"""Enumeration tools -- gobuster, ffuf, nikto, enum4linux.

All functions return JSON strings for DSPy compatibility.
"""

import json

from spider.tools.execution import ToolExecutionBackend, get_default_execution_backend


def gobuster_scan(
    target: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    backend: ToolExecutionBackend | None = None,
    **kwargs,
) -> str:
    """Directory and file brute-forcing against web targets.
    Supports dir, dns, and vhost modes. Default uses common wordlist."""
    url = target if target.startswith("http") else f"http://{target}"
    cmd = ["gobuster", mode, "-u", url, "-w", wordlist, "-q"]
    executor = backend or get_default_execution_backend()
    result = executor.execute(cmd, timeout=600)
    return json.dumps(
        {
            "success": result.exit_code == 0,
            "output": result.stdout[:20000],
            "errors": result.stderr[:2000],
            "exit_code": result.exit_code,
        }
    )


def ffuf_scan(
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,txt",
    backend: ToolExecutionBackend | None = None,
    **kwargs,
) -> str:
    """Fast web fuzzer for discovering hidden endpoints, parameters, and virtual
    hosts"""
    url = target if target.startswith("http") else f"http://{target}"
    cmd = [
        "ffuf",
        "-u",
        f"{url}/FUZZ",
        "-w",
        wordlist,
        "-e",
        extensions,
        "-maxtime-job",
        "300",
        "-noninteractive",
        "-of",
        "json",
    ]
    executor = backend or get_default_execution_backend()
    result = executor.execute(cmd, timeout=600)
    return json.dumps(
        {
            "success": result.exit_code == 0,
            "output": result.stdout[:20000],
            "errors": result.stderr[:2000],
            "exit_code": result.exit_code,
        }
    )


def nikto_scan(
    target: str,
    backend: ToolExecutionBackend | None = None,
    **kwargs,
) -> str:
    """Web server vulnerability scanner. Checks for outdated software,
    dangerous files, configuration issues, and known vulnerabilities"""
    host = target if target.startswith("http") else f"http://{target}"
    cmd = ["nikto", "-host", host, "-Format", "json", "-Tuning", "123456"]
    executor = backend or get_default_execution_backend()
    result = executor.execute(cmd, timeout=600)
    return json.dumps(
        {
            "success": result.exit_code == 0,
            "output": result.stdout[:20000],
            "errors": result.stderr[:2000],
            "exit_code": result.exit_code,
        }
    )


def enum4linux(
    target: str,
    backend: ToolExecutionBackend | None = None,
    **kwargs,
) -> str:
    """Windows/SMB enumeration -- users, shares, group memberships,
    password policies"""
    cmd = ["enum4linux", "-a", target]
    executor = backend or get_default_execution_backend()
    result = executor.execute(cmd, timeout=300)
    return json.dumps(
        {
            "success": result.exit_code == 0,
            "output": result.stdout[:20000],
            "errors": result.stderr[:2000],
            "exit_code": result.exit_code,
        }
    )


def register_all(scope_guard=None, audit_logger=None):
    """Register all enum tools via the adapter."""
    from spider.tools.adapter import make_tool

    return {
        "gobuster_scan": make_tool(
            gobuster_scan,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
            required_binary="gobuster",
        ),
        "ffuf_scan": make_tool(
            ffuf_scan,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
            required_binary="ffuf",
        ),
        "nikto_scan": make_tool(
            nikto_scan,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
            required_binary="nikto",
        ),
        "enum4linux": make_tool(
            enum4linux,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
            required_binary="enum4linux",
        ),
    }
