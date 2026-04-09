"""Enumeration tools -- gobuster, ffuf, nikto, enum4linux.

All functions return JSON strings for DSPy compatibility.
"""

import json
import subprocess


def gobuster_scan(
    target: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    **kwargs,
) -> str:
    """Directory and file brute-forcing against web targets.
    Supports dir, dns, and vhost modes. Default uses common wordlist."""
    url = target if target.startswith("http") else f"http://{target}"
    cmd = ["gobuster", mode, "-u", url, "-w", wordlist, "-q"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    return json.dumps(
        {
            "success": result.returncode == 0,
            "output": result.stdout[:20000],
            "errors": result.stderr[:2000],
            "exit_code": result.returncode,
        }
    )


def ffuf_scan(
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,txt",
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
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    return json.dumps(
        {
            "success": result.returncode == 0,
            "output": result.stdout[:20000],
            "errors": result.stderr[:2000],
            "exit_code": result.returncode,
        }
    )


def nikto_scan(target: str, **kwargs) -> str:
    """Web server vulnerability scanner. Checks for outdated software,
    dangerous files, configuration issues, and known vulnerabilities"""
    host = target if target.startswith("http") else f"http://{target}"
    cmd = ["nikto", "-host", host, "-Format", "json", "-Tuning", "123456"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    return json.dumps(
        {
            "success": result.returncode == 0,
            "output": result.stdout[:20000],
            "errors": result.stderr[:2000],
            "exit_code": result.returncode,
        }
    )


def enum4linux(target: str, **kwargs) -> str:
    """Windows/SMB enumeration -- users, shares, group memberships,
    password policies"""
    cmd = ["enum4linux", "-a", target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return json.dumps(
        {
            "success": result.returncode == 0,
            "output": result.stdout[:20000],
            "errors": result.stderr[:2000],
            "exit_code": result.returncode,
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
        ),
        "ffuf_scan": make_tool(
            ffuf_scan,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
        ),
        "nikto_scan": make_tool(
            nikto_scan,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
        ),
        "enum4linux": make_tool(
            enum4linux,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
        ),
    }
