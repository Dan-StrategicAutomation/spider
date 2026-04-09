"""Vulnerability scanners -- nuclei, nmap NSE, trivy."""

import json
import subprocess
from typing import Any


def nuclei_scan(
    target: str,
    templates: str = "",
    severity: str = "",
    **kwargs,
) -> str:
    """Run nuclei vulnerability scan.

    Template-based detection using thousands of YAML-based templates
    for common vulnerabilities and misconfigurations.
    """
    cmd = ["nuclei", "-target", target, "-json", "-silent"]
    if severity:
        cmd.extend(["-severity", severity])
    if templates:
        cmd.extend(["-t", templates])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        findings: list[dict[str, Any]] = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return json.dumps(
            {
                "success": True,
                "findings": findings,
                "total": len(findings),
            }
        )
    except FileNotFoundError:
        return json.dumps(
            {
                "success": False,
                "error": "nuclei not found in PATH",
            }
        )
    except subprocess.TimeoutExpired:
        return json.dumps(
            {
                "success": False,
                "error": "nuclei scan timed out",
            }
        )
    except Exception as exc:
        return json.dumps(
            {
                "success": False,
                "error": str(exc),
            }
        )


def nmap_nse(target: str, scripts: str = "vuln,exploit", **kwargs) -> str:
    """Run nmap NSE scripts for vulnerability detection and default
    credential checks."""
    cmd = [
        "nmap",
        "--script",
        scripts,
        "--script-args",
        "unsafe=1",
        "-T4",
        target,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
        return json.dumps(
            {
                "success": True,
                "output": result.stdout,
                "errors": result.stderr,
            }
        )
    except FileNotFoundError:
        return json.dumps(
            {
                "success": False,
                "error": "nmap not found in PATH",
            }
        )
    except subprocess.TimeoutExpired:
        return json.dumps(
            {
                "success": False,
                "error": "nmap NSE scan timed out",
            }
        )
    except Exception as exc:
        return json.dumps(
            {
                "success": False,
                "error": str(exc),
            }
        )


def trivy_scan(target: str, scan_type: str = "image", **kwargs) -> str:
    """Run trivy vulnerability scanner for container images and filesystems."""
    cmd = [
        "trivy",
        "--format",
        "json",
        "--quiet",
        scan_type,
        target,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        try:
            data = json.loads(result.stdout)
            return json.dumps(
                {
                    "success": True,
                    "results": data.get("Results", []),
                    "total_vulns": sum(
                        len(r.get("Vulnerabilities", [])) for r in data.get("Results", [])
                    ),
                }
            )
        except json.JSONDecodeError:
            return json.dumps(
                {
                    "success": True,
                    "output": result.stdout,
                }
            )
    except FileNotFoundError:
        return json.dumps(
            {
                "success": False,
                "error": "trivy not found in PATH",
            }
        )
    except subprocess.TimeoutExpired:
        return json.dumps(
            {
                "success": False,
                "error": "trivy scan timed out",
            }
        )
    except Exception as exc:
        return json.dumps(
            {
                "success": False,
                "error": str(exc),
            }
        )


def register_all(scope_guard=None, audit_logger=None):
    """Register vulnerability scanner tools with the adapter."""
    from spider.tools.adapter import make_tool

    return {
        "nuclei_scan": make_tool(
            nuclei_scan,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
            required_binary="nuclei",
        ),
        "nmap_nse": make_tool(
            nmap_nse,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
            required_binary="nmap",
        ),
        "trivy_scan": make_tool(
            trivy_scan,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
            required_binary="trivy",
        ),
    }
