"""Reconnaissance tools -- nmap, whois, DNS enumeration, subdomain discovery.

All functions return JSON strings for DSPy compatibility.
"""

import json
import subprocess


def nmap_scan(target: str, ports: str = "-T4 -sV -p-", args: str = "-sC", **kwargs) -> str:
    """Run nmap scan against target. Returns open ports, service versions, and OS
    detection. Use for comprehensive reconnaissance of a single host."""
    cmd = ["nmap"] + ports.split() + args.split() + ["-oX", "-", target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    return json.dumps({
        "success": result.returncode == 0,
        "xml_output": result.stdout[:50000],
        "errors": result.stderr[:2000],
        "exit_code": result.returncode,
    })


def masscan_scan(target: str, ports: str = "1-65535", rate: str = "1000", **kwargs) -> str:
    """Run masscan for fast port scanning of targets or ranges. Finds open ports
    quickly, then hand off to nmap for service detection"""
    cmd = ["masscan", "-p", ports, target, "--rate", rate, "--output-format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return json.dumps({
        "success": result.returncode == 0,
        "output": result.stdout[:50000],
        "errors": result.stderr[:2000],
        "exit_code": result.returncode,
    })


def whois_lookup(target: str, **kwargs) -> str:
    """WHOIS database query for domain registration info, nameservers, contact
    details, and registration dates"""
    cmd = ["whois", target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return json.dumps({
        "success": result.returncode == 0,
        "output": result.stdout[:10000],
        "exit_code": result.returncode,
    })


def dns_enum(target: str, **kwargs) -> str:
    """DNS enumeration -- A, AAAA, MX, TXT, NS records. Identifies mail servers,
    SPF records, and DNS infrastructure"""
    records = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "SRV"]
    results = {}
    for record in records:
        try:
            cmd = ["dig", record, target, "+short"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            results[record] = r.stdout.strip()
        except Exception as e:
            results[record] = f"Error: {e}"
    return json.dumps({
        "success": True,
        "domain": target,
        "records": results,
    })


def subdomain_enum(target: str, **kwargs) -> str:
    """Subdomain discovery via DNS brute-forcing with common subdomain wordlist.
    Checks for A and CNAME records for each candidate"""
    # Quick check using dig with common subdomains
    common = ["www", "mail", "ftp", "admin", "dev", "api", "staging", "test",
              "beta", "prod", "internal", "portal", "app", "db", "git"]
    found = []
    for sub in common:
        try:
            cmd = ["dig", "+short", f"{sub}.{target}"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            answer = r.stdout.strip()
            if answer:
                found.append({"subdomain": f"{sub}.{target}", "records": answer})
        except Exception:
            pass
    return json.dumps({
        "success": True,
        "domain": target,
        "subdomains_found": found,
        "count": len(found),
    })


def register_all(scope_guard=None, audit_logger=None):
    """Register all recon tools via the adapter."""
    from spider.tools.adapter import make_tool
    return {
        "nmap_scan": make_tool(nmap_scan, scope_guard=scope_guard, audit_logger=audit_logger),
        "masscan_scan": make_tool(masscan_scan, scope_guard=scope_guard, audit_logger=audit_logger),
        "whois_lookup": make_tool(
            whois_lookup,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
        ),
        "dns_enum": make_tool(
            dns_enum,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
        ),
        "subdomain_enum": make_tool(
            subdomain_enum,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
        ),
    }
