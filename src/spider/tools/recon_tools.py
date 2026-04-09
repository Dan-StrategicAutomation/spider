"""Reconnaissance tools -- nmap, whois, DNS enumeration, subdomain discovery, port scan.

All functions return JSON strings for DSPy compatibility.

Python-native implementations (dns_enum, subdomain_enum, whois_lookup, tcp_port_scan)
use library imports so they work without system binaries installed.  nmap_scan and
masscan_scan still shell out to the respective binaries and are registered only when
those binaries are present.
"""

import json
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Python-native tools (no binary required)
# ---------------------------------------------------------------------------


def dns_enum(target: str, **kwargs) -> str:
    """DNS enumeration using dnspython -- A, AAAA, MX, TXT, NS, SOA, SRV records.

    Identifies mail servers, SPF/DMARC records, and DNS infrastructure.
    Returns a JSON object with a 'records' dict keyed by record type.
    """
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return json.dumps({"error": "dnspython not installed", "success": False})

    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "SRV"]
    results: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10.0

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            results[rtype] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results[rtype] = []
        except dns.exception.DNSException as exc:
            results[rtype] = [f"error: {exc}"]

    return json.dumps({"success": True, "domain": target, "records": results})


def subdomain_enum(target: str, **kwargs) -> str:
    """Subdomain discovery via DNS brute-forcing with a built-in common subdomain list.

    Checks A and CNAME records for each candidate using dnspython.
    Returns a JSON object listing resolved subdomains and their records.
    """
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return json.dumps({"error": "dnspython not installed", "success": False})

    common = [
        "www",
        "mail",
        "ftp",
        "admin",
        "dev",
        "api",
        "staging",
        "test",
        "beta",
        "prod",
        "internal",
        "portal",
        "app",
        "db",
        "git",
        "smtp",
        "imap",
        "pop",
        "ns1",
        "ns2",
        "mx",
        "vpn",
        "remote",
        "cdn",
        "static",
    ]

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    found: list[dict[str, str]] = []

    def _check(sub: str) -> dict[str, str] | None:
        fqdn = f"{sub}.{target}"
        for rtype in ("A", "CNAME"):
            try:
                answers = resolver.resolve(fqdn, rtype)
                records = " ".join(r.to_text() for r in answers)
                return {"subdomain": fqdn, "type": rtype, "records": records}
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                pass
        return None

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_check, sub): sub for sub in common}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return json.dumps(
        {
            "success": True,
            "domain": target,
            "subdomains_found": found,
            "count": len(found),
        }
    )


def whois_lookup(target: str, **kwargs) -> str:
    """WHOIS database query for domain registration info, nameservers, contact
    details, and registration dates.  Uses python-whois library; does not require
    the system whois binary.

    Returns a JSON object with parsed registration fields.
    """
    try:
        import whois
    except ImportError:
        return json.dumps({"error": "python-whois not installed", "success": False})

    try:
        data = whois.whois(target)
        # whois returns a dict-like object; convert to a plain dict for serialisation
        payload: dict = {}
        for key, value in data.items():
            if isinstance(value, list):
                payload[key] = [str(v) for v in value]
            elif value is not None:
                payload[key] = str(value)
        return json.dumps({"success": True, "domain": target, "whois": payload})
    except Exception as exc:
        return json.dumps({"success": False, "domain": target, "error": str(exc)})


DEFAULT_PORTS = "21,22,23,25,53,80,110,443,445,3306,3389,5432,6379,8080,8443"


def tcp_port_scan(target: str, ports: str = DEFAULT_PORTS, timeout: float = 1.0, **kwargs) -> str:
    """TCP connect port scanner using the Python stdlib socket module.

    Intended for quick host reachability checks and lightweight port discovery.
    Not a replacement for nmap/masscan -- use those for thorough service detection.

    Args:
        target:  IP address or hostname to scan.
        ports:   Comma-separated list of ports or ranges (e.g. '22,80,443' or '1-1024').
        timeout: Per-port connection timeout in seconds (default 1.0).

    Returns a JSON object with open/closed/filtered port lists.
    """
    # Parse port spec into a sorted de-duplicated list
    port_list: list[int] = []
    for part in ports.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            port_list.extend(range(int(lo), int(hi) + 1))
        else:
            port_list.append(int(part))
    port_list = sorted(set(port_list))

    open_ports: list[int] = []
    closed_ports: list[int] = []

    def _probe(port: int) -> tuple[int, bool]:
        try:
            with socket.create_connection((target, port), timeout=timeout):
                return port, True
        except (ConnectionRefusedError, OSError):
            return port, False

    with ThreadPoolExecutor(max_workers=min(64, len(port_list))) as pool:
        futures = {pool.submit(_probe, p): p for p in port_list}
        for future in as_completed(futures):
            port, is_open = future.result()
            (open_ports if is_open else closed_ports).append(port)

    return json.dumps(
        {
            "success": True,
            "target": target,
            "scanned": len(port_list),
            "open": sorted(open_ports),
            "closed": sorted(closed_ports),
            "note": "TCP connect scan only -- use nmap_scan for service/version detection",
        }
    )


# ---------------------------------------------------------------------------
# Binary-backed tools (require nmap / masscan)
# ---------------------------------------------------------------------------


def nmap_scan(target: str, ports: str = "-T4 -sV -p-", args: str = "-sC", **kwargs) -> str:
    """Run nmap scan against target. Returns open ports, service versions, and OS
    detection. Use for comprehensive reconnaissance of a single host."""
    cmd = ["nmap"] + ports.split() + args.split() + ["-oX", "-", target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    return json.dumps(
        {
            "success": result.returncode == 0,
            "xml_output": result.stdout[:50000],
            "errors": result.stderr[:2000],
            "exit_code": result.returncode,
        }
    )


def masscan_scan(target: str, ports: str = "1-65535", rate: str = "1000", **kwargs) -> str:
    """Run masscan for fast port scanning of targets or ranges. Finds open ports
    quickly, then hand off to nmap for service detection"""
    cmd = ["masscan", "-p", ports, target, "--rate", rate, "--output-format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return json.dumps(
        {
            "success": result.returncode == 0,
            "output": result.stdout[:50000],
            "errors": result.stderr[:2000],
            "exit_code": result.returncode,
        }
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_all(scope_guard=None, audit_logger=None):
    """Register all recon tools via the adapter.

    Python-native tools (dns_enum, subdomain_enum, whois_lookup, tcp_port_scan)
    are always registered.  Binary tools (nmap_scan, masscan_scan) are registered
    only when the binary is present on PATH.
    """
    from spider.tools.adapter import make_tool

    tools = {
        # Always available -- Python library implementations
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
        "whois_lookup": make_tool(
            whois_lookup,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
        ),
        "tcp_port_scan": make_tool(
            tcp_port_scan,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
        ),
        # Binary-backed -- registered only if binary present
        "nmap_scan": make_tool(
            nmap_scan,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
            required_binary="nmap",
        ),
        "masscan_scan": make_tool(
            masscan_scan,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
            required_binary="masscan",
        ),
    }

    # Filter out None entries (missing binaries)
    return {name: tool for name, tool in tools.items() if tool is not None}
