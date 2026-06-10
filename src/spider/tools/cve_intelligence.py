"""cve_intelligence -- NVD + CISA KEV + EPSS CVE lookup tool."""

import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any


def _fetch_nvd(cpe: str, service: str, version: str) -> list[dict[str, Any]]:
    """Fetch CVEs from NVD API 2.0 for a service/version."""
    try:
        import httpx
    except ImportError:
        return []

    keyword = cpe or f"cpe:2.3:a:*:{service}:*"

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 50,
    }
    if version and version != "unknown":
        params["keywordSearch"] = f"{service} {version}"

    try:
        resp = httpx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            cves = []
            for vuln in data.get("vulnerabilities", []):
                cve_item = vuln.get("cve", {})
                cve_id = cve_item.get("id", "")
                desc = ""
                for d in cve_item.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                metrics = cve_item.get("metrics", {})
                cvss = 0.0
                severity = "NONE"
                for key in ("cvssMetricV31", "cvssMetricV30"):
                    if key in metrics:
                        entry = metrics[key][0]
                        cvss = entry.get("cvssData", {}).get("baseScore", 0.0)
                        severity = entry.get("cvssData", {}).get("baseSeverity", "NONE")
                        break

                refs = [r.get("url", "") for r in cve_item.get("references", [])]

                cves.append(
                    {
                        "cve_id": cve_id,
                        "summary": desc[:300] + "..." if len(desc) > 300 else desc,
                        "cvss_score": cvss,
                        "severity": severity,
                        "references": refs[:2],
                    }
                )
            return cves
    except Exception:
        pass
    return []


def _fetch_kev(cve_ids: list[str]) -> dict[str, Any]:
    """Check CISA Known Exploited Vulnerabilities catalog."""
    kev_lookup: dict[str, Any] = {}
    try:
        import httpx

        resp = httpx.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                vid = vuln.get("cveID", "")
                if vid in cve_ids:
                    kev_lookup[vid] = {
                        "in_kev": True,
                        "due_date": vuln.get("dueDate", ""),
                        "short_description": vuln.get("shortDescription", ""),
                    }
    except Exception:
        pass
    return kev_lookup


def _fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for CVEs."""
    epss_lookup: dict[str, float] = {}
    try:
        import httpx

        for cve_id in cve_ids:
            resp = httpx.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": cve_id},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("data", []):
                    if entry.get("cve") == cve_id:
                        score = entry.get("epss", 0.0)
                        epss_lookup[cve_id] = float(score) if score else 0.0
    except Exception:
        pass
    return epss_lookup


def cve_intelligence(
    service: str,
    version: str,
    cpe: str = "",
    limit: int = 10,
    **kwargs,
) -> str:
    """Look up known CVEs for a service/version across NVD, CISA KEV, and EPSS.

    Returns a JSON string of prioritized vulnerability findings with exploit
    availability indicators and severity scores. Result set is limited to 'limit'
    items to fit within context windows.
    """
    cves = _fetch_nvd(cpe, service, version)
    if not cves:
        return json.dumps(
            {
                "success": True,
                "cves": [],
                "total": 0,
                "note": f"No CVEs found for {service} {version}",
            }
        )

    cve_ids = [c["cve_id"] for c in cves]

    with ThreadPoolExecutor(max_workers=3) as executor:
        kev_future = executor.submit(_fetch_kev, cve_ids)
        epss_future = executor.submit(_fetch_epss, cve_ids)
        kev_data = kev_future.result()
        epss_data = epss_future.result()

    for cve in cves:
        cve_id = cve["cve_id"]
        kev = kev_data.get(cve_id, {})
        cve["in_kev"] = kev.get("in_kev", False)
        cve["epss_score"] = epss_data.get(cve_id, 0.0)

    # Prioritize: KEV > CVSS > EPSS
    cves.sort(key=lambda c: (c["in_kev"], c["cvss_score"], c["epss_score"]), reverse=True)

    total_found = len(cves)
    cves = cves[:limit]

    return json.dumps(
        {
            "success": True,
            "cves": cves,
            "total": total_found,
            "limit": limit,
        }
    )


def register_all(scope_guard=None, audit_logger=None):
    """Register CVE intelligence tools with the adapter."""
    from spider.tools.adapter import make_tool

    return {
        "cve_intelligence": make_tool(
            cve_intelligence,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
        ),
    }
