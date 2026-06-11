"""cve_intelligence -- NVD + CISA KEV + EPSS CVE lookup tool."""

import asyncio
import json
from typing import Any

from spider.config import SpiderConfig
from spider.intelligence.cve_db import NVDAPI
from spider.intelligence.epss import EPSSClient
from spider.intelligence.kev import KEVClient


def _format_nvd_vulnerability(vuln: dict[str, Any]) -> dict[str, Any]:
    """Convert an NVD vulnerability item into the tool response schema."""
    cve_item = vuln.get("cve", {})
    cve_id = cve_item.get("id", "")
    desc = ""
    for description in cve_item.get("descriptions", []):
        if description.get("lang") == "en":
            desc = description.get("value", "")
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

    refs = [reference.get("url", "") for reference in cve_item.get("references", [])]

    return {
        "cve_id": cve_id,
        "summary": f"{desc[:300]}..." if len(desc) > 300 else desc,
        "cvss_score": cvss,
        "severity": severity,
        "references": refs[:2],
    }


def _nvd_keyword(cpe: str, service: str, version: str) -> str:
    """Build the NVD keyword used for service/version intelligence lookups."""
    if version and version != "unknown":
        return f"{service} {version}"
    return cpe or f"cpe:2.3:a:*:{service}:*"


def _fetch_nvd(cpe: str, service: str, version: str) -> list[dict[str, Any]]:
    """Fetch CVEs from NVD API 2.0 through the shared intelligence repository."""
    client = NVDAPI(api_key=SpiderConfig().nvd_api_key)
    vulnerabilities = client.search(_nvd_keyword(cpe, service, version), results_per_page=50)
    return [_format_nvd_vulnerability(vuln) for vuln in vulnerabilities]


def _fetch_kev(cve_ids: list[str]) -> dict[str, Any]:
    """Check CISA Known Exploited Vulnerabilities catalog through the shared repository."""
    return KEVClient().lookup(cve_ids)


def _fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for CVEs through the shared intelligence repository."""
    return EPSSClient().batch_score(cve_ids)


async def fetch_all_async(
    cpe: str,
    service: str,
    version: str,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, float]]:
    """Fetch NVD, KEV, and EPSS data without blocking graph waves."""
    nvd_client = NVDAPI(api_key=SpiderConfig().nvd_api_key)
    vulnerabilities = await nvd_client.search_async(_nvd_keyword(cpe, service, version), 50)
    cves = [_format_nvd_vulnerability(vuln) for vuln in vulnerabilities]
    cve_ids = [cve["cve_id"] for cve in cves]
    kev_task = asyncio.create_task(KEVClient().lookup_async(cve_ids))
    epss_task = asyncio.create_task(EPSSClient().batch_score_async(cve_ids))
    kev_data, epss_data = await asyncio.gather(kev_task, epss_task)
    return cves, kev_data, epss_data


async def cve_intelligence_async(
    service: str,
    version: str,
    cpe: str = "",
    limit: int = 10,
    **kwargs: Any,
) -> str:
    """Async-compatible CVE lookup across NVD, CISA KEV, and EPSS."""
    cves, kev_data, epss_data = await fetch_all_async(cpe, service, version)
    return _build_response(service, version, cves, kev_data, epss_data, limit)


def _build_response(
    service: str,
    version: str,
    cves: list[dict[str, Any]],
    kev_data: dict[str, Any],
    epss_data: dict[str, float],
    limit: int,
) -> str:
    """Build the tool JSON response from normalized CVE intelligence."""
    if not cves:
        return json.dumps(
            {
                "success": True,
                "cves": [],
                "total": 0,
                "note": f"No CVEs found for {service} {version}",
            }
        )

    for cve in cves:
        cve_id = cve["cve_id"]
        kev = kev_data.get(cve_id, {})
        cve["in_kev"] = kev.get("in_kev", False)
        cve["epss_score"] = epss_data.get(cve_id, 0.0)

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


def cve_intelligence(
    service: str,
    version: str,
    cpe: str = "",
    limit: int = 10,
    **kwargs: Any,
) -> str:
    """Look up known CVEs for a service/version across NVD, CISA KEV, and EPSS.

    Returns a JSON string of prioritized vulnerability findings with exploit
    availability indicators and severity scores. Result set is limited to 'limit'
    items to fit within context windows.
    """
    cves = _fetch_nvd(cpe, service, version)
    cve_ids = [cve["cve_id"] for cve in cves]
    kev_data = _fetch_kev(cve_ids)
    epss_data = _fetch_epss(cve_ids)
    return _build_response(service, version, cves, kev_data, epss_data, limit)


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
