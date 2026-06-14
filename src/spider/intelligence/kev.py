"""CISA Known Exploited Vulnerabilities catalog.

Downloaded from CISA's public API. Cached locally with daily refresh.
"""

from typing import Any

import requests

from spider.intelligence.cache import KEV_TTL_SECONDS
from spider.intelligence.repository import IntelligenceRepository

KEV_SOURCE_CATALOG = "kev:catalog"
KEV_CACHE_KEY = "known_exploited_vulnerabilities"


class KEVClient:
    """CISA Known Exploited Vulnerabilities client."""

    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, repository: IntelligenceRepository | None = None):
        self.repository = repository or IntelligenceRepository.default()

    def _fetch(self) -> list[dict[str, Any]]:
        cached = self.repository.cache.get(KEV_SOURCE_CATALOG, KEV_CACHE_KEY)
        if cached is not None:
            return cached
        resp = requests.get(self.URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        entries = data.get("vulnerabilities", [])
        self.repository.cache.set(KEV_SOURCE_CATALOG, KEV_CACHE_KEY, entries, KEV_TTL_SECONDS)
        return entries

    async def fetch_async(self) -> list[dict[str, Any]]:
        """Async-compatible KEV catalog fetch using a controlled executor."""
        return await self.repository.run_blocking(self._fetch)

    def _fetch_dict(self) -> dict[str, Any]:
        """Fetch and index KEV catalog by CVE ID."""
        if not hasattr(self, "_cached_dict"):
            entries = self._fetch()
            self._cached_dict = {item.get("cveID", ""): item for item in entries if "cveID" in item}
        return self._cached_dict

    def is_exploited(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog (actively exploited in the wild)."""
        return cve_id in self._fetch_dict()

    async def is_exploited_async(self, cve_id: str) -> bool:
        """Async-compatible KEV membership check using a controlled executor."""
        return await self.repository.run_blocking(self.is_exploited, cve_id)

    def lookup(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Return KEV metadata for the requested CVE IDs."""
        catalog = self._fetch_dict()
        res = {}
        for cve_id in cve_ids:
            if cve_id in catalog:
                item = catalog[cve_id]
                res[cve_id] = {
                    "in_kev": True,
                    "due_date": item.get("dueDate", ""),
                    "short_description": item.get("shortDescription", ""),
                }
        return res

    async def lookup_async(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Async-compatible KEV metadata lookup."""
        return await self.repository.run_blocking(self.lookup, cve_ids)
