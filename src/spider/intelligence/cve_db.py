"""NVD API 2.0 client backed by shared caching and rate limiting.

NVD rate limit: 0.6 req/sec without API key, 5 req/sec with key.
Caching: SQLite cache with 24h TTL.
"""

from typing import Any

import requests

from spider.intelligence.cache import NVD_TTL_SECONDS
from spider.intelligence.repository import IntelligenceRepository

NVD_SOURCE_CVE = "nvd:cve"
NVD_SOURCE_CPE = "nvd:cpe"
NVD_SOURCE_KEYWORD = "nvd:keyword"


class NVDAPI:
    """NIST National Vulnerability Database API 2.0 client."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str = "", repository: IntelligenceRepository | None = None):
        self.api_key = api_key
        self.repository = repository or IntelligenceRepository.default()

    def _headers(self) -> dict[str, str]:
        return {"apiKey": self.api_key} if self.api_key else {}

    def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        self.repository.nvd_rate_limiter(self.api_key).wait()
        resp = requests.get(self.BASE_URL, params=params, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        return resp.json()

    def lookup_cve(self, cve_id: str) -> dict[str, Any]:
        """Look up a single CVE using the shared persistent cache."""
        cached = self.repository.cache.get(NVD_SOURCE_CVE, cve_id)
        if cached is not None:
            return cached
        data = self._get({"cveId": cve_id})
        result = data.get("vulnerabilities", [{}])[0] if data.get("vulnerabilities") else {}
        self.repository.cache.set(NVD_SOURCE_CVE, cve_id, result, NVD_TTL_SECONDS)
        return result

    async def lookup_cve_async(self, cve_id: str) -> dict[str, Any]:
        """Async-compatible CVE lookup that runs blocking work in a controlled executor."""
        return await self.repository.run_blocking(self.lookup_cve, cve_id)

    def lookup_by_cpe(self, cpe: str) -> list[dict[str, Any]]:
        """Look up all CVEs affecting a CPE using the shared persistent cache."""
        cached = self.repository.cache.get(NVD_SOURCE_CPE, cpe)
        if cached is not None:
            return cached
        data = self._get({"cpeName": cpe})
        result = data.get("vulnerabilities", [])
        self.repository.cache.set(NVD_SOURCE_CPE, cpe, result, NVD_TTL_SECONDS)
        return result

    async def lookup_by_cpe_async(self, cpe: str) -> list[dict[str, Any]]:
        """Async-compatible CPE lookup that runs blocking work in a controlled executor."""
        return await self.repository.run_blocking(self.lookup_by_cpe, cpe)

    def search(self, keyword: str, results_per_page: int = 50) -> list[dict[str, Any]]:
        """Search NVD by keyword using the shared persistent cache."""
        cache_key = f"{keyword}:{results_per_page}"
        cached = self.repository.cache.get(NVD_SOURCE_KEYWORD, cache_key)
        if cached is not None:
            return cached
        data = self._get({"keywordSearch": keyword, "resultsPerPage": results_per_page})
        result = data.get("vulnerabilities", [])
        self.repository.cache.set(NVD_SOURCE_KEYWORD, cache_key, result, NVD_TTL_SECONDS)
        return result

    async def search_async(self, keyword: str, results_per_page: int = 50) -> list[dict[str, Any]]:
        """Async-compatible keyword search that runs blocking work in a controlled executor."""
        return await self.repository.run_blocking(self.search, keyword, results_per_page)
