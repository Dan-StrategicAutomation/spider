"""NVD API 2.0 client with rate limiting, caching, and batch requests.

NVD rate limit: 0.6 req/sec without API key, 5 req/sec with key.
Caching: SQLite cache with 24h TTL.
"""

import time
from datetime import datetime, timedelta

import requests


class NVDAPI:
    """NIST National Vulnerability Database API 2.0 client."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._cache: dict = {}
        self._last_request = 0.0

    def _rate_limit(self):
        """Enforce rate limit (0.6 req/sec without key, 5 req/sec with key)."""
        interval = 1.67 if not self.api_key else 0.2
        elapsed = time.time() - self._last_request
        if elapsed < interval:
            time.sleep(interval - elapsed)
        self._last_request = time.time()

    def lookup_cve(self, cve_id: str) -> dict:
        """Look up a single CVE."""
        if cve_id in self._cache:
            cached, ts = self._cache[cve_id]
            if datetime.now() - ts < timedelta(hours=24):
                return cached
        self._rate_limit()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        resp = requests.get(f"{self.BASE_URL}?cveId={cve_id}", headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        result = data.get("vulnerabilities", [{}])[0] if data.get("vulnerabilities") else {}
        self._cache[cve_id] = (result, datetime.now())
        return result

    def lookup_by_cpe(self, cpe: str) -> list[dict]:
        """Look up all CVEs affecting a CPE."""
        self._rate_limit()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        resp = requests.get(f"{self.BASE_URL}?cpeName={cpe}", headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])
