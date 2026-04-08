"""CISA Known Exploited Vulnerabilities catalog.

Downloaded from CISA's public API. Cached locally with daily refresh.
"""

from datetime import datetime, timedelta

import requests


class KEVClient:
    """CISA Known Exploited Vulnerabilities client."""

    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        self._entries = None
        self._last_fetch = None

    def _fetch(self) -> list[dict]:
        if (
            self._entries
            and self._last_fetch
            and (datetime.now() - self._last_fetch) < timedelta(hours=24)
        ):
            return self._entries
        resp = requests.get(self.URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        self._entries = data.get("vulnerabilities", [])
        self._last_fetch = datetime.now()
        return self._entries

    def is_exploited(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog (actively exploited in the wild)."""
        return any(v.get("cveID") == cve_id for v in self._fetch())
