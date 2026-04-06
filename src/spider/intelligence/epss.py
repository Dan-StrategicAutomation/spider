"""EPSS -- Exploit Prediction Scoring System.

Predicts the probability that a vulnerability will be exploited in the next 30 days.
"""

import requests
from functools import lru_cache

class EPSSClient:
    """FIRST EPSS client."""

    BASE_URL = "https://api.first.org/data/v1/epss"

    @lru_cache(maxsize=5000)
    def get_score(self, cve_id: str) -> float:
        """Get EPSS score for a CVE (0.0 to 1.0)."""
        try:
            resp = requests.get(f"{self.BASE_URL}?cve={cve_id}", timeout=15)
            resp.raise_for_status()
            data = resp.json()
            entry = data.get("data", [{}])[0]
            return float(entry.get("epss", 0.0))
        except Exception:
            return 0.0
