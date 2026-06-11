"""EPSS -- Exploit Prediction Scoring System.

Predicts the probability that a vulnerability will be exploited in the next 30 days.
"""

import requests

from spider.intelligence.cache import EPSS_TTL_SECONDS
from spider.intelligence.repository import IntelligenceRepository

EPSS_SOURCE_SCORE = "epss:score"
EPSS_BATCH_SIZE = 50


class EPSSClient:
    """FIRST EPSS (Exploit Prediction Scoring System) API client."""

    BASE_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, repository: IntelligenceRepository | None = None):
        self.repository = repository or IntelligenceRepository.default()

    def get_score(self, cve_id: str) -> float:
        """Get EPSS score for a CVE (0.0 to 1.0) using the shared cache."""
        cached = self.repository.cache.get(EPSS_SOURCE_SCORE, cve_id)
        if cached is not None:
            return float(cached)
        score = self._fetch_score(cve_id)
        self.repository.cache.set(EPSS_SOURCE_SCORE, cve_id, score, EPSS_TTL_SECONDS)
        return score

    async def get_score_async(self, cve_id: str) -> float:
        """Async-compatible EPSS lookup that runs blocking HTTP in a controlled executor."""
        return await self.repository.run_blocking(self.get_score, cve_id)

    def batch_score(self, cve_ids: list[str]) -> dict[str, float]:
        """Get EPSS scores using shared per-CVE cache entries and batched API calls."""
        scores: dict[str, float] = {}
        missing: list[str] = []
        for cve_id in cve_ids:
            cached = self.repository.cache.get(EPSS_SOURCE_SCORE, cve_id)
            if cached is None:
                missing.append(cve_id)
            else:
                scores[cve_id] = float(cached)

        for i in range(0, len(missing), EPSS_BATCH_SIZE):
            chunk = missing[i : i + EPSS_BATCH_SIZE]
            fetched = self._fetch_scores(chunk)
            for cve_id in chunk:
                score = fetched.get(cve_id, 0.0)
                scores[cve_id] = score
                self.repository.cache.set(EPSS_SOURCE_SCORE, cve_id, score, EPSS_TTL_SECONDS)

        return scores

    async def batch_score_async(self, cve_ids: list[str]) -> dict[str, float]:
        """Async-compatible batch EPSS lookup."""
        return await self.repository.run_blocking(self.batch_score, cve_ids)

    def _fetch_score(self, cve_id: str) -> float:
        """Fetch one score from API without caching."""
        return self._fetch_scores([cve_id]).get(cve_id, 0.0)

    def _fetch_scores(self, cve_ids: list[str]) -> dict[str, float]:
        """Fetch scores from API without caching, using FIRST's batched CVE query."""
        if not cve_ids:
            return {}
        try:
            resp = requests.get(
                self.BASE_URL,
                params={"cve": ",".join(cve_ids)},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            scores: dict[str, float] = {}
            requested = set(cve_ids)
            for entry in data.get("data", []):
                cve_id = entry.get("cve")
                if cve_id in requested:
                    score = entry.get("epss", 0.0)
                    scores[cve_id] = float(score) if score else 0.0
            return scores
        except Exception:
            return {}
