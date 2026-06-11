"""Shared intelligence repository and cache tests."""

import asyncio
import sqlite3
import time
from pathlib import Path
from typing import Any

from spider.intelligence.cache import EPSS_TTL_SECONDS, KEV_TTL_SECONDS, NVD_TTL_SECONDS
from spider.intelligence.cve_db import NVDAPI
from spider.intelligence.epss import EPSSClient
from spider.intelligence.kev import KEVClient
from spider.intelligence.repository import IntelligenceRepository, SharedNVDRateLimiter


class FakeResponse:
    """Minimal requests response test double."""

    def __init__(self, payload: dict[str, Any]):
        self.payload = payload

    def raise_for_status(self) -> None:
        """Simulate a successful HTTP response."""

    def json(self) -> dict[str, Any]:
        """Return the configured JSON payload."""
        return self.payload


def _repository(tmp_path: Path) -> IntelligenceRepository:
    return IntelligenceRepository(cache_path=tmp_path / "intelligence.db", max_workers=2)


def test_nvd_cache_is_persistent_across_client_instances(tmp_path, monkeypatch):
    """NVD cache state lives in the shared repository, not each client instance."""
    repository = _repository(tmp_path)
    calls = 0

    def fake_get(*args: Any, **kwargs: Any) -> FakeResponse:
        nonlocal calls
        calls += 1
        return FakeResponse({"vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}]})

    monkeypatch.setattr(
        "spider.intelligence.repository.SharedNVDRateLimiter.wait", lambda self: None
    )
    monkeypatch.setattr("spider.intelligence.cve_db.requests.get", fake_get)

    first = NVDAPI(repository=repository).lookup_cve("CVE-2026-0001")
    second = NVDAPI(repository=repository).lookup_cve("CVE-2026-0001")

    assert calls == 1
    assert first == second
    assert first["cve"]["id"] == "CVE-2026-0001"


def test_epss_and_kev_share_persistent_cache(tmp_path, monkeypatch):
    """EPSS and KEV clients reuse SQLite cache entries across instances."""
    repository = _repository(tmp_path)
    epss_calls = 0
    kev_calls = 0

    def fake_epss_get(*args: Any, **kwargs: Any) -> FakeResponse:
        nonlocal epss_calls
        epss_calls += 1
        return FakeResponse({"data": [{"cve": "CVE-2026-0002", "epss": "0.42"}]})

    def fake_kev_get(*args: Any, **kwargs: Any) -> FakeResponse:
        nonlocal kev_calls
        kev_calls += 1
        return FakeResponse(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-0002",
                        "dueDate": "2026-07-01",
                        "shortDescription": "Test vulnerability",
                    }
                ]
            }
        )

    def fake_get(url: str, *args: Any, **kwargs: Any) -> FakeResponse:
        if "api.first.org" in url:
            return fake_epss_get(url, *args, **kwargs)
        return fake_kev_get(url, *args, **kwargs)

    monkeypatch.setattr("requests.get", fake_get)

    assert EPSSClient(repository=repository).get_score("CVE-2026-0002") == 0.42
    assert EPSSClient(repository=repository).get_score("CVE-2026-0002") == 0.42
    assert KEVClient(repository=repository).is_exploited("CVE-2026-0002") is True
    assert KEVClient(repository=repository).is_exploited("CVE-2026-0002") is True

    assert epss_calls == 1
    assert kev_calls == 1


def test_epss_batch_score_batches_missing_cves_and_caches_per_cve(tmp_path, monkeypatch):
    """Batch EPSS lookups should preserve the 50-CVE API batching optimisation."""
    repository = _repository(tmp_path)
    requested_batches: list[str] = []

    def fake_get(*args: Any, **kwargs: Any) -> FakeResponse:
        cve_param = kwargs.get("params", {}).get("cve", "")
        requested_batches.append(cve_param)
        return FakeResponse(
            {
                "data": [
                    {"cve": cve_id, "epss": "0.5"}
                    for cve_id in cve_param.split(",")
                    if cve_id
                ]
            }
        )

    monkeypatch.setattr("spider.intelligence.epss.requests.get", fake_get)

    cve_ids = [f"CVE-2026-{i:04d}" for i in range(120)]
    scores = EPSSClient(repository=repository).batch_score(cve_ids)
    cached_scores = EPSSClient(repository=repository).batch_score(cve_ids)

    assert len(scores) == 120
    assert cached_scores == scores
    assert requested_batches == [
        ",".join(cve_ids[:50]),
        ",".join(cve_ids[50:100]),
        ",".join(cve_ids[100:]),
    ]


def test_documented_ttls_are_persisted(tmp_path):
    """NVD, EPSS, and KEV TTLs are 24-hour SQLite expiration windows."""
    repository = _repository(tmp_path)
    repository.cache.set("nvd:cve", "CVE-2026-0003", {"ok": True}, NVD_TTL_SECONDS)
    repository.cache.set("epss:score", "CVE-2026-0003", 0.7, EPSS_TTL_SECONDS)
    repository.cache.set("kev:catalog", "catalog", [], KEV_TTL_SECONDS)

    with sqlite3.connect(tmp_path / "intelligence.db") as conn:
        rows = conn.execute(
            "SELECT source, ROUND(expires_at - created_at) FROM intelligence_cache ORDER BY source"
        ).fetchall()

    assert rows == [("epss:score", 86400.0), ("kev:catalog", 86400.0), ("nvd:cve", 86400.0)]


def test_expired_cache_rows_are_not_returned(tmp_path):
    """Expired rows are deleted and treated as misses."""
    repository = _repository(tmp_path)
    repository.cache.set("nvd:cve", "expired", {"stale": True}, ttl_seconds=-1)

    assert repository.cache.get("nvd:cve", "expired") is None

    with sqlite3.connect(tmp_path / "intelligence.db") as conn:
        count = conn.execute("SELECT COUNT(*) FROM intelligence_cache").fetchone()[0]
    assert count == 0


def test_nvd_rate_limiter_is_shared_across_instances(tmp_path, monkeypatch):
    """Anonymous NVD clients coordinate through the same shared limiter."""
    SharedNVDRateLimiter._limiters = {}
    sleeps: list[float] = []
    limiter = SharedNVDRateLimiter.for_api_key("")
    limiter.interval_seconds = 10.0

    monkeypatch.setattr(
        "spider.intelligence.repository.time.sleep", lambda seconds: sleeps.append(seconds)
    )
    monkeypatch.setattr("spider.intelligence.repository.time.monotonic", lambda: 100.0)

    assert SharedNVDRateLimiter.for_api_key("") is limiter
    repository = _repository(tmp_path)
    NVDAPI(repository=repository).repository.nvd_rate_limiter("").wait()
    NVDAPI(repository=repository).repository.nvd_rate_limiter("").wait()

    assert sleeps == [10.0]


async def test_async_lookup_runs_blocking_http_in_executor(tmp_path, monkeypatch):
    """Async client methods avoid blocking the event loop with synchronous requests."""
    repository = _repository(tmp_path)

    def slow_get(*args: Any, **kwargs: Any) -> FakeResponse:
        time.sleep(0.05)
        return FakeResponse({"vulnerabilities": [{"cve": {"id": "CVE-2026-0004"}}]})

    monkeypatch.setattr(
        "spider.intelligence.repository.SharedNVDRateLimiter.wait", lambda self: None
    )
    monkeypatch.setattr("spider.intelligence.cve_db.requests.get", slow_get)

    cve_task = asyncio.create_task(NVDAPI(repository=repository).lookup_cve_async("CVE-2026-0004"))
    sleep_task = asyncio.create_task(asyncio.sleep(0.01, result="event-loop-advanced"))

    assert await sleep_task == "event-loop-advanced"
    assert (await cve_task)["cve"]["id"] == "CVE-2026-0004"
