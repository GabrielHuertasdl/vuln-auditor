"""
EPSS (Exploit Prediction Scoring System) integration — Phase 3.

Queries https://api.first.org/data/v1/epss for CVE exploitation probabilities.
Scores range 0→1 (probability of exploitation in the next 30 days).
Results are cached in memory per process lifetime to avoid redundant API calls.
"""
from __future__ import annotations

import logging
from functools import lru_cache

import httpx

log = logging.getLogger(__name__)

_EPSS_API = "https://api.first.org/data/v1/epss"
_TIMEOUT = 8.0

# In-memory cache: cve_id → (epss_score, percentile)
_cache: dict[str, tuple[float, float]] = {}


async def get_epss_scores(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """
    Fetch EPSS scores for a list of CVE IDs.
    Returns dict: {cve_id: (epss_score, percentile)}
    Silently returns empty dict on network failure.
    """
    if not cve_ids:
        return {}

    to_fetch = [c for c in cve_ids if c not in _cache]
    if to_fetch:
        # EPSS API accepts up to 30 CVEs per request
        for chunk in _chunked(to_fetch, 30):
            params = {"cve": ",".join(chunk)}
            try:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    resp = await client.get(_EPSS_API, params=params)
                    resp.raise_for_status()
                    for item in resp.json().get("data", []):
                        cve = item.get("cve", "").upper()
                        score = float(item.get("epss", 0))
                        pct = float(item.get("percentile", 0))
                        _cache[cve] = (score, pct)
            except Exception as e:
                log.debug("EPSS API unavailable: %s", e)

    return {cve: _cache[cve] for cve in cve_ids if cve in _cache}


def _chunked(lst: list, size: int):
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def epss_risk_level(score: float) -> str:
    """Map EPSS score to risk label."""
    if score >= 0.5:
        return "critical"
    if score >= 0.1:
        return "high"
    if score >= 0.01:
        return "medium"
    if score > 0:
        return "low"
    return "none"
