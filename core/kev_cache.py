"""
CISA Known Exploited Vulnerabilities (KEV) catalog — Phase 3.

Downloads and caches the CISA KEV JSON feed. The catalog is refreshed at
most once per process lifetime (TTL gated). KEV membership is a strong
exploitation signal: these vulnerabilities are actively exploited in the wild
and have CISA-mandated remediation deadlines for federal agencies.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
from __future__ import annotations

import logging
import time
from typing import TypedDict

import httpx

log = logging.getLogger(__name__)

_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_REFRESH_INTERVAL = 86_400  # 24 h
_TIMEOUT = 15.0

# In-memory store
_kev_set: set[str] = set()          # uppercase CVE IDs
_kev_meta: dict[str, "_KevEntry"] = {}  # CVE ID → metadata
_last_fetched: float = 0.0


class _KevEntry(TypedDict):
    cve_id: str
    vendor: str
    product: str
    name: str
    due_date: str | None


async def refresh_kev(force: bool = False) -> None:
    """Download/update the KEV catalog (no-op if recently refreshed)."""
    global _last_fetched
    if not force and time.time() - _last_fetched < _REFRESH_INTERVAL:
        return
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(_KEV_URL)
            resp.raise_for_status()
            catalog = resp.json()
        new_set: set[str] = set()
        new_meta: dict[str, _KevEntry] = {}
        for entry in catalog.get("vulnerabilities", []):
            cve = entry.get("cveID", "").upper()
            if not cve:
                continue
            new_set.add(cve)
            new_meta[cve] = _KevEntry(
                cve_id=cve,
                vendor=entry.get("vendorProject", ""),
                product=entry.get("product", ""),
                name=entry.get("vulnerabilityName", ""),
                due_date=entry.get("dueDate"),
            )
        _kev_set.clear()
        _kev_set.update(new_set)
        _kev_meta.clear()
        _kev_meta.update(new_meta)
        _last_fetched = time.time()
        log.info("KEV catalog updated: %d entries", len(_kev_set))
    except Exception as e:
        log.warning("KEV catalog unavailable: %s", e)


def is_in_kev(cve_id: str) -> bool:
    return cve_id.upper() in _kev_set


def get_kev_entry(cve_id: str) -> _KevEntry | None:
    return _kev_meta.get(cve_id.upper())


def kev_due_date(cve_id: str) -> str | None:
    entry = get_kev_entry(cve_id)
    return entry["due_date"] if entry else None
