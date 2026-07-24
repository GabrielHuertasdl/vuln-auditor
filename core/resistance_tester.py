"""
Resistance Tester — active heuristic probing of endpoints.

Sends ≤3 requests per endpoint to detect common web vulnerabilities:
  SQLi (error-based), XSS reflection, path traversal,
  open redirect, SSRF hint.

NOT a full scanner. Quick signal only — false positives possible.
"""
from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from core.schemas import ResistanceProbeResult, ResistanceTestResult

log = logging.getLogger(__name__)

_PROBE_TIMEOUT = 8.0
_MAX_ENDPOINTS = 20
_MAX_REQUESTS_PER_ENDPOINT = 3

_UA = "VulnAuditor-ResistanceTester/1.0 (security research; non-malicious)"

_SQLI_ERROR = re.compile(
    r"(sql syntax|mysql_fetch|pg_query|sqlite_error|unclosed quotation|"
    r"ORA-\d{5}|syntax error.*near|unterminated string|division by zero|"
    r"you have an error in your sql)",
    re.IGNORECASE,
)
_XSS_MARKER = "xss-vulnaudit-marker"
_REDIRECT_CANARY = "//evil-vulnaudit-test.example.com"
_SSRF_CANARY = "http://vulnaudit-canary.internal.example.com"

_REDIRECT_PARAMS = {
    "redirect", "next", "url", "return", "returnurl", "goto",
    "location", "dest", "destination", "redir", "ref",
}
_URL_PARAMS = {
    "url", "uri", "endpoint", "host", "server", "target",
    "src", "source", "fetch", "proxy", "link", "path",
}
_FILE_LIKE = re.compile(r"\.(php|html|jsp|asp|txt|conf|log|py)$|/[a-z_-]+$", re.IGNORECASE)

_resistance_semaphore: asyncio.Semaphore | None = None


def _get_resistance_semaphore() -> asyncio.Semaphore:
    global _resistance_semaphore
    if _resistance_semaphore is None:
        _resistance_semaphore = asyncio.Semaphore(2)
    return _resistance_semaphore


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def _probe_sqli(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    original_value: str,
) -> ResistanceProbeResult | None:
    payload = original_value + "'"
    probe_url = _inject_param(url, param, payload)
    try:
        resp = await client.get(probe_url)
        body = resp.text[:8000]
        m = _SQLI_ERROR.search(body)
        if m or resp.status_code == 500:
            snippet = m.group(0)[:80] if m else f"HTTP {resp.status_code}"
            return ResistanceProbeResult(
                url=url,
                probe_type="sqli",
                parameter=param,
                vulnerable=True,
                severity="high",
                evidence=f"param={param!r} payload=quote → {resp.status_code}, body match: {snippet!r}",
                request_count=1,
            )
    except Exception as e:
        log.debug("SQLi probe error %s param=%s: %s", url, param, e)
    return None


async def _probe_xss(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    original_value: str,
) -> ResistanceProbeResult | None:
    payload = f"<{_XSS_MARKER}>"
    probe_url = _inject_param(url, param, payload)
    try:
        resp = await client.get(probe_url)
        if payload in resp.text:
            offset = resp.text.find(payload)
            return ResistanceProbeResult(
                url=url,
                probe_type="xss",
                parameter=param,
                vulnerable=True,
                severity="high",
                evidence=f"param={param!r} marker reflected unencoded at offset {offset}",
                request_count=1,
            )
    except Exception as e:
        log.debug("XSS probe error %s param=%s: %s", url, param, e)
    return None


async def _probe_path_traversal(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    original_value: str,
) -> ResistanceProbeResult | None:
    if not _FILE_LIKE.search(original_value):
        return None
    payload = "../../../../etc/passwd"
    probe_url = _inject_param(url, param, payload)
    try:
        resp = await client.get(probe_url)
        if "root:" in resp.text and "/bin/" in resp.text:
            return ResistanceProbeResult(
                url=url,
                probe_type="path_traversal",
                parameter=param,
                vulnerable=True,
                severity="high",
                evidence=f"param={param!r} payload=../../../../etc/passwd → passwd file content detected",
                request_count=1,
            )
    except Exception as e:
        log.debug("Path traversal probe error %s param=%s: %s", url, param, e)
    return None


async def _probe_open_redirect(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    original_value: str,
) -> ResistanceProbeResult | None:
    if param.lower() not in _REDIRECT_PARAMS:
        return None
    probe_url = _inject_param(url, param, _REDIRECT_CANARY)
    try:
        resp = await client.get(probe_url)
        location = resp.headers.get("location", "")
        if resp.status_code in (301, 302, 303, 307, 308) and "evil-vulnaudit-test" in location:
            return ResistanceProbeResult(
                url=url,
                probe_type="open_redirect",
                parameter=param,
                vulnerable=True,
                severity="medium",
                evidence=f"param={param!r} → {resp.status_code} Location: {location[:100]}",
                request_count=1,
            )
    except Exception as e:
        log.debug("Open redirect probe error %s param=%s: %s", url, param, e)
    return None


async def _probe_ssrf(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    original_value: str,
) -> ResistanceProbeResult | None:
    if param.lower() not in _URL_PARAMS:
        return None
    probe_url = _inject_param(url, param, _SSRF_CANARY)
    try:
        resp = await client.get(probe_url)
        # Any successful response when pointing at an internal canary is suspicious
        if resp.status_code == 200 and len(resp.content) > 0:
            return ResistanceProbeResult(
                url=url,
                probe_type="ssrf_hint",
                parameter=param,
                vulnerable=True,
                severity="medium",
                evidence=(
                    f"param={param!r} accepted external URL {_SSRF_CANARY!r} → "
                    f"status {resp.status_code} (possible SSRF)"
                ),
                request_count=1,
            )
    except Exception as e:
        log.debug("SSRF probe error %s param=%s: %s", url, param, e)
    return None


async def _run_probe_safe(coro) -> ResistanceProbeResult | None:
    sem = _get_resistance_semaphore()
    async with sem:
        try:
            return await asyncio.wait_for(coro, timeout=_PROBE_TIMEOUT)
        except (asyncio.TimeoutError, Exception):
            return None


class ResistanceTester:
    def __init__(
        self,
        probe_timeout: float = _PROBE_TIMEOUT,
        max_endpoints: int = _MAX_ENDPOINTS,
        max_requests_per_endpoint: int = _MAX_REQUESTS_PER_ENDPOINT,
    ) -> None:
        self.probe_timeout = probe_timeout
        self.max_endpoints = max_endpoints
        self.max_requests_per_endpoint = max_requests_per_endpoint

    async def test(
        self,
        seed_url: str,
        crawled_urls: list[str],
        scan_id: str,
    ) -> ResistanceTestResult:
        # Collect URLs with query params
        candidate_urls = [seed_url] + crawled_urls
        endpoints_with_params = []
        seen: set[str] = set()
        for url in candidate_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if params and url not in seen:
                seen.add(url)
                endpoints_with_params.append((url, params))

        # Prioritize by param count (more params = more surface)
        endpoints_with_params.sort(key=lambda x: -len(x[1]))
        endpoints = endpoints_with_params[: self.max_endpoints]

        all_probes: list[ResistanceProbeResult] = []

        async with httpx.AsyncClient(
            timeout=self.probe_timeout,
            follow_redirects=False,
            headers={"User-Agent": _UA},
        ) as client:
            for url, params in endpoints:
                budget = [0]  # mutable counter

                for param_name, values in params.items():
                    if budget[0] >= self.max_requests_per_endpoint:
                        break
                    original_val = values[0] if values else ""

                    # Pick probe based on param name heuristics
                    probe_coros = []
                    pname = param_name.lower()

                    if pname in _REDIRECT_PARAMS:
                        probe_coros.append(_probe_open_redirect(client, url, param_name, original_val))
                    elif pname in _URL_PARAMS:
                        probe_coros.append(_probe_ssrf(client, url, param_name, original_val))
                    elif _FILE_LIKE.search(original_val):
                        probe_coros.append(_probe_path_traversal(client, url, param_name, original_val))
                    else:
                        # Generic params: try SQLi first, then XSS if budget allows
                        probe_coros.append(_probe_sqli(client, url, param_name, original_val))
                        if budget[0] + len(probe_coros) < self.max_requests_per_endpoint:
                            probe_coros.append(_probe_xss(client, url, param_name, original_val))

                    for coro in probe_coros:
                        if budget[0] >= self.max_requests_per_endpoint:
                            break
                        result = await _run_probe_safe(coro)
                        budget[0] += 1
                        if result is not None:
                            all_probes.append(result)

        vulnerable_count = sum(1 for p in all_probes if p.vulnerable)
        return ResistanceTestResult(
            scan_id=scan_id,
            probed_endpoints=len(endpoints),
            vulnerable_count=vulnerable_count,
            probes=all_probes,
        )
