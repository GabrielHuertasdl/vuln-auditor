"""
HTTP Surface Scanner — analyzes HTTP response headers for security posture.

Fetches seed URL + up to 5 crawled endpoints and checks:
  CORS, CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
  Server fingerprint, Cookie flags, Auth header signals.
"""
from __future__ import annotations

import logging

import httpx

from core.schemas import HTTPHeaderAnalysis, HTTPHeaderIssue, SurfaceScanResult

log = logging.getLogger(__name__)

_MAX_SAMPLE_URLS = 5
_UA = "VulnAuditor-Scanner/1.0 (security research; non-malicious)"


def _check_headers(url: str, headers: httpx.Headers, status_code: int) -> HTTPHeaderAnalysis:
    issues: list[HTTPHeaderIssue] = []

    # CORS
    cors = headers.get("access-control-allow-origin")
    if cors == "*":
        issues.append(HTTPHeaderIssue(
            header="Access-Control-Allow-Origin",
            issue="wildcard — any origin can make cross-origin requests",
            severity="high",
            recommendation="Restrict to specific trusted origins instead of *",
        ))

    # CSP
    csp = headers.get("content-security-policy")
    if not csp:
        issues.append(HTTPHeaderIssue(
            header="Content-Security-Policy",
            issue="missing",
            severity="medium",
            recommendation="Add a Content-Security-Policy header to mitigate XSS",
        ))
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        issues.append(HTTPHeaderIssue(
            header="Content-Security-Policy",
            issue="contains unsafe-inline or unsafe-eval",
            severity="medium",
            recommendation="Remove unsafe-inline/unsafe-eval to strengthen CSP",
        ))

    # HSTS
    hsts_val = headers.get("strict-transport-security")
    hsts = bool(hsts_val)
    if not hsts and url.startswith("https://"):
        issues.append(HTTPHeaderIssue(
            header="Strict-Transport-Security",
            issue="missing on HTTPS endpoint",
            severity="medium",
            recommendation="Add HSTS with max-age >= 31536000",
        ))

    # X-Frame-Options
    xfo = headers.get("x-frame-options")
    if not xfo:
        issues.append(HTTPHeaderIssue(
            header="X-Frame-Options",
            issue="missing — clickjacking not mitigated",
            severity="low",
            recommendation="Add X-Frame-Options: DENY or SAMEORIGIN",
        ))

    # X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    xcto_ok = xcto == "nosniff"
    if not xcto_ok:
        issues.append(HTTPHeaderIssue(
            header="X-Content-Type-Options",
            issue="missing or not set to nosniff",
            severity="low",
            recommendation="Add X-Content-Type-Options: nosniff",
        ))

    # Server fingerprint
    server = headers.get("server")
    if server:
        issues.append(HTTPHeaderIssue(
            header="Server",
            issue=f"version exposed: {server}",
            severity="informational",
            recommendation="Remove or obscure the Server header",
        ))

    # Cookies
    raw_cookies = headers.get_list("set-cookie") if hasattr(headers, "get_list") else []
    cookie_summaries: list[str] = []
    for cookie in raw_cookies:
        name = cookie.split("=")[0].strip()
        flags: list[str] = []
        cl = cookie.lower()
        if "secure" not in cl:
            flags.append("missing Secure")
        if "httponly" not in cl:
            flags.append("missing HttpOnly")
        if "samesite" not in cl:
            flags.append("missing SameSite")
        if flags:
            issues.append(HTTPHeaderIssue(
                header="Set-Cookie",
                issue=f"'{name}': {', '.join(flags)}",
                severity="medium",
                recommendation=f"Add Secure; HttpOnly; SameSite=Strict to '{name}'",
            ))
        cookie_summaries.append(f"{name} [{'OK' if not flags else ', '.join(flags)}]")

    # Auth signals
    auth_signals: list[str] = []
    www_auth = headers.get("www-authenticate", "").lower()
    if "basic" in www_auth:
        auth_signals.append("Basic auth")
    if "bearer" in www_auth:
        auth_signals.append("Bearer token")
    if "digest" in www_auth:
        auth_signals.append("Digest auth")

    return HTTPHeaderAnalysis(
        url=url,
        status_code=status_code,
        cors_policy=cors,
        csp_policy=csp,
        hsts=hsts,
        x_frame_options=xfo,
        x_content_type_options=xcto_ok,
        server_header=server,
        cookies=cookie_summaries,
        auth_signals=auth_signals,
        issues=issues,
    )


class SurfaceScanner:
    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def scan(
        self,
        seed_url: str,
        crawled_urls: list[str],
        scan_id: str,
    ) -> SurfaceScanResult:
        sample = [seed_url] + [u for u in crawled_urls if u != seed_url][:_MAX_SAMPLE_URLS]
        analyzed: list[HTTPHeaderAnalysis] = []

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": _UA},
        ) as client:
            for url in sample:
                try:
                    response = await client.get(url)
                    analysis = _check_headers(url, response.headers, response.status_code)
                    analyzed.append(analysis)
                except Exception as e:
                    log.debug("Surface scan error for %s: %s", url, e)

        return SurfaceScanResult(
            scan_id=scan_id,
            analyzed_urls=analyzed,
            total_issues=sum(len(a.issues) for a in analyzed),
        )
