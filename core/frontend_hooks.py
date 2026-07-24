"""
Frontend Hooks Detector — passive client-side security analyzer.

Fetches HTML pages and inline/external JS to detect:
  - Dangerous DOM sinks (eval, innerHTML, document.write, etc.)
  - Exposed credentials/API keys in JS
  - postMessage calls without origin check
  - Open redirect patterns via window.location assignment
"""
from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urljoin

import httpx

from core.schemas import FrontendHookIssue, FrontendHooksResult

log = logging.getLogger(__name__)

_MAX_PAGES = 10
_MAX_SCRIPTS_PER_PAGE = 5
_TIMEOUT = 8.0
_RATE_INTERVAL = 0.5  # 2 req/s
_SNIPPET_LEN = 120

_UA = "VulnAuditor-HooksScanner/1.0 (security research; non-malicious)"

_DANGEROUS_SINKS = re.compile(
    r"(eval\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|document\.writeln\s*\()",
    re.IGNORECASE,
)
_POSTMESSAGE = re.compile(r"\.postMessage\s*\(", re.IGNORECASE)
_ORIGIN_CHECK = re.compile(r"event\.origin\s*(===|!==|==)", re.IGNORECASE)
_OPEN_REDIRECT = re.compile(
    r"(?:window\.location|location\.href|location\.replace\s*\()"
    r"\s*=\s*[^;]*?(?:location|url|redirect|href|next|return)\s*",
    re.IGNORECASE,
)
_CREDENTIAL_PATTERN = re.compile(
    r'(?:api[_-]?key|apikey|token|secret|password|authorization|auth_token|access_token)'
    r'\s*[=:]\s*["\']([A-Za-z0-9+/\-_]{16,})["\']',
    re.IGNORECASE,
)
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_SCRIPT_INLINE = re.compile(
    r"<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
_SCRIPT_SRC = re.compile(
    r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
    re.IGNORECASE,
)


def _snippet(text: str, pos: int) -> str:
    start = max(0, pos - 20)
    end = min(len(text), pos + _SNIPPET_LEN)
    return text[start:end].strip().replace("\n", " ")


def _check_dangerous_sinks(text: str, source_url: str) -> list[FrontendHookIssue]:
    issues: list[FrontendHookIssue] = []
    seen: set[str] = set()
    for m in _DANGEROUS_SINKS.finditer(text):
        sink = m.group(1).split("(")[0].split("=")[0].strip()
        evidence = _snippet(text, m.start())
        key = f"{sink}:{evidence[:40]}"
        if key not in seen:
            seen.add(key)
            issues.append(FrontendHookIssue(
                url=source_url,
                issue_type="dangerous_sink",
                sink_name=sink,
                evidence=evidence,
                severity="high",
            ))
    return issues


def _check_postmessage(text: str, source_url: str) -> list[FrontendHookIssue]:
    issues: list[FrontendHookIssue] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if _POSTMESSAGE.search(line):
            context_start = max(0, i - 20)
            context_end = min(len(lines), i + 20)
            context = "\n".join(lines[context_start:context_end])
            if not _ORIGIN_CHECK.search(context):
                issues.append(FrontendHookIssue(
                    url=source_url,
                    issue_type="postmessage_no_origin",
                    sink_name="postMessage",
                    evidence=line.strip()[:_SNIPPET_LEN],
                    severity="medium",
                    line_hint=f"~line {i + 1}",
                ))
    return issues


def _check_credentials(text: str, source_url: str) -> list[FrontendHookIssue]:
    issues: list[FrontendHookIssue] = []
    seen: set[str] = set()
    for m in _CREDENTIAL_PATTERN.finditer(text):
        val = m.group(1)
        key = val[:8]
        if key not in seen:
            seen.add(key)
            masked = val[:4] + "***" + val[-2:]
            issues.append(FrontendHookIssue(
                url=source_url,
                issue_type="exposed_credential",
                sink_name=None,
                evidence=f"{m.group(0)[:40].split('=')[0]} = '{masked}...'",
                severity="high",
            ))
    for m in _AWS_KEY.finditer(text):
        key = m.group(0)[:4]
        if key not in seen:
            seen.add(key)
            issues.append(FrontendHookIssue(
                url=source_url,
                issue_type="exposed_credential",
                sink_name="AWS_ACCESS_KEY",
                evidence=f"AKIA{m.group(0)[4:8]}***",
                severity="high",
            ))
    return issues


def _check_open_redirects(text: str, source_url: str) -> list[FrontendHookIssue]:
    issues: list[FrontendHookIssue] = []
    seen: set[str] = set()
    for m in _OPEN_REDIRECT.finditer(text):
        evidence = _snippet(text, m.start())
        key = evidence[:40]
        if key not in seen:
            seen.add(key)
            issues.append(FrontendHookIssue(
                url=source_url,
                issue_type="open_redirect",
                sink_name="window.location",
                evidence=evidence,
                severity="medium",
            ))
    return issues


def _analyze_text(text: str, source_url: str) -> list[FrontendHookIssue]:
    issues: list[FrontendHookIssue] = []
    issues.extend(_check_dangerous_sinks(text, source_url))
    issues.extend(_check_postmessage(text, source_url))
    issues.extend(_check_credentials(text, source_url))
    issues.extend(_check_open_redirects(text, source_url))
    return issues


def _extract_inline_scripts(html: str) -> list[str]:
    return [m.group(1) for m in _SCRIPT_INLINE.finditer(html) if m.group(1).strip()]


def _extract_script_srcs(html: str, base_url: str) -> list[str]:
    srcs = []
    for m in _SCRIPT_SRC.finditer(html):
        href = m.group(1)
        if href.startswith("//"):
            href = "https:" + href
        abs_url = href if href.startswith("http") else urljoin(base_url, href)
        srcs.append(abs_url)
    return srcs


class FrontendHooksDetector:
    def __init__(
        self,
        max_pages: int = _MAX_PAGES,
        max_scripts_per_page: int = _MAX_SCRIPTS_PER_PAGE,
        timeout: float = _TIMEOUT,
    ) -> None:
        self.max_pages = max_pages
        self.max_scripts_per_page = max_scripts_per_page
        self.timeout = timeout

    async def analyze(
        self,
        seed_url: str,
        crawled_urls: list[str],
        scan_id: str,
    ) -> FrontendHooksResult:
        pages = [seed_url] + [u for u in crawled_urls if u != seed_url][: self.max_pages - 1]
        all_issues: list[FrontendHookIssue] = []
        fetched_scripts: set[str] = set()
        last_req_time = 0.0
        analyzed_count = 0

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": _UA},
        ) as client:
            for page_url in pages:
                # Rate limit
                now = asyncio.get_event_loop().time()
                elapsed = now - last_req_time
                if elapsed < _RATE_INTERVAL:
                    await asyncio.sleep(_RATE_INTERVAL - elapsed)
                last_req_time = asyncio.get_event_loop().time()

                try:
                    resp = await client.get(page_url)
                    ct = resp.headers.get("content-type", "")
                    if "text/html" not in ct and "javascript" not in ct:
                        continue
                    html = resp.text
                    analyzed_count += 1

                    # Inline scripts
                    for script_text in _extract_inline_scripts(html):
                        all_issues.extend(_analyze_text(script_text, page_url))

                    # External scripts (deduped across all pages)
                    srcs = _extract_script_srcs(html, page_url)
                    for src_url in srcs[: self.max_scripts_per_page]:
                        if src_url in fetched_scripts:
                            continue
                        fetched_scripts.add(src_url)
                        now = asyncio.get_event_loop().time()
                        elapsed = now - last_req_time
                        if elapsed < _RATE_INTERVAL:
                            await asyncio.sleep(_RATE_INTERVAL - elapsed)
                        last_req_time = asyncio.get_event_loop().time()
                        try:
                            js_resp = await client.get(src_url)
                            if js_resp.status_code == 200:
                                all_issues.extend(_analyze_text(js_resp.text, src_url))
                        except Exception as e:
                            log.debug("JS fetch error %s: %s", src_url, e)

                except Exception as e:
                    log.debug("Page fetch error %s: %s", page_url, e)

        return FrontendHooksResult(
            scan_id=scan_id,
            analyzed_urls=analyzed_count,
            issues=all_issues,
            total_issues=len(all_issues),
        )
