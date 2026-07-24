"""
URL Architecture Crawler — async BFS over a web target.

Constraints:
  - Max 50 URLs per scan
  - Max depth 2
  - Rate: 1 req/s
  - Respects robots.txt (basic)
  - No JavaScript rendering — raw HTTP only
"""
from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from urllib.parse import urljoin, urlparse

import httpx

from core.schemas import CrawledURL, URLArchitectureResult

log = logging.getLogger(__name__)

_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
    ".zip", ".tar", ".gz",
}

_FORM_PATTERN = re.compile(r"<form[\s>]", re.IGNORECASE)
_LINK_PATTERN = re.compile(r'href=["\']([^"\'#?][^"\']*)["\']', re.IGNORECASE)
_AUTH_PATTERN = re.compile(r"(login|signin|password|authenticate|logout)", re.IGNORECASE)

_UA = "VulnAuditor-Crawler/1.0 (security research; non-malicious)"


class URLArchitectureCrawler:
    def __init__(
        self,
        max_urls: int = 50,
        max_depth: int = 2,
        rate_limit: float = 1.0,
        timeout: float = 10.0,
    ) -> None:
        self.max_urls = max_urls
        self.max_depth = max_depth
        self._interval = 1.0 / rate_limit
        self.timeout = timeout

    async def crawl(self, seed_url: str, scan_id: str) -> URLArchitectureResult:
        parsed_seed = urlparse(seed_url)
        base_domain = f"{parsed_seed.scheme}://{parsed_seed.netloc}"

        robots_url: str | None = None
        sitemap_url: str | None = None
        crawled: list[CrawledURL] = []
        visited: set[str] = set()
        queue: deque[tuple[str, int, list[str]]] = deque()
        queue.append((seed_url, 0, []))

        headers = {"User-Agent": _UA}

        # Check robots.txt
        disallowed: set[str] = set()
        robots_txt_url = f"{base_domain}/robots.txt"
        try:
            async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
                r = await client.get(robots_txt_url, headers=headers)
                if r.status_code == 200:
                    robots_url = robots_txt_url
                    for line in r.text.splitlines():
                        if line.startswith("Disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                disallowed.add(path)
                        if line.lower().startswith("sitemap:") and sitemap_url is None:
                            sitemap_url = line.split(":", 1)[1].strip()
        except Exception:
            pass

        if sitemap_url is None:
            sitemap_url = f"{base_domain}/sitemap.xml"

        forms_found = 0
        redirects_found = 0
        last_req_time = 0.0

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers=headers,
        ) as client:
            while queue and len(crawled) < self.max_urls:
                url, depth, redirect_chain = queue.popleft()
                if url in visited:
                    continue
                visited.add(url)

                # Rate limiting
                now = asyncio.get_event_loop().time()
                elapsed = now - last_req_time
                if elapsed < self._interval:
                    await asyncio.sleep(self._interval - elapsed)
                last_req_time = asyncio.get_event_loop().time()

                parsed = urlparse(url)

                # Skip disallowed paths
                if any(parsed.path.startswith(d) for d in disallowed):
                    continue

                # Skip non-crawlable extensions
                path_lower = parsed.path.lower()
                if any(path_lower.endswith(ext) for ext in _SKIP_EXTENSIONS):
                    continue

                try:
                    response = await client.get(url)
                    actual_url = str(response.url)
                    current_chain = redirect_chain + ([url] if actual_url != url else [])
                    if current_chain:
                        redirects_found += 1

                    body = ""
                    content_type = response.headers.get("content-type", "")
                    if len(response.content) < 500_000:
                        body = response.text

                    has_forms = bool(_FORM_PATTERN.search(body))
                    has_auth = bool(_AUTH_PATTERN.search(body)) or bool(_AUTH_PATTERN.search(url))
                    if has_forms:
                        forms_found += 1

                    crawled.append(CrawledURL(
                        url=actual_url,
                        depth=depth,
                        status_code=response.status_code,
                        content_type=content_type.split(";")[0].strip() or None,
                        has_forms=has_forms,
                        has_auth_signals=has_auth,
                        redirect_chain=current_chain,
                    ))

                    # Enqueue same-domain links from HTML
                    if depth < self.max_depth and "text/html" in content_type:
                        for href in _LINK_PATTERN.findall(body):
                            abs_url = urljoin(actual_url, href).split("#")[0].split("?")[0]
                            if abs_url.startswith(base_domain) and abs_url not in visited:
                                queue.append((abs_url, depth + 1, current_chain))

                except Exception as e:
                    log.debug("Crawl error for %s: %s", url, e)

        return URLArchitectureResult(
            scan_id=scan_id,
            seed_url=seed_url,
            crawled_urls=crawled,
            forms_found=forms_found,
            redirects_found=redirects_found,
            sitemap_url=sitemap_url,
            robots_url=robots_url,
            total_urls_discovered=len(visited),
        )
