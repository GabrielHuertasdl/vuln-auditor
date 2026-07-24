"""Tests for core/resistance_tester.py."""
from __future__ import annotations

import httpx
import pytest
import respx

from core.resistance_tester import (
    ResistanceTester,
    _REDIRECT_CANARY,
    _inject_param,
    _probe_open_redirect,
    _probe_path_traversal,
    _probe_sqli,
    _probe_ssrf,
    _probe_xss,
)


# ── _inject_param ─────────────────────────────────────────────────────────────

class TestInjectParam:
    def test_replaces_existing_param(self):
        url = "https://example.com/search?q=hello&page=1"
        result = _inject_param(url, "q", "injected")
        assert "q=injected" in result
        assert "page=1" in result

    def test_adds_new_param(self):
        url = "https://example.com/search"
        result = _inject_param(url, "q", "test")
        assert "q=test" in result

    def test_preserves_other_params(self):
        url = "https://example.com/?a=1&b=2&c=3"
        result = _inject_param(url, "b", "INJECTED")
        assert "a=1" in result
        assert "c=3" in result
        assert "b=INJECTED" in result

    def test_handles_no_existing_params(self):
        url = "https://example.com/page"
        result = _inject_param(url, "id", "1")
        assert "id=1" in result
        assert "example.com" in result


# ── _probe_sqli ───────────────────────────────────────────────────────────────

class TestProbeSqli:
    @respx.mock
    async def test_returns_result_on_sql_error_in_body(self):
        url = "https://example.com/search?q=test"
        injected = _inject_param(url, "q", "test'")
        respx.get(injected).mock(
            return_value=httpx.Response(200, text="You have an error in your SQL syntax")
        )
        async with httpx.AsyncClient(follow_redirects=False) as client:
            result = await _probe_sqli(client, url, "q", "test")
        assert result is not None
        assert result.vulnerable is True
        assert result.probe_type == "sqli"
        assert result.severity == "high"

    @respx.mock
    async def test_returns_result_on_500(self):
        url = "https://example.com/page?id=1"
        injected = _inject_param(url, "id", "1'")
        respx.get(injected).mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        async with httpx.AsyncClient(follow_redirects=False) as client:
            result = await _probe_sqli(client, url, "id", "1")
        assert result is not None
        assert result.vulnerable is True

    @respx.mock
    async def test_returns_none_on_normal_response(self):
        url = "https://example.com/search?q=hello"
        injected = _inject_param(url, "q", "hello'")
        respx.get(injected).mock(
            return_value=httpx.Response(200, text="No results found")
        )
        async with httpx.AsyncClient(follow_redirects=False) as client:
            result = await _probe_sqli(client, url, "q", "hello")
        assert result is None

    @respx.mock
    async def test_returns_none_on_connection_error(self):
        url = "https://example.com/page?id=1"
        injected = _inject_param(url, "id", "1'")
        respx.get(injected).mock(side_effect=httpx.ConnectError("refused"))
        async with httpx.AsyncClient(follow_redirects=False) as client:
            result = await _probe_sqli(client, url, "id", "1")
        assert result is None


# ── _probe_xss ────────────────────────────────────────────────────────────────

class TestProbeXss:
    @respx.mock
    async def test_returns_result_on_reflection(self):
        url = "https://example.com/search?q=hello"
        marker = "<xss-vulnaudit-marker>"
        encoded_marker = marker.replace("<", "%3C").replace(">", "%3E")
        # respx matches the URL after injection — the marker is URL-encoded in the query string
        respx.get(url.replace("q=hello", f"q={encoded_marker}")).mock(
            return_value=httpx.Response(200, text=f"Results for: {marker}")
        )
        async with httpx.AsyncClient(follow_redirects=False) as client:
            result = await _probe_xss(client, url, "q", "hello")
        assert result is not None
        assert result.vulnerable is True
        assert result.probe_type == "xss"

    @respx.mock
    async def test_returns_none_when_not_reflected(self):
        url = "https://example.com/search?q=hello"
        marker_encoded = "%3Cxss-vulnaudit-marker%3E"
        respx.get(url.replace("q=hello", f"q={marker_encoded}")).mock(
            return_value=httpx.Response(200, text="Results: nothing found")
        )
        async with httpx.AsyncClient(follow_redirects=False) as client:
            result = await _probe_xss(client, url, "q", "hello")
        assert result is None


# ── _probe_path_traversal ─────────────────────────────────────────────────────

class TestProbePathTraversal:
    @respx.mock
    async def test_skips_non_file_like_values(self):
        url = "https://example.com/page?q=hello"
        async with httpx.AsyncClient(follow_redirects=False) as client:
            result = await _probe_path_traversal(client, url, "q", "hello")
        # "hello" doesn't look like a file path → should skip
        assert result is None

    @respx.mock
    async def test_returns_result_on_passwd_in_body(self):
        url = "https://example.com/download?file=report.php"
        respx.get(url.replace("file=report.php", "file=..%2F..%2F..%2F..%2Fetc%2Fpasswd")).mock(
            return_value=httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\nnobody:x:99:99:")
        )
        async with httpx.AsyncClient(follow_redirects=False) as client:
            result = await _probe_path_traversal(client, url, "file", "report.php")
        assert result is not None
        assert result.vulnerable is True
        assert result.probe_type == "path_traversal"

    @respx.mock
    async def test_returns_none_on_normal_response(self):
        url = "https://example.com/download?file=report.php"
        respx.get(url.replace("file=report.php", "file=..%2F..%2F..%2F..%2Fetc%2Fpasswd")).mock(
            return_value=httpx.Response(200, text="Access denied")
        )
        async with httpx.AsyncClient(follow_redirects=False) as client:
            result = await _probe_path_traversal(client, url, "file", "report.php")
        assert result is None


# ── _probe_open_redirect ──────────────────────────────────────────────────────

class TestProbeOpenRedirect:
    @respx.mock
    async def test_skips_non_redirect_params(self):
        url = "https://example.com/page?q=hello"
        async with httpx.AsyncClient(follow_redirects=False) as client:
            result = await _probe_open_redirect(client, url, "q", "hello")
        assert result is None

    @respx.mock
    async def test_returns_result_on_redirect_to_canary(self):
        url = "https://example.com/login?next=/"
        injected = _inject_param(url, "next", _REDIRECT_CANARY)
        respx.get(injected).mock(
            return_value=httpx.Response(
                302,
                headers={"location": f"https:{_REDIRECT_CANARY}/"},
                text="",
            )
        )
        async with httpx.AsyncClient(follow_redirects=False) as client:
            result = await _probe_open_redirect(client, url, "next", "/")
        assert result is not None
        assert result.vulnerable is True
        assert result.probe_type == "open_redirect"
        assert result.severity == "medium"

    @respx.mock
    async def test_returns_none_when_redirect_to_safe_url(self):
        url = "https://example.com/login?redirect=/"
        injected = _inject_param(url, "redirect", _REDIRECT_CANARY)
        respx.get(injected).mock(
            return_value=httpx.Response(302, headers={"location": "/"}, text="")
        )
        async with httpx.AsyncClient(follow_redirects=False) as client:
            result = await _probe_open_redirect(client, url, "redirect", "/")
        assert result is None


# ── ResistanceTester (integration) ───────────────────────────────────────────

class TestResistanceTester:
    @respx.mock
    async def test_skips_urls_without_params(self):
        # No URLs with query params → 0 endpoints probed
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="home")
        )
        tester = ResistanceTester()
        result = await tester.test(
            "https://example.com/",
            ["https://example.com/about", "https://example.com/contact"],
            "scan-001",
        )
        assert result.probed_endpoints == 0
        assert result.vulnerable_count == 0

    @respx.mock
    async def test_probes_endpoints_with_params(self):
        # Seed URL has params
        seed = "https://example.com/search?q=test"
        # All possible probe injections return safe 200
        respx.get(url__regex=r"https://example\.com/search\?.*").mock(
            return_value=httpx.Response(200, text="safe results")
        )
        tester = ResistanceTester(max_endpoints=5, max_requests_per_endpoint=3)
        result = await tester.test(seed, [], "scan-002")
        assert result.probed_endpoints >= 1

    @respx.mock
    async def test_detects_sqli_vulnerability(self):
        seed = "https://example.com/items?id=1"
        injected = _inject_param(seed, "id", "1'")
        respx.get(injected).mock(
            return_value=httpx.Response(500, text="You have an error in your SQL syntax")
        )
        # All other requests return safe
        respx.get(url__regex=r".*id=.*").mock(
            return_value=httpx.Response(200, text="results")
        )

        tester = ResistanceTester()
        result = await tester.test(seed, [], "scan-003")
        assert result.vulnerable_count >= 1
        sqli_probes = [p for p in result.probes if p.probe_type == "sqli" and p.vulnerable]
        assert len(sqli_probes) >= 1

    @respx.mock
    async def test_respects_max_requests_per_endpoint(self):
        """Never sends more than max_requests_per_endpoint per URL."""
        seed = "https://example.com/page?a=1&b=2&c=3&d=4"
        request_count = 0

        def counting_mock(request):
            nonlocal request_count
            request_count += 1
            return httpx.Response(200, text="ok")

        respx.get(url__regex=r"https://example\.com/page\?.*").mock(side_effect=counting_mock)

        tester = ResistanceTester(max_requests_per_endpoint=2)
        await tester.test(seed, [], "scan-004")

        assert request_count <= 2

    @respx.mock
    async def test_returns_zero_vulnerable_on_all_safe(self):
        seed = "https://example.com/search?q=hello&page=1"
        respx.get(url__regex=r"https://example\.com/search\?.*").mock(
            return_value=httpx.Response(200, text="Normal results page")
        )

        tester = ResistanceTester()
        result = await tester.test(seed, [], "scan-005")

        assert result.vulnerable_count == 0

    @respx.mock
    async def test_prioritizes_urls_with_more_params(self):
        """URLs with more params should be probed first (within max_endpoints)."""
        urls = [
            "https://example.com/a?x=1",
            "https://example.com/b?x=1&y=2&z=3",
        ]
        # Make /b return a SQLi error so it shows up in result.probes
        respx.get(url__regex=r".*b\?.*1%27.*").mock(
            return_value=httpx.Response(500, text="SQL syntax error near '1'")
        )
        respx.get(url__regex=r"https://example\.com/.*").mock(
            return_value=httpx.Response(200, text="safe")
        )

        tester = ResistanceTester(max_endpoints=1)
        result = await tester.test(urls[0], [urls[1]], "scan-006")

        # With max_endpoints=1, /b (3 params) should be picked over /a (1 param)
        assert result.probed_endpoints == 1
        # /b triggered SQLi → shows up in probes
        probed_urls = {p.url for p in result.probes}
        assert any("/b" in u for u in probed_urls)

    @respx.mock
    async def test_handles_connection_errors_gracefully(self):
        seed = "https://example.com/page?q=test"
        respx.get(url__regex=r".*").mock(side_effect=httpx.ConnectError("refused"))

        tester = ResistanceTester()
        # Should not raise
        result = await tester.test(seed, [], "scan-007")
        assert result.vulnerable_count == 0
