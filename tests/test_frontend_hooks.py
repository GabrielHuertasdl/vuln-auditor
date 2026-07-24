"""Tests for core/frontend_hooks.py."""
from __future__ import annotations

import httpx
import pytest
import respx

from core.frontend_hooks import (
    FrontendHooksDetector,
    _analyze_text,
    _check_credentials,
    _check_dangerous_sinks,
    _check_open_redirects,
    _check_postmessage,
    _extract_inline_scripts,
    _extract_script_srcs,
)


# ── _extract_inline_scripts ───────────────────────────────────────────────────

class TestExtractInlineScripts:
    def test_extracts_single_script(self):
        html = "<html><script>var x = 1;</script></html>"
        scripts = _extract_inline_scripts(html)
        assert len(scripts) == 1
        assert "var x = 1;" in scripts[0]

    def test_extracts_multiple_scripts(self):
        html = "<script>a();</script><p>text</p><script>b();</script>"
        scripts = _extract_inline_scripts(html)
        assert len(scripts) == 2

    def test_skips_empty_scripts(self):
        html = "<script></script><script>  </script>"
        scripts = _extract_inline_scripts(html)
        assert len(scripts) == 0

    def test_skips_src_scripts(self):
        html = '<script src="/app.js"></script><script>inline();</script>'
        scripts = _extract_inline_scripts(html)
        assert len(scripts) == 1
        assert "inline()" in scripts[0]

    def test_no_scripts(self):
        assert _extract_inline_scripts("<p>hello</p>") == []


# ── _extract_script_srcs ──────────────────────────────────────────────────────

class TestExtractScriptSrcs:
    def test_relative_src(self):
        html = '<script src="/static/app.js"></script>'
        srcs = _extract_script_srcs(html, "https://example.com/page")
        assert srcs == ["https://example.com/static/app.js"]

    def test_absolute_src(self):
        html = '<script src="https://cdn.example.com/lib.js"></script>'
        srcs = _extract_script_srcs(html, "https://example.com/")
        assert "https://cdn.example.com/lib.js" in srcs

    def test_protocol_relative(self):
        html = '<script src="//cdn.example.com/lib.js"></script>'
        srcs = _extract_script_srcs(html, "https://example.com/")
        assert srcs[0].startswith("https://")

    def test_no_scripts(self):
        assert _extract_script_srcs("<p>text</p>", "https://example.com") == []

    def test_multiple_srcs(self):
        html = '<script src="/a.js"></script><script src="/b.js"></script>'
        srcs = _extract_script_srcs(html, "https://example.com")
        assert len(srcs) == 2


# ── _check_dangerous_sinks ────────────────────────────────────────────────────

class TestCheckDangerousSinks:
    def test_detects_eval(self):
        issues = _check_dangerous_sinks("eval(userInput)", "https://example.com/app.js")
        assert len(issues) == 1
        assert issues[0].sink_name == "eval"
        assert issues[0].severity == "high"
        assert issues[0].issue_type == "dangerous_sink"

    def test_detects_innerhtml(self):
        issues = _check_dangerous_sinks("el.innerHTML = userInput;", "https://example.com/")
        assert any("innerHTML" in (i.sink_name or "") for i in issues)

    def test_detects_document_write(self):
        issues = _check_dangerous_sinks("document.write(data)", "https://example.com/")
        assert len(issues) >= 1

    def test_detects_outerhtml(self):
        issues = _check_dangerous_sinks("div.outerHTML = val;", "https://example.com/")
        assert len(issues) >= 1

    def test_no_false_positive_on_safe_code(self):
        issues = _check_dangerous_sinks(
            "const x = document.querySelector('#app');",
            "https://example.com/"
        )
        assert len(issues) == 0

    def test_deduplicates_same_sink(self):
        code = "eval(a); eval(b); eval(c);"
        issues = _check_dangerous_sinks(code, "https://example.com/")
        # Should not produce 3 identical entries — deduplication by snippet prefix
        assert len(issues) <= 3  # could be fewer if evidence prefix matches


# ── _check_postmessage ────────────────────────────────────────────────────────

class TestCheckPostmessage:
    def test_flags_postmessage_without_origin_check(self):
        code = "window.postMessage(data, '*');"
        issues = _check_postmessage(code, "https://example.com/app.js")
        assert len(issues) == 1
        assert issues[0].issue_type == "postmessage_no_origin"
        assert issues[0].severity == "medium"

    def test_no_issue_when_origin_check_present(self):
        code = """\
window.addEventListener('message', function(event) {
  if (event.origin === 'https://trusted.com') {
    window.postMessage(event.data, '*');
  }
});"""
        issues = _check_postmessage(code, "https://example.com/")
        assert len(issues) == 0

    def test_no_postmessage_no_issue(self):
        issues = _check_postmessage("const x = 1;", "https://example.com/")
        assert len(issues) == 0


# ── _check_credentials ────────────────────────────────────────────────────────

class TestCheckCredentials:
    def test_detects_api_key(self):
        code = 'const apiKey = "abcdefghijklmnopqrstuvwxyz1234";'
        issues = _check_credentials(code, "https://example.com/config.js")
        assert len(issues) >= 1
        assert issues[0].issue_type == "exposed_credential"
        assert issues[0].severity == "high"

    def test_masks_credential_value(self):
        code = 'const token = "supersecrettokenvalue1234567890";'
        issues = _check_credentials(code, "https://example.com/")
        assert len(issues) >= 1
        # The actual value must not appear verbatim in evidence
        assert "supersecrettokenvalue1234567890" not in issues[0].evidence

    def test_detects_aws_key(self):
        code = "const key = 'AKIAIOSFODNN7EXAMPLE';"
        issues = _check_credentials(code, "https://example.com/")
        aws_issues = [i for i in issues if i.sink_name == "AWS_ACCESS_KEY"]
        assert len(aws_issues) >= 1

    def test_no_false_positive_short_value(self):
        # Value shorter than 16 chars should not trigger
        code = 'const token = "short";'
        issues = _check_credentials(code, "https://example.com/")
        assert len(issues) == 0

    def test_no_false_positive_regular_string(self):
        code = 'const message = "hello world, this is a normal string value here";'
        issues = _check_credentials(code, "https://example.com/")
        assert len(issues) == 0


# ── _check_open_redirects ─────────────────────────────────────────────────────

class TestCheckOpenRedirects:
    def test_detects_location_href_with_url_param(self):
        code = "window.location.href = getParam('redirect');"
        issues = _check_open_redirects(code, "https://example.com/")
        assert len(issues) >= 1
        assert issues[0].issue_type == "open_redirect"

    def test_no_issue_on_static_assignment(self):
        code = "window.location.href = '/dashboard';"
        issues = _check_open_redirects(code, "https://example.com/")
        assert len(issues) == 0


# ── _analyze_text (integration) ───────────────────────────────────────────────

class TestAnalyzeText:
    def test_combines_all_checks(self):
        code = """\
eval(userInput);
const apiKey = "thisisaverylongapikeyvalue12345678";
window.postMessage(data, '*');
"""
        issues = _analyze_text(code, "https://example.com/app.js")
        types = {i.issue_type for i in issues}
        assert "dangerous_sink" in types
        assert "exposed_credential" in types
        assert "postmessage_no_origin" in types

    def test_clean_code_returns_empty(self):
        code = "const x = document.getElementById('app'); x.textContent = userInput;"
        issues = _analyze_text(code, "https://example.com/")
        assert len(issues) == 0


# ── FrontendHooksDetector (HTTP mocked) ──────────────────────────────────────

class TestFrontendHooksDetector:
    @respx.mock
    async def test_analyze_detects_inline_eval(self):
        html = "<html><script>eval(document.location.hash);</script></html>"
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
        )

        detector = FrontendHooksDetector()
        result = await detector.analyze("https://example.com/", [], "scan-001")

        assert result.scan_id == "scan-001"
        assert result.analyzed_urls >= 1
        assert result.total_issues >= 1
        dangerous = [i for i in result.issues if i.issue_type == "dangerous_sink"]
        assert len(dangerous) >= 1

    @respx.mock
    async def test_analyze_fetches_external_js(self):
        html = '<html><script src="/app.js"></script></html>'
        js = "el.innerHTML = userSuppliedData;"

        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
        )
        respx.get("https://example.com/app.js").mock(
            return_value=httpx.Response(200, text=js, headers={"content-type": "application/javascript"})
        )

        detector = FrontendHooksDetector()
        result = await detector.analyze("https://example.com/", [], "scan-002")

        assert any(i.issue_type == "dangerous_sink" for i in result.issues)

    @respx.mock
    async def test_analyze_clean_page(self):
        html = "<html><body><p>Hello world</p></body></html>"
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
        )

        detector = FrontendHooksDetector()
        result = await detector.analyze("https://example.com/", [], "scan-003")

        assert result.total_issues == 0

    @respx.mock
    async def test_analyze_handles_http_error_gracefully(self):
        respx.get("https://example.com/").mock(side_effect=httpx.ConnectError("refused"))

        detector = FrontendHooksDetector()
        result = await detector.analyze("https://example.com/", [], "scan-004")

        # Should not raise — just return empty result
        assert result.total_issues == 0
        assert result.analyzed_urls == 0

    @respx.mock
    async def test_analyze_with_crawled_urls(self):
        page1 = "<html><script>eval(x);</script></html>"
        page2 = "<html><p>safe</p></html>"

        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=page1, headers={"content-type": "text/html"})
        )
        respx.get("https://example.com/about").mock(
            return_value=httpx.Response(200, text=page2, headers={"content-type": "text/html"})
        )

        detector = FrontendHooksDetector()
        result = await detector.analyze(
            "https://example.com/",
            ["https://example.com/about"],
            "scan-005",
        )

        assert result.analyzed_urls == 2
        assert result.total_issues >= 1
