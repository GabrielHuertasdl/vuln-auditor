"""Tests for core/stack_detector.py."""
import pytest

from core.schemas import RawFinding, ToolName
from core.stack_detector import detect_stack, is_api_target


def _raw(
    tool: ToolName = ToolName.NIKTO,
    title: str = "Finding",
    description: str = "",
    evidence: str | None = None,
    path: str = "/",
) -> RawFinding:
    return RawFinding(
        id=f"{tool.value}_{title[:8]}",
        tool=tool,
        host="target.example.com",
        title=title,
        description=description,
        evidence=evidence,
        path=path,
        raw_severity="low",
        raw_confidence="medium",
    )


# ── Server detection ──────────────────────────────────────────────────────────

def test_detect_apache_from_nmap() -> None:
    raw = _raw(ToolName.NMAP, description="Apache httpd 2.4.51")
    stack = detect_stack([raw])
    assert "Apache" in stack


def test_detect_nginx_from_nmap() -> None:
    raw = _raw(ToolName.NMAP, description="nginx 1.18.0")
    stack = detect_stack([raw])
    assert "Nginx" in stack


def test_detect_php_from_evidence() -> None:
    raw = _raw(evidence="X-Powered-By: PHP/8.1.0")
    stack = detect_stack([raw])
    assert "PHP" in stack


def test_detect_nodejs_from_evidence() -> None:
    raw = _raw(evidence="X-Powered-By: Express\nServer: Node.js")
    stack = detect_stack([raw])
    assert "Node.js" in stack or "Node.js/Express" in stack


def test_detect_wordpress_from_path() -> None:
    raw = _raw(path="/wp-content/themes/twentytwenty/")
    stack = detect_stack([raw])
    assert "WordPress" in stack


def test_detect_django_from_cookie() -> None:
    raw = _raw(evidence="Set-Cookie: csrftoken=abc123; sessionid=xyz")
    stack = detect_stack([raw])
    assert "Django" in stack


def test_detect_waf_cloudflare() -> None:
    raw = _raw(evidence="Server: cloudflare\nCF-RAY: 123abc")
    stack = detect_stack([raw])
    assert "WAF/Cloudflare" in stack


def test_detect_iis_from_server_header() -> None:
    raw = _raw(evidence="Server: Microsoft-IIS/10.0")
    stack = detect_stack([raw])
    assert "IIS" in stack


def test_detect_asp_net_from_path() -> None:
    raw = _raw(path="/default.aspx")
    stack = detect_stack([raw])
    assert "ASP.NET" in stack


def test_stack_deduplication() -> None:
    """Same technology detected from multiple findings → appears once."""
    raws = [
        _raw(ToolName.NMAP, description="Apache httpd 2.4"),
        _raw(ToolName.NIKTO, evidence="Server: Apache"),
    ]
    stack = detect_stack(raws)
    assert stack.count("Apache") == 1


def test_empty_findings_returns_empty_stack() -> None:
    assert detect_stack([]) == []


def test_target_url_contributes_to_detection() -> None:
    stack = detect_stack([], target_url="https://example.com/wp-admin/")
    assert "WordPress" in stack


# ── API target detection ──────────────────────────────────────────────────────

def test_api_target_from_path() -> None:
    raw = _raw(path="/api/v1/users")
    assert is_api_target([raw]) is True


def test_api_target_from_url() -> None:
    assert is_api_target([], target_url="https://example.com/api/v2/products") is True


def test_api_target_from_json_content_type() -> None:
    raw = _raw(evidence="Content-Type: application/json")
    assert is_api_target([raw]) is True


def test_non_api_target() -> None:
    raw = _raw(path="/about", evidence="Content-Type: text/html")
    assert is_api_target([raw], target_url="https://example.com/about") is False
