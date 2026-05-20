"""Tests for Phase 2: Auto-remediation Templates."""
from __future__ import annotations
import pytest
from core.remediation import (
    get_all_templates,
    get_template_by_id,
    get_remediation_for_finding,
    filter_snippets_for_stack,
)
from core.schemas import Finding, Severity, Confidence, ToolName


def _finding(owasp: str | None = None, cwe_ids: list[int] | None = None, stack: list[str] | None = None) -> Finding:
    return Finding(
        id="test-f-001",
        scan_id="scan-001",
        correlation_key="test",
        title="Test",
        description="desc",
        host="example.com",
        path="/login",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        sources=[ToolName.ZAP],
        owasp_category=owasp,
        cwe_ids=cwe_ids or [],
        detected_stack=stack or [],
    )


def test_all_templates_loaded():
    templates = get_all_templates()
    assert len(templates) >= 7
    for t in templates:
        assert t.id
        assert t.title
        assert len(t.stacks) >= 1


def test_get_template_by_id():
    t = get_template_by_id("sql-injection")
    assert t is not None
    assert "SQL" in t.title
    assert 89 in t.cwe_refs


def test_get_template_by_id_not_found():
    assert get_template_by_id("does-not-exist") is None


def test_remediation_by_cwe_sqli():
    f = _finding(cwe_ids=[89])
    templates = get_remediation_for_finding(f)
    assert any(t.id == "sql-injection" for t in templates)


def test_remediation_by_cwe_xss():
    f = _finding(cwe_ids=[79])
    templates = get_remediation_for_finding(f)
    assert any(t.id == "xss-reflected" or t.id == "csp-missing" for t in templates)


def test_remediation_by_owasp_a03():
    f = _finding(owasp="A03:2021-Injection")
    templates = get_remediation_for_finding(f)
    ids = [t.id for t in templates]
    assert "sql-injection" in ids or "xss-reflected" in ids


def test_no_duplicate_templates_returned():
    f = _finding(owasp="A03:2021-Injection", cwe_ids=[89])
    templates = get_remediation_for_finding(f)
    ids = [t.id for t in templates]
    assert len(ids) == len(set(ids))


def test_filter_snippets_for_django():
    t = get_template_by_id("sql-injection")
    snippets = filter_snippets_for_stack(t, ["django", "python"])
    assert len(snippets) >= 1
    assert all(s.stack == "django" for s in snippets)


def test_filter_snippets_unknown_stack_returns_all():
    t = get_template_by_id("hsts-missing")
    snippets = filter_snippets_for_stack(t, [])
    assert len(snippets) == len(t.stacks)


def test_snippets_have_real_code():
    t = get_template_by_id("sql-injection")
    for s in t.stacks:
        assert len(s.code) > 20
        assert s.language
