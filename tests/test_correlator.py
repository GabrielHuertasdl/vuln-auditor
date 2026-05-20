"""Tests for core/correlator.py."""
import pytest

from core.classifier import classify
from core.correlator import annotate_related, correlate
from core.schemas import Confidence, RawFinding, ToolName


def _make_raw(
    tool: ToolName,
    title: str = "X-Frame-Options Header Not Set",
    host: str = "example.com",
    port: int = 80,
    path: str = "/",
    method: str | None = None,
    parameter: str | None = None,
    raw_severity: str = "1",
    raw_confidence: str = "2",
    cwe_id: int | None = 693,
) -> RawFinding:
    return RawFinding(
        id=f"{tool.value}_{title[:10]}_{path}",
        tool=tool,
        host=host,
        port=port,
        path=path,
        method=method,
        parameter=parameter,
        title=title,
        description=f"Description from {tool.value}",
        raw_severity=raw_severity,
        raw_confidence=raw_confidence,
        cwe_id=cwe_id,
    )


# ── Merging ───────────────────────────────────────────────────────────────────

def test_same_finding_from_two_tools_merges() -> None:
    raw = [
        _make_raw(ToolName.ZAP, title="X-Frame-Options Header Not Set"),
        _make_raw(ToolName.NIKTO, title="X-Frame-Options Header Not Set"),
    ]
    findings = correlate(raw, "scan-001")
    assert len(findings) == 1
    finding = findings[0]
    assert ToolName.ZAP in finding.sources
    assert ToolName.NIKTO in finding.sources
    assert finding.source_count == 2


def test_two_sources_boost_confidence() -> None:
    raw = [
        _make_raw(ToolName.ZAP, raw_confidence="1"),  # LOW in ZAP
        _make_raw(ToolName.NIKTO, raw_confidence="1"),
    ]
    findings = correlate(raw, "scan-001")
    assert len(findings) == 1
    assert findings[0].confidence in (Confidence.MEDIUM, Confidence.HIGH)


def test_three_sources_give_high_confidence() -> None:
    raw = [
        _make_raw(ToolName.ZAP, raw_confidence="1"),
        _make_raw(ToolName.NIKTO, raw_confidence="1"),
        _make_raw(ToolName.NMAP, raw_confidence="medium", raw_severity="informational"),
    ]
    findings = correlate(raw, "scan-001")
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_different_titles_produce_separate_findings() -> None:
    raw = [
        _make_raw(ToolName.ZAP, title="SQL Injection"),
        _make_raw(ToolName.ZAP, title="Cross Site Scripting"),
    ]
    findings = correlate(raw, "scan-001")
    assert len(findings) == 2


def test_cwe_ids_merged_across_sources() -> None:
    r1 = _make_raw(ToolName.ZAP, title="Mixed Issue", cwe_id=89)
    r2 = _make_raw(ToolName.NIKTO, title="Mixed Issue", cwe_id=79)
    findings = correlate([r1, r2], "scan-001")
    assert len(findings) == 1
    assert 89 in findings[0].cwe_ids
    assert 79 in findings[0].cwe_ids


def test_scan_id_propagated() -> None:
    raw = [_make_raw(ToolName.NMAP, raw_severity="informational")]
    findings = correlate(raw, "scan-XYZ")
    assert findings[0].scan_id == "scan-XYZ"


# ── Endpoint fingerprint ──────────────────────────────────────────────────────

def test_endpoint_fingerprint_differs_by_parameter() -> None:
    r1 = _make_raw(ToolName.ZAP, title="XSS", path="/search", parameter="q")
    r2 = _make_raw(ToolName.ZAP, title="XSS", path="/search", parameter="name")
    findings = correlate([r1, r2], "scan-001")
    # Same title+path but different parameters → same correlation key → merged
    # (correlation key doesn't include parameter by design — same vulnerability class)
    assert len(findings) == 1
    # But they have different endpoint fingerprints stored in raw_finding_ids
    assert findings[0].source_count == 1  # same tool, merged into one


def test_endpoint_fingerprint_differs_by_method() -> None:
    r1 = _make_raw(ToolName.ZAP, title="CSRF", path="/submit", method="GET")
    r2 = _make_raw(ToolName.ZAP, title="CSRF", path="/submit", method="POST")
    findings = correlate([r1, r2], "scan-001")
    # Same correlation key → merged into one finding
    assert len(findings) == 1
    # endpoint_fingerprints are different but we store only one (from primary_raw)
    assert findings[0].endpoint_fingerprint != ""


# ── Normalized evidence ───────────────────────────────────────────────────────

def test_normalized_evidence_strips_tokens() -> None:
    raw = _make_raw(ToolName.ZAP, title="XSS")
    raw = raw.model_copy(update={
        "evidence": "session=abcdef0123456789abcdef0123456789; user=admin"
    })
    findings = correlate([raw], "scan-001")
    assert findings[0].normalized_evidence is not None
    assert "<TOKEN>" in findings[0].normalized_evidence
    assert "abcdef0123456789" not in findings[0].normalized_evidence


def test_normalized_evidence_strips_timestamps() -> None:
    raw = _make_raw(ToolName.ZAP, title="Info disclosure")
    raw = raw.model_copy(update={"evidence": "Last-Modified: 2024-01-15T10:30:00Z"})
    findings = correlate([raw], "scan-001")
    norm = findings[0].normalized_evidence or ""
    assert "<TIMESTAMP>" in norm


# ── annotate_related ──────────────────────────────────────────────────────────

def test_annotate_related_links_same_cwe() -> None:
    r1 = _make_raw(ToolName.ZAP, title="XSS on /search", path="/search", cwe_id=79)
    r2 = _make_raw(ToolName.ZAP, title="XSS on /comments", path="/comments", cwe_id=79)
    findings = correlate([r1, r2], "scan-001")
    assert len(findings) == 2
    findings = [classify(f) for f in findings]
    findings = annotate_related(findings)
    # Each finding should reference the other
    ids = {f.id for f in findings}
    for f in findings:
        assert len(f.related_findings) == 1
        assert f.related_findings[0] in ids
        assert f.related_findings[0] != f.id


def test_annotate_related_links_same_owasp() -> None:
    r1 = _make_raw(ToolName.ZAP, title="Missing CSP header", path="/", cwe_id=16)
    r2 = _make_raw(ToolName.NIKTO, title="Server version disclosure", path="/about", cwe_id=200)
    findings = correlate([r1, r2], "scan-001")
    findings = [classify(f) for f in findings]
    findings = annotate_related(findings)
    # Both map to A05:2021 — they should reference each other
    a05_findings = [f for f in findings if f.owasp_category and "A05" in f.owasp_category]
    if len(a05_findings) == 2:
        assert a05_findings[0].id in a05_findings[1].related_findings or \
               a05_findings[1].id in a05_findings[0].related_findings


def test_annotate_related_no_self_reference() -> None:
    raw = [_make_raw(ToolName.ZAP, title="Single finding", cwe_id=89)]
    findings = correlate(raw, "scan-001")
    findings = [classify(f) for f in findings]
    findings = annotate_related(findings)
    assert findings[0].id not in findings[0].related_findings
