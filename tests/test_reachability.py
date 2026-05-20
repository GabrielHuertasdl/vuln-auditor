"""Tests for Phase 2: Reachability Analysis."""
from __future__ import annotations
import pytest
from core.reachability import ReachabilityEngine, ExposureLevel
from core.schemas import Finding, Severity, Confidence, ToolName


def _finding(path: str, method: str = "GET", severity: str = "high") -> Finding:
    sev = Severity(severity)
    return Finding(
        id=f"f-{path.replace('/', '_')}",
        scan_id="scan-001",
        correlation_key=f"test:{path}",
        title="Test Finding",
        description="desc",
        host="example.com",
        path=path,
        method=method,
        severity=sev,
        confidence=Confidence.HIGH,
        sources=[ToolName.NMAP],
    )


engine = ReachabilityEngine()


def test_public_path_gets_high_multiplier():
    findings = [_finding("/login", "POST")]
    results = engine.analyze(findings)
    assert len(results) == 1
    r = results[0]
    assert r.exposure_level == ExposureLevel.PUBLIC
    assert r.is_public is True
    assert r.risk_multiplier > 1.0


def test_admin_path_gets_reduced_multiplier():
    findings = [_finding("/admin/users")]
    results = engine.analyze(findings)
    r = results[0]
    assert r.exposure_level == ExposureLevel.ADMIN
    assert r.requires_auth is True
    assert r.risk_multiplier < 1.0


def test_api_path_gets_highest_multiplier():
    findings = [_finding("/api/v1/users", "POST")]
    results = engine.analyze(findings)
    r = results[0]
    assert r.exposure_level == ExposureLevel.API
    assert r.is_api_endpoint is True
    assert r.risk_multiplier > 1.5


def test_post_method_boosts_multiplier():
    get_f = _finding("/contact", "GET")
    post_f = _finding("/contact", "POST")
    post_f = post_f.model_copy(update={"id": "post-contact"})
    get_results = engine.analyze([get_f])
    post_results = engine.analyze([post_f])
    assert post_results[0].risk_multiplier > get_results[0].risk_multiplier


def test_noise_findings_are_skipped():
    f = _finding("/admin")
    f = f.model_copy(update={"is_noise": True})
    results = engine.analyze([f])
    assert results == []


def test_apply_multipliers_tags_findings():
    findings = [_finding("/api/data", "GET")]
    reach = engine.analyze(findings)
    tagged = engine.apply_multipliers(findings, reach)
    assert any("reachability:" in tag for tag in tagged[0].tags)


def test_multiplier_capped_at_3():
    """Multiplier never exceeds 3.0 regardless of factors."""
    findings = [_finding("/api/v1/critical", "POST", severity="critical")]
    results = engine.analyze(findings)
    assert results[0].risk_multiplier <= 3.0
