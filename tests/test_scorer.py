"""Tests for core/scorer.py — all scoring dimensions."""
import pytest

from core.schemas import Confidence, Exploitability, Finding, Priority, RemediationEffort, Severity, ToolName
from core.scorer import (
    assign_exploitability,
    assign_priority,
    assign_remediation_effort,
    boost_confidence,
    maybe_elevate_to_critical,
    score_finding_extended,
)


def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        id="f1",
        scan_id="s1",
        correlation_key="k1",
        title="Test Finding",
        description="A test finding",
        host="example.com",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        sources=[ToolName.ZAP],
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ── boost_confidence ──────────────────────────────────────────────────────────

def test_boost_confidence_single_source_unchanged() -> None:
    assert boost_confidence(Confidence.MEDIUM, 1) == Confidence.MEDIUM
    assert boost_confidence(Confidence.LOW, 1) == Confidence.LOW


def test_boost_confidence_two_sources_upgrades() -> None:
    assert boost_confidence(Confidence.LOW, 2) == Confidence.MEDIUM
    assert boost_confidence(Confidence.MEDIUM, 2) == Confidence.HIGH
    assert boost_confidence(Confidence.HIGH, 2) == Confidence.HIGH


def test_boost_confidence_three_sources_always_high() -> None:
    assert boost_confidence(Confidence.LOW, 3) == Confidence.HIGH
    assert boost_confidence(Confidence.MEDIUM, 3) == Confidence.HIGH


# ── maybe_elevate_to_critical ─────────────────────────────────────────────────

def test_elevate_to_critical_sql_injection() -> None:
    finding = _make_finding(cwe_ids=[89], severity=Severity.HIGH, confidence=Confidence.HIGH)
    result = maybe_elevate_to_critical(finding)
    assert result.severity == Severity.CRITICAL


def test_elevate_to_critical_keyword() -> None:
    finding = _make_finding(
        title="Remote Code Execution via deserialization",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    )
    result = maybe_elevate_to_critical(finding)
    assert result.severity == Severity.CRITICAL


def test_no_elevation_when_confidence_medium() -> None:
    finding = _make_finding(cwe_ids=[89], severity=Severity.HIGH, confidence=Confidence.MEDIUM)
    result = maybe_elevate_to_critical(finding)
    assert result.severity == Severity.HIGH


def test_no_elevation_when_severity_not_high() -> None:
    finding = _make_finding(cwe_ids=[89], severity=Severity.MEDIUM, confidence=Confidence.HIGH)
    result = maybe_elevate_to_critical(finding)
    assert result.severity == Severity.MEDIUM


def test_no_elevation_for_non_critical_cwe() -> None:
    finding = _make_finding(cwe_ids=[200], severity=Severity.HIGH, confidence=Confidence.HIGH)
    result = maybe_elevate_to_critical(finding)
    assert result.severity == Severity.HIGH


# ── assign_exploitability ─────────────────────────────────────────────────────

def test_exploitability_easy_for_sqli_high_confidence() -> None:
    finding = _make_finding(cwe_ids=[89], confidence=Confidence.HIGH)
    assert assign_exploitability(finding) == Exploitability.EASY


def test_exploitability_easy_for_xss_high_confidence() -> None:
    finding = _make_finding(cwe_ids=[79], confidence=Confidence.HIGH)
    assert assign_exploitability(finding) == Exploitability.EASY


def test_exploitability_easy_for_default_credentials() -> None:
    finding = _make_finding(
        title="Default credentials in use",
        description="Admin panel uses default password",
        confidence=Confidence.HIGH,
    )
    assert assign_exploitability(finding) == Exploitability.EASY


def test_exploitability_moderate_for_ssrf() -> None:
    finding = _make_finding(cwe_ids=[918], confidence=Confidence.MEDIUM)
    assert assign_exploitability(finding) == Exploitability.MODERATE


def test_exploitability_difficult_for_low_confidence() -> None:
    finding = _make_finding(confidence=Confidence.LOW, severity=Severity.MEDIUM)
    assert assign_exploitability(finding) == Exploitability.DIFFICULT


def test_exploitability_difficult_for_informational() -> None:
    finding = _make_finding(severity=Severity.INFORMATIONAL, confidence=Confidence.MEDIUM)
    assert assign_exploitability(finding) == Exploitability.DIFFICULT


# ── assign_priority ───────────────────────────────────────────────────────────

def test_priority_immediate_for_critical_high_confidence() -> None:
    finding = _make_finding(
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        exploitability=Exploitability.EASY,
    )
    assert assign_priority(finding) == Priority.IMMEDIATE


def test_priority_high_for_high_severity() -> None:
    finding = _make_finding(severity=Severity.HIGH, confidence=Confidence.MEDIUM)
    assert assign_priority(finding) == Priority.HIGH


def test_priority_medium_for_medium_severity() -> None:
    finding = _make_finding(severity=Severity.MEDIUM, confidence=Confidence.MEDIUM)
    assert assign_priority(finding) == Priority.MEDIUM


def test_priority_high_for_medium_with_high_conf_multi_source() -> None:
    finding = _make_finding(
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        source_count=2,
        sources=[ToolName.ZAP, ToolName.NIKTO],
    )
    assert assign_priority(finding) == Priority.HIGH


def test_priority_low_for_low_severity() -> None:
    finding = _make_finding(severity=Severity.LOW)
    assert assign_priority(finding) == Priority.LOW


def test_priority_deferred_for_informational() -> None:
    finding = _make_finding(severity=Severity.INFORMATIONAL)
    assert assign_priority(finding) == Priority.DEFERRED


def test_priority_deferred_for_noise() -> None:
    finding = _make_finding(severity=Severity.HIGH, is_noise=True)
    assert assign_priority(finding) == Priority.DEFERRED


def test_priority_deferred_for_duplicate() -> None:
    finding = _make_finding(severity=Severity.HIGH, duplicate_of="other-id")
    assert assign_priority(finding) == Priority.DEFERRED


# ── assign_remediation_effort ─────────────────────────────────────────────────

def test_effort_minutes_for_missing_header() -> None:
    finding = _make_finding(
        title="Missing X-Frame-Options header",
        description="The response does not include X-Frame-Options",
        cwe_ids=[693],
    )
    assert assign_remediation_effort(finding) == RemediationEffort.MINUTES


def test_effort_hours_for_xss() -> None:
    finding = _make_finding(
        title="Reflected XSS",
        description="Cross-site scripting in search parameter",
        cwe_ids=[79],
    )
    assert assign_remediation_effort(finding) == RemediationEffort.HOURS


def test_effort_days_for_sqli() -> None:
    finding = _make_finding(
        title="SQL Injection",
        description="SQL injection in login form",
        cwe_ids=[89],
    )
    assert assign_remediation_effort(finding) == RemediationEffort.DAYS


def test_effort_weeks_for_ssrf() -> None:
    finding = _make_finding(
        title="SSRF",
        description="Server-side request forgery in file upload endpoint",
        cwe_ids=[918],
    )
    assert assign_remediation_effort(finding) == RemediationEffort.WEEKS


# ── score_finding_extended ────────────────────────────────────────────────────

def test_score_extended_populates_all_dimensions() -> None:
    finding = _make_finding(
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_ids=[89],
        title="SQL Injection in login",
    )
    result = score_finding_extended(finding)
    assert result.exploitability != Exploitability.UNKNOWN
    assert result.remediation_effort is not None
    assert result.priority is not None


def test_score_extended_immediate_for_confirmed_sqli() -> None:
    finding = _make_finding(
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe_ids=[89],
        title="SQL Injection",
    )
    result = score_finding_extended(finding)
    assert result.priority == Priority.IMMEDIATE
    assert result.exploitability == Exploitability.EASY
