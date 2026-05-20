"""Tests for PostureScorer — aggregate metrics and score breakdown."""
import pytest
from core.schemas import VerificationRecord, VerificationStatus, Finding, PostureScore, Confidence, Severity
from core.scorer import PostureScorer

def test_posture_scorer_breakdown():
    scorer = PostureScorer()
    scan_id = "test_scan"
    
    verifications = [
        VerificationRecord(id="1", scan_id=scan_id, control_id="WSTG-CONF-01", status=VerificationStatus.FAIL),
        VerificationRecord(id="2", scan_id=scan_id, control_id="WSTG-CRYP-01", status=VerificationStatus.SUSPECTED),
        VerificationRecord(id="3", scan_id=scan_id, control_id="WSTG-AUTH-01", status=VerificationStatus.PASS),
        VerificationRecord(id="4", scan_id=scan_id, control_id="WSTG-SESS-01", status=VerificationStatus.INSUFFICIENT_EVIDENCE),
        VerificationRecord(id="5", scan_id=scan_id, control_id="WSTG-IDNT-01", status=VerificationStatus.NOT_APPLICABLE),
    ]
    
    findings = [] # Simplified
    
    score = scorer.calculate(scan_id, verifications, findings)
    
    # Check breakdown
    assert score.score_breakdown["WSTG-CONF-01"] == -25.0
    assert score.score_breakdown["WSTG-CRYP-01"] == -10.0
    assert "WSTG-AUTH-01" not in score.score_breakdown
    assert "WSTG-SESS-01" not in score.score_breakdown
    assert "WSTG-IDNT-01" not in score.score_breakdown

def test_posture_scorer_domain_health():
    scorer = PostureScorer()
    scan_id = "test_scan"
    
    verifications = [
        # Domain CONF
        VerificationRecord(id="1", scan_id=scan_id, control_id="WSTG-CONF-01", status=VerificationStatus.FAIL),
        VerificationRecord(id="2", scan_id=scan_id, control_id="WSTG-CONF-02", status=VerificationStatus.PASS),
    ]
    
    score = scorer.calculate(scan_id, verifications, [])
    
    # Domain health: 100 - 25 = 75
    assert score.domain_scores["CONF"] == 75.0

def test_posture_scorer_coverage():
    scorer = PostureScorer()
    scan_id = "test_scan"
    
    verifications = [
        VerificationRecord(id="1", scan_id=scan_id, control_id="WSTG-CONF-01", status=VerificationStatus.PASS),
        VerificationRecord(id="2", scan_id=scan_id, control_id="WSTG-CONF-02", status=VerificationStatus.INSUFFICIENT_EVIDENCE),
        VerificationRecord(id="3", scan_id=scan_id, control_id="WSTG-CONF-03", status=VerificationStatus.NOT_APPLICABLE),
    ]
    
    score = scorer.calculate(scan_id, verifications, [])
    
    # Applicable: 2 (CONF-01, CONF-02). Verified: 1 (CONF-01). 1/2 = 50%
    assert score.coverage_score == 50.0
