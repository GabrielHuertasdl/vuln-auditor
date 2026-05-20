import uuid
from datetime import UTC, datetime
from core.schemas import (
    PostureScore,
    VerificationRecord,
    VerificationStatus,
    Confidence
)
from core.diff import DiffEngine

def test_diff_engine_regressions():
    engine = DiffEngine()
    scan_id = "curr_scan"
    prev_id = "prev_scan"
    
    curr_score = PostureScore(
        scan_id=scan_id, 
        overall_score=50.0, 
        coverage_score=100.0, 
        confidence_score=100.0, 
        exposure_score=0.0,
        score_breakdown={"WSTG-CONF-01": -25.0, "WSTG-CRYP-01": 0.0, "WSTG-AUTH-01": -10.0, "WSTG-SESS-01": -25.0}
    )
    prev_score = PostureScore(
        scan_id=prev_id, 
        overall_score=100.0, 
        coverage_score=100.0, 
        confidence_score=100.0, 
        exposure_score=0.0,
        score_breakdown={"WSTG-CONF-01": 0.0, "WSTG-CRYP-01": 0.0, "WSTG-AUTH-01": 0.0, "WSTG-SESS-01": 0.0}
    )
    
    prev_verifs = [
        VerificationRecord(id="1", scan_id=prev_id, control_id="WSTG-CONF-01", status=VerificationStatus.PASS),
        VerificationRecord(id="2", scan_id=prev_id, control_id="WSTG-CRYP-01", status=VerificationStatus.PASS),
        VerificationRecord(id="3", scan_id=prev_id, control_id="WSTG-AUTH-01", status=VerificationStatus.PASS),
        VerificationRecord(id="4", scan_id=prev_id, control_id="WSTG-SESS-01", status=VerificationStatus.INSUFFICIENT_EVIDENCE),
    ]
    
    curr_verifs = [
        # PASS -> FAIL (Critical Regression)
        VerificationRecord(id="1c", scan_id=scan_id, control_id="WSTG-CONF-01", status=VerificationStatus.FAIL, evidence_summary="Bug found"),
        # PASS -> INSUFFICIENT (Coverage Gap)
        VerificationRecord(id="2c", scan_id=scan_id, control_id="WSTG-CRYP-01", status=VerificationStatus.INSUFFICIENT_EVIDENCE),
        # PASS -> SUSPECTED (Suspected Regression)
        VerificationRecord(id="3c", scan_id=scan_id, control_id="WSTG-AUTH-01", status=VerificationStatus.SUSPECTED, evidence_summary="Maybe a bug"),
        # INSUFFICIENT -> FAIL (Confirmed Failure)
        VerificationRecord(id="4c", scan_id=scan_id, control_id="WSTG-SESS-01", status=VerificationStatus.FAIL),
    ]
    
    diff = engine.calculate(scan_id, curr_score, curr_verifs, prev_id, prev_score, prev_verifs)
    
    # Check Regressions
    assert len(diff.regressions) == 4
    
    crit = next(r for r in diff.regressions if r.control_id == "WSTG-CONF-01")
    assert crit.type == "critical"
    
    gap = next(r for r in diff.regressions if r.control_id == "WSTG-CRYP-01")
    assert gap.type == "coverage"
    assert "WSTG-CRYP-01" in diff.coverage_gaps
    
    susp = next(r for r in diff.regressions if r.control_id == "WSTG-AUTH-01")
    assert susp.type == "suspected"

    conf = next(r for r in diff.regressions if r.control_id == "WSTG-SESS-01")
    assert conf.type == "confirmed_failure"
    
    # Score Trend
    assert diff.score_trend.overall_change == -50.0
    assert diff.score_trend.breakdown_delta["WSTG-CONF-01"] == -25.0
    assert diff.score_trend.breakdown_delta["WSTG-AUTH-01"] == -10.0
    assert diff.score_trend.breakdown_delta["WSTG-SESS-01"] == -25.0

def test_diff_engine_improvements_and_persistent():
    engine = DiffEngine()
    scan_id = "curr_scan"
    prev_id = "prev_scan"
    
    curr_score = PostureScore(
        scan_id=scan_id, 
        overall_score=90.0, 
        coverage_score=100.0, 
        confidence_score=100.0, 
        exposure_score=0.0,
        score_breakdown={"WSTG-AUTH-01": -10.0}
    )
    prev_score = PostureScore(
        scan_id=prev_id, 
        overall_score=40.0, 
        coverage_score=100.0, 
        confidence_score=100.0, 
        exposure_score=0.0,
        score_breakdown={"WSTG-CONF-01": -25.0, "WSTG-CRYP-01": -25.0, "WSTG-AUTH-01": -25.0}
    )
    
    prev_verifs = [
        # FAIL -> PASS (Verified Fix)
        VerificationRecord(id="1", scan_id=prev_id, control_id="WSTG-CONF-01", status=VerificationStatus.FAIL),
        # FAIL -> FAIL (Persistent Failure)
        VerificationRecord(id="2", scan_id=prev_id, control_id="WSTG-CRYP-01", status=VerificationStatus.FAIL),
        # FAIL -> SUSPECTED (Risk Reduction)
        VerificationRecord(id="3", scan_id=prev_id, control_id="WSTG-AUTH-01", status=VerificationStatus.FAIL),
        # INSUFFICIENT -> PASS (Verification Gain)
        VerificationRecord(id="4", scan_id=prev_id, control_id="WSTG-SESS-01", status=VerificationStatus.INSUFFICIENT_EVIDENCE),
        # INSUFFICIENT -> INSUFFICIENT (Persistent Gap)
        VerificationRecord(id="5", scan_id=prev_id, control_id="WSTG-IDNT-01", status=VerificationStatus.INSUFFICIENT_EVIDENCE),
        # INSUFFICIENT -> SUSPECTED (Visibility Improvement)
        VerificationRecord(id="6", scan_id=prev_id, control_id="WSTG-INPV-01", status=VerificationStatus.INSUFFICIENT_EVIDENCE),
    ]
    
    curr_verifs = [
        VerificationRecord(id="1c", scan_id=scan_id, control_id="WSTG-CONF-01", status=VerificationStatus.PASS),
        VerificationRecord(id="2c", scan_id=scan_id, control_id="WSTG-CRYP-01", status=VerificationStatus.FAIL),
        VerificationRecord(id="3c", scan_id=scan_id, control_id="WSTG-AUTH-01", status=VerificationStatus.SUSPECTED),
        VerificationRecord(id="4c", scan_id=scan_id, control_id="WSTG-SESS-01", status=VerificationStatus.PASS),
        VerificationRecord(id="5c", scan_id=scan_id, control_id="WSTG-IDNT-01", status=VerificationStatus.INSUFFICIENT_EVIDENCE),
        VerificationRecord(id="6c", scan_id=scan_id, control_id="WSTG-INPV-01", status=VerificationStatus.SUSPECTED),
    ]
    
    diff = engine.calculate(scan_id, curr_score, curr_verifs, prev_id, prev_score, prev_verifs)
    
    # Improvements
    assert len(diff.improvements) == 4
    
    fix = next(i for i in diff.improvements if i.control_id == "WSTG-CONF-01")
    assert fix.type == "verification"
    
    reduction = next(i for i in diff.improvements if i.control_id == "WSTG-AUTH-01")
    assert reduction.type == "reduction"
    
    gain = next(i for i in diff.improvements if i.control_id == "WSTG-SESS-01")
    assert gain.type == "verification"
    assert "WSTG-SESS-01" in diff.coverage_gains

    vis = next(i for i in diff.improvements if i.control_id == "WSTG-INPV-01")
    assert vis.type == "visibility"
    assert "WSTG-INPV-01" in diff.coverage_gains
    
    # Persistent
    assert "WSTG-CRYP-01" in diff.persistent_fails
    assert "WSTG-IDNT-01" in diff.persistent_coverage_gaps
    
    # Score Trend
    assert diff.score_trend.overall_change == 50.0
    assert diff.score_trend.breakdown_delta["WSTG-CONF-01"] == 25.0
    assert diff.score_trend.breakdown_delta["WSTG-AUTH-01"] == 15.0

