"""
Diff Engine — detects changes between two scans (regressions, improvements, trends).
"""
from __future__ import annotations

from typing import Any
from core.schemas import (
    ControlImprovement,
    ControlRegression,
    PostureScore,
    ScanDiff,
    ScoreTrend,
    VerificationRecord,
    VerificationStatus,
)


class DiffEngine:
    """
    Calculates differences between a current scan and a previous baseline.
    """

    def calculate(
        self,
        current_scan_id: str,
        current_score: PostureScore,
        current_verifications: list[VerificationRecord],
        previous_scan_id: str | None = None,
        previous_score: PostureScore | None = None,
        previous_verifications: list[VerificationRecord] | None = None,
    ) -> ScanDiff:
        """
        Computes the standard diff summary.
        """
        diff = ScanDiff(
            current_scan_id=current_scan_id,
            previous_scan_id=previous_scan_id,
        )

        if not previous_score or not previous_verifications:
            return diff

        # 1. Score Trend
        diff.score_trend = ScoreTrend(
            overall_change=round(current_score.overall_score - previous_score.overall_score, 1),
            coverage_change=round(current_score.coverage_score - previous_score.coverage_score, 1),
            confidence_change=round(current_score.confidence_score - previous_score.confidence_score, 1),
            domain_changes={
                d: round(current_score.domain_scores.get(d, 0) - previous_score.domain_scores.get(d, 0), 1)
                for d in set(current_score.domain_scores) | set(previous_score.domain_scores)
            },
            breakdown_delta={
                c: round(current_score.score_breakdown.get(c, 0) - previous_score.score_breakdown.get(c, 0), 1)
                for c in set(current_score.score_breakdown) | set(previous_score.score_breakdown)
                if round(current_score.score_breakdown.get(c, 0) - previous_score.score_breakdown.get(c, 0), 1) != 0
            }
        )

        # 2. Verification Diff
        prev_map = {v.control_id: v for v in previous_verifications}
        
        for curr_v in current_verifications:
            prev_v = prev_map.get(curr_v.control_id)
            if not prev_v:
                continue

            # ── 1. Regressions ────────────────────────────────────────────────
            # Critical Regression: Anything not-FAIL -> FAIL
            if prev_v.status != VerificationStatus.FAIL and curr_v.status == VerificationStatus.FAIL:
                reg_type = "critical"
                if prev_v.status == VerificationStatus.INSUFFICIENT_EVIDENCE:
                    reg_type = "confirmed_failure"
                
                diff.regressions.append(
                    ControlRegression(
                        control_id=curr_v.control_id,
                        type=reg_type,
                        previous_status=prev_v.status,
                        current_status=curr_v.status,
                        reason=curr_v.evidence_summary
                    )
                )
            
            # Suspected Regression: PASS -> SUSPECTED
            elif prev_v.status == VerificationStatus.PASS and curr_v.status == VerificationStatus.SUSPECTED:
                diff.regressions.append(
                    ControlRegression(
                        control_id=curr_v.control_id,
                        type="suspected",
                        previous_status=prev_v.status,
                        current_status=curr_v.status,
                        reason=curr_v.evidence_summary
                    )
                )

            # Coverage Regression (Gap): PASS -> INSUFFICIENT
            elif prev_v.status == VerificationStatus.PASS and curr_v.status == VerificationStatus.INSUFFICIENT_EVIDENCE:
                diff.regressions.append(
                    ControlRegression(
                        control_id=curr_v.control_id,
                        type="coverage",
                        previous_status=prev_v.status,
                        current_status=curr_v.status,
                        reason="Evidence that previously confirmed PASS is no longer detectable."
                    )
                )
                diff.coverage_gaps.append(curr_v.control_id)

            # ── 2. Improvements ───────────────────────────────────────────────
            # Verification Gain: FAIL/SUSPECTED/INSUFFICIENT -> PASS
            elif prev_v.status != VerificationStatus.PASS and curr_v.status == VerificationStatus.PASS:
                diff.improvements.append(
                    ControlImprovement(
                        control_id=curr_v.control_id,
                        type="verification",
                        previous_status=prev_v.status,
                        current_status=curr_v.status
                    )
                )
                if prev_v.status == VerificationStatus.INSUFFICIENT_EVIDENCE:
                    diff.coverage_gains.append(curr_v.control_id)

            # Risk Reduction: FAIL -> SUSPECTED
            elif prev_v.status == VerificationStatus.FAIL and curr_v.status == VerificationStatus.SUSPECTED:
                diff.improvements.append(
                    ControlImprovement(
                        control_id=curr_v.control_id,
                        type="reduction",
                        previous_status=prev_v.status,
                        current_status=curr_v.status
                    )
                )

            # Visibility Improvement: INSUFFICIENT -> SUSPECTED
            elif prev_v.status == VerificationStatus.INSUFFICIENT_EVIDENCE and curr_v.status == VerificationStatus.SUSPECTED:
                diff.improvements.append(
                    ControlImprovement(
                        control_id=curr_v.control_id,
                        type="visibility",
                        previous_status=prev_v.status,
                        current_status=curr_v.status
                    )
                )
                diff.coverage_gains.append(curr_v.control_id)

            # ── 3. Persistent States ──────────────────────────────────────────
            elif prev_v.status == VerificationStatus.FAIL and curr_v.status == VerificationStatus.FAIL:
                diff.persistent_fails.append(curr_v.control_id)
            
            elif prev_v.status == VerificationStatus.INSUFFICIENT_EVIDENCE and curr_v.status == VerificationStatus.INSUFFICIENT_EVIDENCE:
                diff.persistent_coverage_gaps.append(curr_v.control_id)

        return diff
