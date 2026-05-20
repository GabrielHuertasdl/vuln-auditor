"""
Scoring engine — assigns severity, priority, exploitability, and remediation effort.

All rules are explicit and traceable. No black-box scoring.
Each public function documents the logic it applies.
"""
from __future__ import annotations

from core.schemas import (
    Confidence,
    Exploitability,
    Finding,
    PostureScore,
    Priority,
    RawFinding,
    RemediationEffort,
    Severity,
    ToolName,
    VerificationRecord,
    VerificationStatus,
)

# ── Tool-specific severity/confidence maps ─────────────────────────────────────

_ZAP_SEVERITY_MAP: dict[str, Severity] = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFORMATIONAL,
}

_ZAP_CONFIDENCE_MAP: dict[str, Confidence] = {
    "3": Confidence.HIGH,
    "2": Confidence.MEDIUM,
    "1": Confidence.LOW,
    "0": Confidence.LOW,
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]
_CONFIDENCE_ORDER = [Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW]

# CWEs that warrant elevation to CRITICAL when confidence is HIGH and severity is HIGH
_CRITICAL_CWES = {89, 78, 77, 918, 22, 94, 502, 306}

# CWEs associated with EASY exploitability (well-understood, commonly exploited)
_EASY_EXPLOIT_CWES = {79, 89, 1392}  # XSS, SQLi, default creds

# CWEs associated with MODERATE exploitability
_MODERATE_EXPLOIT_CWES = {78, 94, 22, 918, 611, 502, 352, 384, 601}

# CWEs associated with architectural effort (WEEKS to fix)
_WEEKS_EFFORT_CWES = {918, 502, 306, 287}

# CWEs fixable in DAYS
_DAYS_EFFORT_CWES = {89, 78, 77, 94, 384, 601}

# CWEs fixable in MINUTES (config/header changes)
_MINUTES_EFFORT_CWES = {693, 16, 1021}  # clickjacking, missing headers


def score_raw_finding(raw: RawFinding) -> tuple[Severity, Confidence]:
    """Map tool-native severity/confidence to unified enums."""
    if raw.tool == ToolName.ZAP:
        sev = _ZAP_SEVERITY_MAP.get(raw.raw_severity, Severity.INFORMATIONAL)
        conf = _ZAP_CONFIDENCE_MAP.get(raw.raw_confidence, Confidence.MEDIUM)
    elif raw.tool == ToolName.NMAP:
        sev = _nmap_severity(raw.raw_severity, raw.title)
        conf = Confidence.HIGH if raw.raw_confidence == "high" else Confidence.MEDIUM
    else:
        # Nikto and unknown tools: keyword-based fallback
        sev = _keyword_severity(raw.raw_severity, raw.title, raw.description)
        conf = Confidence.MEDIUM
    return sev, conf


def boost_confidence(base: Confidence, source_count: int) -> Confidence:
    """
    Elevate confidence when multiple independent tools report the same finding.

    Rules:
      1 source  → unchanged
      2 sources → one level up (LOW→MEDIUM, MEDIUM→HIGH, HIGH stays HIGH)
      3+ sources → always HIGH
    """
    if source_count >= 3:
        return Confidence.HIGH
    if source_count == 2:
        idx = _CONFIDENCE_ORDER.index(base)
        return _CONFIDENCE_ORDER[max(0, idx - 1)]
    return base


def pick_highest_severity(severities: list[Severity]) -> Severity:
    for s in _SEVERITY_ORDER:
        if s in severities:
            return s
    return Severity.INFORMATIONAL


def maybe_elevate_to_critical(finding: Finding) -> Finding:
    """
    Elevate HIGH→CRITICAL when evidence is strong enough.

    Conditions (ALL must be true):
      - Current severity is HIGH
      - Confidence is HIGH
      - CWE is in the critical set OR title contains a critical keyword

    Rationale: scanner tools rarely auto-classify CRITICAL; this rule
    promotes confirmed injection/RCE findings to their real impact level.
    """
    if finding.severity != Severity.HIGH:
        return finding
    if finding.confidence != Confidence.HIGH:
        return finding
    has_critical_cwe = bool(finding.cwe_ids and set(finding.cwe_ids) & _CRITICAL_CWES)
    has_critical_keyword = any(
        k in finding.title.lower()
        for k in ("remote code execution", "command injection", "sql injection")
    )
    if has_critical_cwe or has_critical_keyword:
        return finding.model_copy(update={"severity": Severity.CRITICAL})
    return finding


def assign_exploitability(finding: Finding) -> Exploitability:
    """
    Estimate ease of exploitation from available evidence.

    Rules (applied in order, first match wins):
      EASY:
        - CWE in easy-exploit set + confidence HIGH
        - Title/description contains "default credential" or "unauthenticated"
      MODERATE:
        - CWE in moderate-exploit set
        - Severity HIGH or CRITICAL with confidence MEDIUM
      DIFFICULT:
        - Confidence LOW
        - Severity LOW or INFORMATIONAL
      UNKNOWN:
        - Default when no signal is available
    """
    text = (finding.title + " " + finding.description).lower()

    # Easy: well-known trivially exploited classes
    if finding.confidence == Confidence.HIGH:
        if set(finding.cwe_ids) & _EASY_EXPLOIT_CWES:
            return Exploitability.EASY
        if any(k in text for k in ("default credential", "default password", "unauthenticated")):
            return Exploitability.EASY

    # Moderate: conditions required or limited attack surface
    if set(finding.cwe_ids) & _MODERATE_EXPLOIT_CWES:
        return Exploitability.MODERATE
    if finding.severity in (Severity.HIGH, Severity.CRITICAL) and finding.confidence == Confidence.MEDIUM:
        return Exploitability.MODERATE

    # Difficult: low-quality evidence or low-impact finding
    if finding.confidence == Confidence.LOW:
        return Exploitability.DIFFICULT
    if finding.severity in (Severity.LOW, Severity.INFORMATIONAL):
        return Exploitability.DIFFICULT

    return Exploitability.UNKNOWN


def assign_priority(finding: Finding) -> Priority:
    """
    Assign remediation urgency independent of raw technical severity.

    Rules (applied in order):
      IMMEDIATE — critical + high confidence, or critical + easy exploitability
      HIGH      — high severity (any confidence), or medium + high confidence + multi-source
      MEDIUM    — medium severity (general case)
      LOW       — low severity
      DEFERRED  — informational, noise, or duplicate
    """
    if finding.is_noise or finding.duplicate_of:
        return Priority.DEFERRED

    if finding.severity == Severity.INFORMATIONAL:
        return Priority.DEFERRED

    if finding.severity == Severity.LOW:
        return Priority.LOW

    if finding.severity == Severity.MEDIUM:
        if finding.confidence == Confidence.HIGH and finding.source_count >= 2:
            return Priority.HIGH
        return Priority.MEDIUM

    if finding.severity == Severity.HIGH:
        return Priority.HIGH

    # CRITICAL
    if finding.confidence == Confidence.HIGH or finding.exploitability == Exploitability.EASY:
        return Priority.IMMEDIATE
    return Priority.HIGH


def assign_remediation_effort(finding: Finding) -> RemediationEffort:
    """
    Estimate remediation cost (order of magnitude).

    Rules (CWE-based, then keyword-based):
      MINUTES — missing headers, clickjacking, default config change
      HOURS   — XSS, CSRF, info disclosure, SSL/TLS config
      DAYS    — injection, broken auth, path traversal
      WEEKS   — SSRF, deserialization, broken access control architecture
    """
    if set(finding.cwe_ids) & _WEEKS_EFFORT_CWES:
        return RemediationEffort.WEEKS
    if set(finding.cwe_ids) & _DAYS_EFFORT_CWES:
        return RemediationEffort.DAYS
    if set(finding.cwe_ids) & _MINUTES_EFFORT_CWES:
        return RemediationEffort.MINUTES

    text = (finding.title + " " + finding.description).lower()

    if any(k in text for k in ("x-frame", "content-security-policy", "hsts", "x-content-type",
                                "missing header", "default password", "default credential")):
        return RemediationEffort.MINUTES

    if any(k in text for k in ("xss", "cross-site scripting", "csrf", "ssl", "tls",
                                "certificate", "information disclosure", "server version")):
        return RemediationEffort.HOURS

    if any(k in text for k in ("sql injection", "command injection", "path traversal",
                                "authentication", "session", "open redirect")):
        return RemediationEffort.DAYS

    if any(k in text for k in ("ssrf", "deserialization", "server-side request forgery",
                                "access control", "privilege escalation")):
        return RemediationEffort.WEEKS

    # Default by severity
    if finding.severity in (Severity.CRITICAL, Severity.HIGH):
        return RemediationEffort.DAYS
    return RemediationEffort.HOURS


def calculate_business_risk_score(
    severity: Severity,
    business_impact: str | None = None,
    asset_criticality: int = 1,  # 1-5 scale
) -> float:
    """
    Calculates a business risk score (0-100).
    Formula: (SeverityWeight * 0.6) + (BusinessImpactWeight * 0.3) + (CriticalityWeight * 0.1)
    """
    sev_weights = {
        Severity.CRITICAL: 100,
        Severity.HIGH: 80,
        Severity.MEDIUM: 50,
        Severity.LOW: 20,
        Severity.INFORMATIONAL: 5,
    }

    impact_weights = {
        "critical": 100,
        "high": 80,
        "medium": 50,
        "low": 20,
        None: 50, # Default to medium if unknown
    }

    s_weight = sev_weights.get(severity, 50)
    i_weight = impact_weights.get((business_impact or "").lower(), 50)
    c_weight = min(max(asset_criticality, 1), 5) * 20 # scale 1-5 to 20-100

    score = (s_weight * 0.6) + (i_weight * 0.3) + (c_weight * 0.1)
    return round(score, 1)


def score_finding_extended(
finding: Finding) -> Finding:
    """
    Apply exploitability, remediation_effort, and final priority in one pass.
    Call this after classification so CWE IDs and owasp_category are set.
    """
    exploitability = assign_exploitability(finding)
    effort = assign_remediation_effort(finding)
    # Re-assign priority now that exploitability is known
    finding = finding.model_copy(update={
        "exploitability": exploitability,
        "remediation_effort": effort,
    })
    priority = assign_priority(finding)
    return finding.model_copy(update={"priority": priority})


# ── Internal helpers ──────────────────────────────────────────────────────────

def _nmap_severity(raw_sev: str, title: str) -> Severity:
    if raw_sev == "high":
        return Severity.HIGH
    if raw_sev == "medium":
        return Severity.MEDIUM
    if raw_sev == "informational":
        return Severity.INFORMATIONAL
    return Severity.LOW


def _keyword_severity(raw_sev: str, title: str, description: str) -> Severity:
    text = (title + " " + description).lower()
    if any(k in text for k in ("sql injection", "remote code execution", "command injection")):
        return Severity.HIGH
    if any(k in text for k in ("xss", "cross-site scripting", "csrf", "path traversal")):
        return Severity.MEDIUM
    if raw_sev == "high":
        return Severity.HIGH
    if raw_sev == "medium":
        return Severity.MEDIUM
    return Severity.LOW


class PostureScorer:
    """
    Calculates aggregate security posture metrics.
    """

    CONFIDENCE_WEIGHT = {
        Confidence.HIGH: 1.0,
        Confidence.MEDIUM: 0.7,
        Confidence.LOW: 0.4,
    }

    def calculate(
        self,
        scan_id: str,
        verifications: list[VerificationRecord],
        findings: list[Finding],
    ) -> PostureScore:
        """
        Computes all posture metrics and returns a PostureScore snapshot.
        """
        # 1. Domain Health Scores
        # Group verifications by domain (using prefix for now, e.g. WSTG-CONF -> CONF)
        domain_health = {}
        score_breakdown = {}

        for v in verifications:
            if v.status == VerificationStatus.NOT_APPLICABLE:
                continue
                
            domain_code = v.control_id.split("-")[1] if "-" in v.control_id else "GEN"
            if domain_code not in domain_health:
                domain_health[domain_code] = 100.0

            deduction = 0.0
            if v.status == VerificationStatus.FAIL:
                deduction = 25.0
            elif v.status == VerificationStatus.SUSPECTED:
                deduction = 10.0
            
            if deduction > 0:
                domain_health[domain_code] -= deduction
                score_breakdown[v.control_id] = -deduction

        for d in domain_health:
            domain_health[d] = max(0.0, domain_health[d])

        # 2. Coverage Score
        applicable_verifications = [v for v in verifications if v.status != VerificationStatus.NOT_APPLICABLE]
        total_controls = len(applicable_verifications)
        verified_controls = len(
            [
                v
                for v in applicable_verifications
                if v.status in (VerificationStatus.PASS, VerificationStatus.FAIL)
            ]
        )
        coverage_score = (verified_controls / total_controls * 100) if total_controls > 0 else 0

        # 3. Confidence Score
        if findings:
            confidence_sum = sum(self.CONFIDENCE_WEIGHT[f.confidence] for f in findings)
            confidence_score = (confidence_sum / len(findings) * 100)
        else:
            confidence_score = 100.0

        # 4. Exposure Score (finding count proxy)
        exposure_score = min(100.0, len(findings) * 5.0)

        # 5. Overall Score (Weighted: 70% Domain Health, 20% Coverage, 10% Confidence)
        # Exclude NOT_APPLICABLE from domain health average
        active_domains = [s for v, s in domain_health.items()]
        avg_domain_health = sum(active_domains) / len(active_domains) if active_domains else 0
        
        overall_score = (avg_domain_health * 0.7) + (coverage_score * 0.2) + (confidence_score * 0.1)

        return PostureScore(
            scan_id=scan_id,
            overall_score=round(overall_score, 1),
            domain_scores={d: round(s, 1) for d, s in domain_health.items()},
            coverage_score=round(coverage_score, 1),
            confidence_score=round(confidence_score, 1),
            exposure_score=round(exposure_score, 1),
            score_breakdown=score_breakdown,
        )
