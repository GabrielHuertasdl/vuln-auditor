"""Unified data models for the vulnerability auditor pipeline."""
from __future__ import annotations

import re
import hashlib
import urllib.parse
from datetime import datetime, UTC
from enum import Enum
from typing import Any

from pydantic import AnyHttpUrl, BaseModel, Field, computed_field


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    ANALYZING = "analyzing"
    DONE = "done"
    FAILED = "failed"
    PARTIAL = "partial"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Priority(str, Enum):
    """Urgency of remediation — independent of technical severity.

    Rules (transparent):
      IMMEDIATE — critical+high_confidence OR high+easy_exploitability
      HIGH      — high severity (any confidence), or medium+high_conf+multi-source
      MEDIUM    — medium severity (general case)
      LOW       — low severity
      DEFERRED  — informational or noise
    """
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    DEFERRED = "deferred"


class Exploitability(str, Enum):
    """Apparent ease of exploitation based on observable evidence.

    Rules (transparent):
      EASY      — no auth required, well-known exploit path, or trivial steps evident
      MODERATE  — some conditions or attacker knowledge required
      DIFFICULT — complex prerequisites, limited attack surface, or low-impact
      UNKNOWN   — insufficient evidence to assess
    """
    EASY = "easy"
    MODERATE = "moderate"
    DIFFICULT = "difficult"
    UNKNOWN = "unknown"


class RemediationEffort(str, Enum):
    """Estimated effort to remediate (order of magnitude).

    Rules (transparent):
      MINUTES — config change, add HTTP header, rotate credential
      HOURS   — single-component fix (patch, one function change)
      DAYS    — multi-component change or refactor
      WEEKS   — architectural or cross-cutting change
    """
    MINUTES = "minutes"
    HOURS = "hours"
    DAYS = "days"
    WEEKS = "weeks"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DuplicateType(str, Enum):
    EXACT = "exact"        # Identical endpoint fingerprint + title
    PROBABLE = "probable"  # Same correlation key, different instance
    RELATED = "related"    # Same CWE/OWASP category, different location


class ToolName(str, Enum):
    # DAST
    ZAP = "zap"
    NMAP = "nmap"
    NIKTO = "nikto"
    # SAST
    SEMGREP = "semgrep"
    # SCA
    TRIVY = "trivy"
    NPM_AUDIT = "npm_audit"
    PIP_AUDIT = "pip_audit"
    # IaC
    CHECKOV = "checkov"


class VerificationStatus(str, Enum):
    PASS = "verified_pass"
    FAIL = "verified_fail"
    SUSPECTED = "suspected_issue"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NOT_APPLICABLE = "not_applicable"


class DiscoveryType(str, Enum):
    TLS = "tls"
    HEADER = "header"
    TECH = "tech"
    ENDPOINT = "endpoint"
    COOKIE = "cookie"
    SERVICE = "service"


class RawFinding(BaseModel):
    """Internal-only: output of a scanner parser before correlation."""
    id: str
    tool: ToolName
    host: str
    port: int | None = None
    protocol: str = "tcp"
    path: str = "/"
    method: str | None = None
    parameter: str | None = None
    title: str
    description: str
    evidence: str | None = None
    raw_severity: str = "informational"
    raw_confidence: str = "medium"
    cwe_id: int | None = None
    wasc_id: int | None = None
    solution: str | None = None
    references: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """Unified, correlated, scored finding — persisted and served via API."""
    id: str
    scan_id: str
    correlation_key: str
    endpoint_fingerprint: str = ""
    title: str
    description: str
    host: str
    port: int | None = None
    protocol: str = "tcp"
    path: str = "/"
    method: str | None = None
    parameter: str | None = None
    evidence: str | None = None
    normalized_evidence: str | None = None

    # Scoring dimensions — each independently justified
    severity: Severity           # Technical impact
    priority: Priority = Priority.MEDIUM   # Urgency of remediation
    confidence: Confidence       # Quality of evidence
    exploitability: Exploitability = Exploitability.UNKNOWN  # Ease of exploitation
    remediation_effort: RemediationEffort = RemediationEffort.HOURS  # Cost to fix

    # Classification
    owasp_category: str | None = None       # OWASP Top 10 2021
    owasp_api_category: str | None = None   # OWASP API Security Top 10 2023
    cwe_ids: list[int] = Field(default_factory=list)

    # Source tracking
    sources: list[ToolName] = Field(default_factory=list)
    source_count: int = 1
    raw_finding_ids: list[str] = Field(default_factory=list)

    # Remediation
    solution: str | None = None
    references: list[str] = Field(default_factory=list)

    # Context
    tags: list[str] = Field(default_factory=list)
    detected_stack: list[str] = Field(default_factory=list)

    # Deduplication
    duplicate_of: str | None = None
    duplicate_type: DuplicateType | None = None
    related_findings: list[str] = Field(default_factory=list)
    is_noise: bool = False

    # AI enrichment
    ai_summary: str | None = None
    ai_mitigation: str | None = None
    ai_generated: bool = False

    # Enterprise / Business Context
    business_impact: str | None = None
    labels: list[str] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class VerificationDomain(BaseModel):
    id: str
    name: str
    description: str | None = None


class SecurityControl(BaseModel):
    id: str
    domain_id: str
    code: str  # e.g. WSTG-CONF-01
    name: str
    description: str


class VerificationRecord(BaseModel):
    id: str
    scan_id: str
    control_id: str
    status: VerificationStatus
    evidence_summary: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssetDiscovery(BaseModel):
    id: str
    scan_id: str
    type: DiscoveryType
    data: dict[str, Any]
    confidence: Confidence
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PostureScore(BaseModel):
    scan_id: str
    overall_score: float
    domain_scores: dict[str, float] = Field(default_factory=dict)
    coverage_score: float
    confidence_score: float
    exposure_score: float
    # Explanatory breakdown: control_id -> points deducted/added
    score_breakdown: dict[str, float] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScoreTrend(BaseModel):
    overall_change: float
    coverage_change: float
    confidence_change: float
    domain_changes: dict[str, float] = Field(default_factory=dict)
    # Explanatory delta: control_id -> change in points contribution
    breakdown_delta: dict[str, float] = Field(default_factory=dict)


class ControlRegression(BaseModel):
    control_id: str
    type: str  # "critical" (-> FAIL), "suspected" (-> SUSPECTED), "coverage" (-> INSUFFICIENT), "confirmed_failure" (INSUFFICIENT -> FAIL)
    previous_status: VerificationStatus
    current_status: VerificationStatus
    reason: str | None = None


class ControlImprovement(BaseModel):
    control_id: str
    type: str  # "verification" (-> PASS), "reduction" (FAIL -> SUSPECTED), "visibility" (INSUFFICIENT -> SUSPECTED)
    previous_status: VerificationStatus
    current_status: VerificationStatus


class ScanDiff(BaseModel):
    current_scan_id: str
    previous_scan_id: str | None = None
    score_trend: ScoreTrend | None = None
    regressions: list[ControlRegression] = Field(default_factory=list)
    improvements: list[ControlImprovement] = Field(default_factory=list)
    persistent_fails: list[str] = Field(default_factory=list)
    persistent_coverage_gaps: list[str] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)
    coverage_gains: list[str] = Field(default_factory=list)


class ScanTargetType(str, Enum):
    WEB = "web"
    API = "api"
    NETWORK = "network"


class ScanRequest(BaseModel):
    target_url: AnyHttpUrl
    target_type: ScanTargetType = ScanTargetType.WEB
    openapi_spec_url: str | None = None
    tools: list[ToolName] = Field(default_factory=lambda: list(ToolName))
    options: dict[str, Any] = Field(default_factory=dict)
    scan_mode: str = "full"  # "quick" | "full"


class ScanCreated(BaseModel):
    scan_id: str
    status: ScanStatus = ScanStatus.PENDING
    target: str
    poll_url: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanResult(BaseModel):
    scan_id: str
    target: str
    status: ScanStatus = ScanStatus.PENDING
    scan_mode: str = "full"
    tools_requested: list[ToolName] = Field(default_factory=list)
    tools_succeeded: list[ToolName] = Field(default_factory=list)
    tools_failed: dict[str, str] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    severity_summary: dict[str, int] = Field(default_factory=dict)
    priority_summary: dict[str, int] = Field(default_factory=dict)
    detected_stack: list[str] = Field(default_factory=list)
    ai_executive_summary: str | None = None
    ai_generated: bool = False
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    report_path: str | None = None
    error: str | None = None

    # Posture & Verification (New)
    verifications: list[VerificationRecord] = Field(default_factory=list)
    discovery_items: list[AssetDiscovery] = Field(default_factory=list)
    posture_score: PostureScore | None = None
    posture_diff: ScanDiff | None = None

    # Historical Context (Enterprise)
    new_findings_count: int = 0
    resolved_findings_count: int = 0
    regressed_findings_count: int = 0

    @computed_field
    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def compute_severity_summary(self) -> None:
        """Counts only non-noise, non-duplicate findings."""
        sev: dict[str, int] = {s.value: 0 for s in Severity}
        pri: dict[str, int] = {p.value: 0 for p in Priority}
        for f in self.findings:
            if not f.is_noise and not f.duplicate_of:
                sev[f.severity.value] += 1
                pri[f.priority.value] += 1
        self.severity_summary = sev
        self.priority_summary = pri


# ── Fingerprinting ────────────────────────────────────────────────────────────

def make_correlation_key(host: str, port: int | None, path: str, title: str) -> str:
    """
    Broad grouping key for merging same-issue findings from different tools.

    Normalization applied:
      - host: lowercase, stripped
      - port: string or empty
      - path: URL path only (no query/fragment), trailing slash removed, lowercase
      - title: version numbers replaced with X, lowercase

    Example: host=example.com port=443 path=/login title="SQL Injection"
    → deterministic 16-char hex digest
    """
    host_n = host.lower().strip()
    port_n = str(port) if port else ""
    path_n = urllib.parse.urlparse(path).path.rstrip("/").lower() or "/"
    title_n = re.sub(r"\d+(\.\d+)+", "X", title.lower().strip())
    raw = f"{host_n}:{port_n}:{path_n}:{title_n}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def make_endpoint_fingerprint(
    host: str,
    port: int | None,
    method: str | None,
    path: str,
    parameter: str | None,
) -> str:
    """
    Narrow key for detecting exact-instance duplicates within a scan.

    More specific than correlation_key: includes HTTP method and parameter,
    so GET /search?q= and POST /search?q= are treated as distinct findings.

    Normalization:
      - method: uppercase or empty
      - parameter: lowercase or empty
      - path: same as correlation_key
    """
    host_n = host.lower().strip()
    port_n = str(port) if port else ""
    method_n = (method or "").upper()
    path_n = urllib.parse.urlparse(path).path.rstrip("/").lower() or "/"
    param_n = (parameter or "").lower()
    raw = f"{host_n}:{port_n}:{method_n}:{path_n}:{param_n}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
