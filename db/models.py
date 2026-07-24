"""SQLAlchemy 2.0 declarative models for the VulnAuditor ASPM platform."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ── Core tenant model ─────────────────────────────────────────────────────────

class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    slug: Mapped[Optional[str]] = mapped_column(String, unique=True, nullable=True, index=True)
    website: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # Legacy single API key hash (kept for backward compat, prefer api_keys table)
    api_key_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    plan: Mapped[str] = mapped_column(String, default="free", nullable=False)
    scan_quota: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    scans_this_month: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    quota_reset_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Enterprise flags
    sso_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    settings_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Stripe billing
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(String, unique=True, nullable=True, index=True)
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(String, unique=True, nullable=True, index=True)
    stripe_subscription_status: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    billing_period_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    targets: Mapped[list["Target"]] = relationship("Target", back_populates="org", lazy="select")
    scans: Mapped[list["ScanRecord"]] = relationship("ScanRecord", back_populates="org", lazy="select")
    findings: Mapped[list["FindingRecord"]] = relationship("FindingRecord", back_populates="org", lazy="select")
    memberships: Mapped[list["Membership"]] = relationship("Membership", back_populates="org", lazy="select")
    api_keys: Mapped[list["APIKeyRecord"]] = relationship("APIKeyRecord", back_populates="org", lazy="select")
    webhooks: Mapped[list["WebhookEndpoint"]] = relationship("WebhookEndpoint", back_populates="org", lazy="select")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="org", lazy="select")


# ── Users & Identity ──────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    password_hash: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # Nullable for SSO-only users
    name: Mapped[str] = mapped_column(String, nullable=False)
    # Primary org (backward compat) — role stored in Membership for multi-org
    org_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False)
    role: Mapped[str] = mapped_column(String, default="admin", nullable=False)  # owner|admin|analyst|viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Enterprise fields
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    org: Mapped["Organization"] = relationship("Organization")
    memberships: Mapped[list["Membership"]] = relationship(
        "Membership", foreign_keys="Membership.user_id", back_populates="user", lazy="select"
    )
    oidc_accounts: Mapped[list["OIDCAccount"]] = relationship("OIDCAccount", back_populates="user", lazy="select")
    refresh_tokens: Mapped[list["RefreshTokenRecord"]] = relationship(
        "RefreshTokenRecord", back_populates="user", lazy="select"
    )


class Membership(Base):
    """Explicit user ↔ org ↔ role junction table. Supports future multi-org membership."""
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "org_id", name="uq_membership"),)

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String, nullable=False)  # owner|admin|analyst|viewer
    invited_by: Mapped[Optional[str]] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    invited_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped["User"] = relationship("User", foreign_keys=[user_id], back_populates="memberships")
    org: Mapped["Organization"] = relationship("Organization", back_populates="memberships")


class InviteToken(Base):
    """Pending email invitations to join an organization."""
    __tablename__ = "invite_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False, index=True)
    role: Mapped[str] = mapped_column(String, nullable=False)
    token_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    invited_by: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RefreshTokenRecord(Base):
    """Persisted refresh tokens for revocation support."""
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    device_hint: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")


class OIDCAccount(Base):
    """Link between a local User and an external OIDC identity provider."""
    __tablename__ = "oidc_accounts"
    __table_args__ = (UniqueConstraint("provider", "provider_sub", name="uq_oidc_account"),)

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String, nullable=False)  # google|azure|okta
    provider_sub: Mapped[str] = mapped_column(String, nullable=False)  # Subject claim from ID token
    provider_email: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="oidc_accounts")


# ── API Keys ──────────────────────────────────────────────────────────────────

class APIKeyRecord(Base):
    """Named, scoped, per-org API keys. Replaces the single api_key_hash on Organization."""
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    key_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    key_prefix: Mapped[str] = mapped_column(String, nullable=False)  # First 8 chars — shown in UI
    scopes: Mapped[str] = mapped_column(String, default='["read","write"]', nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    org: Mapped["Organization"] = relationship("Organization", back_populates="api_keys")


# ── Audit Log ─────────────────────────────────────────────────────────────────

class AuditLog(Base):
    """Immutable audit trail for security-relevant events."""
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    org_id: Mapped[Optional[str]] = mapped_column(
        String, ForeignKey("organizations.id"), nullable=True, index=True
    )
    actor_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    actor_email: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    action: Mapped[str] = mapped_column(String, nullable=False, index=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    org: Mapped[Optional["Organization"]] = relationship("Organization", back_populates="audit_logs")


# ── Webhooks ──────────────────────────────────────────────────────────────────

class WebhookEndpoint(Base):
    """Outbound webhook endpoint configuration."""
    __tablename__ = "webhook_endpoints"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    url: Mapped[str] = mapped_column(String, nullable=False)
    secret_hash: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # HMAC signing secret
    events: Mapped[str] = mapped_column(
        String, default='["scan.completed","finding.created","finding.status_changed"]', nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    org: Mapped["Organization"] = relationship("Organization", back_populates="webhooks")
    deliveries: Mapped[list["WebhookDelivery"]] = relationship(
        "WebhookDelivery", back_populates="endpoint", lazy="select"
    )


class WebhookDelivery(Base):
    """Log of webhook delivery attempts."""
    __tablename__ = "webhook_deliveries"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(
        String, ForeignKey("webhook_endpoints.id"), nullable=False, index=True
    )
    event: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    succeeded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    delivered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    endpoint: Mapped["WebhookEndpoint"] = relationship("WebhookEndpoint", back_populates="deliveries")


# ── Security scan models ───────────────────────────────────────────────────────

class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("org_id", "url", name="uq_target_org_url"),)

    id: Mapped[str] = mapped_column(String, primary_key=True)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False)
    url: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    tags: Mapped[str] = mapped_column(String, default="[]", nullable=False)
    schedule: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    scan_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    org: Mapped["Organization"] = relationship("Organization", back_populates="targets")
    scans: Mapped[list["ScanRecord"]] = relationship("ScanRecord", back_populates="target", lazy="select")
    findings: Mapped[list["FindingRecord"]] = relationship(
        "FindingRecord", back_populates="target", lazy="select"
    )


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False)
    target_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("targets.id"), nullable=True)
    initiated_by: Mapped[Optional[str]] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String, nullable=False)
    scan_mode: Mapped[str] = mapped_column(String, default="full", nullable=False)
    tools_requested: Mapped[str] = mapped_column(String, default="[]", nullable=False)
    tools_succeeded: Mapped[str] = mapped_column(String, default="[]", nullable=False)
    tools_failed: Mapped[str] = mapped_column(String, default="{}", nullable=False)
    detected_stack: Mapped[str] = mapped_column(String, default="[]", nullable=False)
    severity_summary: Mapped[str] = mapped_column(String, default="{}", nullable=False)
    priority_summary: Mapped[str] = mapped_column(String, default="{}", nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    new_finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    regressed_finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ai_executive_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_generated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    report_path: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    progress_pct: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    progress_message: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    org: Mapped["Organization"] = relationship("Organization", back_populates="scans")
    target: Mapped[Optional["Target"]] = relationship("Target", back_populates="scans")
    scan_findings: Mapped[list["ScanFinding"]] = relationship(
        "ScanFinding", back_populates="scan", lazy="select"
    )
    verifications: Mapped[list["VerificationRecord"]] = relationship(
        "VerificationRecord", back_populates="scan", lazy="select"
    )
    discovery_items: Mapped[list["AssetDiscovery"]] = relationship(
        "AssetDiscovery", back_populates="scan", lazy="select"
    )
    posture_score: Mapped[Optional["PostureScore"]] = relationship(
        "PostureScore", back_populates="scan", uselist=False
    )


class FindingRecord(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "org_id", "target_id", "global_fingerprint", name="uq_finding_org_target_fp"
        ),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False)
    target_id: Mapped[str] = mapped_column(String, ForeignKey("targets.id"), nullable=False)
    global_fingerprint: Mapped[str] = mapped_column(String, nullable=False)
    correlation_key: Mapped[str] = mapped_column(String, nullable=False)
    endpoint_fingerprint: Mapped[str] = mapped_column(String, default="", nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    host: Mapped[str] = mapped_column(String, nullable=False)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String, default="tcp", nullable=False)
    path: Mapped[str] = mapped_column(String, default="/", nullable=False)
    method: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    parameter: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    priority: Mapped[str] = mapped_column(String, nullable=False)
    confidence: Mapped[str] = mapped_column(String, nullable=False)
    exploitability: Mapped[str] = mapped_column(String, default="unknown", nullable=False)
    remediation_effort: Mapped[str] = mapped_column(String, default="hours", nullable=False)
    owasp_category: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    owasp_api_category: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cwe_ids: Mapped[str] = mapped_column(String, default="[]", nullable=False)
    status: Mapped[str] = mapped_column(String, default="open", nullable=False)
    is_noise: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    duplicate_of: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    related_findings: Mapped[str] = mapped_column(String, default="[]", nullable=False)
    tags: Mapped[str] = mapped_column(String, default="[]", nullable=False)
    detected_stack: Mapped[str] = mapped_column(String, default="[]", nullable=False)
    sources: Mapped[str] = mapped_column(String, default="[]", nullable=False)
    source_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    normalized_evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    solution: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[str] = mapped_column(String, default="[]", nullable=False)
    ai_mitigation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    first_seen_scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    last_seen_scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_note: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    org: Mapped["Organization"] = relationship("Organization", back_populates="findings")
    target: Mapped["Target"] = relationship("Target", back_populates="findings")
    scan_findings: Mapped[list["ScanFinding"]] = relationship(
        "ScanFinding", back_populates="finding", lazy="select"
    )
    status_history: Mapped[list["FindingStatusHistory"]] = relationship(
        "FindingStatusHistory", back_populates="finding", lazy="select"
    )


class ScanFinding(Base):
    __tablename__ = "scan_findings"
    __table_args__ = (UniqueConstraint("scan_id", "finding_id", name="uq_scan_finding"),)

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    finding_id: Mapped[str] = mapped_column(String, ForeignKey("findings.id"), nullable=False)
    is_new: Mapped[bool] = mapped_column(Boolean, nullable=False)
    is_regressed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    severity_snapshot: Mapped[str] = mapped_column(String, nullable=False)
    confidence_snapshot: Mapped[str] = mapped_column(String, nullable=False)
    evidence_snapshot: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan: Mapped["ScanRecord"] = relationship("ScanRecord", back_populates="scan_findings")
    finding: Mapped["FindingRecord"] = relationship("FindingRecord", back_populates="scan_findings")


class FindingStatusHistory(Base):
    __tablename__ = "finding_status_history"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    finding_id: Mapped[str] = mapped_column(String, ForeignKey("findings.id"), nullable=False)
    scan_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    status_from: Mapped[str] = mapped_column(String, nullable=False)
    status_to: Mapped[str] = mapped_column(String, nullable=False)
    severity_from: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    severity_to: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    changed_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    note: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    finding: Mapped["FindingRecord"] = relationship("FindingRecord", back_populates="status_history")


# ── Verification & Posture models ─────────────────────────────────────────────

class VerificationDomain(Base):
    __tablename__ = "verification_domains"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    controls: Mapped[list["SecurityControl"]] = relationship(
        "SecurityControl", back_populates="domain", lazy="select"
    )


class SecurityControl(Base):
    __tablename__ = "security_controls"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    domain_id: Mapped[str] = mapped_column(
        String, ForeignKey("verification_domains.id"), nullable=False
    )
    code: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)

    domain: Mapped["VerificationDomain"] = relationship("VerificationDomain", back_populates="controls")
    verifications: Mapped[list["VerificationRecord"]] = relationship(
        "VerificationRecord", back_populates="control", lazy="select"
    )


class VerificationRecord(Base):
    __tablename__ = "verification_records"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    control_id: Mapped[str] = mapped_column(String, ForeignKey("security_controls.id"), nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    evidence_summary: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    scan: Mapped["ScanRecord"] = relationship("ScanRecord", back_populates="verifications")
    control: Mapped["SecurityControl"] = relationship("SecurityControl", back_populates="verifications")


class AssetDiscovery(Base):
    __tablename__ = "asset_discovery"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    type: Mapped[str] = mapped_column(String, nullable=False)
    data: Mapped[dict] = mapped_column(JSON, nullable=False)
    confidence: Mapped[str] = mapped_column(String, nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scan: Mapped["ScanRecord"] = relationship("ScanRecord", back_populates="discovery_items")


class PostureScore(Base):
    __tablename__ = "posture_scores"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    overall_score: Mapped[float] = mapped_column(Float, nullable=False)
    domain_scores: Mapped[dict] = mapped_column(JSON, nullable=False)
    coverage_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    exposure_score: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scan: Mapped["ScanRecord"] = relationship("ScanRecord", back_populates="posture_score")


# ── Dead-letter queue for permanently failed background jobs ──────────────────

class FailedJob(Base):
    __tablename__ = "failed_jobs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    function: Mapped[str] = mapped_column(String, nullable=False)
    scan_id: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    error: Mapped[str] = mapped_column(Text, nullable=False)
    kwargs_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False)
    failed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
