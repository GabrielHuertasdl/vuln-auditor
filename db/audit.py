"""Audit log event types and async emission helpers.

Design: fire-and-forget — audit log failures never block the main request.
All audit events are immutable once written.

Usage:
    from db.audit import AuditAction, emit_audit

    await emit_audit(
        action=AuditAction.SCAN_CREATED,
        org_id=org.id,
        actor=current_user,
        resource_type="scan",
        resource_id=scan_id,
        request=request,
        details={"target": target_url},
    )
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import Request
    from db.models import User

log = logging.getLogger(__name__)


class AuditAction(str, Enum):
    # Auth
    AUTH_LOGIN = "auth.login"
    AUTH_LOGIN_FAILED = "auth.login_failed"
    AUTH_LOGOUT = "auth.logout"
    AUTH_REGISTER = "auth.register"
    AUTH_PASSWORD_CHANGED = "auth.password_changed"
    AUTH_TOKEN_REFRESHED = "auth.token_refreshed"
    AUTH_TOKEN_REVOKED = "auth.token_revoked"
    AUTH_SSO_LINKED = "auth.sso_linked"

    # Users
    USER_INVITED = "user.invited"
    USER_INVITE_ACCEPTED = "user.invite_accepted"
    USER_ROLE_CHANGED = "user.role_changed"
    USER_DEACTIVATED = "user.deactivated"
    USER_ACTIVATED = "user.activated"

    # Organization
    ORG_UPDATED = "org.updated"
    ORG_SETTINGS_CHANGED = "org.settings_changed"

    # API keys
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"

    # Targets
    TARGET_CREATED = "target.created"
    TARGET_UPDATED = "target.updated"
    TARGET_DELETED = "target.deleted"

    # Scans
    SCAN_CREATED = "scan.created"
    SCAN_CANCELLED = "scan.cancelled"
    SCAN_DELETED = "scan.deleted"

    # Findings
    FINDING_STATUS_CHANGED = "finding.status_changed"

    # Reports
    REPORT_EXPORTED = "report.exported"

    # Webhooks
    WEBHOOK_CREATED = "webhook.created"
    WEBHOOK_UPDATED = "webhook.updated"
    WEBHOOK_DELETED = "webhook.deleted"

    # Billing
    BILLING_PLAN_CHANGED = "billing.plan_changed"
    BILLING_SUBSCRIPTION_CREATED = "billing.subscription_created"
    BILLING_SUBSCRIPTION_CANCELLED = "billing.subscription_cancelled"

    # SSO
    SSO_CONFIGURED = "sso.configured"
    SSO_DISABLED = "sso.disabled"

    # Integrations
    INTEGRATION_CONFIGURED = "integration.configured"
    INTEGRATION_DELETED = "integration.deleted"


async def emit_audit(
    action: AuditAction,
    org_id: str | None = None,
    actor: "User | None" = None,
    actor_id: str | None = None,
    actor_email: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
    request: "Request | None" = None,
) -> None:
    """
    Async fire-and-forget audit log emission.
    Failures are logged as warnings but never raised.
    """
    _actor_id = actor_id or (actor.id if actor else None)
    _actor_email = actor_email or (actor.email if actor else None)

    ip_address: str | None = None
    user_agent: str | None = None
    if request is not None:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            ip_address = forwarded_for.split(",")[0].strip()
        else:
            ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("User-Agent")

    asyncio.create_task(
        _write_audit_log(
            action=action,
            org_id=org_id,
            actor_id=_actor_id,
            actor_email=_actor_email,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    )


async def _write_audit_log(
    action: AuditAction,
    org_id: str | None,
    actor_id: str | None,
    actor_email: str | None,
    resource_type: str | None,
    resource_id: str | None,
    details: dict[str, Any] | None,
    ip_address: str | None,
    user_agent: str | None,
) -> None:
    try:
        from db.database import get_session
        from db.models import AuditLog

        record = AuditLog(
            id=str(uuid.uuid4()),
            org_id=org_id,
            actor_id=actor_id,
            actor_email=actor_email,
            action=action.value,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=datetime.now(UTC),
        )
        async with get_session() as session:
            session.add(record)
    except Exception as e:
        log.warning("Audit log write failed (non-fatal): %s", e)
