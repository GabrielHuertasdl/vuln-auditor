"""Audit log endpoints — /api/v1/audit.

Read-only access to the organization's immutable audit trail.
Requires Pro or Enterprise plan + AUDIT_READ permission.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from api.rbac import Permission, require_permission
from core.entitlements import Feature, check_entitlement, plan_upgrade_message
from db.database import get_session
from db.models import User
from db.repositories import AuditRepository, OrgRepository

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditLogResponse(BaseModel):
    id: str
    actor_id: str | None
    actor_email: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    details: dict | None
    ip_address: str | None
    created_at: datetime


@router.get("", response_model=list[AuditLogResponse])
async def get_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    action: str | None = Query(default=None, description="Filter by action prefix, e.g. 'auth'"),
    actor_id: str | None = Query(default=None),
    current_user: User = Depends(require_permission(Permission.AUDIT_READ)),
) -> list[AuditLogResponse]:
    """
    Return the organization's audit log. Available on Pro and Enterprise plans.
    """
    async with get_session() as session:
        org_repo = OrgRepository(session)
        org = await org_repo.get_by_id(current_user.org_id)

    if org and not check_entitlement(org.plan, Feature.AUDIT_LOGS):
        raise HTTPException(
            status_code=402, detail=plan_upgrade_message(org.plan, Feature.AUDIT_LOGS)
        )

    async with get_session() as session:
        repo = AuditRepository(session)
        logs = await repo.list_for_org(
            org_id=current_user.org_id,
            limit=limit,
            offset=offset,
            action_filter=action,
            actor_id=actor_id,
        )

    return [
        AuditLogResponse(
            id=log.id,
            actor_id=log.actor_id,
            actor_email=log.actor_email,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            details=log.details,
            ip_address=log.ip_address,
            created_at=log.created_at,
        )
        for log in logs
    ]
