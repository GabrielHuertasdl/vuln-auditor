"""API key management endpoints — /api/v1/api-keys.

Named, scoped, revocable API keys. One key is returned in plaintext ONCE at creation.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.rbac import Permission, require_permission
from core.entitlements import Feature, check_entitlement, within_limit, get_plan_limits, plan_upgrade_message
from db.audit import AuditAction, emit_audit
from db.database import get_session
from db.models import User
from db.repositories import APIKeyRepository, OrgRepository

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


class APIKeyCreate(BaseModel):
    name: str
    scopes: list[str] = ["read", "write"]
    expires_at: datetime | None = None


class APIKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    scopes: list[str]
    is_active: bool
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class APIKeyCreatedResponse(APIKeyResponse):
    raw_key: str


import json as _json


def _serialize(record) -> APIKeyResponse:
    return APIKeyResponse(
        id=record.id,
        name=record.name,
        key_prefix=record.key_prefix,
        scopes=_json.loads(record.scopes) if isinstance(record.scopes, str) else record.scopes,
        is_active=record.is_active,
        expires_at=record.expires_at,
        last_used_at=record.last_used_at,
        created_at=record.created_at,
    )


@router.get("", response_model=list[APIKeyResponse])
async def list_api_keys(
    current_user: User = Depends(require_permission(Permission.API_KEYS_READ)),
) -> list[APIKeyResponse]:
    async with get_session() as session:
        repo = APIKeyRepository(session)
        keys = await repo.list_for_org(current_user.org_id)
        return [_serialize(k) for k in keys]


@router.post("", response_model=APIKeyCreatedResponse, status_code=201)
async def create_api_key(
    body: APIKeyCreate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.API_KEYS_CREATE)),
) -> APIKeyCreatedResponse:
    """Create a new API key. The raw key is returned ONCE — store it securely."""
    async with get_session() as session:
        org_repo = OrgRepository(session)
        org = await org_repo.get_by_id(current_user.org_id)
        if org is None:
            raise HTTPException(status_code=404, detail="Organization not found")

        limits = get_plan_limits(org.plan)
        api_key_repo = APIKeyRepository(session)
        existing = await api_key_repo.list_for_org(current_user.org_id)

        if not within_limit(len(existing), limits.max_api_keys):
            raise HTTPException(
                status_code=402,
                detail=f"API key limit reached ({limits.max_api_keys}). Upgrade your plan.",
            )

        record, raw_key = await api_key_repo.create(
            org_id=current_user.org_id,
            name=body.name,
            created_by=current_user.id,
            scopes=body.scopes,
            expires_at=body.expires_at,
        )

    await emit_audit(
        action=AuditAction.API_KEY_CREATED,
        org_id=current_user.org_id,
        actor=current_user,
        resource_type="api_key",
        resource_id=record.id,
        request=request,
        details={"name": body.name, "scopes": body.scopes},
    )

    response = APIKeyCreatedResponse(
        **_serialize(record).model_dump(),
        raw_key=raw_key,
    )
    return response


@router.delete("/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: str,
    request: Request,
    current_user: User = Depends(require_permission(Permission.API_KEYS_REVOKE)),
) -> None:
    async with get_session() as session:
        repo = APIKeyRepository(session)
        revoked = await repo.revoke(key_id, current_user.org_id)

    if not revoked:
        raise HTTPException(status_code=404, detail="API key not found")

    await emit_audit(
        action=AuditAction.API_KEY_REVOKED,
        org_id=current_user.org_id,
        actor=current_user,
        resource_type="api_key",
        resource_id=key_id,
        request=request,
    )
