"""User management endpoints — /api/v1/users.

Covers: list members, invite, accept invite, update role, deactivate, get profile.
All endpoints require authentication and appropriate RBAC permissions.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr

from api.rbac import Permission, require_permission
from core.config import settings
from core.entitlements import Feature, check_entitlement, within_limit, get_plan_limits, plan_upgrade_message
from db.audit import AuditAction, emit_audit
from db.database import get_session
from db.models import Organization, User
from db.repositories import (
    InviteTokenRepository,
    MembershipRepository,
    OrgRepository,
    UserRepository,
)

router = APIRouter(prefix="/users", tags=["users"])

_VALID_ROLES = {"owner", "admin", "analyst", "viewer"}


# ── Pydantic models ────────────────────────────────────────────────────────────

class MemberResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime


class InviteRequest(BaseModel):
    email: EmailStr
    role: str = "analyst"


class InviteResponse(BaseModel):
    invite_id: str
    email: str
    role: str
    expires_at: datetime
    # invite_url is returned only in development mode (production sends email)
    invite_url: str | None = None


class UpdateRoleRequest(BaseModel):
    role: str


class AcceptInviteRequest(BaseModel):
    token: str
    name: str
    password: str


# ── Helpers ────────────────────────────────────────────────────────────────────

def _serialize_user(user: User) -> MemberResponse:
    return MemberResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
        is_active=user.is_active,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
    )


async def _get_org_from_user(user: User) -> Organization:
    async with get_session() as session:
        repo = OrgRepository(session)
        org = await repo.get_by_id(user.org_id)
        if org is None:
            raise HTTPException(status_code=404, detail="Organization not found")
        return org


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("", response_model=list[MemberResponse])
async def list_members(
    current_user: User = Depends(require_permission(Permission.USERS_READ)),
) -> list[MemberResponse]:
    """List all active members in the current organization."""
    async with get_session() as session:
        repo = UserRepository(session)
        users = await repo.list_for_org(current_user.org_id)
        return [_serialize_user(u) for u in users]


@router.post("/invite", response_model=InviteResponse, status_code=201)
async def invite_member(
    body: InviteRequest,
    request: Request,
    current_user: User = Depends(require_permission(Permission.USERS_INVITE)),
) -> InviteResponse:
    """
    Invite a new user to the organization via email.

    In development mode, the invite URL is returned in the response.
    In production, integrate an email provider to deliver the invite.
    """
    if body.role not in _VALID_ROLES:
        raise HTTPException(
            status_code=422, detail=f"Invalid role. Must be one of: {sorted(_VALID_ROLES)}"
        )

    org = await _get_org_from_user(current_user)

    # Check plan: multiple members
    if not check_entitlement(org.plan, Feature.MULTIPLE_MEMBERS):
        raise HTTPException(
            status_code=402, detail=plan_upgrade_message(org.plan, Feature.MULTIPLE_MEMBERS)
        )

    # Check member limit
    async with get_session() as session:
        user_repo = UserRepository(session)
        existing_users = await user_repo.list_for_org(current_user.org_id)
        limits = get_plan_limits(org.plan)
        if not within_limit(len(existing_users), limits.max_members):
            raise HTTPException(
                status_code=402,
                detail=f"Member limit reached ({limits.max_members}). Upgrade your plan.",
            )

    # Create invite token
    async with get_session() as session:
        invite_repo = InviteTokenRepository(session)
        invite, raw_token = await invite_repo.create(
            org_id=current_user.org_id,
            email=body.email,
            role=body.role,
            invited_by=current_user.id,
        )

    await emit_audit(
        action=AuditAction.USER_INVITED,
        org_id=current_user.org_id,
        actor=current_user,
        resource_type="invite",
        resource_id=invite.id,
        request=request,
        details={"email": body.email, "role": body.role},
    )

    invite_url = None
    if settings.is_development:
        base = settings.frontend_url.rstrip("/")
        invite_url = f"{base}/accept-invite?token={raw_token}"

    return InviteResponse(
        invite_id=invite.id,
        email=invite.email,
        role=invite.role,
        expires_at=invite.expires_at,
        invite_url=invite_url,
    )


@router.get("/pending-invites")
async def list_pending_invites(
    current_user: User = Depends(require_permission(Permission.USERS_INVITE)),
) -> list[dict]:
    """List pending (unaccepted, non-expired) invites for the organization."""
    async with get_session() as session:
        repo = InviteTokenRepository(session)
        invites = await repo.list_pending_for_org(current_user.org_id)
        return [
            {
                "id": i.id,
                "email": i.email,
                "role": i.role,
                "expires_at": i.expires_at,
                "created_at": i.created_at,
            }
            for i in invites
        ]


@router.post("/accept-invite", status_code=201)
async def accept_invite(body: AcceptInviteRequest, request: Request) -> dict:
    """
    Accept an invite and create a new user account.
    Returns the same token response as /auth/register.
    """
    from api.user_auth import _hash_password, _issue_tokens

    async with get_session() as session:
        invite_repo = InviteTokenRepository(session)
        invite = await invite_repo.get_valid(body.token)
        if invite is None:
            raise HTTPException(status_code=400, detail="Invalid or expired invite token")

        user_repo = UserRepository(session)
        existing = await user_repo.get_by_email(invite.email)
        if existing:
            raise HTTPException(status_code=409, detail="Email already has an account")

        user = await user_repo.create(
            email=invite.email,
            password_hash=_hash_password(body.password),
            name=body.name,
            org_id=invite.org_id,
            role=invite.role,
        )

        membership_repo = MembershipRepository(session)
        await membership_repo.create(
            user_id=user.id, org_id=invite.org_id, role=invite.role, invited_by=invite.invited_by
        )
        await invite_repo.accept(invite.id)

        org_repo = OrgRepository(session)
        org = await org_repo.get_by_id(invite.org_id)
        org_name = org.name if org else None

    await emit_audit(
        action=AuditAction.USER_INVITE_ACCEPTED,
        org_id=invite.org_id,
        actor=user,
        resource_type="user",
        resource_id=user.id,
        request=request,
    )

    token_response = await _issue_tokens(user, org_name, request)
    return token_response.model_dump()


@router.patch("/{user_id}/role", response_model=MemberResponse)
async def update_member_role(
    user_id: str,
    body: UpdateRoleRequest,
    request: Request,
    current_user: User = Depends(require_permission(Permission.USERS_UPDATE_ROLE)),
) -> MemberResponse:
    """Update a member's role in the organization. Cannot demote the last owner."""
    if body.role not in _VALID_ROLES:
        raise HTTPException(
            status_code=422, detail=f"Invalid role. Must be one of: {sorted(_VALID_ROLES)}"
        )

    async with get_session() as session:
        user_repo = UserRepository(session)
        target = await user_repo.get_by_id(user_id)

        if target is None or target.org_id != current_user.org_id:
            raise HTTPException(status_code=404, detail="User not found in organization")

        if target.id == current_user.id:
            raise HTTPException(status_code=400, detail="Cannot change your own role")

        # Prevent demoting the last owner
        if target.role == "owner" and body.role != "owner":
            owners = [u for u in await user_repo.list_for_org(current_user.org_id) if u.role == "owner"]
            if len(owners) <= 1:
                raise HTTPException(
                    status_code=400, detail="Cannot demote the last owner. Promote another user first."
                )

        old_role = target.role
        await user_repo.update_role(user_id, body.role)
        await user_repo.get_by_id(user_id)  # reload
        target.role = body.role

    await emit_audit(
        action=AuditAction.USER_ROLE_CHANGED,
        org_id=current_user.org_id,
        actor=current_user,
        resource_type="user",
        resource_id=user_id,
        request=request,
        details={"old_role": old_role, "new_role": body.role},
    )

    return _serialize_user(target)


@router.delete("/{user_id}", status_code=204)
async def deactivate_member(
    user_id: str,
    request: Request,
    current_user: User = Depends(require_permission(Permission.USERS_DEACTIVATE)),
) -> None:
    """Deactivate a member (soft-delete). They can no longer log in."""
    async with get_session() as session:
        user_repo = UserRepository(session)
        target = await user_repo.get_by_id(user_id)

        if target is None or target.org_id != current_user.org_id:
            raise HTTPException(status_code=404, detail="User not found in organization")

        if target.id == current_user.id:
            raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

        if target.role == "owner":
            owners = [u for u in await user_repo.list_for_org(current_user.org_id) if u.role == "owner"]
            if len(owners) <= 1:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot deactivate the last owner.",
                )

        await user_repo.deactivate(user_id)

        # Revoke all refresh tokens
        from db.repositories import RefreshTokenRepository
        rt_repo = RefreshTokenRepository(session)
        await rt_repo.revoke_all_for_user(user_id)

    await emit_audit(
        action=AuditAction.USER_DEACTIVATED,
        org_id=current_user.org_id,
        actor=current_user,
        resource_type="user",
        resource_id=user_id,
        request=request,
    )
