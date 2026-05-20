"""JWT-based user authentication: register, login, refresh, logout, me.

Security model:
  - Access tokens: short-lived (60 min default), JWT signed with HS256
  - Refresh tokens: long-lived (7 days), stored as hash in DB for revocation
  - Password hashing: PBKDF2-SHA256, 260k iterations
  - Login failures tracked per user (rate limiting layer handles lockout)
  - Refresh token rotation: issuing a new refresh token revokes the old one
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr

from core.config import settings
from db.audit import AuditAction, emit_audit
from db.database import get_session
from db.models import User
from db.repositories import (
    MembershipRepository,
    OrgRepository,
    RefreshTokenRepository,
    UserRepository,
)

router = APIRouter(prefix="/auth", tags=["auth"])

_bearer = HTTPBearer(auto_error=False)


# ── Pydantic models ────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    org_name: str | None = None
    invite_token: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: "UserInfo"


class UserInfo(BaseModel):
    id: str
    email: str
    name: str
    role: str
    org_id: str
    org_name: str | None = None

    model_config = {"from_attributes": True}


TokenResponse.model_rebuild()


# ── Password helpers ───────────────────────────────────────────────────────────

def _hash_password(plain: str) -> str:
    salt = secrets.token_hex(32)
    key = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 260_000)
    return f"pbkdf2:{salt}:{key.hex()}"


def _verify_password(plain: str, stored: str) -> bool:
    try:
        _, salt, key_hex = stored.split(":")
    except ValueError:
        return False
    key = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 260_000)
    return secrets.compare_digest(key.hex(), key_hex)


# ── JWT helpers ────────────────────────────────────────────────────────────────

def _create_token(data: dict, expires_delta: timedelta) -> str:
    payload = {**data, "exp": datetime.now(UTC) + expires_delta}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_access_token(user_id: str, org_id: str, role: str) -> str:
    return _create_token(
        {"sub": user_id, "org": org_id, "role": role, "type": "access"},
        timedelta(minutes=settings.access_token_expire_minutes),
    )


def create_refresh_token_value() -> str:
    """Generate a secure random refresh token value (not a JWT)."""
    return secrets.token_urlsafe(48)


def decode_access_token(token: str) -> dict:
    """Raises JWTError on invalid/expired token."""
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    if payload.get("type") != "access":
        raise JWTError("not an access token")
    return payload


# ── FastAPI dependencies ───────────────────────────────────────────────────────

async def get_current_user_from_bearer(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
) -> User | None:
    if credentials is None:
        return None
    try:
        payload = decode_access_token(credentials.credentials)
        user_id: str = payload["sub"]
    except (JWTError, KeyError):
        return None

    async with get_session() as session:
        repo = UserRepository(session)
        user = await repo.get_by_id(user_id)
        return user if user and user.is_active else None


async def _issue_tokens(user: User, org_name: str | None, request: Request | None = None) -> TokenResponse:
    """Create access + refresh tokens, persist refresh token hash in DB."""
    access_token = create_access_token(user.id, user.org_id, user.role)
    raw_refresh = create_refresh_token_value()

    device_hint = None
    if request:
        ua = request.headers.get("User-Agent", "")
        device_hint = ua[:120] if ua else None

    async with get_session() as session:
        rt_repo = RefreshTokenRepository(session)
        await rt_repo.store(user.id, raw_refresh, settings.refresh_token_expire_days, device_hint)

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        user=UserInfo(
            id=user.id,
            email=user.email,
            name=user.name,
            role=user.role,
            org_id=user.org_id,
            org_name=org_name,
        ),
    )


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(body: RegisterRequest, request: Request) -> TokenResponse:
    async with get_session() as session:
        user_repo = UserRepository(session)
        existing = await user_repo.get_by_email(body.email)
        if existing:
            raise HTTPException(status_code=409, detail="Email already registered")

        org_repo = OrgRepository(session)

        # Handle invite token flow
        if body.invite_token:
            from db.repositories import InviteTokenRepository
            invite_repo = InviteTokenRepository(session)
            invite = await invite_repo.get_valid(body.invite_token)
            if invite is None:
                raise HTTPException(status_code=400, detail="Invalid or expired invite token")
            if invite.email.lower() != body.email.lower():
                raise HTTPException(status_code=400, detail="Invite email does not match")

            org = await org_repo.get_by_id(invite.org_id)
            if org is None:
                raise HTTPException(status_code=404, detail="Organization not found")

            user = await user_repo.create(
                email=body.email,
                password_hash=_hash_password(body.password),
                name=body.name,
                org_id=org.id,
                role=invite.role,
            )

            membership_repo = MembershipRepository(session)
            await membership_repo.create(
                user_id=user.id, org_id=org.id, role=invite.role, invited_by=invite.invited_by
            )
            await invite_repo.accept(invite.id)
            org_name = org.name
        else:
            # New org registration
            org_name = body.org_name or f"{body.name}'s Workspace"
            org, _raw_key = await org_repo.create_org(org_name, plan="free", quota=-1)

            user = await user_repo.create(
                email=body.email,
                password_hash=_hash_password(body.password),
                name=body.name,
                org_id=org.id,
                role="owner",
            )

            membership_repo = MembershipRepository(session)
            await membership_repo.create(user_id=user.id, org_id=org.id, role="owner")

    await emit_audit(
        action=AuditAction.AUTH_REGISTER,
        org_id=org.id,
        actor=user,
        resource_type="user",
        resource_id=user.id,
        request=request,
    )

    return await _issue_tokens(user, org_name, request)


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request) -> TokenResponse:
    async with get_session() as session:
        user_repo = UserRepository(session)
        user = await user_repo.get_by_email(body.email)

        if user is None or not _verify_password(body.password, user.password_hash or ""):
            if user:
                await user_repo.record_login(user.id, success=False)
            await emit_audit(
                action=AuditAction.AUTH_LOGIN_FAILED,
                actor_email=body.email,
                request=request,
                details={"reason": "invalid_credentials"},
            )
            raise HTTPException(status_code=401, detail="Invalid email or password")

        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account deactivated")

        await user_repo.record_login(user.id, success=True)

        org_repo = OrgRepository(session)
        org = await org_repo.get_by_id(user.org_id)
        org_name = org.name if org else None

    await emit_audit(
        action=AuditAction.AUTH_LOGIN,
        org_id=user.org_id,
        actor=user,
        resource_type="user",
        resource_id=user.id,
        request=request,
    )

    return await _issue_tokens(user, org_name, request)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest, request: Request) -> TokenResponse:
    """Rotate refresh token: validates, revokes old, issues new pair."""
    async with get_session() as session:
        rt_repo = RefreshTokenRepository(session)
        rt_record = await rt_repo.get_valid(body.refresh_token)

        if rt_record is None:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

        # Rotate: revoke old token
        await rt_repo.revoke(body.refresh_token)

        user_repo = UserRepository(session)
        user = await user_repo.get_by_id(rt_record.user_id)
        if user is None or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or deactivated")

        org_repo = OrgRepository(session)
        org = await org_repo.get_by_id(user.org_id)
        org_name = org.name if org else None

    await emit_audit(
        action=AuditAction.AUTH_TOKEN_REFRESHED,
        org_id=user.org_id,
        actor=user,
        request=request,
    )

    return await _issue_tokens(user, org_name, request)


@router.post("/logout", status_code=204)
async def logout(body: LogoutRequest, request: Request) -> None:
    """Revoke the given refresh token."""
    async with get_session() as session:
        rt_repo = RefreshTokenRepository(session)
        revoked = await rt_repo.revoke(body.refresh_token)

    if revoked:
        # Best-effort: identify user for audit
        user = await get_current_user_from_bearer(None)
        await emit_audit(
            action=AuditAction.AUTH_LOGOUT,
            request=request,
        )


@router.get("/me", response_model=UserInfo)
async def me(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
) -> UserInfo:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_access_token(credentials.credentials)
        user_id: str = payload["sub"]
    except (JWTError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid token")

    async with get_session() as session:
        user_repo = UserRepository(session)
        user = await user_repo.get_by_id(user_id)
        if user is None or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found")

        org_repo = OrgRepository(session)
        org = await org_repo.get_by_id(user.org_id)
        org_name = org.name if org else None

    return UserInfo(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
        org_id=user.org_id,
        org_name=org_name,
    )
