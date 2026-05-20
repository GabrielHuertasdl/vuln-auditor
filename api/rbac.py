"""Role-Based Access Control for the VulnAuditor ASPM platform.

Roles (ordered by privilege):
  owner    — full control, including billing and org deletion
  admin    — full control except org deletion
  analyst  — read/write scans, findings, targets; no user/billing management
  viewer   — read-only access to all security data

Usage:
    @router.delete("/targets/{id}")
    async def delete_target(
        ...,
        user: User = Depends(require_permission(Permission.TARGETS_DELETE)),
    ):
"""
from __future__ import annotations

from enum import Enum
from typing import Annotated

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from db.models import User

_bearer = HTTPBearer(auto_error=False)


class Permission(str, Enum):
    # Organization
    ORG_READ = "org:read"
    ORG_UPDATE = "org:update"
    ORG_DELETE = "org:delete"

    # User management
    USERS_READ = "users:read"
    USERS_INVITE = "users:invite"
    USERS_UPDATE_ROLE = "users:update_role"
    USERS_DEACTIVATE = "users:deactivate"

    # API keys
    API_KEYS_READ = "api_keys:read"
    API_KEYS_CREATE = "api_keys:create"
    API_KEYS_REVOKE = "api_keys:revoke"

    # Targets
    TARGETS_READ = "targets:read"
    TARGETS_CREATE = "targets:create"
    TARGETS_UPDATE = "targets:update"
    TARGETS_DELETE = "targets:delete"

    # Scans
    SCANS_READ = "scans:read"
    SCANS_CREATE = "scans:create"
    SCANS_CANCEL = "scans:cancel"
    SCANS_DELETE = "scans:delete"

    # Findings
    FINDINGS_READ = "findings:read"
    FINDINGS_UPDATE_STATUS = "findings:update_status"

    # Reports
    REPORTS_READ = "reports:read"
    REPORTS_EXPORT = "reports:export"

    # Integrations & webhooks
    INTEGRATIONS_READ = "integrations:read"
    INTEGRATIONS_MANAGE = "integrations:manage"

    # Billing
    BILLING_READ = "billing:read"
    BILLING_MANAGE = "billing:manage"

    # Settings (org-level)
    SETTINGS_READ = "settings:read"
    SETTINGS_MANAGE = "settings:manage"

    # Audit logs
    AUDIT_READ = "audit:read"

    # SSO / OIDC config
    SSO_MANAGE = "sso:manage"


# ── Role → Permission mapping ─────────────────────────────────────────────────

_ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "owner": set(Permission),  # all permissions

    "admin": {
        Permission.ORG_READ, Permission.ORG_UPDATE,
        Permission.USERS_READ, Permission.USERS_INVITE,
        Permission.USERS_UPDATE_ROLE, Permission.USERS_DEACTIVATE,
        Permission.API_KEYS_READ, Permission.API_KEYS_CREATE, Permission.API_KEYS_REVOKE,
        Permission.TARGETS_READ, Permission.TARGETS_CREATE,
        Permission.TARGETS_UPDATE, Permission.TARGETS_DELETE,
        Permission.SCANS_READ, Permission.SCANS_CREATE,
        Permission.SCANS_CANCEL, Permission.SCANS_DELETE,
        Permission.FINDINGS_READ, Permission.FINDINGS_UPDATE_STATUS,
        Permission.REPORTS_READ, Permission.REPORTS_EXPORT,
        Permission.INTEGRATIONS_READ, Permission.INTEGRATIONS_MANAGE,
        Permission.BILLING_READ,
        Permission.SETTINGS_READ, Permission.SETTINGS_MANAGE,
        Permission.AUDIT_READ,
        Permission.SSO_MANAGE,
    },

    "analyst": {
        Permission.ORG_READ,
        Permission.USERS_READ,
        Permission.API_KEYS_READ,
        Permission.TARGETS_READ, Permission.TARGETS_CREATE,
        Permission.TARGETS_UPDATE,
        Permission.SCANS_READ, Permission.SCANS_CREATE, Permission.SCANS_CANCEL,
        Permission.FINDINGS_READ, Permission.FINDINGS_UPDATE_STATUS,
        Permission.REPORTS_READ, Permission.REPORTS_EXPORT,
        Permission.INTEGRATIONS_READ,
        Permission.SETTINGS_READ,
    },

    "viewer": {
        Permission.ORG_READ,
        Permission.TARGETS_READ,
        Permission.SCANS_READ,
        Permission.FINDINGS_READ,
        Permission.REPORTS_READ,
        Permission.INTEGRATIONS_READ,
        Permission.SETTINGS_READ,
    },
}


def get_role_permissions(role: str) -> set[Permission]:
    return _ROLE_PERMISSIONS.get(role, set())


def has_permission(role: str, permission: Permission) -> bool:
    return permission in get_role_permissions(role)


# ── FastAPI dependencies ──────────────────────────────────────────────────────

async def _get_current_user_from_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
) -> User | None:
    """Extract User from Bearer JWT. Returns None on missing/invalid token."""
    if credentials is None:
        return None
    try:
        from api.user_auth import decode_access_token
        from db.database import get_session
        from db.repositories import UserRepository

        payload = decode_access_token(credentials.credentials)
        user_id: str = payload["sub"]
        async with get_session() as session:
            repo = UserRepository(session)
            user = await repo.get_by_id(user_id)
            return user if user and user.is_active else None
    except Exception:
        return None


async def get_authenticated_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
) -> User:
    """Require a valid JWT. Raises 401 otherwise."""
    user = await _get_current_user_from_token(credentials)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def require_permission(permission: Permission):
    """
    FastAPI dependency factory. Returns a dependency that:
    1. Requires a valid JWT
    2. Checks the user's role has the given permission

    Usage:
        user: User = Depends(require_permission(Permission.TARGETS_DELETE))
    """
    async def _dependency(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
    ) -> User:
        user = await _get_current_user_from_token(credentials)
        if user is None:
            raise HTTPException(status_code=401, detail="Authentication required.")
        if not has_permission(user.role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied. Required: {permission.value}. Your role: {user.role}.",
            )
        return user

    return _dependency


def require_any_permission(*permissions: Permission):
    """Require any one of the given permissions (OR logic)."""
    async def _dependency(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
    ) -> User:
        user = await _get_current_user_from_token(credentials)
        if user is None:
            raise HTTPException(status_code=401, detail="Authentication required.")
        user_perms = get_role_permissions(user.role)
        if not any(p in user_perms for p in permissions):
            required = " | ".join(p.value for p in permissions)
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied. Required one of: {required}. Your role: {user.role}.",
            )
        return user

    return _dependency
