"""API authentication: X-API-Key header OR Bearer JWT token."""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from db.database import get_session
from db.models import Organization
from db.repositories import OrgRepository

log = logging.getLogger(__name__)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
_bearer = HTTPBearer(auto_error=False)

# Fixed UUID for the demo org — same every restart
DEMO_ORG_ID = "00000000-0000-0000-0000-000000000001"


async def _ensure_demo_org(session: AsyncSession) -> Organization:
    """Create the demo org if it doesn't exist yet."""
    repo = OrgRepository(session)
    org = await repo.get_by_id(DEMO_ORG_ID)
    if org is None:
        from datetime import UTC, datetime
        import hashlib

        org = Organization(
            id=DEMO_ORG_ID,
            name=settings.demo_org_name,
            api_key_hash=hashlib.sha256(b"demo-org-no-key").hexdigest(),
            plan="free",
            scan_quota=-1,
            scans_this_month=0,
            quota_reset_at=_next_month_start(),
            created_at=datetime.now(UTC),
        )
        session.add(org)
        await session.flush()
        log.info("Demo org created (id=%s)", DEMO_ORG_ID)
    return org


def _next_month_start():
    from datetime import UTC, datetime
    now = datetime.now(UTC)
    if now.month == 12:
        return now.replace(year=now.year + 1, month=1, day=1,
                           hour=0, minute=0, second=0, microsecond=0)
    return now.replace(month=now.month + 1, day=1,
                       hour=0, minute=0, second=0, microsecond=0)


async def get_current_org(
    api_key: str | None = Security(API_KEY_HEADER),
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)] = None,
) -> Organization:
    """
    Resolve the current organization from:
    1. X-API-Key header (existing API key flow)
    2. Authorization: Bearer <jwt> (UI flow — decodes JWT → user → org)
    3. Demo org if require_auth=False and no credentials provided
    """
    # ── Bearer JWT path ────────────────────────────────────────────────────────
    if credentials is not None:
        from api.user_auth import decode_access_token
        from db.repositories import UserRepository
        try:
            payload = decode_access_token(credentials.credentials)
            user_id: str = payload["sub"]
            org_id: str = payload["org"]
        except (JWTError, KeyError):
            raise HTTPException(status_code=401, detail="Invalid or expired token")

        async with get_session() as session:
            repo = OrgRepository(session)
            org = await repo.get_by_id(org_id)
            if org is None:
                raise HTTPException(status_code=401, detail="Organization not found")
            return org

    # ── API key path ───────────────────────────────────────────────────────────
    if api_key:
        async with get_session() as session:
            repo = OrgRepository(session)
            org = await repo.get_by_api_key(api_key)
            if org is None:
                raise HTTPException(status_code=401, detail="Invalid API key")
            return org

    # ── Demo / development mode ────────────────────────────────────────────────
    if settings.require_auth:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Provide X-API-Key or Authorization: Bearer token.",
        )

    async with get_session() as session:
        return await _ensure_demo_org(session)
