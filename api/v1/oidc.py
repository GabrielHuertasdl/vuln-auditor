"""OIDC SSO endpoints — /api/v1/auth/oidc.

Supported providers:
  - google   — Google Workspace (OIDC, fully implemented)
  - azure    — Microsoft Azure AD / Entra ID (OIDC, configured + interface ready)
  - okta     — Okta (OIDC, configured + interface ready)

Flow:
  1. GET  /api/v1/auth/oidc/{provider}/authorize  → redirect to provider
  2. GET  /api/v1/auth/oidc/{provider}/callback   → exchange code, create/link user, issue JWT

Requires authlib: pip install authlib httpx
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from core.config import settings
from db.audit import AuditAction, emit_audit
from db.database import get_session
from db.repositories import MembershipRepository, OIDCRepository, OrgRepository, UserRepository

log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/oidc", tags=["sso"])

# ── Provider configuration ─────────────────────────────────────────────────────

_PROVIDERS: dict[str, dict[str, Any]] = {
    "google": {
        "name": "Google",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openid-connect.googleapis.com/v1/userinfo",
        "client_id_setting": "oidc_google_client_id",
        "client_secret_setting": "oidc_google_client_secret",
        "scope": "openid email profile",
    },
    "azure": {
        "name": "Azure AD",
        "authorization_endpoint": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
        "token_endpoint": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        "userinfo_endpoint": "https://graph.microsoft.com/v1.0/me",
        "client_id_setting": "oidc_azure_client_id",
        "client_secret_setting": "oidc_azure_client_secret",
        "tenant_setting": "oidc_azure_tenant_id",
        "scope": "openid email profile",
    },
    "okta": {
        "name": "Okta",
        "authorization_endpoint": "https://{domain}/oauth2/v1/authorize",
        "token_endpoint": "https://{domain}/oauth2/v1/token",
        "userinfo_endpoint": "https://{domain}/oauth2/v1/userinfo",
        "client_id_setting": "oidc_okta_client_id",
        "client_secret_setting": "oidc_okta_client_secret",
        "domain_setting": "oidc_okta_domain",
        "scope": "openid email profile",
    },
}


def _get_provider_config(provider: str) -> dict[str, Any]:
    if provider not in _PROVIDERS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown OIDC provider '{provider}'. Supported: {list(_PROVIDERS)}",
        )
    cfg = _PROVIDERS[provider].copy()
    client_id = getattr(settings, cfg["client_id_setting"], None)
    client_secret = getattr(settings, cfg["client_secret_setting"], None)

    if not client_id or not client_secret:
        raise HTTPException(
            status_code=501,
            detail=f"OIDC provider '{provider}' is not configured. Set {cfg['client_id_setting'].upper()} and {cfg['client_secret_setting'].upper()} in your environment.",
        )

    # Interpolate tenant/domain placeholders
    if "tenant_setting" in cfg:
        tenant = getattr(settings, cfg["tenant_setting"], "common")
        cfg["authorization_endpoint"] = cfg["authorization_endpoint"].format(tenant=tenant or "common")
        cfg["token_endpoint"] = cfg["token_endpoint"].format(tenant=tenant or "common")

    if "domain_setting" in cfg:
        domain = getattr(settings, cfg["domain_setting"], "")
        if not domain:
            raise HTTPException(status_code=501, detail="Okta domain not configured (OIDC_OKTA_DOMAIN)")
        cfg["authorization_endpoint"] = cfg["authorization_endpoint"].format(domain=domain)
        cfg["token_endpoint"] = cfg["token_endpoint"].format(domain=domain)
        cfg["userinfo_endpoint"] = cfg["userinfo_endpoint"].format(domain=domain)

    cfg["client_id"] = client_id
    cfg["client_secret"] = client_secret
    return cfg


# ── Response models ────────────────────────────────────────────────────────────

class OIDCStatusResponse(BaseModel):
    provider: str
    name: str
    configured: bool
    enabled: bool


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/status", response_model=list[OIDCStatusResponse])
async def oidc_status() -> list[OIDCStatusResponse]:
    """Return the configuration status of all OIDC providers."""
    result = []
    for provider, cfg in _PROVIDERS.items():
        client_id = getattr(settings, cfg["client_id_setting"], None)
        result.append(OIDCStatusResponse(
            provider=provider,
            name=cfg["name"],
            configured=bool(client_id),
            enabled=bool(client_id),
        ))
    return result


@router.get("/{provider}/authorize")
async def oidc_authorize(provider: str, request: Request) -> RedirectResponse:
    """Redirect to the OIDC provider's authorization endpoint."""
    try:
        from authlib.integrations.httpx_client import AsyncOAuth2Client
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="authlib is required for SSO. Install with: pip install authlib",
        )

    cfg = _get_provider_config(provider)
    redirect_uri = f"{settings.oidc_redirect_base_url}/api/v1/auth/oidc/{provider}/callback"

    import secrets as _secrets
    state = _secrets.token_urlsafe(32)
    request.session["oidc_state"] = state
    request.session["oidc_provider"] = provider

    client = AsyncOAuth2Client(
        client_id=cfg["client_id"],
        client_secret=cfg["client_secret"],
        redirect_uri=redirect_uri,
        scope=cfg["scope"],
    )

    url, _state = client.create_authorization_url(
        cfg["authorization_endpoint"],
        state=state,
        access_type="offline" if provider == "google" else None,
    )

    return RedirectResponse(url=url)


@router.get("/{provider}/callback")
async def oidc_callback(provider: str, request: Request, code: str, state: str) -> dict:
    """
    Handle the OIDC callback:
    1. Exchange code for tokens
    2. Fetch user info from provider
    3. Create or link local user
    4. Issue VulnAuditor JWT pair
    """
    try:
        from authlib.integrations.httpx_client import AsyncOAuth2Client
    except ImportError:
        raise HTTPException(
            status_code=501, detail="authlib is required for SSO."
        )

    # Validate state to prevent CSRF
    session_state = request.session.get("oidc_state")
    if not session_state or not _secure_compare(state, session_state):
        raise HTTPException(status_code=400, detail="Invalid OAuth state parameter.")

    cfg = _get_provider_config(provider)
    redirect_uri = f"{settings.oidc_redirect_base_url}/api/v1/auth/oidc/{provider}/callback"

    try:
        client = AsyncOAuth2Client(
            client_id=cfg["client_id"],
            client_secret=cfg["client_secret"],
            redirect_uri=redirect_uri,
        )
        token = await client.fetch_token(
            cfg["token_endpoint"],
            code=code,
            grant_type="authorization_code",
        )

        # Fetch user info
        import httpx as _httpx
        async with _httpx.AsyncClient() as http:
            headers = {"Authorization": f"Bearer {token['access_token']}"}
            resp = await http.get(cfg["userinfo_endpoint"], headers=headers)
            resp.raise_for_status()
            userinfo = resp.json()

    except Exception as e:
        log.error("OIDC token exchange failed for provider=%s: %s", provider, e)
        raise HTTPException(status_code=502, detail=f"OIDC authentication failed: {e}")

    # Extract standard claims
    provider_sub = userinfo.get("sub") or userinfo.get("id")
    provider_email = (
        userinfo.get("email")
        or userinfo.get("mail")
        or userinfo.get("userPrincipalName", "")
    )
    provider_name = (
        userinfo.get("name")
        or userinfo.get("displayName")
        or provider_email.split("@")[0]
    )

    if not provider_sub or not provider_email:
        raise HTTPException(
            status_code=400,
            detail="OIDC provider did not return required user info (sub, email).",
        )

    async with get_session() as session:
        oidc_repo = OIDCRepository(session)
        user_repo = UserRepository(session)
        org_repo = OrgRepository(session)

        # Check if OIDC account already linked
        existing_oidc = await oidc_repo.get_by_sub(provider, provider_sub)

        if existing_oidc:
            user = await user_repo.get_by_id(existing_oidc.user_id)
            if user is None or not user.is_active:
                raise HTTPException(status_code=403, detail="Account deactivated.")
        else:
            # Check if user with this email already exists
            user = await user_repo.get_by_email(provider_email)

            if user is None:
                # Create new user + org
                org_name = f"{provider_name}'s Workspace"
                org, _raw_key = await org_repo.create_org(org_name, plan="free", quota=-1)

                user = await user_repo.create(
                    email=provider_email,
                    password_hash=None,
                    name=provider_name,
                    org_id=org.id,
                    role="owner",
                )

                membership_repo = MembershipRepository(session)
                await membership_repo.create(user_id=user.id, org_id=org.id, role="owner")

            # Link OIDC account
            await oidc_repo.link(user.id, provider, provider_sub, provider_email)

        org = await org_repo.get_by_id(user.org_id)
        org_name = org.name if org else None

    await emit_audit(
        action=AuditAction.AUTH_SSO_LINKED,
        org_id=user.org_id,
        actor=user,
        resource_type="oidc_account",
        request=request,
        details={"provider": provider},
    )

    from api.user_auth import _issue_tokens
    token_response = await _issue_tokens(user, org_name, request)

    # Redirect to frontend with tokens in query params (or use session cookie)
    frontend_redirect = (
        f"{settings.frontend_url}/auth/callback"
        f"?access_token={token_response.access_token}"
        f"&refresh_token={token_response.refresh_token}"
    )
    return RedirectResponse(url=frontend_redirect)


def _secure_compare(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())
