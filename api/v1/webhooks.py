"""Webhook management endpoints — /api/v1/webhooks.

Supports Slack, Teams, PagerDuty, and generic HTTP endpoints.
Payloads are signed with HMAC-SHA256 when a secret is configured.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, HttpUrl

from api.rbac import Permission, require_permission
from core.entitlements import Feature, check_entitlement, within_limit, get_plan_limits, plan_upgrade_message
from db.audit import AuditAction, emit_audit
from db.database import get_session
from db.models import User
from db.repositories import OrgRepository, WebhookRepository

log = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

SUPPORTED_EVENTS = [
    "scan.created",
    "scan.completed",
    "scan.failed",
    "finding.created",
    "finding.status_changed",
    "finding.regression",
    "report.exported",
    "user.invited",
    "billing.plan_changed",
]


# ── Pydantic models ────────────────────────────────────────────────────────────

class WebhookCreate(BaseModel):
    name: str
    url: HttpUrl
    events: list[str] = ["scan.completed", "finding.regression"]
    secret: str | None = None


class WebhookResponse(BaseModel):
    id: str
    name: str
    url: str
    events: list[str]
    is_active: bool
    created_at: datetime
    last_triggered_at: datetime | None


class WebhookDeliveryResponse(BaseModel):
    id: str
    event: str
    status_code: int | None
    succeeded: bool
    attempt_count: int
    created_at: datetime
    delivered_at: datetime | None


def _serialize(endpoint) -> WebhookResponse:
    events = json.loads(endpoint.events) if isinstance(endpoint.events, str) else endpoint.events
    return WebhookResponse(
        id=endpoint.id,
        name=endpoint.name,
        url=endpoint.url,
        events=events,
        is_active=endpoint.is_active,
        created_at=endpoint.created_at,
        last_triggered_at=endpoint.last_triggered_at,
    )


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("", response_model=list[WebhookResponse])
async def list_webhooks(
    current_user: User = Depends(require_permission(Permission.INTEGRATIONS_READ)),
) -> list[WebhookResponse]:
    async with get_session() as session:
        repo = WebhookRepository(session)
        endpoints = await repo.list_for_org(current_user.org_id)
        return [_serialize(ep) for ep in endpoints]


@router.post("", response_model=WebhookResponse, status_code=201)
async def create_webhook(
    body: WebhookCreate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.INTEGRATIONS_MANAGE)),
) -> WebhookResponse:
    # Check plan entitlement
    async with get_session() as session:
        org_repo = OrgRepository(session)
        org = await org_repo.get_by_id(current_user.org_id)
        if org is None:
            raise HTTPException(status_code=404, detail="Organization not found")

    if not check_entitlement(org.plan, Feature.WEBHOOKS):
        raise HTTPException(
            status_code=402, detail=plan_upgrade_message(org.plan, Feature.WEBHOOKS)
        )

    # Validate events
    invalid_events = [e for e in body.events if e not in SUPPORTED_EVENTS]
    if invalid_events:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported events: {invalid_events}. Supported: {SUPPORTED_EVENTS}",
        )

    limits = get_plan_limits(org.plan)
    async with get_session() as session:
        wh_repo = WebhookRepository(session)
        existing = await wh_repo.list_for_org(current_user.org_id)

        if not within_limit(len(existing), limits.max_webhooks):
            raise HTTPException(
                status_code=402,
                detail=f"Webhook limit reached ({limits.max_webhooks}). Upgrade your plan.",
            )

        endpoint = await wh_repo.create(
            org_id=current_user.org_id,
            name=body.name,
            url=str(body.url),
            events=body.events,
            created_by=current_user.id,
            secret=body.secret,
        )

    await emit_audit(
        action=AuditAction.WEBHOOK_CREATED,
        org_id=current_user.org_id,
        actor=current_user,
        resource_type="webhook",
        resource_id=endpoint.id,
        request=request,
        details={"name": body.name, "events": body.events},
    )

    return _serialize(endpoint)


@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: str,
    request: Request,
    current_user: User = Depends(require_permission(Permission.INTEGRATIONS_MANAGE)),
) -> None:
    async with get_session() as session:
        repo = WebhookRepository(session)
        deactivated = await repo.deactivate(webhook_id, current_user.org_id)

    if not deactivated:
        raise HTTPException(status_code=404, detail="Webhook not found")

    await emit_audit(
        action=AuditAction.WEBHOOK_DELETED,
        org_id=current_user.org_id,
        actor=current_user,
        resource_type="webhook",
        resource_id=webhook_id,
        request=request,
    )


@router.post("/{webhook_id}/test", status_code=202)
async def test_webhook(
    webhook_id: str,
    current_user: User = Depends(require_permission(Permission.INTEGRATIONS_MANAGE)),
) -> dict:
    """Dispatch a test event to verify the webhook endpoint is reachable."""
    async with get_session() as session:
        repo = WebhookRepository(session)
        endpoint = await repo.get(webhook_id, current_user.org_id)

    if endpoint is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    test_payload = {
        "event": "webhook.test",
        "org_id": current_user.org_id,
        "message": "This is a test delivery from VulnAuditor ASPM.",
    }

    asyncio.create_task(
        _deliver_webhook(endpoint.id, endpoint.url, endpoint.secret_hash, "webhook.test", test_payload)
    )

    return {"message": "Test delivery scheduled.", "webhook_id": webhook_id}


# ── Delivery engine ────────────────────────────────────────────────────────────

def _sign_payload(payload_bytes: bytes, secret_hash: str | None) -> str | None:
    """Generate HMAC-SHA256 signature for the payload."""
    if not secret_hash:
        return None
    sig = hmac.new(secret_hash.encode(), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


async def dispatch_webhook_event(
    org_id: str, event: str, payload: dict
) -> None:
    """
    Find all active webhook endpoints subscribed to the event and deliver the payload.
    Called fire-and-forget from scan/finding routes.
    """
    try:
        async with get_session() as session:
            repo = WebhookRepository(session)
            endpoints = await repo.get_active_for_event(org_id, event)

        for endpoint in endpoints:
            asyncio.create_task(
                _deliver_webhook(endpoint.id, endpoint.url, endpoint.secret_hash, event, payload)
            )
    except Exception as e:
        log.warning("Webhook dispatch error for org=%s event=%s: %s", org_id, event, e)


async def _deliver_webhook(
    endpoint_id: str,
    url: str,
    secret_hash: str | None,
    event: str,
    payload: dict,
    max_retries: int = 3,
) -> None:
    """Deliver a webhook with exponential backoff retry."""
    payload_bytes = json.dumps(payload, default=str).encode()
    signature = _sign_payload(payload_bytes, secret_hash)

    headers = {
        "Content-Type": "application/json",
        "X-VulnAuditor-Event": event,
        "X-VulnAuditor-Delivery": endpoint_id,
    }
    if signature:
        headers["X-VulnAuditor-Signature"] = signature

    status_code = None
    response_body = None
    succeeded = False

    for attempt in range(1, max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, content=payload_bytes, headers=headers)
                status_code = response.status_code
                response_body = response.text[:500]
                succeeded = 200 <= status_code < 300
                if succeeded:
                    break
        except Exception as e:
            log.warning("Webhook delivery attempt %d failed for %s: %s", attempt, url, e)
            response_body = str(e)

        if attempt < max_retries and not succeeded:
            await asyncio.sleep(2 ** attempt)  # 2s, 4s backoff

    try:
        async with get_session() as session:
            repo = WebhookRepository(session)
            await repo.log_delivery(
                endpoint_id=endpoint_id,
                event=event,
                payload=payload,
                status_code=status_code,
                response_body=response_body,
                succeeded=succeeded,
            )
    except Exception as e:
        log.warning("Failed to log webhook delivery: %s", e)

    if not succeeded:
        log.warning("Webhook delivery failed after %d attempts: endpoint=%s event=%s", max_retries, endpoint_id, event)
