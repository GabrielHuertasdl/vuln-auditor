"""Billing routes: Stripe Checkout session + webhook handler."""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.auth import get_current_org
from core.config import settings
from db.database import get_session
from db.models import Organization
from db.repositories import OrgRepository

log = logging.getLogger(__name__)
router = APIRouter(prefix="/billing", tags=["billing"])

_PLAN_BY_PRICE: dict[str, str] = {}


def _plan_by_price_id(price_id: str) -> str:
    """Map Stripe price ID → plan name."""
    if settings.stripe_price_pro_monthly and price_id == settings.stripe_price_pro_monthly:
        return "pro"
    if settings.stripe_price_enterprise_monthly and price_id == settings.stripe_price_enterprise_monthly:
        return "enterprise"
    return "pro"


class CheckoutRequest(BaseModel):
    price_id: str | None = None
    success_url: str | None = None
    cancel_url: str | None = None


@router.post("/checkout")
async def create_checkout_session(
    body: CheckoutRequest,
    org: Organization = Depends(get_current_org),
) -> dict:
    """Create a Stripe Checkout session for upgrading the org plan."""
    if not settings.stripe_secret_key:
        raise HTTPException(status_code=503, detail="Stripe not configured")

    try:
        import stripe  # type: ignore[import]
        stripe.api_key = settings.stripe_secret_key
    except ImportError:
        raise HTTPException(status_code=503, detail="stripe package not installed")

    price_id = body.price_id or settings.stripe_price_pro_monthly
    if not price_id:
        raise HTTPException(status_code=400, detail="price_id required (or configure STRIPE_PRICE_PRO_MONTHLY)")

    frontend_url = settings.frontend_url.rstrip("/")
    success_url = body.success_url or f"{frontend_url}/settings?billing=success"
    cancel_url = body.cancel_url or f"{frontend_url}/settings?billing=cancelled"

    customer_id = org.stripe_customer_id

    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=customer_id or None,
        customer_email=None if customer_id else None,
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={"org_id": org.id},
    )

    return {"checkout_url": session.url, "session_id": session.id}


@router.post("/webhook")
async def stripe_webhook(request: Request) -> dict:
    """Stripe webhook: verify signature and update org billing state."""
    if not settings.stripe_secret_key:
        raise HTTPException(status_code=503, detail="Stripe not configured")

    try:
        import stripe  # type: ignore[import]
        stripe.api_key = settings.stripe_secret_key
    except ImportError:
        raise HTTPException(status_code=503, detail="stripe package not installed")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    if not settings.stripe_webhook_secret:
        raise HTTPException(status_code=503, detail="STRIPE_WEBHOOK_SECRET not configured")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, settings.stripe_webhook_secret)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook parse error: {e}")

    event_type: str = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        org_id: str | None = data.get("metadata", {}).get("org_id")
        customer_id: str | None = data.get("customer")
        subscription_id: str | None = data.get("subscription")

        if org_id and customer_id and subscription_id:
            try:
                sub = stripe.Subscription.retrieve(subscription_id)
                plan = _plan_by_price_id(sub["items"]["data"][0]["price"]["id"])
                period_end = datetime.fromtimestamp(sub["current_period_end"], tz=UTC)

                async with get_session() as session:
                    repo = OrgRepository(session)
                    await repo.update_billing(
                        org_id=org_id,
                        stripe_customer_id=customer_id,
                        stripe_subscription_id=subscription_id,
                        stripe_subscription_status=sub["status"],
                        billing_period_end=period_end,
                        plan=plan,
                    )
                log.info("Checkout completed: org=%s plan=%s sub=%s", org_id, plan, subscription_id)
            except Exception as e:
                log.exception("Failed to process checkout.session.completed: %s", e)

    elif event_type in ("customer.subscription.updated", "customer.subscription.deleted"):
        subscription_id = data.get("id")
        status: str = data.get("status", "")
        period_end_ts = data.get("current_period_end")
        period_end = datetime.fromtimestamp(period_end_ts, tz=UTC) if period_end_ts else None

        if subscription_id:
            try:
                plan = "free" if event_type == "customer.subscription.deleted" else _plan_by_price_id(
                    data["items"]["data"][0]["price"]["id"]
                )
                async with get_session() as session:
                    repo = OrgRepository(session)
                    await repo.update_billing_by_subscription(
                        stripe_subscription_id=subscription_id,
                        stripe_subscription_status=status,
                        billing_period_end=period_end,
                        plan=plan,
                    )
                log.info("Subscription %s event=%s status=%s plan=%s", subscription_id, event_type, status, plan)
            except Exception as e:
                log.exception("Failed to process %s: %s", event_type, e)

    return {"received": True}


@router.get("/portal")
async def create_portal_session(
    org: Organization = Depends(get_current_org),
) -> dict:
    """Create a Stripe Customer Portal session for managing the subscription."""
    if not settings.stripe_secret_key:
        raise HTTPException(status_code=503, detail="Stripe not configured")

    if not org.stripe_customer_id:
        raise HTTPException(status_code=400, detail="No Stripe customer found for this org")

    try:
        import stripe  # type: ignore[import]
        stripe.api_key = settings.stripe_secret_key
    except ImportError:
        raise HTTPException(status_code=503, detail="stripe package not installed")

    return_url = f"{settings.frontend_url.rstrip('/')}/settings"
    portal = stripe.billing_portal.Session.create(
        customer=org.stripe_customer_id,
        return_url=return_url,
    )
    return {"portal_url": portal.url}
