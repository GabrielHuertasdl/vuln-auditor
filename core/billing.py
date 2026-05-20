"""Billing integration scaffold for VulnAuditor ASPM.

Provides a clean adapter interface for Stripe (and future payment providers).
Stripe integration is production-ready when STRIPE_SECRET_KEY is configured.

Usage:
    from core.billing import get_billing_adapter, BillingPlan

    adapter = get_billing_adapter()
    session = await adapter.create_checkout_session(
        org_id=org.id,
        plan=BillingPlan.PRO,
        success_url="https://app.vulnauditor.com/settings/billing?success=1",
        cancel_url="https://app.vulnauditor.com/settings/billing",
    )
    redirect to session.url
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

log = logging.getLogger(__name__)


class BillingPlan(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


@dataclass
class CheckoutSession:
    session_id: str
    url: str
    plan: BillingPlan


@dataclass
class SubscriptionStatus:
    plan: BillingPlan
    status: str  # active | past_due | canceled | trialing
    current_period_end: int | None  # Unix timestamp
    cancel_at_period_end: bool
    stripe_customer_id: str | None
    stripe_subscription_id: str | None


class BillingAdapter(ABC):
    """Abstract billing adapter interface."""

    @abstractmethod
    async def create_checkout_session(
        self,
        org_id: str,
        plan: BillingPlan,
        success_url: str,
        cancel_url: str,
        customer_email: str | None = None,
    ) -> CheckoutSession:
        """Create a checkout session for plan upgrade."""

    @abstractmethod
    async def create_customer_portal_session(
        self,
        stripe_customer_id: str,
        return_url: str,
    ) -> str:
        """Return a Stripe Customer Portal URL for billing management."""

    @abstractmethod
    async def get_subscription_status(
        self, stripe_customer_id: str
    ) -> SubscriptionStatus | None:
        """Return current subscription status for a customer."""

    @abstractmethod
    async def handle_webhook(self, payload: bytes, signature: str) -> dict[str, Any]:
        """Process a Stripe webhook event. Returns parsed event data."""


# ── Stripe implementation ─────────────────────────────────────────────────────

class StripeAdapter(BillingAdapter):
    """
    Stripe billing adapter.

    Requires:
      - STRIPE_SECRET_KEY environment variable
      - STRIPE_WEBHOOK_SECRET for webhook verification
      - STRIPE_PRICE_PRO_MONTHLY price ID
      - STRIPE_PRICE_ENTERPRISE_MONTHLY price ID (optional)

    Install: pip install stripe
    """

    def __init__(
        self,
        secret_key: str,
        webhook_secret: str | None,
        price_pro: str | None,
        price_enterprise: str | None,
    ) -> None:
        self.secret_key = secret_key
        self.webhook_secret = webhook_secret
        self.price_pro = price_pro
        self.price_enterprise = price_enterprise

        try:
            import stripe as _stripe
            self._stripe = _stripe
            self._stripe.api_key = secret_key
        except ImportError:
            raise RuntimeError(
                "Stripe billing requires the stripe package. Install with: pip install stripe"
            )

    def _price_for_plan(self, plan: BillingPlan) -> str:
        if plan == BillingPlan.PRO:
            if not self.price_pro:
                raise ValueError("STRIPE_PRICE_PRO_MONTHLY is not configured")
            return self.price_pro
        if plan == BillingPlan.ENTERPRISE:
            if not self.price_enterprise:
                raise ValueError("STRIPE_PRICE_ENTERPRISE_MONTHLY is not configured")
            return self.price_enterprise
        raise ValueError(f"No price configured for plan: {plan}")

    async def create_checkout_session(
        self,
        org_id: str,
        plan: BillingPlan,
        success_url: str,
        cancel_url: str,
        customer_email: str | None = None,
    ) -> CheckoutSession:
        import asyncio
        price_id = self._price_for_plan(plan)
        kwargs: dict[str, Any] = {
            "mode": "subscription",
            "line_items": [{"price": price_id, "quantity": 1}],
            "success_url": success_url,
            "cancel_url": cancel_url,
            "metadata": {"org_id": org_id, "plan": plan.value},
        }
        if customer_email:
            kwargs["customer_email"] = customer_email

        session = await asyncio.to_thread(
            self._stripe.checkout.Session.create, **kwargs
        )
        return CheckoutSession(session_id=session.id, url=session.url, plan=plan)

    async def create_customer_portal_session(
        self, stripe_customer_id: str, return_url: str
    ) -> str:
        import asyncio
        session = await asyncio.to_thread(
            self._stripe.billing_portal.Session.create,
            customer=stripe_customer_id,
            return_url=return_url,
        )
        return session.url

    async def get_subscription_status(
        self, stripe_customer_id: str
    ) -> SubscriptionStatus | None:
        import asyncio
        subs = await asyncio.to_thread(
            self._stripe.Subscription.list,
            customer=stripe_customer_id,
            status="all",
            limit=1,
        )
        if not subs.data:
            return None
        sub = subs.data[0]
        plan_meta = sub.metadata.get("plan", "free")
        try:
            plan = BillingPlan(plan_meta)
        except ValueError:
            plan = BillingPlan.FREE

        return SubscriptionStatus(
            plan=plan,
            status=sub.status,
            current_period_end=sub.current_period_end,
            cancel_at_period_end=sub.cancel_at_period_end,
            stripe_customer_id=stripe_customer_id,
            stripe_subscription_id=sub.id,
        )

    async def handle_webhook(self, payload: bytes, signature: str) -> dict[str, Any]:
        if not self.webhook_secret:
            raise ValueError("STRIPE_WEBHOOK_SECRET is not configured")
        import asyncio
        event = await asyncio.to_thread(
            self._stripe.Webhook.construct_event,
            payload,
            signature,
            self.webhook_secret,
        )
        return dict(event)


# ── No-op adapter (when Stripe is not configured) ─────────────────────────────

class NoOpBillingAdapter(BillingAdapter):
    """Placeholder adapter when billing is not configured."""

    async def create_checkout_session(self, org_id, plan, success_url, cancel_url, customer_email=None):
        raise NotImplementedError(
            "Billing is not configured. Set STRIPE_SECRET_KEY to enable billing."
        )

    async def create_customer_portal_session(self, stripe_customer_id, return_url):
        raise NotImplementedError("Billing is not configured.")

    async def get_subscription_status(self, stripe_customer_id):
        return None

    async def handle_webhook(self, payload, signature):
        raise NotImplementedError("Billing is not configured.")


# ── Factory ───────────────────────────────────────────────────────────────────

_adapter_instance: BillingAdapter | None = None


def get_billing_adapter() -> BillingAdapter:
    global _adapter_instance
    if _adapter_instance is not None:
        return _adapter_instance

    from core.config import settings

    if settings.stripe_secret_key:
        _adapter_instance = StripeAdapter(
            secret_key=settings.stripe_secret_key,
            webhook_secret=settings.stripe_webhook_secret,
            price_pro=settings.stripe_price_pro_monthly,
            price_enterprise=settings.stripe_price_enterprise_monthly,
        )
        log.info("Stripe billing adapter initialized")
    else:
        _adapter_instance = NoOpBillingAdapter()
        log.info("Billing not configured — using no-op adapter")

    return _adapter_instance
