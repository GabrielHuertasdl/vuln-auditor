"""Tests for api/v1/billing.py — Stripe Checkout, webhook, portal."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from core.config import settings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _stripe_mock():
    """Build a minimal stripe module mock."""
    m = MagicMock()
    m.error.SignatureVerificationError = type(
        "SignatureVerificationError", (Exception,), {}
    )
    return m


# ── Checkout ──────────────────────────────────────────────────────────────────

class TestBillingCheckout:
    def test_returns_503_when_stripe_not_configured(self, test_client: TestClient):
        orig = settings.stripe_secret_key
        settings.stripe_secret_key = None
        try:
            resp = test_client.post("/api/v1/billing/checkout", json={})
            assert resp.status_code == 503
            assert "not configured" in resp.json()["detail"].lower()
        finally:
            settings.stripe_secret_key = orig

    def test_returns_400_when_no_price_id_configured(self, test_client: TestClient):
        """Returns 400 if no price_id in body and no default configured."""
        orig_key = settings.stripe_secret_key
        orig_price = settings.stripe_price_pro_monthly
        settings.stripe_secret_key = "sk_test_fake"
        settings.stripe_price_pro_monthly = None
        try:
            stripe_mock = _stripe_mock()
            with patch.dict("sys.modules", {"stripe": stripe_mock}):
                resp = test_client.post("/api/v1/billing/checkout", json={})
            assert resp.status_code == 400
        finally:
            settings.stripe_secret_key = orig_key
            settings.stripe_price_pro_monthly = orig_price

    def test_creates_checkout_session_and_returns_url(self, test_client: TestClient):
        orig_key = settings.stripe_secret_key
        orig_price = settings.stripe_price_pro_monthly
        settings.stripe_secret_key = "sk_test_fake"
        settings.stripe_price_pro_monthly = "price_pro"
        try:
            stripe_mock = _stripe_mock()
            fake_session = MagicMock()
            fake_session.url = "https://checkout.stripe.com/pay/cs_test_abc"
            fake_session.id = "cs_test_abc"
            stripe_mock.checkout.Session.create.return_value = fake_session

            with patch.dict("sys.modules", {"stripe": stripe_mock}):
                resp = test_client.post("/api/v1/billing/checkout", json={})

            assert resp.status_code == 200
            data = resp.json()
            assert data["checkout_url"] == "https://checkout.stripe.com/pay/cs_test_abc"
            assert data["session_id"] == "cs_test_abc"
        finally:
            settings.stripe_secret_key = orig_key
            settings.stripe_price_pro_monthly = orig_price

    def test_uses_custom_price_id_from_body(self, test_client: TestClient):
        orig_key = settings.stripe_secret_key
        settings.stripe_secret_key = "sk_test_fake"
        try:
            stripe_mock = _stripe_mock()
            fake_session = MagicMock()
            fake_session.url = "https://checkout.stripe.com/pay/cs_custom"
            fake_session.id = "cs_custom"
            stripe_mock.checkout.Session.create.return_value = fake_session

            with patch.dict("sys.modules", {"stripe": stripe_mock}):
                resp = test_client.post(
                    "/api/v1/billing/checkout",
                    json={"price_id": "price_enterprise_test"},
                )

            assert resp.status_code == 200
            # Verify the custom price_id was passed to Stripe
            call_kwargs = stripe_mock.checkout.Session.create.call_args[1]
            assert call_kwargs["line_items"][0]["price"] == "price_enterprise_test"
        finally:
            settings.stripe_secret_key = orig_key


# ── Webhook ───────────────────────────────────────────────────────────────────

class TestBillingWebhook:
    def test_returns_503_when_not_configured(self, test_client: TestClient):
        orig = settings.stripe_secret_key
        settings.stripe_secret_key = None
        try:
            resp = test_client.post(
                "/api/v1/billing/webhook",
                content=b"payload",
                headers={"stripe-signature": "t=123,v1=abc"},
            )
            assert resp.status_code == 503
        finally:
            settings.stripe_secret_key = orig

    def test_returns_503_when_webhook_secret_missing(self, test_client: TestClient):
        orig_key = settings.stripe_secret_key
        orig_secret = settings.stripe_webhook_secret
        settings.stripe_secret_key = "sk_test_fake"
        settings.stripe_webhook_secret = None
        try:
            stripe_mock = _stripe_mock()
            with patch.dict("sys.modules", {"stripe": stripe_mock}):
                resp = test_client.post(
                    "/api/v1/billing/webhook",
                    content=b"payload",
                    headers={"stripe-signature": "t=123,v1=abc"},
                )
            assert resp.status_code == 503
        finally:
            settings.stripe_secret_key = orig_key
            settings.stripe_webhook_secret = orig_secret

    def test_returns_400_on_invalid_signature(self, test_client: TestClient):
        orig_key = settings.stripe_secret_key
        orig_secret = settings.stripe_webhook_secret
        settings.stripe_secret_key = "sk_test_fake"
        settings.stripe_webhook_secret = "whsec_test"
        try:
            stripe_mock = _stripe_mock()
            stripe_mock.Webhook.construct_event.side_effect = (
                stripe_mock.error.SignatureVerificationError("bad sig", "sig_header")
            )
            with patch.dict("sys.modules", {"stripe": stripe_mock}):
                resp = test_client.post(
                    "/api/v1/billing/webhook",
                    content=b"payload",
                    headers={"stripe-signature": "t=bad,v1=bad"},
                )
            assert resp.status_code == 400
            assert "signature" in resp.json()["detail"].lower()
        finally:
            settings.stripe_secret_key = orig_key
            settings.stripe_webhook_secret = orig_secret

    def test_returns_200_on_valid_checkout_completed_event(self, test_client: TestClient):
        orig_key = settings.stripe_secret_key
        orig_secret = settings.stripe_webhook_secret
        settings.stripe_secret_key = "sk_test_fake"
        settings.stripe_webhook_secret = "whsec_test"
        try:
            stripe_mock = _stripe_mock()
            event = {
                "type": "checkout.session.completed",
                "data": {
                    "object": {
                        "metadata": {"org_id": "00000000-0000-0000-0000-000000000001"},
                        "customer": "cus_test",
                        "subscription": "sub_test",
                    }
                },
            }
            stripe_mock.Webhook.construct_event.return_value = event

            fake_sub = {
                "items": {"data": [{"price": {"id": "price_pro"}}]},
                "status": "active",
                "current_period_end": 1999999999,
            }
            stripe_mock.Subscription.retrieve.return_value = fake_sub

            with patch.dict("sys.modules", {"stripe": stripe_mock}):
                resp = test_client.post(
                    "/api/v1/billing/webhook",
                    content=b"{}",
                    headers={"stripe-signature": "t=123,v1=valid"},
                )
            assert resp.status_code == 200
            assert resp.json()["received"] is True
        finally:
            settings.stripe_secret_key = orig_key
            settings.stripe_webhook_secret = orig_secret

    def test_returns_200_on_subscription_deleted_event(self, test_client: TestClient):
        orig_key = settings.stripe_secret_key
        orig_secret = settings.stripe_webhook_secret
        settings.stripe_secret_key = "sk_test_fake"
        settings.stripe_webhook_secret = "whsec_test"
        try:
            stripe_mock = _stripe_mock()
            event = {
                "type": "customer.subscription.deleted",
                "data": {
                    "object": {
                        "id": "sub_test_del",
                        "status": "canceled",
                        "current_period_end": 1999999999,
                        "items": {"data": [{"price": {"id": "price_pro"}}]},
                    }
                },
            }
            stripe_mock.Webhook.construct_event.return_value = event

            with patch.dict("sys.modules", {"stripe": stripe_mock}):
                resp = test_client.post(
                    "/api/v1/billing/webhook",
                    content=b"{}",
                    headers={"stripe-signature": "t=123,v1=valid"},
                )
            assert resp.status_code == 200
        finally:
            settings.stripe_secret_key = orig_key
            settings.stripe_webhook_secret = orig_secret

    def test_ignores_unknown_event_type(self, test_client: TestClient):
        orig_key = settings.stripe_secret_key
        orig_secret = settings.stripe_webhook_secret
        settings.stripe_secret_key = "sk_test_fake"
        settings.stripe_webhook_secret = "whsec_test"
        try:
            stripe_mock = _stripe_mock()
            event = {
                "type": "payment_intent.succeeded",
                "data": {"object": {}},
            }
            stripe_mock.Webhook.construct_event.return_value = event

            with patch.dict("sys.modules", {"stripe": stripe_mock}):
                resp = test_client.post(
                    "/api/v1/billing/webhook",
                    content=b"{}",
                    headers={"stripe-signature": "t=123,v1=valid"},
                )
            assert resp.status_code == 200
            assert resp.json()["received"] is True
        finally:
            settings.stripe_secret_key = orig_key
            settings.stripe_webhook_secret = orig_secret


# ── Portal ────────────────────────────────────────────────────────────────────

class TestBillingPortal:
    def test_returns_503_when_stripe_not_configured(self, test_client: TestClient):
        orig = settings.stripe_secret_key
        settings.stripe_secret_key = None
        try:
            resp = test_client.get("/api/v1/billing/portal")
            assert resp.status_code == 503
        finally:
            settings.stripe_secret_key = orig

    def test_returns_400_when_org_has_no_stripe_customer(self, test_client: TestClient):
        """Demo org has no stripe_customer_id, so portal returns 400."""
        orig = settings.stripe_secret_key
        settings.stripe_secret_key = "sk_test_fake"
        try:
            stripe_mock = _stripe_mock()
            with patch.dict("sys.modules", {"stripe": stripe_mock}):
                resp = test_client.get("/api/v1/billing/portal")
            assert resp.status_code == 400
            assert "customer" in resp.json()["detail"].lower()
        finally:
            settings.stripe_secret_key = orig
