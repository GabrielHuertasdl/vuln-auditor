"""API v1 router — aggregates all /api/v1/* sub-routers.

This router is mounted at /api/v1 in api/app.py.
It includes:
  - All existing legacy routes (for backward compat under /api/v1/)
  - New enterprise-only routes: users, api-keys, webhooks, oidc, compliance, audit
"""
from fastapi import APIRouter

from api.routes import router as legacy_router
from api.v1.users import router as users_router
from api.v1.api_keys import router as api_keys_router
from api.v1.webhooks import router as webhooks_router
from api.v1.oidc import router as oidc_router
from api.v1.compliance import router as compliance_router
from api.v1.audit import router as audit_router
from api.v1.billing import router as billing_router

v1_router = APIRouter(prefix="/api/v1")

# Include existing routes under /api/v1/ prefix
v1_router.include_router(legacy_router)

# New enterprise routes
v1_router.include_router(users_router)
v1_router.include_router(api_keys_router)
v1_router.include_router(webhooks_router)
v1_router.include_router(oidc_router)
v1_router.include_router(compliance_router)
v1_router.include_router(audit_router)
v1_router.include_router(billing_router)
