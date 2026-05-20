"""Application configuration loaded from environment variables.

Multi-environment support:
  APP_ENV=development  (default) — SQLite, relaxed auth, verbose logging
  APP_ENV=staging      — PostgreSQL required, auth enforced
  APP_ENV=production   — PostgreSQL required, auth enforced, strict secrets

Critical production requirements enforced at startup:
  - JWT_SECRET must not be the default value
  - DATABASE_URL must point to PostgreSQL
  - REQUIRE_AUTH must be true
"""
from __future__ import annotations

import secrets
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_INSECURE_JWT_SECRETS = {
    "dev-secret-change-in-production-please",
    "change-me-in-production",
    "secret",
    "dev",
    "development",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # ── Environment ────────────────────────────────────────────────────────────
    app_env: Literal["development", "staging", "production"] = "development"
    project_name: str = "VulnAuditor ASPM"
    data_dir: Path = Path("./data")
    log_level: str = "INFO"

    # ── Database ───────────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///data/vulnaudit.db"

    # ── Redis ──────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379"

    # ── Security & Auth ────────────────────────────────────────────────────────
    require_auth: bool = False
    demo_org_name: str = "Demo Organization"
    jwt_secret: str = "dev-secret-change-in-production-please"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    # ── OIDC / SSO ─────────────────────────────────────────────────────────────
    oidc_google_client_id: str | None = None
    oidc_google_client_secret: str | None = None
    oidc_azure_client_id: str | None = None
    oidc_azure_client_secret: str | None = None
    oidc_azure_tenant_id: str | None = None
    oidc_okta_domain: str | None = None
    oidc_okta_client_id: str | None = None
    oidc_okta_client_secret: str | None = None
    oidc_redirect_base_url: str = "http://localhost:8000"

    # ── Storage ────────────────────────────────────────────────────────────────
    # "local" or "s3"
    storage_backend: Literal["local", "s3"] = "local"
    s3_bucket: str | None = None
    s3_region: str = "us-east-1"
    s3_access_key_id: str | None = None
    s3_secret_access_key: str | None = None
    s3_endpoint_url: str | None = None  # MinIO or custom endpoint

    # ── Target scanning ────────────────────────────────────────────────────────
    allow_private_scanning: bool = False
    allowed_targets: list[str] = Field(default_factory=list)
    blocked_targets: list[str] = Field(default_factory=list)

    # ── Scanner timeouts ───────────────────────────────────────────────────────
    zap_api_url: str | None = None
    zap_spider_timeout: int = 600
    zap_ascan_timeout: int = 1800
    nmap_timeout: int = 1800
    nmap_flags: str = "-sV -sC --script=vuln -T4"
    scan_timeout_seconds: int = 1800

    # ── AI ─────────────────────────────────────────────────────────────────────
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-4-6"
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-1.5-flash"
    ai_timeout_seconds: int = 30
    ai_max_retries: int = 2

    # ── Billing / Stripe ───────────────────────────────────────────────────────
    stripe_secret_key: str | None = None
    stripe_webhook_secret: str | None = None
    stripe_price_pro_monthly: str | None = None
    stripe_price_enterprise_monthly: str | None = None

    # ── Notifications ──────────────────────────────────────────────────────────
    notification_webhook_url: str | None = None
    slack_webhook_url: str | None = None
    jira_api_url: str | None = None
    jira_api_key: str | None = None

    # ── CI/CD ──────────────────────────────────────────────────────────────────
    ci_fail_threshold: str | None = None

    # ── Frontend ───────────────────────────────────────────────────────────────
    frontend_url: str = "http://localhost:5173"

    # ── Rate limiting (requests per window) ───────────────────────────────────
    rate_limit_auth: str = "10/minute"
    rate_limit_scan_create: str = "10/hour"
    rate_limit_ai: str = "30/hour"
    rate_limit_report_export: str = "20/hour"
    rate_limit_default: str = "200/hour"

    @field_validator("data_dir", mode="before")
    @classmethod
    def create_data_dir(cls, v: str | Path) -> Path:
        p = Path(v)
        p.mkdir(parents=True, exist_ok=True)
        (p / "scans").mkdir(exist_ok=True)
        return p

    @model_validator(mode="after")
    def enforce_production_requirements(self) -> "Settings":
        if self.app_env == "production":
            # Reject insecure JWT secret
            if self.jwt_secret.lower() in _INSECURE_JWT_SECRETS or len(self.jwt_secret) < 32:
                raise ValueError(
                    "JWT_SECRET is insecure for production. "
                    "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
                )
            # Require PostgreSQL
            if "sqlite" in self.database_url:
                raise ValueError(
                    "DATABASE_URL must point to PostgreSQL in production. "
                    "SQLite is not suitable for multi-worker deployments."
                )
            # Require auth
            if not self.require_auth:
                raise ValueError(
                    "REQUIRE_AUTH must be true in production. "
                    "Set REQUIRE_AUTH=true in your environment."
                )

        if self.app_env in ("staging", "production"):
            if self.jwt_secret.lower() in _INSECURE_JWT_SECRETS:
                import logging
                logging.getLogger(__name__).warning(
                    "JWT_SECRET is using a default/insecure value in %s environment. "
                    "Set JWT_SECRET to a strong random secret.",
                    self.app_env,
                )

        return self

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    def generate_jwt_secret_hint(self) -> str:
        """Return a securely generated JWT secret for use in .env files."""
        return secrets.token_hex(32)


settings = Settings()
