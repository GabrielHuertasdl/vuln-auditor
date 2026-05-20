"""enterprise_features

Adds enterprise tables for Phase 2:
  - memberships         — explicit user-org-role with invite tracking
  - invite_tokens       — pending email invitations
  - refresh_tokens      — DB-backed refresh token revocation
  - oidc_accounts       — SSO identity provider links
  - api_keys            — named, scoped, revocable API keys per org
  - audit_logs          — immutable security audit trail
  - webhook_endpoints   — outbound webhook configuration
  - webhook_deliveries  — webhook delivery log

Also alters existing tables:
  - organizations: adds slug, website, sso_enabled, settings_json
  - users: adds last_login_at, failed_login_count, mfa_enabled
  - scans: adds initiated_by
  - finding_status_history: adds changed_by
  - findings: changes String columns to Text for long content

Revision ID: 002_enterprise
Revises: cdc5d0b00106
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002_enterprise"
down_revision: Union[str, Sequence[str], None] = "cdc5d0b00106"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # All tables and columns are created in migration 001 (cdc5d0b00106).
    # This migration is kept as a marker for existing deployments that ran the
    # original split schema. Fresh installs skip all ALTER/CREATE here.
    pass


def _upgrade_legacy() -> None:
    # ── Alter organizations ────────────────────────────────────────────────────
    with op.batch_alter_table("organizations", schema=None) as batch_op:
        batch_op.add_column(sa.Column("slug", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("website", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("sso_enabled", sa.Boolean(), server_default="0", nullable=False))
        batch_op.add_column(sa.Column("settings_json", sa.JSON(), nullable=True))
        batch_op.create_unique_constraint("uq_org_slug", ["slug"])

    # ── Alter users ────────────────────────────────────────────────────────────
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("failed_login_count", sa.Integer(), server_default="0", nullable=False))
        batch_op.add_column(sa.Column("mfa_enabled", sa.Boolean(), server_default="0", nullable=False))
        # password_hash becomes nullable for SSO-only users
        batch_op.alter_column("password_hash", existing_type=sa.String(), nullable=True)

    # ── Alter scans ────────────────────────────────────────────────────────────
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("initiated_by", sa.String(), sa.ForeignKey("users.id"), nullable=True)
        )

    # ── Alter finding_status_history ──────────────────────────────────────────
    with op.batch_alter_table("finding_status_history", schema=None) as batch_op:
        batch_op.add_column(sa.Column("changed_by", sa.String(), nullable=True))

    # ── memberships ───────────────────────────────────────────────────────────
    op.create_table(
        "memberships",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("invited_by", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("invited_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="1", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "org_id", name="uq_membership"),
    )
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    op.create_index("ix_memberships_org_id", "memberships", ["org_id"])

    # ── invite_tokens ─────────────────────────────────────────────────────────
    op.create_table(
        "invite_tokens",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("invited_by", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_invite_tokens_email", "invite_tokens", ["email"])

    # ── refresh_tokens ────────────────────────────────────────────────────────
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("device_hint", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index("ix_refresh_tokens_token_hash", "refresh_tokens", ["token_hash"])

    # ── oidc_accounts ─────────────────────────────────────────────────────────
    op.create_table(
        "oidc_accounts",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("provider_sub", sa.String(), nullable=False),
        sa.Column("provider_email", sa.String(), nullable=True),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider", "provider_sub", name="uq_oidc_account"),
    )
    op.create_index("ix_oidc_accounts_user_id", "oidc_accounts", ["user_id"])

    # ── api_keys ──────────────────────────────────────────────────────────────
    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("key_hash", sa.String(), nullable=False),
        sa.Column("key_prefix", sa.String(), nullable=False),
        sa.Column("scopes", sa.String(), server_default='["read","write"]', nullable=False),
        sa.Column("created_by", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="1", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_hash"),
    )
    op.create_index("ix_api_keys_org_id", "api_keys", ["org_id"])
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"])

    # ── audit_logs ────────────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("actor_id", sa.String(), nullable=True),
        sa.Column("actor_email", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("resource_type", sa.String(), nullable=True),
        sa.Column("resource_id", sa.String(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_org_id", "audit_logs", ["org_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # ── webhook_endpoints ─────────────────────────────────────────────────────
    op.create_table(
        "webhook_endpoints",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("secret_hash", sa.String(), nullable=True),
        sa.Column(
            "events",
            sa.String(),
            server_default='["scan.completed","finding.created","finding.status_changed"]',
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), server_default="1", nullable=False),
        sa.Column("created_by", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_webhook_endpoints_org_id", "webhook_endpoints", ["org_id"])

    # ── webhook_deliveries ────────────────────────────────────────────────────
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column(
            "endpoint_id", sa.String(), sa.ForeignKey("webhook_endpoints.id"), nullable=False
        ),
        sa.Column("event", sa.String(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("response_body", sa.Text(), nullable=True),
        sa.Column("attempt_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("succeeded", sa.Boolean(), server_default="0", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_webhook_deliveries_endpoint_id", "webhook_deliveries", ["endpoint_id"])


def downgrade() -> None:
    pass


def _downgrade_legacy() -> None:
    op.drop_table("webhook_deliveries")
    op.drop_table("webhook_endpoints")
    op.drop_table("audit_logs")
    op.drop_table("api_keys")
    op.drop_table("oidc_accounts")
    op.drop_table("refresh_tokens")
    op.drop_table("invite_tokens")
    op.drop_table("memberships")

    with op.batch_alter_table("finding_status_history", schema=None) as batch_op:
        batch_op.drop_column("changed_by")

    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.drop_column("initiated_by")

    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("mfa_enabled")
        batch_op.drop_column("failed_login_count")
        batch_op.drop_column("last_login_at")
        batch_op.alter_column("password_hash", existing_type=sa.String(), nullable=False)

    with op.batch_alter_table("organizations", schema=None) as batch_op:
        batch_op.drop_constraint("uq_org_slug", type_="unique")
        batch_op.drop_column("settings_json")
        batch_op.drop_column("sso_enabled")
        batch_op.drop_column("website")
        batch_op.drop_column("slug")
