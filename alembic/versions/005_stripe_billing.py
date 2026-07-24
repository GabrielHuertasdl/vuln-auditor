"""Add Stripe billing columns to organizations and failed_jobs dead-letter table.

Revision ID: 005_stripe_billing
Revises: 004_scan_progress
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "005_stripe_billing"
down_revision = "004_scan_progress"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("organizations") as batch_op:
        batch_op.add_column(sa.Column("stripe_customer_id", sa.String(), unique=True, nullable=True))
        batch_op.add_column(sa.Column("stripe_subscription_id", sa.String(), unique=True, nullable=True))
        batch_op.add_column(sa.Column("stripe_subscription_status", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("billing_period_end", sa.DateTime(timezone=True), nullable=True))

    op.create_index("ix_orgs_stripe_customer", "organizations", ["stripe_customer_id"])
    op.create_index("ix_orgs_stripe_subscription", "organizations", ["stripe_subscription_id"])

    op.create_table(
        "failed_jobs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("function", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("kwargs_json", sa.JSON(), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("failed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_failed_jobs_scan_id", "failed_jobs", ["scan_id"])
    op.create_index("ix_failed_jobs_failed_at", "failed_jobs", ["failed_at"])


def downgrade() -> None:
    op.drop_index("ix_failed_jobs_failed_at", table_name="failed_jobs")
    op.drop_index("ix_failed_jobs_scan_id", table_name="failed_jobs")
    op.drop_table("failed_jobs")

    op.drop_index("ix_orgs_stripe_subscription", table_name="organizations")
    op.drop_index("ix_orgs_stripe_customer", table_name="organizations")
    with op.batch_alter_table("organizations") as batch_op:
        batch_op.drop_column("billing_period_end")
        batch_op.drop_column("stripe_subscription_status")
        batch_op.drop_column("stripe_subscription_id")
        batch_op.drop_column("stripe_customer_id")
