"""scan_progress_columns

Adds progress_pct (int) and progress_message (str) to scans table.

Revision ID: 004_scan_progress
Revises: 003_seed_wstg
"""
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "004_scan_progress"
down_revision: Union[str, Sequence[str], None] = "003_seed_wstg"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("progress_pct", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "scans",
        sa.Column("progress_message", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "progress_message")
    op.drop_column("scans", "progress_pct")
