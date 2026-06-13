"""transform load preflight

Revision ID: 9f2d2f4c6b10
Revises: 8a3735a3fc8a
Create Date: 2026-06-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "9f2d2f4c6b10"
down_revision: Union[str, Sequence[str], None] = "8a3735a3fc8a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("pipeline_logs_cve_id_fkey", "pipeline_logs", type_="foreignkey")
    op.alter_column(
        "cve_enriched",
        "cvss_score",
        existing_type=sa.Numeric(precision=3, scale=1),
        type_=sa.Numeric(precision=4, scale=1),
        existing_nullable=True,
    )
    op.drop_column("cve_enriched", "cvss_metrics")
    op.alter_column(
        "cve_cvss_history",
        "old_score",
        existing_type=sa.Numeric(precision=3, scale=1),
        type_=sa.Numeric(precision=4, scale=1),
        existing_nullable=True,
    )
    op.alter_column(
        "cve_cvss_history",
        "new_score",
        existing_type=sa.Numeric(precision=3, scale=1),
        type_=sa.Numeric(precision=4, scale=1),
        existing_nullable=True,
    )
    op.add_column("cve_enriched", sa.Column("is_updated", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index(op.f("ix_cve_enriched_is_updated"), "cve_enriched", ["is_updated"], unique=False)
    op.add_column("cve_cvss_history", sa.Column("old_attack_vector", sa.String(length=32), nullable=True))
    op.add_column("cve_cvss_history", sa.Column("new_attack_vector", sa.String(length=32), nullable=True))
    op.add_column("cve_cvss_history", sa.Column("old_attack_complexity", sa.String(length=32), nullable=True))
    op.add_column("cve_cvss_history", sa.Column("new_attack_complexity", sa.String(length=32), nullable=True))
    op.add_column("cve_cvss_history", sa.Column("old_attack_requirements", sa.String(length=32), nullable=True))
    op.add_column("cve_cvss_history", sa.Column("new_attack_requirements", sa.String(length=32), nullable=True))
    op.add_column("cve_cvss_history", sa.Column("old_privileges_required", sa.String(length=32), nullable=True))
    op.add_column("cve_cvss_history", sa.Column("new_privileges_required", sa.String(length=32), nullable=True))
    op.add_column("cve_cvss_history", sa.Column("old_user_interaction", sa.String(length=32), nullable=True))
    op.add_column("cve_cvss_history", sa.Column("new_user_interaction", sa.String(length=32), nullable=True))
    op.add_column("cve_cvss_history", sa.Column("old_exploit_maturity", sa.String(length=32), nullable=True))
    op.add_column("cve_cvss_history", sa.Column("new_exploit_maturity", sa.String(length=32), nullable=True))


def downgrade() -> None:
    op.create_foreign_key(
        "pipeline_logs_cve_id_fkey",
        "pipeline_logs",
        "cve_enriched",
        ["cve_id"],
        ["cve_id"],
        ondelete="SET NULL",
    )
    op.drop_index(op.f("ix_cve_enriched_is_updated"), table_name="cve_enriched")
    op.drop_column("cve_enriched", "is_updated")
    op.drop_column("cve_cvss_history", "new_exploit_maturity")
    op.drop_column("cve_cvss_history", "old_exploit_maturity")
    op.drop_column("cve_cvss_history", "new_user_interaction")
    op.drop_column("cve_cvss_history", "old_user_interaction")
    op.drop_column("cve_cvss_history", "new_privileges_required")
    op.drop_column("cve_cvss_history", "old_privileges_required")
    op.drop_column("cve_cvss_history", "new_attack_requirements")
    op.drop_column("cve_cvss_history", "old_attack_requirements")
    op.drop_column("cve_cvss_history", "new_attack_complexity")
    op.drop_column("cve_cvss_history", "old_attack_complexity")
    op.drop_column("cve_cvss_history", "new_attack_vector")
    op.drop_column("cve_cvss_history", "old_attack_vector")
    op.alter_column(
        "cve_cvss_history",
        "new_score",
        existing_type=sa.Numeric(precision=4, scale=1),
        type_=sa.Numeric(precision=3, scale=1),
        existing_nullable=True,
    )
    op.alter_column(
        "cve_cvss_history",
        "old_score",
        existing_type=sa.Numeric(precision=4, scale=1),
        type_=sa.Numeric(precision=3, scale=1),
        existing_nullable=True,
    )
    op.add_column("cve_enriched", sa.Column("cvss_metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.alter_column(
        "cve_enriched",
        "cvss_score",
        existing_type=sa.Numeric(precision=4, scale=1),
        type_=sa.Numeric(precision=3, scale=1),
        existing_nullable=True,
    )
