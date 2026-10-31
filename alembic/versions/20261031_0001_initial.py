"""Initial CyberForge scan and evidence schema."""

from alembic import op
import sqlalchemy as sa

revision = "20261031_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("source_root", sa.Text(), nullable=False),
        sa.Column("target_origin", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("phase", sa.String(16)),
        sa.Column("progress", sa.JSON()),
        sa.Column("error", sa.Text()),
        sa.Column("counts", sa.JSON(), nullable=False),
        sa.Column("coverage", sa.JSON()),
    )
    op.create_index("ix_scans_state", "scans", ["state"])

    op.create_table(
        "routes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("handler_key", sa.String(512), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("scan_id", "method", "path", "handler_key", name="uq_routes_scan_method_path_handler"),
    )
    op.create_index("ix_routes_scan_id", "routes", ["scan_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("source", sa.String(8), nullable=False),
        sa.Column("cwe", sa.Integer(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("risk", sa.Integer(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])

    op.create_table(
        "issues",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("risk", sa.Integer(), nullable=False),
        sa.Column("cwe", sa.Integer(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("route", sa.JSON()),
        sa.Column("location", sa.JSON()),
        sa.Column("sast", sa.JSON()),
        sa.Column("dast", sa.JSON()),
        sa.Column("correlation", sa.JSON()),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_issues_status_risk", "issues", ["status", "risk"])

    op.create_table(
        "issue_scans",
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("issue_id", sa.String(36), sa.ForeignKey("issues.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("risk", sa.Integer(), nullable=False),
        sa.Column("cwe", sa.Integer(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("route", sa.JSON()),
        sa.Column("location", sa.JSON()),
        sa.Column("sast", sa.JSON()),
        sa.Column("dast", sa.JSON()),
        sa.Column("correlation", sa.JSON()),
    )

    op.create_table(
        "suppressed",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(8), nullable=False),
        sa.Column("cwe", sa.Integer(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("file", sa.Text(), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False),
        sa.Column("sanitizer", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
    )
    op.create_index("ix_suppressed_scan_id", "suppressed", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_suppressed_scan_id", table_name="suppressed")
    op.drop_table("suppressed")
    op.drop_table("issue_scans")
    op.drop_index("ix_issues_status_risk", table_name="issues")
    op.drop_table("issues")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_routes_scan_id", table_name="routes")
    op.drop_table("routes")
    op.drop_index("ix_scans_state", table_name="scans")
    op.drop_table("scans")
