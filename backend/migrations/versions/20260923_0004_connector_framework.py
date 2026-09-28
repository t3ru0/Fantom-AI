"""connector framework + github connector (Connector V1)

Revision ID: 0004_connectors
Revises: 0003_revoked_tokens
Create Date: 2026-09-23
"""
from typing import Sequence, Union

from alembic import op

from app.models import Base

revision: str = "0004_connectors"
down_revision: Union[str, None] = "0003_revoked_tokens"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLES = [
    "connector_installations",
    "connector_metrics",
    "github_installations",
    "github_repositories",
    "github_webhooks",
    "github_webhook_deliveries",
    "github_sync_history",
    "github_oauth_states",
]


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind(), tables=[Base.metadata.tables[t] for t in TABLES])


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind(), tables=[Base.metadata.tables[t] for t in TABLES])
