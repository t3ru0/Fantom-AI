"""auth, tenancy, notifications, reports, api keys

Same approach as 0001: create straight from model metadata. `checkfirst`
(alembic's default for `create_all`) means only the tables added since 0001
get created — orgs/projects/etc. are left untouched.

Revision ID: 0002_auth_tenancy
Revises: 0001_initial
Create Date: 2026-09-22
"""
from typing import Sequence, Union

from alembic import op

from app.models import Base

revision: str = "0002_auth_tenancy"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NEW_TABLES = (
    "users", "memberships", "invitations", "teams", "team_memberships",
    "notifications", "notification_channels", "reports", "api_keys",
)


def upgrade() -> None:
    bind = op.get_bind()
    tables = [Base.metadata.tables[name] for name in NEW_TABLES]
    Base.metadata.create_all(bind=bind, tables=tables)


def downgrade() -> None:
    bind = op.get_bind()
    tables = [Base.metadata.tables[name] for name in reversed(NEW_TABLES)]
    Base.metadata.drop_all(bind=bind, tables=tables)
