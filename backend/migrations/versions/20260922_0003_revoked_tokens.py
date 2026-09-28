"""revoked_tokens (logout blacklist)

Revision ID: 0003_revoked_tokens
Revises: 0002_auth_tenancy
Create Date: 2026-09-22
"""
from typing import Sequence, Union

from alembic import op

from app.models import Base

revision: str = "0003_revoked_tokens"
down_revision: Union[str, None] = "0002_auth_tenancy"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind(), tables=[Base.metadata.tables["revoked_tokens"]])


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind(), tables=[Base.metadata.tables["revoked_tokens"]])
