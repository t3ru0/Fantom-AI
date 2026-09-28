"""initial schema

The first migration creates the whole schema straight from the model metadata,
which is exact by construction and cannot drift from the models on day one.
Every migration after this one is a normal `alembic revision --autogenerate`
diff against a live database.

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-11
"""
from typing import Sequence, Union

from alembic import op

from app.models import Base

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
