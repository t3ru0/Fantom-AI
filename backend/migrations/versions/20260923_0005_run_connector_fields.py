"""runs: branch / delivery_id / github_event_type

Nullable, additive columns so a connector-triggered push run can record which
branch was pushed, the GitHub delivery id and event type - a manual or
legacy-GitHub-App run leaves them NULL exactly as before.

Column-existence-checked (not a plain `add_column`): migration 0001 creates
its tables straight from live model metadata (see its own docstring), so on
a database whose 0001 already ran *after* these columns were added to the
model, they exist already and a plain ADD COLUMN would fail as a duplicate.
On the real upgrade path - a database migrated up through 0004 on the model
as it existed before this change - they don't exist yet and this adds them
exactly as `add_column` would.

Revision ID: 0005_run_connector_fields
Revises: 0004_connectors
Create Date: 2026-09-23
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "0005_run_connector_fields"
down_revision: Union[str, None] = "0004_connectors"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NEW_COLUMNS = [
    sa.Column("branch", sa.String(200), nullable=True),
    sa.Column("delivery_id", sa.String(80), nullable=True),
    sa.Column("github_event_type", sa.String(60), nullable=True),
]


def upgrade() -> None:
    existing = {c["name"] for c in inspect(op.get_bind()).get_columns("runs")}
    with op.batch_alter_table("runs") as batch_op:
        for column in NEW_COLUMNS:
            if column.name not in existing:
                batch_op.add_column(column.copy())


def downgrade() -> None:
    existing = {c["name"] for c in inspect(op.get_bind()).get_columns("runs")}
    with op.batch_alter_table("runs") as batch_op:
        for column in reversed(NEW_COLUMNS):
            if column.name in existing:
                batch_op.drop_column(column.name)
