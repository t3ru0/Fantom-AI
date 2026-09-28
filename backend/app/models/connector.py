"""Generic connector tables. Every provider (github today, gmail/slack/... one
day) has exactly one row per org+account here; provider-specific detail lives
in that provider's own tables (see `app.models.github`), joined back to this
one by `connector_installation_id`.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.connectors.enums import ConnectorProvider, ConnectorStatus
from app.models.base import Base, created_at, pk_uuid, updated_at
from app.models.tables import one_of

CONNECTOR_PROVIDERS = tuple(p.value for p in ConnectorProvider)
CONNECTOR_STATUSES = tuple(s.value for s in ConnectorStatus)


class ConnectorInstallation(Base):
    """One connected account of one provider, for one org. Generic on purpose:
    the GitHub connector points its own `github_installations` row back here
    via `connector_installation_id`, and so will every future provider."""
    __tablename__ = "connector_installations"
    __table_args__ = (
        CheckConstraint(one_of("provider", CONNECTOR_PROVIDERS), name="provider_valid"),
        CheckConstraint(one_of("status", CONNECTOR_STATUSES), name="status_valid"),
        UniqueConstraint("provider", "organization_id", "user_id", name="uq_connector_installations_identity"),
    )
    id: Mapped[uuid.UUID] = pk_uuid()
    provider: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("orgs.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)

    status: Mapped[str] = mapped_column(String(30), nullable=False, default=ConnectorStatus.HEALTHY.value)
    connected_at: Mapped[datetime] = created_at()
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sync_state: Mapped[dict | None] = mapped_column(JSON)     # provider-opaque cursor/etag bag
    last_error: Mapped[str | None] = mapped_column(Text)
    installation_metadata: Mapped[dict | None] = mapped_column("metadata", JSON)

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    metrics: Mapped["ConnectorMetrics"] = relationship(
        back_populates="installation", cascade="all, delete-orphan", uselist=False
    )


class ConnectorMetrics(Base):
    """Rollup updated at the end of each sync / each webhook delivery - never
    computed on read, so the health endpoint and future dashboards don't run a
    live aggregate over provider tables on every page load."""
    __tablename__ = "connector_metrics"

    connector_installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("connector_installations.id", ondelete="CASCADE"), primary_key=True
    )
    repositories_monitored: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    webhooks_active: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    events_received: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    runs_triggered: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    last_sync_duration_ms: Mapped[int | None] = mapped_column(Integer)
    last_successful_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = updated_at()

    installation: Mapped[ConnectorInstallation] = relationship(back_populates="metrics")
