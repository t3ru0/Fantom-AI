"""The interface every connector implements.

Kept deliberately thin and provider-agnostic. `subscribe`/`unsubscribe` are
webhook language, but a polling-only connector (no webhook support at the
provider) can implement both as no-ops and still satisfy the contract - the
manager never assumes a subscription exists, it just calls `sync()` on its
own schedule either way.

Every method takes a plain `db: Session` rather than reaching for its own
connection, because a connector call is always part of a larger request or
worker job that already owns a transaction.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import Any

from sqlalchemy.orm import Session

from app.connectors.enums import ConnectorProvider
from app.connectors.models import (
    AuthorizeResult,
    CallbackResult,
    HealthReport,
    ResourceRef,
    SyncResult,
)


class BaseConnector(ABC):
    """One instance per provider, registered once in `ConnectorRegistry`."""

    provider: ConnectorProvider

    @abstractmethod
    def authorize(self, db: Session, *, org_id: uuid.UUID, user_id: uuid.UUID) -> AuthorizeResult:
        """Start an auth flow. Returns where to send the browser/CLI next."""

    @abstractmethod
    def callback(self, db: Session, *, params: dict[str, Any]) -> CallbackResult:
        """Complete an auth flow from the provider's redirect/response."""

    @abstractmethod
    def refresh(self, db: Session, *, installation_id: uuid.UUID) -> bool:
        """Refresh credentials for one installation. Returns whether it is
        still usable afterward (False means it needs to be reconnected)."""

    @abstractmethod
    def disconnect(self, db: Session, *, installation_id: uuid.UUID) -> None:
        """Tear down: revoke upstream, remove subscriptions, clear local state."""

    @abstractmethod
    def sync(self, db: Session, *, installation_id: uuid.UUID) -> SyncResult:
        """Pull the current resource list and reconcile it against storage."""

    @abstractmethod
    def health(self, db: Session, *, installation_id: uuid.UUID) -> HealthReport:
        """Aggregate health without a live round-trip further than a cheap check."""

    @abstractmethod
    def list_resources(self, db: Session, *, installation_id: uuid.UUID) -> list[ResourceRef]:
        """Everything the connector could monitor for this installation."""

    @abstractmethod
    def subscribe(self, db: Session, *, installation_id: uuid.UUID, resource_id: str) -> None:
        """Start receiving change notifications for one resource. A no-op for
        a polling-only provider."""

    @abstractmethod
    def unsubscribe(self, db: Session, *, installation_id: uuid.UUID, resource_id: str) -> None:
        """Stop receiving change notifications for one resource."""

    @abstractmethod
    def trigger_manual_sync(self, db: Session, *, installation_id: uuid.UUID) -> SyncResult:
        """User-requested, immediate sync - same reconciliation as `sync()`,
        called from the API instead of the scheduler."""
