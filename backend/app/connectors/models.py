"""Provider-agnostic value objects passed across the connector boundary.

These are plain dataclasses, not ORM models - every provider builds one of
these to hand back to `ConnectorManager` / the generic `/connectors` API,
regardless of whether its own resource is a repository, a channel or a doc.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AuthorizeResult:
    """What `authorize()` hands back to the API route: where to send the user."""
    redirect_url: str
    state: str


@dataclass(slots=True)
class CallbackResult:
    """What `callback()` hands back after exchanging a provider's response."""
    installation_id: uuid.UUID
    account_label: str
    scopes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ResourceRef:
    """One thing a connector can monitor: a repository, a channel, a doc."""
    external_id: str
    name: str
    kind: str                      # "repository" | "channel" | "document" | ...
    monitoring_status: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class HealthReport:
    status: str
    token_valid: bool
    webhook_valid: bool | None
    last_sync_at: str | None
    last_sync_duration_ms: int | None
    resource_count: int
    monitored_resource_count: int
    detail: str | None = None


@dataclass(slots=True)
class SyncResult:
    resources_added: int = 0
    resources_updated: int = 0
    resources_removed: int = 0
    duration_ms: int = 0
    success: bool = True
    error_message: str | None = None
