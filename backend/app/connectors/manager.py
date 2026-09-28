"""Generic, provider-agnostic connector bookkeeping: the `connector_metrics`
rollup, and the in-process SSE fan-out for lifecycle events.

The event bus is in-memory by design - this deployment runs one process (see
`app.workers.runner`'s own docstring for why that's the current reality), so
a `asyncio.Queue` per subscriber is correct and needs no new infrastructure.

ponytail: single-process pub/sub, no cross-process fan-out. Ceiling: a second
uvicorn worker would miss events published by the other process. Upgrade path
is a DB-tailed table (same pattern `app/api/live.py` already uses for Run
events) or Redis pub/sub, whichever this product reaches first.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models import ConnectorMetrics


def bump_metrics(db: Session, connector_installation_id: uuid.UUID, **deltas: int) -> None:
    """Adds to counters (events_received, runs_triggered, ...). Creates the
    row on first use - every installation gets exactly one metrics row."""
    row = db.get(ConnectorMetrics, connector_installation_id)
    if row is None:
        row = ConnectorMetrics(connector_installation_id=connector_installation_id)
        db.add(row)
        db.flush()
    for key, delta in deltas.items():
        setattr(row, key, getattr(row, key) + delta)


def set_metrics(db: Session, connector_installation_id: uuid.UUID, **values: Any) -> None:
    """Overwrites gauges (repositories_monitored, webhooks_active, ...)."""
    row = db.get(ConnectorMetrics, connector_installation_id)
    if row is None:
        row = ConnectorMetrics(connector_installation_id=connector_installation_id)
        db.add(row)
        db.flush()
    for key, value in values.items():
        setattr(row, key, value)


def record_sync(db: Session, connector_installation_id: uuid.UUID, *, duration_ms: int, success: bool) -> None:
    values: dict[str, Any] = {"last_sync_duration_ms": duration_ms}
    if success:
        values["last_successful_sync"] = datetime.now(timezone.utc)
    set_metrics(db, connector_installation_id, **values)


# --------------------------------------------------------------- event bus --
@dataclass(slots=True)
class LifecycleEvent:
    kind: str
    organization_id: uuid.UUID
    payload: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


class _EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[uuid.UUID, list[asyncio.Queue[LifecycleEvent]]] = defaultdict(list)

    def subscribe(self, organization_id: uuid.UUID) -> asyncio.Queue[LifecycleEvent]:
        q: asyncio.Queue[LifecycleEvent] = asyncio.Queue(maxsize=200)
        self._subscribers[organization_id].append(q)
        return q

    def unsubscribe(self, organization_id: uuid.UUID, q: asyncio.Queue[LifecycleEvent]) -> None:
        subs = self._subscribers.get(organization_id, [])
        if q in subs:
            subs.remove(q)

    def publish(self, organization_id: uuid.UUID, kind: str, payload: dict[str, Any] | None = None) -> None:
        event = LifecycleEvent(kind=kind, organization_id=organization_id, payload=payload or {})
        for q in list(self._subscribers.get(organization_id, [])):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass    # a slow subscriber drops events rather than backing up publishers


event_bus = _EventBus()
