"""Generic, provider-agnostic connector queries - backs `GET /connectors` and
`GET /connectors/status`. Anything provider-specific lives behind
`ConnectorRegistry`, not here.
"""
from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.connectors.registry import registry
from app.models import ConnectorInstallation


def list_installations(db: Session, *, org_id: uuid.UUID) -> list[ConnectorInstallation]:
    return db.query(ConnectorInstallation).filter(ConnectorInstallation.organization_id == org_id).all()


def status_for_org(db: Session, *, org_id: uuid.UUID) -> list[dict]:
    out = []
    for row in list_installations(db, org_id=org_id):
        entry = {
            "installation_id": str(row.id), "provider": row.provider, "status": row.status,
            "connected_at": row.connected_at.isoformat() if row.connected_at else None,
            "last_sync_at": row.last_sync_at.isoformat() if row.last_sync_at else None,
        }
        if registry.is_registered(row.provider):
            try:
                connector = registry.get(row.provider)
                health = connector.health(db, installation_id=row.id)
                entry["health"] = {
                    "status": health.status, "token_valid": health.token_valid,
                    "webhook_valid": health.webhook_valid, "resource_count": health.resource_count,
                    "monitored_resource_count": health.monitored_resource_count,
                }
            except LookupError:
                pass
        out.append(entry)
    return out
