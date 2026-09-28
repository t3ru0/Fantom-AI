"""Generic, provider-agnostic connector routes. Anything provider-specific
(GitHub today) has its own router - see `app.api.v1.endpoints.github`.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_org
from app.models import Membership, Org
from app.services import connector_service

router = APIRouter(prefix="/connectors", tags=["connectors"])


@router.get("")
def list_connectors(ctx: tuple[Org, Membership] = Depends(get_current_org), db: Session = Depends(get_db)) -> list[dict]:
    org, _ = ctx
    return [
        {"installation_id": str(row.id), "provider": row.provider, "status": row.status,
         "connected_at": row.connected_at.isoformat() if row.connected_at else None,
         "last_sync_at": row.last_sync_at.isoformat() if row.last_sync_at else None}
        for row in connector_service.list_installations(db, org_id=org.id)
    ]


@router.get("/status")
def connectors_status(ctx: tuple[Org, Membership] = Depends(get_current_org), db: Session = Depends(get_db)) -> list[dict]:
    org, _ = ctx
    return connector_service.status_for_org(db, org_id=org.id)
