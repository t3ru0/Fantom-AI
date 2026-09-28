"""Read-only audit trail for the current org."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_org
from app.models import AuditLog, Membership, Org
from app.schemas_auth import AuditLogOut

router = APIRouter(prefix="/api", tags=["audit"])


@router.get("/audit", response_model=list[AuditLogOut])
def list_audit_log(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    ctx: tuple[Org, Membership] = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[AuditLogOut]:
    org, _ = ctx
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.org_id == org.id)
        .order_by(AuditLog.ts.desc())
        .offset(offset).limit(limit)
        .all()
    )
    return [
        AuditLogOut(id=r.id, ts=r.ts, org_id=str(r.org_id) if r.org_id else None,
                    project_id=str(r.project_id) if r.project_id else None,
                    actor=r.actor, action=r.action, detail=r.detail)
        for r in rows
    ]
