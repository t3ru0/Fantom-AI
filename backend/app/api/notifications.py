"""In-app notifications (list, mark read) and outbound channel config
(Slack/Discord/Teams/generic webhook/email). Sending itself lives in
app/services/notify.py, called from the orchestrator when a run completes.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_org, get_current_user, require_role
from app.models import Membership, Notification, NotificationChannel, Org, User
from app.models.tables import NOTIFICATION_CHANNEL_KINDS
from app.schemas_findings import NotificationChannelCreate, NotificationChannelOut, NotificationOut
from app.services.audit import log_action

router = APIRouter(prefix="/api", tags=["notifications"])


@router.get("/notifications", response_model=list[NotificationOut])
def list_notifications(
    unread_only: bool = Query(False),
    ctx: tuple[Org, Membership] = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[NotificationOut]:
    org, _ = ctx
    q = db.query(Notification).filter(Notification.org_id == org.id)
    if unread_only:
        q = q.filter(Notification.read_at.is_(None))
    rows = q.order_by(Notification.created_at.desc()).limit(100).all()
    return [NotificationOut(id=str(n.id), kind=n.kind, title=n.title, body=n.body,
                            read_at=n.read_at, created_at=n.created_at) for n in rows]


@router.put("/notifications/{notification_id}/read", status_code=status.HTTP_204_NO_CONTENT)
def mark_read(notification_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
              db: Session = Depends(get_db)) -> None:
    org, _ = ctx
    n = db.get(Notification, notification_id)
    if n is None or n.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="notification not found")
    if n.read_at is None:
        n.read_at = datetime.now(timezone.utc)
        db.commit()


@router.post("/notifications/channels", response_model=NotificationChannelOut, status_code=status.HTTP_201_CREATED)
def create_channel(payload: NotificationChannelCreate,
                    ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin")),
                    db: Session = Depends(get_db)) -> NotificationChannelOut:
    org, actor = ctx
    if payload.kind not in NOTIFICATION_CHANNEL_KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"kind must be one of {NOTIFICATION_CHANNEL_KINDS}")
    ch = NotificationChannel(id=uuid.uuid4(), org_id=org.id, kind=payload.kind, target=payload.target, enabled=True)
    db.add(ch)
    log_action(db, org_id=org.id, action="notification_channel.create", detail=payload.kind)
    db.commit()
    return NotificationChannelOut(id=str(ch.id), kind=ch.kind, target=ch.target,
                                  enabled=ch.enabled, created_at=ch.created_at)


@router.get("/notifications/channels", response_model=list[NotificationChannelOut])
def list_channels(ctx: tuple[Org, Membership] = Depends(get_current_org), db: Session = Depends(get_db)) -> list[NotificationChannelOut]:
    org, _ = ctx
    rows = db.query(NotificationChannel).filter(NotificationChannel.org_id == org.id).all()
    return [NotificationChannelOut(id=str(c.id), kind=c.kind, target=c.target,
                                   enabled=c.enabled, created_at=c.created_at) for c in rows]


@router.delete("/notifications/channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_channel(channel_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin")),
                    db: Session = Depends(get_db)) -> None:
    org, _ = ctx
    ch = db.get(NotificationChannel, channel_id)
    if ch is None or ch.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="channel not found")
    db.delete(ch)
    log_action(db, org_id=org.id, action="notification_channel.delete", detail=str(channel_id))
    db.commit()
