"""Immutable audit trail. One helper, called from every mutating endpoint.

Never raises: a failed audit write must not fail the request it is describing.
Uses the caller's own session and `db.flush()`, not `db.commit()` — the audit
row commits atomically with whatever the caller does next, so a rolled-back
request leaves no orphaned audit entry for an action that never happened.
"""
from __future__ import annotations

import logging
import uuid

from sqlalchemy.orm import Session

from app.models import AuditLog

log = logging.getLogger(__name__)


def log_action(
    db: Session,
    *,
    action: str,
    actor: str = "system",
    org_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    detail: str | None = None,
    payload: dict | None = None,
) -> None:
    try:
        db.add(AuditLog(
            org_id=org_id, project_id=project_id, actor=actor,
            action=action, detail=detail, payload=payload,
        ))
        db.flush()
    except Exception:
        log.exception("audit log write failed for action=%s actor=%s", action, actor)
