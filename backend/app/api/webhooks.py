"""The webhook endpoint.

Contract with GitHub: verify, acknowledge, and get out of the way. GitHub times
out at 10 seconds and disables a webhook that keeps failing, so nothing slow
happens here — the handler validates, records intent, and returns 202.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, Header, Request, Response, status
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.integrations.github import webhook as wh
from app.models import Project, Run

log = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/github", status_code=status.HTTP_202_ACCEPTED)
async def github(
    request: Request,
    response: Response,
    x_github_event: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> dict:
    body = await request.body()

    # 1. Signature first. Nothing is parsed before this passes.
    if not settings.github_webhook_secret:
        log.error("webhook received but GITHUB_WEBHOOK_SECRET is unset — rejecting")
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"error": "webhook_not_configured"}
    try:
        wh.verify(body, x_hub_signature_256, settings.github_webhook_secret)
    except wh.BadSignature as exc:
        log.warning("rejected delivery %s: %s", x_github_delivery, exc)
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error": "bad_signature"}

    # 2. Now it is safe to parse.
    try:
        payload = wh.load(body)
    except wh.WebhookError as exc:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"error": str(exc)}

    event = (x_github_event or "").lower()

    if event == "ping":
        return {"ok": True, "pong": True}

    if event == "push":
        ev = wh.parse_push(payload)
        if not ev.should_scan:
            return {"ok": True, "skipped": "not a branch push we inspect", "ref": ev.ref}

        project = db.query(Project).filter(Project.origin == ev.repo).first()
        if project is None or project.state == "disconnected":
            log.info("push for %s but no connected project - ignoring", ev.repo)
            return {"ok": True, "skipped": "repository not connected", "repo": ev.repo}

        run = Run(
            id=uuid.uuid4(), project_id=project.id, trigger="push",
            commit_sha=ev.after, commit_message=ev.commit_message, pusher=ev.pusher,
            changed_files=ev.changed_files,
            # A push scans only the changed files, unless this is the project's
            # first run ever - nothing to diff a partial sweep against yet.
            full_sweep=project.last_run_at is None,
            state="queued",
        )
        db.add(run)
        db.commit()

        from app.workers.runner import wake_worker
        wake_worker()

        log.info("queued run %s for %s@%s (%d files changed)",
                 run.id, ev.repo, ev.after[:8], len(ev.changed_files))
        return {
            "ok": True,
            "queued": True,
            "run_id": str(run.id),
            "repo": ev.repo,
            "branch": ev.branch,
            "commit": ev.after,
            "changed_files": len(ev.changed_files),
            "delivery": x_github_delivery,
        }

    if event in ("installation", "installation_repositories"):
        ev = wh.parse_installation(payload)
        log.info("installation %s for %s (%d repos)", ev.action, ev.account, len(ev.repos))
        return {"ok": True, "action": ev.action, "account": ev.account, "repos": len(ev.repos)}

    return {"ok": True, "ignored": event}
