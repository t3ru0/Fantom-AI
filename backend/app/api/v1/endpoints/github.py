"""GitHub connector routes.

`callback()` and the webhook receiver are the two routes GitHub itself hits,
not a logged-in browser, so neither takes `get_current_org` - the callback
authenticates via the signed `state` token (see `security.consume_oauth_state`)
and the webhook receiver authenticates via the per-webhook HMAC secret.
Everything else is a normal bearer-authenticated, org-scoped route.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.connectors.enums import MonitoringStatus
from app.connectors.github import repositories as repo_svc
from app.connectors.github import security
from app.connectors.github.client import GitHubApiError, GitHubClient
from app.connectors.github.oauth import GitHubAuthError, strategy_for
from app.connectors.github.schemas import (
    AuthorizeOut,
    BranchOut,
    ConnectorStatusOut,
    GitHubUserOut,
    HealthOut,
    RepositoryOut,
    RepositorySelectIn,
    RepositorySelectResultOut,
    ScanTriggerOut,
    SyncHistoryOut,
    SyncTriggerOut,
    WebhookResyncOut,
)
from app.connectors.github.service import GitHubConnector, get_github_installation
from app.connectors.github.webhooks import handle_delivery, repair_webhook
from app.connectors.manager import event_bus
from app.connectors.models import SyncResult
from app.db import get_db
from app.deps import get_current_org, get_current_user, require_role
from app.models import ConnectorInstallation, Membership, Org, Project, Run, User
from app.models.github import GithubInstallation, GithubSyncHistory
from app.services.audit import log_action

log = logging.getLogger(__name__)
router = APIRouter(prefix="/connectors/github", tags=["connectors:github"])
connector = GitHubConnector()


def _installation_or_404(db: Session, org: Org) -> GithubInstallation:
    gh = get_github_installation(db, org_id=org.id)
    if gh is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="GitHub is not connected for this org")
    return gh


def _repo_out(repo) -> RepositoryOut:
    return RepositoryOut(
        id=str(repo.id), github_repo_id=repo.github_repo_id, full_name=repo.full_name,
        owner_login=repo.owner_login, name=repo.name, private=repo.private, archived=repo.archived,
        default_branch=repo.default_branch, language=repo.language, topics=repo.topics or [],
        license=repo.license, stars=repo.stars, forks=repo.forks, open_issues=repo.open_issues,
        has_security_policy=repo.has_security_policy, has_dependabot=repo.has_dependabot,
        permissions={"admin": repo.permission_admin, "push": repo.permission_push, "pull": repo.permission_pull,
                     "maintain": repo.permission_maintain, "triage": repo.permission_triage},
        monitoring_status=repo.monitoring_status, monitoring_reason=repo.monitoring_reason,
        project_id=str(repo.project_id) if repo.project_id else None,
        last_synced_at=repo.last_synced_at,
    )


# ------------------------------------------------------------------ OAuth ---
@router.get("/authorize", response_model=AuthorizeOut)
def authorize(user: User = Depends(get_current_user),
             ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin", "security_lead")),
             db: Session = Depends(get_db)) -> AuthorizeOut:
    org, _ = ctx
    result = connector.authorize(db, org_id=org.id, user_id=user.id)
    return AuthorizeOut(authorize_url=result.redirect_url)


@router.get("/callback")
def callback(code: str = Query(...), state: str = Query(...), db: Session = Depends(get_db)):
    integrations_url = f"{settings.frontend_url}/settings/integrations"
    try:
        result = connector.callback(db, params={"code": code, "state": state})
    except (security.StateError, ValueError) as exc:
        return RedirectResponse(f"{integrations_url}?provider=github&status=error&message={quote(str(exc))}")
    except GitHubAuthError as exc:
        log.warning("GitHub OAuth exchange failed: %s", exc)
        return RedirectResponse(f"{integrations_url}?provider=github&status=error&message=exchange_failed")

    # Sync repositories immediately so the integrations page has something to
    # show as soon as it lands, instead of an empty list until the next sync.
    try:
        connector.sync(db, installation_id=result.installation_id)
    except Exception:  # noqa: BLE001 — the connection itself succeeded; a sync hiccup is not fatal here
        log.exception("post-connect sync failed for installation %s", result.installation_id)

    return RedirectResponse(f"{integrations_url}?provider=github&status=connected")


@router.get("/status", response_model=ConnectorStatusOut)
def connector_status(ctx: tuple[Org, Membership] = Depends(get_current_org), db: Session = Depends(get_db)) -> ConnectorStatusOut:
    org, _ = ctx
    gh = get_github_installation(db, org_id=org.id)
    if gh is None:
        return ConnectorStatusOut(connected=False)
    row = db.get(ConnectorInstallation, gh.connector_installation_id)
    from app.models.github import GithubRepository
    total = db.query(GithubRepository).filter(GithubRepository.github_installation_id == gh.id).count()
    monitored = db.query(GithubRepository).filter(
        GithubRepository.github_installation_id == gh.id,
        GithubRepository.monitoring_status == MonitoringStatus.MONITORED.value,
    ).count()
    return ConnectorStatusOut(
        connected=True, status=row.status if row else None, account_login=gh.github_account_login,
        account_type=gh.github_account_type, scopes=gh.scopes or [], token_expires_at=gh.token_expires_at,
        last_sync_at=row.last_sync_at if row else None, repository_count=total, monitored_repository_count=monitored,
    )


@router.post("/refresh")
def refresh(ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin", "security_lead")),
           db: Session = Depends(get_db)) -> dict:
    org, _ = ctx
    gh = _installation_or_404(db, org)
    ok = connector.refresh(db, installation_id=gh.connector_installation_id)
    return {"refreshed": ok}


@router.delete("/disconnect")
def disconnect(ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin")), db: Session = Depends(get_db)) -> dict:
    org, _ = ctx
    gh = _installation_or_404(db, org)
    connector.disconnect(db, installation_id=gh.connector_installation_id)
    return {"disconnected": True}


@router.post("/sync", response_model=SyncTriggerOut, status_code=status.HTTP_202_ACCEPTED)
def trigger_sync(ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin", "security_lead")),
                 db: Session = Depends(get_db)) -> SyncTriggerOut:
    org, _ = ctx
    gh = _installation_or_404(db, org)
    result: SyncResult = connector.trigger_manual_sync(db, installation_id=gh.connector_installation_id)
    return SyncTriggerOut(accepted=result.success, detail=result.error_message or "sync complete")


@router.get("/user", response_model=GitHubUserOut)
def github_user(ctx: tuple[Org, Membership] = Depends(get_current_org), db: Session = Depends(get_db)) -> GitHubUserOut:
    org, _ = ctx
    gh = _installation_or_404(db, org)
    client = GitHubClient(db, gh, strategy_for(gh))
    try:
        data = asyncio.run(client.get_current_user())
    except GitHubApiError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail=f"GitHub said: {exc}") from exc
    return GitHubUserOut(id=data["id"], login=data["login"], name=data.get("name"), avatar_url=data.get("avatar_url"))


# ------------------------------------------------------------ repositories --
@router.get("/repositories")
def list_repositories(
    visibility: str | None = Query(None, pattern="^(private|public)$"),
    archived: bool | None = Query(None), monitored: bool | None = Query(None),
    language: str | None = Query(None), search: str | None = Query(None),
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    ctx: tuple[Org, Membership] = Depends(get_current_org), db: Session = Depends(get_db),
) -> dict:
    org, _ = ctx
    gh = _installation_or_404(db, org)
    rows, total = repo_svc.list_repositories(
        db, gh, visibility=visibility, archived=archived, monitored=monitored,
        language=language, search=search, page=page, page_size=page_size,
    )
    return {"repositories": [_repo_out(r) for r in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/repositories/{repository_id}", response_model=RepositoryOut)
def get_repository(repository_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
                   db: Session = Depends(get_db)) -> RepositoryOut:
    org, _ = ctx
    gh = _installation_or_404(db, org)
    repo = repo_svc.get_repository(db, gh, repository_id)
    if repo is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="repository not found")
    return _repo_out(repo)


@router.get("/repositories/{repository_id}/branches", response_model=list[BranchOut])
def list_branches(repository_id: uuid.UUID, ctx: tuple[Org, Membership] = Depends(get_current_org),
                  db: Session = Depends(get_db)) -> list[BranchOut]:
    org, _ = ctx
    gh = _installation_or_404(db, org)
    repo = repo_svc.get_repository(db, gh, repository_id)
    if repo is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="repository not found")
    client = GitHubClient(db, gh, strategy_for(gh))
    try:
        branches = asyncio.run(client.list_branches(repo.full_name))
    except GitHubApiError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail=f"GitHub said: {exc}") from exc
    return [BranchOut(name=b["name"], sha=b["commit"]["sha"], protected=b.get("protected", False)) for b in branches]


@router.post("/repositories/select", response_model=RepositorySelectResultOut)
def select_repositories(payload: RepositorySelectIn,
                        ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin", "security_lead")),
                        db: Session = Depends(get_db)) -> RepositorySelectResultOut:
    org, _ = ctx
    gh = _installation_or_404(db, org)
    selected, skipped = repo_svc.select_repositories(db, gh, payload.repository_ids)
    return RepositorySelectResultOut(selected=[_repo_out(r) for r in selected], skipped=skipped)


@router.post("/repositories/unselect", response_model=list[RepositoryOut])
def unselect_repositories(payload: RepositorySelectIn,
                          ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin", "security_lead")),
                          db: Session = Depends(get_db)) -> list[RepositoryOut]:
    org, _ = ctx
    gh = _installation_or_404(db, org)
    unselected = repo_svc.unselect_repositories(db, gh, payload.repository_ids)
    return [_repo_out(r) for r in unselected]


@router.post("/repositories/{repository_id}/scan", response_model=ScanTriggerOut, status_code=status.HTTP_202_ACCEPTED)
def scan_repository(repository_id: uuid.UUID,
                    ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin", "security_lead")),
                    db: Session = Depends(get_db)) -> ScanTriggerOut:
    org, _ = ctx
    gh = _installation_or_404(db, org)
    repo = repo_svc.get_repository(db, gh, repository_id)
    if repo is None or repo.project_id is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="repository not found or not yet selected for monitoring")
    project = db.get(Project, repo.project_id)
    run = Run(id=uuid.uuid4(), project_id=project.id, trigger="manual", full_sweep=True, state="queued")
    db.add(run)
    log_action(db, org_id=org.id, project_id=project.id, action="github.manual.scan", detail=repo.full_name)
    db.commit()

    from app.workers.runner import wake_worker
    wake_worker()
    return ScanTriggerOut(run_id=str(run.id), state=run.state)


@router.post("/repositories/{repository_id}/webhook/resync", response_model=WebhookResyncOut)
def resync_webhook(repository_id: uuid.UUID,
                   ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin", "security_lead")),
                   db: Session = Depends(get_db)) -> WebhookResyncOut:
    org, _ = ctx
    gh = _installation_or_404(db, org)
    repo = repo_svc.get_repository(db, gh, repository_id)
    if repo is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="repository not found")
    try:
        webhook = repair_webhook(db, repo, callback_url=security.webhook_callback_url())
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail=f"webhook repair failed: {exc}") from exc
    db.commit()
    if webhook is None:
        return WebhookResyncOut(repaired=False, webhook_id=None,
                                detail="repository is not monitored or has no admin permission")
    return WebhookResyncOut(repaired=True, webhook_id=webhook.webhook_id, detail="webhook recreated")


@router.get("/sync-history", response_model=list[SyncHistoryOut])
def sync_history(ctx: tuple[Org, Membership] = Depends(get_current_org), db: Session = Depends(get_db)) -> list[SyncHistoryOut]:
    org, _ = ctx
    gh = _installation_or_404(db, org)
    rows = (
        db.query(GithubSyncHistory)
        .filter(GithubSyncHistory.installation_id == gh.id)
        .order_by(GithubSyncHistory.created_at.desc())
        .limit(50)
        .all()
    )
    return [SyncHistoryOut(
        id=str(r.id), sync_type=r.sync_type, repositories_added=r.repositories_added,
        repositories_updated=r.repositories_updated, repositories_removed=r.repositories_removed,
        duration_ms=r.duration_ms, success=r.success, error_message=r.error_message, created_at=r.created_at,
    ) for r in rows]


# --------------------------------------------------------------- lifecycle --
@router.get("/events")
async def events(request: Request, ctx: tuple[Org, Membership] = Depends(get_current_org)):
    from starlette.responses import StreamingResponse
    org, _ = ctx

    async def _stream():
        queue = event_bus.subscribe(org.id)
        try:
            while True:
                if await request.is_disconnected():
                    return
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"event: {event.kind}\ndata: {json.dumps(event.payload)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            event_bus.unsubscribe(org.id, queue)

    return StreamingResponse(_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ----------------------------------------------------------------- webhook --
@router.post("/webhook", status_code=status.HTTP_202_ACCEPTED)
async def webhook(request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    try:
        security.check_content_length(request.headers.get("content-length") and int(request.headers["content-length"]))
    except security.PayloadTooLarge as exc:
        response.status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
        return {"error": str(exc)}

    body = await request.body()
    try:
        outcome = handle_delivery(
            db, body=body,
            hook_id=request.headers.get("x-github-hook-id"),
            event=request.headers.get("x-github-event"),
            delivery_id=request.headers.get("x-github-delivery"),
            signature=request.headers.get("x-hub-signature-256"),
        )
    except security.BadSignature as exc:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"error": "bad_signature", "detail": str(exc)}
    except security.ReplayDetected as exc:
        response.status_code = status.HTTP_409_CONFLICT
        return {"error": "replay_detected", "detail": str(exc)}
    except security.SecurityError as exc:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"error": "bad_request", "detail": str(exc)}

    return {"ok": outcome.ok, "detail": outcome.detail, "run_id": outcome.run_id}
