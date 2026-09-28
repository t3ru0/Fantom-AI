"""Webhook lifecycle (create/delete/repair/rotate) and the delivery pipeline
that turns a verified push into a `Run` - reusing the real `Run`/`RunEvent`
state machine, never a parallel one.

Scan dedup is the one place this module has to be careful under concurrency:
two webhook deliveries for the same repository, handled by two different
worker processes, must never create two concurrent `Run` rows. That's closed
with `SELECT ... FOR UPDATE` on the `Project` row - both processes serialize
on the same lock, and only one of them observes "nothing running yet".
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.connectors.enums import LifecycleEvent, MonitoringStatus
from app.connectors.github import security
from app.connectors.github.client import GitHubApiError, GitHubClient
from app.connectors.github.oauth import strategy_for
from app.connectors.manager import bump_metrics, event_bus, set_metrics
from app.core.secrets import manager as secrets_manager
from app.integrations.github.webhook import parse_push
from app.models import Project, Run
from app.models.github import GithubRepository, GithubWebhook, GithubWebhookDelivery
from app.services.audit import log_action

log = logging.getLogger(__name__)

WEBHOOK_EVENTS = ["push", "pull_request", "release", "repository", "create", "delete",
                   "installation_repositories", "ping"]
MAX_WEBHOOK_BODY_BYTES = security.MAX_WEBHOOK_BODY_BYTES


class WebhookOpError(RuntimeError):
    pass


@dataclass(slots=True)
class DeliveryOutcome:
    ok: bool
    detail: str
    run_id: str | None = None


# ------------------------------------------------------------- lifecycle ----
def create_webhook(db: Session, repo: GithubRepository, *, callback_url: str) -> GithubWebhook:
    if not repo.permission_admin:
        raise PermissionError(f"{repo.full_name}: no admin permission, cannot create a webhook")
    strategy = strategy_for(repo.installation)
    client = GitHubClient(db, repo.installation, strategy)
    secret = security.generate_webhook_secret()
    data = asyncio.run(client.create_webhook(repo.full_name, callback_url=callback_url, secret=secret, events=WEBHOOK_EVENTS))

    webhook = GithubWebhook(
        id=uuid.uuid4(), repository_id=repo.id, webhook_id=data["id"], callback_url=callback_url,
        active=True, secret_encrypted=secrets_manager.store_secret(secret),
        delivery_secret_hash=security.hash_secret(secret),
    )
    db.add(webhook)
    log_action(db, org_id=repo.installation.organization_id, action="github.webhook.created",
               detail=repo.full_name, payload={"webhook_id": data["id"], "repository_id": str(repo.id)})
    bump_metrics(db, repo.installation.connector_installation_id, webhooks_active=1)
    db.flush()
    return webhook


def delete_webhook(db: Session, webhook: GithubWebhook) -> None:
    repo = webhook.repository
    strategy = strategy_for(repo.installation)
    client = GitHubClient(db, repo.installation, strategy)
    try:
        asyncio.run(client.delete_webhook(repo.full_name, webhook.webhook_id))
    except GitHubApiError as exc:
        log.warning("upstream delete of webhook %s on %s failed (%s) - removing local row anyway",
                    webhook.webhook_id, repo.full_name, exc)
    log_action(db, org_id=repo.installation.organization_id, action="github.webhook.deleted",
               detail=repo.full_name, payload={"webhook_id": webhook.webhook_id})
    bump_metrics(db, repo.installation.connector_installation_id, webhooks_active=-1)
    db.delete(webhook)
    # `session.delete()` does not update the parent's already-loaded in-memory
    # collection - without this, a later cascade delete of `repo` (e.g. from
    # disconnect() deleting the whole installation) still finds this webhook
    # in `repo.webhooks` and re-issues a DELETE for a row already gone,
    # producing a harmless but noisy "0 rows matched" SAWarning.
    if webhook in repo.webhooks:
        repo.webhooks.remove(webhook)
    db.flush()


def rotate_secret(db: Session, webhook: GithubWebhook, *, grace_hours: int = 24) -> None:
    """New secret takes effect at GitHub immediately; the old one still
    verifies locally for `grace_hours`, so a delivery already in flight when
    the rotation happens does not get rejected."""
    repo = webhook.repository
    strategy = strategy_for(repo.installation)
    client = GitHubClient(db, repo.installation, strategy)
    new_secret = security.generate_webhook_secret()
    asyncio.run(client.update_webhook_secret(repo.full_name, webhook.webhook_id, new_secret))

    webhook.previous_secret_encrypted = webhook.secret_encrypted
    webhook.previous_secret_hash = webhook.delivery_secret_hash
    webhook.previous_secret_expires_at = datetime.now(timezone.utc) + timedelta(hours=grace_hours)
    webhook.secret_encrypted = secrets_manager.store_secret(new_secret)
    webhook.delivery_secret_hash = security.hash_secret(new_secret)
    db.flush()


def repair_webhook(db: Session, repo: GithubRepository, *, callback_url: str) -> GithubWebhook | None:
    """Missing or reporting failures -> delete (if present) and recreate.
    Reuses `create_webhook`/`delete_webhook` rather than duplicating the
    GitHub API calls."""
    if repo.monitoring_status != MonitoringStatus.MONITORED.value or not repo.permission_admin:
        return None
    existing = repo.webhooks[0] if repo.webhooks else None
    if existing is not None:
        try:
            delete_webhook(db, existing)
        except Exception:  # noqa: BLE001 — the local row is stale either way
            log.exception("failed to clean up stale webhook row for %s", repo.full_name)
            db.delete(existing)
            db.flush()
    webhook = create_webhook(db, repo, callback_url=callback_url)
    log_action(db, org_id=repo.installation.organization_id, action="github.webhook.repaired", detail=repo.full_name)
    return webhook


def disable_repository(db: Session, repo: GithubRepository, *, reason: str) -> None:
    """Installation removed / access revoked: mark disabled, don't error."""
    for webhook in list(repo.webhooks):
        try:
            delete_webhook(db, webhook)
        except Exception:  # noqa: BLE001
            log.exception("failed to remove webhook while disabling %s", repo.full_name)
    repo.monitoring_status = MonitoringStatus.DISABLED.value
    repo.monitoring_reason = reason
    db.flush()


# --------------------------------------------------------------- delivery ---
def handle_delivery(
    db: Session, *, body: bytes, hook_id: str | None, event: str | None,
    delivery_id: str | None, signature: str | None,
) -> DeliveryOutcome:
    if not hook_id or not delivery_id or not event:
        raise security.SecurityError("missing X-GitHub-Hook-ID/X-GitHub-Delivery/X-GitHub-Event header")

    webhook = (
        db.query(GithubWebhook)
        .filter(GithubWebhook.webhook_id == int(hook_id))
        .first()
    )
    if webhook is None:
        raise security.SecurityError(f"delivery for unknown webhook id {hook_id}")
    repo = webhook.repository

    try:
        security.verify_delivery_signature(body, signature, webhook)
    except security.BadSignature as exc:
        _record_delivery(db, webhook, delivery_id, event, verified=False, status="rejected")
        log_action(db, org_id=repo.installation.organization_id, action="github.webhook.failed",
                   detail=str(exc), payload={"delivery_id": delivery_id, "webhook_id": hook_id, "event": event})
        db.commit()
        raise

    # Fast pre-check, then the unique constraint on delivery_id is what
    # actually closes the race between two processes handling a duplicate.
    security.check_replay(db, delivery_id)
    delivery = GithubWebhookDelivery(
        id=uuid.uuid4(), delivery_id=delivery_id, webhook_id=webhook.id, repository_id=repo.id,
        event=event, signature_verified=True, processing_status="received",
    )
    db.add(delivery)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise security.ReplayDetected(f"delivery {delivery_id} was already processed") from None

    event_bus.publish(repo.installation.organization_id, "webhook.verified",
                       {"repository": repo.full_name, "event": event, "delivery_id": delivery_id})
    bump_metrics(db, repo.installation.connector_installation_id, events_received=1)

    try:
        outcome = _process_event(db, repo, webhook, event, body, delivery)
        delivery.processing_status = "processed" if outcome.ok else "error"
    except Exception:
        delivery.processing_status = "error"
        db.commit()
        raise
    delivery.processed_at = datetime.now(timezone.utc)
    db.commit()
    return outcome


def _record_delivery(db: Session, webhook: GithubWebhook, delivery_id: str, event: str, *, verified: bool, status: str) -> None:
    db.add(GithubWebhookDelivery(
        id=uuid.uuid4(), delivery_id=delivery_id, webhook_id=webhook.id, repository_id=webhook.repository_id,
        event=event, signature_verified=verified, processing_status=status,
        processed_at=datetime.now(timezone.utc),
    ))


def _process_event(db: Session, repo: GithubRepository, webhook: GithubWebhook, event: str,
                    body: bytes, delivery: GithubWebhookDelivery) -> DeliveryOutcome:
    if event == "ping":
        webhook.last_ping_at = datetime.now(timezone.utc)
        return DeliveryOutcome(ok=True, detail="pong")

    if event == "push":
        return _handle_push(db, repo, body, delivery.delivery_id, event)

    if event == "repository":
        return _handle_repository_event(db, repo, body)

    if event in ("installation", "installation_repositories"):
        # OAuth-App-authenticated repos never receive these (they are a
        # GitHub App concept) - accepted here only so the same endpoint
        # doesn't error if a future GitHub App strategy starts sending them.
        return DeliveryOutcome(ok=True, detail=f"{event} accepted, no action for an OAuth App installation")

    return DeliveryOutcome(ok=True, detail=f"{event} recorded, not scan-triggering")


def _handle_repository_event(db: Session, repo: GithubRepository, body: bytes) -> DeliveryOutcome:
    payload = json.loads(body)
    action = payload.get("action", "")
    gh_repo = payload.get("repository") or {}

    if action == "renamed":
        repo.full_name = gh_repo.get("full_name", repo.full_name)
        repo.name = gh_repo.get("name", repo.name)
    elif action == "archived":
        repo.archived = True
        if repo.monitoring_status == MonitoringStatus.MONITORED.value:
            repo.monitoring_status = MonitoringStatus.ARCHIVED.value
            repo.monitoring_reason = "repository was archived on GitHub"
    elif action == "unarchived":
        repo.archived = False
    elif action == "privatized":
        repo.private = True
    elif action == "publicized":
        repo.private = False
    elif action in ("deleted", "transferred"):
        disable_repository(db, repo, reason=f"repository {action} on GitHub")
    db.flush()
    return DeliveryOutcome(ok=True, detail=f"repository.{action} applied")


def _handle_push(db: Session, repo: GithubRepository, body: bytes, delivery_id: str, event_type: str) -> DeliveryOutcome:
    if repo.monitoring_status != MonitoringStatus.MONITORED.value:
        return DeliveryOutcome(ok=True, detail="repository is not monitored - ignored")

    ev = parse_push(json.loads(body))
    if not ev.should_scan:
        return DeliveryOutcome(ok=True, detail=f"not a branch push we inspect (ref={ev.ref})")

    if repo.project_id is None:
        return DeliveryOutcome(ok=True, detail="repository has no linked project yet - ignored")

    return _queue_scan(
        db, repo, trigger="push", commit_sha=ev.after, commit_message=ev.commit_message,
        pusher=ev.pusher, changed_files=ev.changed_files, branch=ev.branch,
        delivery_id=delivery_id, event_type=event_type,
    )


def _queue_scan(
    db: Session, repo: GithubRepository, *, trigger: str, commit_sha: str | None,
    commit_message: str | None, pusher: str | None, changed_files: list[str] | None,
    branch: str | None, delivery_id: str, event_type: str,
) -> DeliveryOutcome:
    project = db.get(Project, repo.project_id)
    if project is None or project.state == "disconnected":
        return DeliveryOutcome(ok=True, detail="project not connected")

    # Serializes concurrent handlers (any process) for this repository: both
    # take the row lock in turn, only the first sees "nothing running yet".
    locked = db.query(Project).filter(Project.id == project.id).with_for_update().one()
    active = db.query(Run).filter(Run.project_id == locked.id, Run.state.in_(("queued", "running"))).first()

    if active is not None:
        repo.pending_rescan_commit_sha = commit_sha
        repo.pending_rescan_payload = {
            "trigger": trigger, "commit_message": commit_message, "pusher": pusher,
            "changed_files": changed_files, "branch": branch, "delivery_id": delivery_id, "event_type": event_type,
        }
        db.flush()
        return DeliveryOutcome(ok=True, detail="scan already running - queued as pending rescan", run_id=str(active.id))

    run = Run(
        id=uuid.uuid4(), project_id=locked.id, trigger=trigger, commit_sha=commit_sha,
        commit_message=commit_message, pusher=pusher, changed_files=changed_files, branch=branch,
        delivery_id=delivery_id, github_event_type=event_type,
        full_sweep=locked.last_run_at is None, state="queued",
    )
    db.add(run)
    db.flush()

    from app.workers.runner import wake_worker
    wake_worker()

    from app.services.notify import on_push_triggered_scan
    on_push_triggered_scan(db, locked, run)
    log_action(db, org_id=locked.org_id, project_id=locked.id, action="github.push.scan",
               detail=commit_sha, payload={"delivery_id": delivery_id})
    bump_metrics(db, repo.installation.connector_installation_id, runs_triggered=1)
    event_bus.publish(repo.installation.organization_id, "repository.scan.queued",
                       {"repository": repo.full_name, "run_id": str(run.id)})
    return DeliveryOutcome(ok=True, detail="scan queued", run_id=str(run.id))


def maybe_queue_pending_rescan(db: Session, project: Project) -> None:
    """Called once a `Run` finishes - see the two-line hook in
    `app.services.orchestrator.execute`. If a push arrived while that run was
    in flight, exactly one follow-up scan gets queued for it now."""
    repo = db.query(GithubRepository).filter(GithubRepository.project_id == project.id).first()
    if repo is None or repo.pending_rescan_commit_sha is None:
        return
    payload = repo.pending_rescan_payload or {}
    sha = repo.pending_rescan_commit_sha
    repo.pending_rescan_commit_sha = None
    repo.pending_rescan_payload = None
    db.flush()

    run = Run(
        id=uuid.uuid4(), project_id=project.id, trigger=payload.get("trigger", "push"),
        commit_sha=sha, commit_message=payload.get("commit_message"), pusher=payload.get("pusher"),
        changed_files=payload.get("changed_files"), branch=payload.get("branch"),
        delivery_id=payload.get("delivery_id"), github_event_type=payload.get("event_type"),
        full_sweep=False, state="queued",
    )
    db.add(run)
    db.commit()

    from app.workers.runner import wake_worker
    wake_worker()
    log.info("queued pending rescan for project %s at %s", project.id, sha[:8] if sha else "?")
