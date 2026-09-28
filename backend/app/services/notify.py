"""Notifications: an in-app `Notification` row plus a best-effort outbound send.

Outbound channels are plain `httpx.post()` to whatever URL an org configured
in `NotificationChannel` — a Slack/Discord/Teams incoming webhook and a
generic webhook all just want a POST, so there is no vendor SDK anywhere
here. A failed send is logged and swallowed: a broken webhook must never fail
the scan that triggered it.
"""
from __future__ import annotations

import logging
import uuid

import httpx
from sqlalchemy.orm import Session

from app.models import Finding, Notification, NotificationChannel, Project, Run

log = logging.getLogger(__name__)

CRITICAL_SCORE = 80


def _create(db: Session, *, org_id: uuid.UUID, kind: str, title: str,
            body: str | None = None, payload: dict | None = None) -> None:
    db.add(Notification(id=uuid.uuid4(), org_id=org_id, user_id=None,
                        kind=kind, title=title, body=body, payload=payload))
    db.commit()
    _dispatch(db, org_id, kind, title, body)


def _dispatch(db: Session, org_id: uuid.UUID, kind: str, title: str, body: str | None) -> None:
    channels = db.query(NotificationChannel).filter(
        NotificationChannel.org_id == org_id, NotificationChannel.enabled.is_(True)).all()
    for ch in channels:
        try:
            if ch.kind in ("slack", "discord", "teams", "webhook"):
                httpx.post(ch.target, json={"text": f"*{title}*\n{body or ''}"}, timeout=10)
            elif ch.kind == "email":
                from app.services import mail
                mail.send(ch.target, title, body or "")
        except (httpx.HTTPError, OSError) as exc:
            log.warning("notification dispatch to %s (%s) failed: %s", ch.target, ch.kind, exc)


def on_scan_completed(db: Session, project: Project, run: Run, new_findings: int) -> None:
    _create(
        db, org_id=project.org_id, kind="scan_completed",
        title=f"Scan complete: {project.origin}",
        body=f"{new_findings} new finding(s), {run.findings_closed} closed. "
             f"Commit {run.commit_sha[:8] if run.commit_sha else '?'}.",
        payload={"project_id": str(project.id), "run_id": str(run.id)},
    )

    critical = db.query(Finding).filter(
        Finding.project_id == project.id, Finding.state == "open",
        Finding.context_score >= CRITICAL_SCORE, Finding.last_seen_run == run.id,
    ).all()
    for f in critical:
        _create(
            db, org_id=project.org_id, kind="critical_finding",
            title=f"Critical finding in {project.origin}: {f.title[:100]}",
            body=f"Contextual score {f.context_score}. {f.file or f.package or ''}",
            payload={"project_id": str(project.id), "finding_id": str(f.id)},
        )


def on_repo_connected(db: Session, project: Project) -> None:
    _create(db, org_id=project.org_id, kind="repo_connected",
            title=f"Repository connected: {project.origin}",
            payload={"project_id": str(project.id)})


def on_push_triggered_scan(db: Session, project: Project, run: Run) -> None:
    _create(
        db, org_id=project.org_id, kind="push_triggered_scan",
        title=f"Push triggered a scan: {project.origin}",
        body=f"Commit {run.commit_sha[:8] if run.commit_sha else '?'} by {run.pusher or 'unknown'}.",
        payload={"project_id": str(project.id), "run_id": str(run.id), "connector": "github",
                 "resource_type": "repository", "resource_id": str(project.id), "severity": "info"},
    )


# --------------------------------------------------------- GitHub connector --
def on_github_connected(db: Session, *, org_id: uuid.UUID, account_login: str) -> None:
    _create(db, org_id=org_id, kind="github_connected", title="GitHub Connected",
            body=f"Connected as {account_login}.",
            payload={"connector": "github", "account_login": account_login, "severity": "info"})


def on_repository_imported(db: Session, *, org_id: uuid.UUID, count: int) -> None:
    if count <= 0:
        return
    _create(db, org_id=org_id, kind="repository_imported", title="Repository Imported",
            body=f"{count} new repositor{'y' if count == 1 else 'ies'} discovered.",
            payload={"connector": "github", "resource_type": "repository", "count": count, "severity": "info"})


def on_repository_monitoring_enabled(db: Session, *, org_id: uuid.UUID, repo_full_name: str, repository_id: uuid.UUID) -> None:
    _create(db, org_id=org_id, kind="repository_monitoring_enabled", title="Repository Monitoring Enabled",
            body=f"{repo_full_name} is now monitored.",
            payload={"connector": "github", "resource_type": "repository", "resource_id": str(repository_id), "severity": "info"})


def on_webhook_failed(db: Session, *, org_id: uuid.UUID, repo_full_name: str, detail: str) -> None:
    _create(db, org_id=org_id, kind="webhook_failed", title="Webhook Failed",
            body=f"{repo_full_name}: {detail}",
            payload={"connector": "github", "resource_type": "repository", "severity": "warning"})


def on_token_expired(db: Session, *, org_id: uuid.UUID, account_login: str) -> None:
    _create(db, org_id=org_id, kind="token_expired", title="Token Expired",
            body=f"The GitHub token for {account_login} has expired and could not be refreshed. Reconnect required.",
            payload={"connector": "github", "account_login": account_login, "severity": "critical"})


def on_repository_permission_lost(db: Session, *, org_id: uuid.UUID, repo_full_name: str, repository_id: uuid.UUID) -> None:
    _create(db, org_id=org_id, kind="repository_permission_lost", title="Repository Permission Lost",
            body=f"Access to {repo_full_name} was lost. Monitoring is paused for it.",
            payload={"connector": "github", "resource_type": "repository", "resource_id": str(repository_id), "severity": "warning"})


def on_sync_completed(db: Session, *, org_id: uuid.UUID, account_login: str, added: int, updated: int) -> None:
    _create(db, org_id=org_id, kind="sync_completed", title="Sync Completed",
            body=f"{account_login}: {added} added, {updated} updated.",
            payload={"connector": "github", "added": added, "updated": updated, "severity": "info"})


def on_kev_update(db: Session, org_id: uuid.UUID, new_entries: int) -> None:
    if new_entries <= 0:
        return
    _create(db, org_id=org_id, kind="kev_update",
            title=f"CISA KEV catalogue: {new_entries} new entr{'y' if new_entries == 1 else 'ies'}",
            payload={"new_entries": new_entries})
