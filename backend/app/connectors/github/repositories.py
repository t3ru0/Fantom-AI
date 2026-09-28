"""Repository listing (filters + pagination) and the selection flow: turning
a `GithubRepository` row into something the scan pipeline actually watches -
which means giving it a `Project` row (the thing `Run`/`RunEvent` key off of)
and, permission allowing, a webhook.
"""
from __future__ import annotations

import logging
import uuid

from sqlalchemy import func
from sqlalchemy.orm import Query, Session

from app.connectors.enums import MonitoringStatus
from app.connectors.github import security
from app.connectors.github.sync import enrich_repository
from app.connectors.github.webhooks import create_webhook
from app.models import Project
from app.models.github import GithubInstallation, GithubRepository
from app.services.audit import log_action

log = logging.getLogger(__name__)


def _base_query(db: Session, installation: GithubInstallation) -> Query:
    return db.query(GithubRepository).filter(GithubRepository.github_installation_id == installation.id)


def list_repositories(
    db: Session, installation: GithubInstallation, *,
    visibility: str | None = None, archived: bool | None = None, monitored: bool | None = None,
    language: str | None = None, search: str | None = None,
    page: int = 1, page_size: int = 50,
) -> tuple[list[GithubRepository], int]:
    q = _base_query(db, installation)
    if visibility == "private":
        q = q.filter(GithubRepository.private.is_(True))
    elif visibility == "public":
        q = q.filter(GithubRepository.private.is_(False))
    if archived is not None:
        q = q.filter(GithubRepository.archived.is_(archived))
    if monitored is not None:
        q = q.filter(
            GithubRepository.monitoring_status == MonitoringStatus.MONITORED.value
            if monitored else GithubRepository.monitoring_status != MonitoringStatus.MONITORED.value
        )
    if language:
        q = q.filter(GithubRepository.language == language)
    if search:
        q = q.filter(GithubRepository.full_name.ilike(f"%{search}%"))

    total = q.with_entities(func.count(GithubRepository.id)).scalar() or 0
    rows = (
        q.order_by(GithubRepository.full_name.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return rows, total


def get_repository(db: Session, installation: GithubInstallation, repository_id: uuid.UUID) -> GithubRepository | None:
    return _base_query(db, installation).filter(GithubRepository.id == repository_id).first()


def _get_or_create_project(db: Session, installation: GithubInstallation, repo: GithubRepository) -> Project:
    project = db.query(Project).filter(
        Project.org_id == installation.organization_id, Project.origin == repo.full_name
    ).first()
    if project is None:
        project = Project(
            id=uuid.uuid4(), org_id=installation.organization_id, name=repo.name,
            source="github", origin=repo.full_name, branch=repo.default_branch or "main",
            gh_repo_id=repo.github_repo_id, is_private=repo.private, default_branch=repo.default_branch,
            context_complete=False,
        )
        db.add(project)
        db.flush()
    return project


def select_repositories(
    db: Session, installation: GithubInstallation, repository_ids: list[str]
) -> tuple[list[GithubRepository], dict[str, str]]:
    selected: list[GithubRepository] = []
    skipped: dict[str, str] = {}

    for raw_id in repository_ids:
        try:
            repo_id = uuid.UUID(raw_id)
        except ValueError:
            skipped[raw_id] = "not a valid repository id"
            continue
        repo = get_repository(db, installation, repo_id)
        if repo is None:
            skipped[raw_id] = "repository not found for this installation"
            continue
        if repo.monitoring_status == MonitoringStatus.PERMISSION_LOST.value:
            skipped[raw_id] = "access to this repository was lost - resync first"
            continue

        try:
            enrich_repository(db, repo)
        except Exception:  # noqa: BLE001 — enrichment is best-effort, selection still proceeds
            log.exception("enrichment failed for %s, continuing with basic metadata", repo.full_name)

        project = _get_or_create_project(db, installation, repo)
        repo.project_id = project.id

        if repo.permission_admin:
            try:
                create_webhook(db, repo, callback_url=security.webhook_callback_url())
                repo.monitoring_status = MonitoringStatus.MONITORED.value
                repo.monitoring_reason = None
            except Exception as exc:  # noqa: BLE001
                log.exception("webhook creation failed for %s", repo.full_name)
                repo.monitoring_status = MonitoringStatus.MANUAL_ONLY.value
                repo.monitoring_reason = f"webhook creation failed: {exc}"
                from app.services.notify import on_webhook_failed
                on_webhook_failed(db, org_id=installation.organization_id, repo_full_name=repo.full_name, detail=str(exc))
        else:
            repo.monitoring_status = MonitoringStatus.MANUAL_ONLY.value
            repo.monitoring_reason = "no admin permission on this repository - webhook not created"

        log_action(db, org_id=installation.organization_id, project_id=project.id,
                   action="github.repo.selected", detail=repo.full_name,
                   payload={"repository_id": str(repo.id), "monitoring_status": repo.monitoring_status})

        if repo.monitoring_status == MonitoringStatus.MONITORED.value:
            from app.services.notify import on_repository_monitoring_enabled
            on_repository_monitoring_enabled(db, org_id=installation.organization_id,
                                             repo_full_name=repo.full_name, repository_id=repo.id)

        selected.append(repo)

    db.commit()
    return selected, skipped


def unselect_repositories(db: Session, installation: GithubInstallation, repository_ids: list[str]) -> list[GithubRepository]:
    unselected: list[GithubRepository] = []
    for raw_id in repository_ids:
        try:
            repo_id = uuid.UUID(raw_id)
        except ValueError:
            continue
        repo = get_repository(db, installation, repo_id)
        if repo is None:
            continue
        for webhook in list(repo.webhooks):
            from app.connectors.github.webhooks import delete_webhook
            delete_webhook(db, webhook)
        repo.monitoring_status = MonitoringStatus.MANUAL_ONLY.value
        repo.monitoring_reason = "unselected by user"
        log_action(db, org_id=installation.organization_id, project_id=repo.project_id,
                   action="github.repo.unselected", detail=repo.full_name)
        unselected.append(repo)
    db.commit()
    return unselected
