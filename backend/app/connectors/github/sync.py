"""Repository sync: pulls the current repo list and reconciles it against
`github_repositories`, upserting by `github_repo_id` (immutable across a
rename or a transfer - only `full_name`/`owner_login` need to move).

Batched: one bulk SELECT loads every existing row for the installation up
front (no N+1), all changes accumulate in memory, and the whole reconciliation
commits in chunks of `_COMMIT_EVERY` rather than one commit per repository -
that's what keeps a 10,000-repo org's sync from being 10,000 round trips.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.connectors.enums import MonitoringStatus
from app.connectors.github.client import GitHubApiError, GitHubClient
from app.connectors.github.oauth import strategy_for
from app.models import ConnectorInstallation
from app.models.github import GithubInstallation, GithubRepository, GithubSyncHistory

log = logging.getLogger(__name__)
_COMMIT_EVERY = 1000


def _repo_fields(item: dict) -> dict:
    owner = (item.get("owner") or {}).get("login", "")
    perms = item.get("permissions") or {}
    license_info = item.get("license") or {}
    return dict(
        full_name=item.get("full_name", ""), owner_login=owner, name=item.get("name", ""),
        private=bool(item.get("private", True)), archived=bool(item.get("archived", False)),
        default_branch=item.get("default_branch"), language=item.get("language"),
        license=license_info.get("spdx_id") or license_info.get("name"),
        stars=item.get("stargazers_count") or 0, forks=item.get("forks_count") or 0,
        open_issues=item.get("open_issues_count") or 0,
        permission_admin=bool(perms.get("admin")), permission_push=bool(perms.get("push")),
        permission_pull=bool(perms.get("pull")), permission_maintain=bool(perms.get("maintain")),
        permission_triage=bool(perms.get("triage")),
    )


def sync_installation(db: Session, installation: GithubInstallation, *, sync_type: str = "incremental") -> GithubSyncHistory:
    started = time.time()
    added = updated = removed = 0
    error_message: str | None = None
    success = True
    newly_lost: list[GithubRepository] = []

    connector_row = db.get(ConnectorInstallation, installation.connector_installation_id)
    etag = (connector_row.sync_state or {}).get("repos_etag") if connector_row and sync_type == "incremental" else None

    try:
        strategy = strategy_for(installation)
        client = GitHubClient(db, installation, strategy)
        page = asyncio.run(client.list_repositories(etag=etag))

        if page.not_modified:
            log.info("installation %s: repository list unchanged (etag hit)", installation.id)
        else:
            existing = {
                r.github_repo_id: r
                for r in db.query(GithubRepository).filter(
                    GithubRepository.github_installation_id == installation.id
                ).all()
            }
            seen_ids: set[int] = set()
            processed = 0

            for item in page.items:
                repo_id = item.get("id")
                if repo_id is None:
                    continue
                seen_ids.add(repo_id)
                fields = _repo_fields(item)
                row = existing.get(repo_id)
                if row is None:
                    row = GithubRepository(
                        id=uuid.uuid4(), github_installation_id=installation.id,
                        github_repo_id=repo_id, monitoring_status=MonitoringStatus.MANUAL_ONLY.value,
                        **fields,
                    )
                    db.add(row)
                    added += 1
                else:
                    changed = any(getattr(row, k) != v for k, v in fields.items())
                    for k, v in fields.items():
                        setattr(row, k, v)
                    if row.monitoring_status == MonitoringStatus.PERMISSION_LOST.value:
                        # access came back - hand it back to whatever the user last chose.
                        row.monitoring_status = MonitoringStatus.MANUAL_ONLY.value
                        row.monitoring_reason = None
                        changed = True
                    if fields["archived"] and row.monitoring_status == MonitoringStatus.MONITORED.value:
                        row.monitoring_status = MonitoringStatus.ARCHIVED.value
                        row.monitoring_reason = "repository was archived on GitHub"
                        changed = True
                    if changed:
                        updated += 1
                row.last_synced_at = datetime.now(timezone.utc)

                processed += 1
                if processed % _COMMIT_EVERY == 0:
                    db.commit()

            # Anything previously known but absent from this listing is no
            # longer accessible (deleted, transferred out, or access revoked).
            # Soft-disabled, never deleted - see `models.github.GithubRepository`.
            for repo_id, row in existing.items():
                if repo_id in seen_ids:
                    continue
                if row.monitoring_status in (MonitoringStatus.MONITORED.value, MonitoringStatus.MANUAL_ONLY.value):
                    row.monitoring_status = MonitoringStatus.PERMISSION_LOST.value
                    row.monitoring_reason = "no longer visible to this installation"
                    removed += 1
                    newly_lost.append(row)

            if connector_row is not None:
                connector_row.sync_state = {**(connector_row.sync_state or {}), "repos_etag": page.etag}

    except GitHubApiError as exc:
        success = False
        error_message = str(exc)[:2000]
        log.warning("sync failed for installation %s: %s", installation.id, exc)

    if connector_row is not None:
        connector_row.last_sync_at = datetime.now(timezone.utc)
        if success:
            connector_row.last_error = None
        else:
            connector_row.last_error = error_message

    history = GithubSyncHistory(
        id=uuid.uuid4(), installation_id=installation.id, sync_type=sync_type,
        repositories_added=added, repositories_updated=updated, repositories_removed=removed,
        duration_ms=int((time.time() - started) * 1000), success=success, error_message=error_message,
    )
    db.add(history)
    db.commit()

    if newly_lost:
        from app.services.notify import on_repository_permission_lost
        for row in newly_lost:
            on_repository_permission_lost(db, org_id=installation.organization_id,
                                          repo_full_name=row.full_name, repository_id=row.id)

    return history


def enrich_repository(db: Session, repo: GithubRepository) -> None:
    """Per-repo detail (topics, security policy, dependabot, branch sha) is
    deliberately NOT fetched during bulk sync - that would be one extra API
    call per repository, i.e. exactly the N+1 the sync path has to avoid at
    10,000 repos. It is fetched here instead, once, when a repository is
    actually selected for monitoring."""
    installation = repo.installation
    strategy = strategy_for(installation)
    client = GitHubClient(db, installation, strategy)

    async def _fetch() -> tuple[list[str], dict, dict]:
        topics = await client.list_topics(repo.full_name)
        security = await client.repository_security_settings(repo.full_name)
        branches = await client.list_branches(repo.full_name)
        return topics, security, {b["name"]: b for b in branches}

    topics, security, branches = asyncio.run(_fetch())
    repo.topics = topics
    repo.has_security_policy = security["has_security_policy"]
    repo.has_dependabot = security["has_dependabot"]
    if repo.default_branch and repo.default_branch in branches:
        repo.default_branch_sha = branches[repo.default_branch]["commit"]["sha"]
