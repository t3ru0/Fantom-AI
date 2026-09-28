"""`GitHubConnector`: the `BaseConnector` implementation, plus the OAuth
connect/disconnect flow that only makes sense for GitHub (a generic
`authorize()`/`callback()` shape, filled in with GitHub's PKCE + account
lookup). Repository listing/selection business rules live in
`repositories.py`; this module is the connector's own lifecycle.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.connectors.base import BaseConnector
from app.connectors.enums import ConnectorProvider, ConnectorStatus, MonitoringStatus
from app.connectors.github import security
from app.connectors.github.oauth import GitHubAuthError, OAuthAppStrategy, TokenExpired, strategy_for
from app.connectors.github.sync import sync_installation
from app.connectors.github.webhooks import create_webhook, delete_webhook
from app.connectors.manager import event_bus, record_sync, set_metrics
from app.connectors.models import AuthorizeResult, CallbackResult, HealthReport, ResourceRef, SyncResult
from app.core.secrets import manager as secrets_manager
from app.models import ConnectorInstallation
from app.models.github import GithubInstallation, GithubRepository
from app.services.demo_repos import remove_demo_projects
from app.services.audit import log_action

log = logging.getLogger(__name__)


class ConnectorNotFound(LookupError):
    pass


def _get_or_create_connector_installation(
    db: Session, *, org_id: uuid.UUID, user_id: uuid.UUID
) -> ConnectorInstallation:
    row = (
        db.query(ConnectorInstallation)
        .filter(
            ConnectorInstallation.provider == ConnectorProvider.GITHUB.value,
            ConnectorInstallation.organization_id == org_id,
            ConnectorInstallation.user_id == user_id,
        )
        .first()
    )
    if row is None:
        row = ConnectorInstallation(
            id=uuid.uuid4(), provider=ConnectorProvider.GITHUB.value,
            organization_id=org_id, user_id=user_id, status=ConnectorStatus.HEALTHY.value,
        )
        db.add(row)
        db.flush()
    return row


def get_github_installation(db: Session, *, org_id: uuid.UUID) -> GithubInstallation | None:
    return (
        db.query(GithubInstallation)
        .filter(GithubInstallation.organization_id == org_id)
        .order_by(GithubInstallation.created_at.desc())
        .first()
    )


def require_github_installation(db: Session, installation_id: uuid.UUID) -> GithubInstallation:
    gh = (
        db.query(GithubInstallation)
        .filter(GithubInstallation.connector_installation_id == installation_id)
        .first()
    )
    if gh is None:
        raise ConnectorNotFound(f"no GitHub installation for connector installation {installation_id}")
    return gh


class GitHubConnector(BaseConnector):
    provider = ConnectorProvider.GITHUB

    # ------------------------------------------------------------- OAuth ----
    def authorize(self, db: Session, *, org_id: uuid.UUID, user_id: uuid.UUID) -> AuthorizeResult:
        verifier, challenge = security.generate_pkce_pair()
        state = security.create_oauth_state(db, org_id=org_id, user_id=user_id, code_verifier=verifier)
        db.commit()
        url = OAuthAppStrategy().build_authorize_url(state=state, code_challenge=challenge)
        return AuthorizeResult(redirect_url=url, state=state)

    def callback(self, db: Session, *, params: dict) -> CallbackResult:
        state_token, code = params.get("state"), params.get("code")
        if not state_token or not code:
            raise ValueError("callback is missing 'code' or 'state'")

        resolved = security.consume_oauth_state(db, state_token)
        token = OAuthAppStrategy().exchange_code(code=code, code_verifier=resolved.code_verifier)

        connector_row = _get_or_create_connector_installation(db, org_id=resolved.org_id, user_id=resolved.user_id)
        gh = require_github_installation(db, connector_row.id) if _has_github_row(db, connector_row.id) else None
        expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=token.expires_in) if token.expires_in else None
        )
        if gh is None:
            gh = GithubInstallation(
                id=uuid.uuid4(), connector_installation_id=connector_row.id,
                organization_id=resolved.org_id, user_id=resolved.user_id, auth_strategy="oauth_app",
                access_token_encrypted=secrets_manager.store_secret(token.access_token),
                refresh_token_encrypted=(
                    secrets_manager.store_secret(token.refresh_token) if token.refresh_token else None
                ),
                token_expires_at=expires_at, scopes=token.scopes,
                github_account_id=token.account_id, github_account_login=token.account_login,
                github_account_type=token.account_type,
            )
            db.add(gh)
        else:
            gh.access_token_encrypted = secrets_manager.store_secret(token.access_token)
            if token.refresh_token:
                gh.refresh_token_encrypted = secrets_manager.store_secret(token.refresh_token)
            gh.token_expires_at = expires_at
            gh.scopes = token.scopes
            gh.github_account_id, gh.github_account_login, gh.github_account_type = (
                token.account_id, token.account_login, token.account_type
            )

        connector_row.status = ConnectorStatus.HEALTHY.value
        connector_row.last_error = None
        remove_demo_projects(db, resolved.org_id)
        db.flush()
        log_action(db, org_id=resolved.org_id, actor=str(resolved.user_id), action="github.connected",
                   detail=token.account_login, payload={"account_login": token.account_login, "scopes": token.scopes})
        db.commit()

        from app.services.notify import on_github_connected
        on_github_connected(db, org_id=resolved.org_id, account_login=token.account_login)
        event_bus.publish(resolved.org_id, "connector.connected", {"provider": "github", "account_login": token.account_login})

        return CallbackResult(installation_id=connector_row.id, account_label=token.account_login, scopes=token.scopes)

    def refresh(self, db: Session, *, installation_id: uuid.UUID) -> bool:
        gh = require_github_installation(db, installation_id)
        ok = strategy_for(gh).refresh(db, gh)
        connector_row = db.get(ConnectorInstallation, installation_id)
        if connector_row is not None:
            connector_row.status = ConnectorStatus.HEALTHY.value if ok else ConnectorStatus.EXPIRED.value
        db.commit()
        if not ok:
            from app.services.notify import on_token_expired
            on_token_expired(db, org_id=gh.organization_id, account_login=gh.github_account_login)
            log_action(db, org_id=gh.organization_id, action="github.token.expired", detail=gh.github_account_login)
            db.commit()
        return ok

    def disconnect(self, db: Session, *, installation_id: uuid.UUID) -> None:
        gh = require_github_installation(db, installation_id)
        org_id = gh.organization_id
        for repo in list(gh.repositories):
            for webhook in list(repo.webhooks):
                try:
                    delete_webhook(db, webhook)
                except Exception:  # noqa: BLE001 — disconnect must finish even if GitHub is unreachable
                    log.exception("failed to remove webhook for %s during disconnect", repo.full_name)

        try:
            strategy_for(gh).revoke(db, gh)
        except GitHubAuthError as exc:
            log.warning("upstream token revocation failed during disconnect of %s: %s", installation_id, exc)

        secrets_manager.delete_secret(gh.access_token_encrypted)
        secrets_manager.delete_secret(gh.refresh_token_encrypted)

        connector_row = db.get(ConnectorInstallation, installation_id)
        db.delete(gh)
        if connector_row is not None:
            connector_row.status = ConnectorStatus.DISCONNECTED.value
            connector_row.last_error = None
        # Audit history is preserved: rows already written to audit_log are
        # never touched by a disconnect - only the credential and connector
        # state disappear.
        log_action(db, org_id=org_id, action="github.disconnected")
        db.commit()
        event_bus.publish(org_id, "connector.disconnected", {"provider": "github"})

    # -------------------------------------------------------------- sync ----
    def sync(self, db: Session, *, installation_id: uuid.UUID) -> SyncResult:
        return self._run_sync(db, installation_id, sync_type="incremental")

    def trigger_manual_sync(self, db: Session, *, installation_id: uuid.UUID) -> SyncResult:
        return self._run_sync(db, installation_id, sync_type="full")

    def _run_sync(self, db: Session, installation_id: uuid.UUID, *, sync_type: str) -> SyncResult:
        gh = require_github_installation(db, installation_id)
        event_bus.publish(gh.organization_id, "connector.sync.started", {"provider": "github"})
        log_action(db, org_id=gh.organization_id, action="github.sync.started")
        db.commit()

        history = sync_installation(db, gh, sync_type=sync_type)
        monitored = (
            db.query(GithubRepository)
            .filter(GithubRepository.github_installation_id == gh.id,
                    GithubRepository.monitoring_status == MonitoringStatus.MONITORED.value)
            .count()
        )
        total = db.query(GithubRepository).filter(GithubRepository.github_installation_id == gh.id).count()
        set_metrics(db, installation_id, repositories_monitored=monitored)
        record_sync(db, installation_id, duration_ms=history.duration_ms, success=history.success)

        from app.services.notify import on_repository_imported, on_sync_completed
        on_repository_imported(db, org_id=gh.organization_id, count=history.repositories_added)
        on_sync_completed(db, org_id=gh.organization_id, account_login=gh.github_account_login,
                          added=history.repositories_added, updated=history.repositories_updated)
        log_action(db, org_id=gh.organization_id, action="github.sync.completed",
                   payload={"added": history.repositories_added, "updated": history.repositories_updated,
                            "removed": history.repositories_removed, "total": total})
        db.commit()
        event_bus.publish(gh.organization_id, "connector.sync.completed" if history.success else "connector.sync.failed",
                           {"provider": "github", "added": history.repositories_added})

        return SyncResult(
            resources_added=history.repositories_added, resources_updated=history.repositories_updated,
            resources_removed=history.repositories_removed, duration_ms=history.duration_ms,
            success=history.success, error_message=history.error_message,
        )

    # ------------------------------------------------------------ health ----
    def health(self, db: Session, *, installation_id: uuid.UUID) -> HealthReport:
        gh = require_github_installation(db, installation_id)
        connector_row = db.get(ConnectorInstallation, installation_id)

        token_valid = True
        detail = None
        if gh.token_expires_at and gh.token_expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            try:
                token_valid = strategy_for(gh).refresh(db, gh)
                db.commit()
            except GitHubAuthError as exc:
                token_valid = False
                detail = str(exc)

        total = db.query(GithubRepository).filter(GithubRepository.github_installation_id == gh.id).count()
        monitored = (
            db.query(GithubRepository)
            .filter(GithubRepository.github_installation_id == gh.id,
                    GithubRepository.monitoring_status == MonitoringStatus.MONITORED.value)
            .count()
        )
        webhook_valid = None
        if monitored:
            webhook_valid = any(
                r.webhooks for r in gh.repositories if r.monitoring_status == MonitoringStatus.MONITORED.value
            )

        status = connector_row.status if connector_row else ConnectorStatus.ERROR.value
        if not token_valid:
            status = ConnectorStatus.EXPIRED.value
        elif webhook_valid is False:
            status = ConnectorStatus.WEBHOOK_FAILED.value

        return HealthReport(
            status=status, token_valid=token_valid, webhook_valid=webhook_valid,
            last_sync_at=connector_row.last_sync_at.isoformat() if connector_row and connector_row.last_sync_at else None,
            last_sync_duration_ms=connector_row.metrics.last_sync_duration_ms if connector_row and connector_row.metrics else None,
            resource_count=total, monitored_resource_count=monitored, detail=detail,
        )

    # -------------------------------------------------------- resources -----
    def list_resources(self, db: Session, *, installation_id: uuid.UUID) -> list[ResourceRef]:
        gh = require_github_installation(db, installation_id)
        return [
            ResourceRef(
                external_id=str(r.github_repo_id), name=r.full_name, kind="repository",
                monitoring_status=r.monitoring_status,
                metadata={"private": r.private, "archived": r.archived, "language": r.language},
            )
            for r in gh.repositories
        ]

    def subscribe(self, db: Session, *, installation_id: uuid.UUID, resource_id: str) -> None:
        repo = db.get(GithubRepository, uuid.UUID(resource_id))
        if repo is None or repo.github_installation_id != require_github_installation(db, installation_id).id:
            raise LookupError(f"repository {resource_id} not found for this installation")
        if not repo.permission_admin:
            repo.monitoring_status = MonitoringStatus.MANUAL_ONLY.value
            repo.monitoring_reason = "no admin permission on this repository - webhook not created"
            db.commit()
            return
        create_webhook(db, repo, callback_url=security.webhook_callback_url())
        repo.monitoring_status = MonitoringStatus.MONITORED.value
        repo.monitoring_reason = None
        db.commit()

    def unsubscribe(self, db: Session, *, installation_id: uuid.UUID, resource_id: str) -> None:
        repo = db.get(GithubRepository, uuid.UUID(resource_id))
        if repo is None:
            return
        for webhook in list(repo.webhooks):
            delete_webhook(db, webhook)
        repo.monitoring_status = MonitoringStatus.MANUAL_ONLY.value
        db.commit()


def _has_github_row(db: Session, connector_installation_id: uuid.UUID) -> bool:
    return (
        db.query(GithubInstallation)
        .filter(GithubInstallation.connector_installation_id == connector_installation_id)
        .first()
        is not None
    )


