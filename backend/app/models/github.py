"""GitHub connector tables. `github_installations` is the provider-specific
extension of the generic `connector_installations` row (one-to-one, joined by
`connector_installation_id`); everything else hangs off it.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.connectors.enums import MonitoringStatus
from app.core.secrets.encryption import EncryptedString
from app.models.base import Base, created_at, pk_uuid, updated_at
from app.models.tables import one_of

MONITORING_STATUSES = tuple(s.value for s in MonitoringStatus)


class GithubInstallation(Base):
    __tablename__ = "github_installations"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_github_installations_org_user"),
    )
    id: Mapped[uuid.UUID] = pk_uuid()
    connector_installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("connector_installations.id", ondelete="CASCADE"), unique=True, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)

    # ---- credential (auth strategy: OAuth App today) -----------------------
    auth_strategy: Mapped[str] = mapped_column(String(30), nullable=False, default="oauth_app")
    access_token_encrypted: Mapped[str] = mapped_column(EncryptedString, nullable=False)
    refresh_token_encrypted: Mapped[str | None] = mapped_column(EncryptedString)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scopes: Mapped[list[str] | None] = mapped_column(JSON)

    # ---- GitHub account this installation authenticated as ----------------
    github_account_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    github_account_login: Mapped[str] = mapped_column(String(200), nullable=False)
    github_account_type: Mapped[str] = mapped_column(String(20), nullable=False, default="User")

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    repositories: Mapped[list["GithubRepository"]] = relationship(
        back_populates="installation", cascade="all, delete-orphan"
    )
    sync_history: Mapped[list["GithubSyncHistory"]] = relationship(
        back_populates="installation", cascade="all, delete-orphan"
    )


class GithubRepository(Base):
    __tablename__ = "github_repositories"
    __table_args__ = (
        UniqueConstraint("github_installation_id", "github_repo_id", name="uq_github_repositories_installation_repo"),
        CheckConstraint(one_of("monitoring_status", MONITORING_STATUSES), name="monitoring_status_valid"),
        Index("ix_github_repositories_monitoring", "monitoring_status"),
    )
    id: Mapped[uuid.UUID] = pk_uuid()
    github_installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("github_installations.id", ondelete="CASCADE"), index=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )

    github_repo_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(400), nullable=False)
    owner_login: Mapped[str] = mapped_column(String(200), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    private: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    default_branch: Mapped[str | None] = mapped_column(String(200))
    default_branch_sha: Mapped[str | None] = mapped_column(String(64))
    language: Mapped[str | None] = mapped_column(String(80))
    topics: Mapped[list[str] | None] = mapped_column(JSON)
    license: Mapped[str | None] = mapped_column(String(120))
    stars: Mapped[int] = mapped_column(Integer, default=0)
    forks: Mapped[int] = mapped_column(Integer, default=0)
    open_issues: Mapped[int] = mapped_column(Integer, default=0)
    has_security_policy: Mapped[bool] = mapped_column(Boolean, default=False)
    has_dependabot: Mapped[bool] = mapped_column(Boolean, default=False)

    permission_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    permission_push: Mapped[bool] = mapped_column(Boolean, default=False)
    permission_pull: Mapped[bool] = mapped_column(Boolean, default=False)
    permission_maintain: Mapped[bool] = mapped_column(Boolean, default=False)
    permission_triage: Mapped[bool] = mapped_column(Boolean, default=False)

    monitoring_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=MonitoringStatus.MANUAL_ONLY.value
    )
    monitoring_reason: Mapped[str | None] = mapped_column(Text)

    etag: Mapped[str | None] = mapped_column(String(200))     # conditional GET on this repo
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Set when a push arrives while a scan is already running for this repo's
    # project - the dedup guard in `webhooks.py` stores the newest commit here
    # instead of queuing a second concurrent Run, and the orchestrator queues
    # exactly one follow-up scan for it once the in-flight run finishes.
    pending_rescan_commit_sha: Mapped[str | None] = mapped_column(String(64))
    pending_rescan_payload: Mapped[dict | None] = mapped_column(JSON)

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    installation: Mapped[GithubInstallation] = relationship(back_populates="repositories")
    webhooks: Mapped[list["GithubWebhook"]] = relationship(back_populates="repository", cascade="all, delete-orphan")


class GithubWebhook(Base):
    __tablename__ = "github_webhooks"
    id: Mapped[uuid.UUID] = pk_uuid()
    repository_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("github_repositories.id", ondelete="CASCADE"), index=True
    )
    webhook_id: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    callback_url: Mapped[str] = mapped_column(Text, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # The secret itself is kept encrypted (needed to compute the expected HMAC
    # on each delivery); `delivery_secret_hash` is a one-way fingerprint of it
    # for logging/audit, so the secret's plaintext form never appears in a log
    # line or an audit payload. A grace-window previous pair lets a delivery
    # signed under the old secret still verify right after a rotation.
    secret_encrypted: Mapped[str] = mapped_column(EncryptedString, nullable=False)
    delivery_secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_secret_encrypted: Mapped[str | None] = mapped_column(EncryptedString)
    previous_secret_hash: Mapped[str | None] = mapped_column(String(64))
    previous_secret_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    last_ping_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_delivery_failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    repository: Mapped[GithubRepository] = relationship(back_populates="webhooks")
    deliveries: Mapped[list["GithubWebhookDelivery"]] = relationship(
        back_populates="webhook", cascade="all, delete-orphan"
    )


class GithubWebhookDelivery(Base):
    """Every delivery is checked against this table before processing - a
    repeated `delivery_id` is a replay regardless of signature validity."""
    __tablename__ = "github_webhook_deliveries"
    __table_args__ = (Index("ix_github_webhook_deliveries_webhook", "webhook_id"),)

    id: Mapped[uuid.UUID] = pk_uuid()
    delivery_id: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    webhook_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("github_webhooks.id", ondelete="SET NULL")
    )
    repository_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("github_repositories.id", ondelete="SET NULL")
    )
    event: Mapped[str] = mapped_column(String(60), nullable=False)
    signature_verified: Mapped[bool] = mapped_column(Boolean, nullable=False)
    received_at: Mapped[datetime] = created_at()
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    processing_status: Mapped[str] = mapped_column(String(20), nullable=False, default="received")
    replay_detected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    webhook: Mapped[GithubWebhook | None] = relationship(back_populates="deliveries")


class GithubSyncHistory(Base):
    __tablename__ = "github_sync_history"
    __table_args__ = (Index("ix_github_sync_history_installation", "installation_id"),)

    id: Mapped[uuid.UUID] = pk_uuid()
    installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("github_installations.id", ondelete="CASCADE"), index=True
    )
    sync_type: Mapped[str] = mapped_column(String(20), nullable=False, default="incremental")
    repositories_added: Mapped[int] = mapped_column(Integer, default=0)
    repositories_updated: Mapped[int] = mapped_column(Integer, default=0)
    repositories_removed: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at()

    installation: Mapped[GithubInstallation] = relationship(back_populates="sync_history")


class GithubOAuthState(Base):
    """The PKCE verifier, server-side. Keyed by a random `sid` that is itself
    embedded (signed, timestamped) inside the `state` param sent to GitHub -
    see `app.connectors.github.security`. Rows are single-use and pruned by
    `expires_at`, ten minutes after creation."""
    __tablename__ = "github_oauth_states"

    sid: Mapped[str] = mapped_column(String(64), primary_key=True)
    code_verifier_encrypted: Mapped[str] = mapped_column(EncryptedString, nullable=False)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = created_at()
