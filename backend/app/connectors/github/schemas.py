"""Pydantic v2 I/O shapes for the GitHub connector API."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AuthorizeOut(BaseModel):
    authorize_url: str


class GitHubUserOut(BaseModel):
    id: int
    login: str
    name: str | None = None
    avatar_url: str | None = None


class ConnectorStatusOut(BaseModel):
    connected: bool
    status: str | None = None
    account_login: str | None = None
    account_type: str | None = None
    scopes: list[str] = Field(default_factory=list)
    token_expires_at: datetime | None = None
    last_sync_at: datetime | None = None
    repository_count: int = 0
    monitored_repository_count: int = 0


class HealthOut(BaseModel):
    status: str
    token_valid: bool
    webhook_valid: bool | None
    last_sync_at: datetime | None
    last_sync_duration_ms: int | None
    repository_count: int
    monitored_repository_count: int
    detail: str | None = None


class RepositoryOut(BaseModel):
    id: str
    github_repo_id: int
    full_name: str
    owner_login: str
    name: str
    private: bool
    archived: bool
    default_branch: str | None
    language: str | None
    topics: list[str] = Field(default_factory=list)
    license: str | None
    stars: int
    forks: int
    open_issues: int
    has_security_policy: bool
    has_dependabot: bool
    permissions: dict[str, bool]
    monitoring_status: str
    monitoring_reason: str | None
    project_id: str | None
    last_synced_at: datetime | None


class BranchOut(BaseModel):
    name: str
    sha: str
    protected: bool


class RepositorySelectIn(BaseModel):
    repository_ids: list[str] = Field(..., min_length=1)


class RepositorySelectResultOut(BaseModel):
    selected: list[RepositoryOut]
    skipped: dict[str, str] = Field(default_factory=dict)   # repository_id -> reason


class SyncHistoryOut(BaseModel):
    id: str
    sync_type: str
    repositories_added: int
    repositories_updated: int
    repositories_removed: int
    duration_ms: int
    success: bool
    error_message: str | None
    created_at: datetime


class SyncTriggerOut(BaseModel):
    accepted: bool
    detail: str


class ScanTriggerOut(BaseModel):
    run_id: str
    state: str


class WebhookResyncOut(BaseModel):
    repaired: bool
    webhook_id: int | None
    detail: str
