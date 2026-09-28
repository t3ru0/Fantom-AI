"""The full schema.

Design rules enforced here:
  * Money is nullable everywhere. A project without business context stores NULL
    exposure, never a guessed number.  (see projects.context_complete)
  * Findings are keyed by a stable fingerprint, not by line number, so "age"
    survives refactors and reformatting.
  * Agents are rows. They are created, they go dormant, they are never deleted.
  * Every run writes an append-only event stream, which is what the live floor
    replays over SSE.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, created_at, pk_uuid, updated_at

# --------------------------------------------------------------------------
# Controlled vocabularies. Text + CheckConstraint rather than PG enums, because
# adding a value to a PG enum inside a migration is needlessly painful.
# --------------------------------------------------------------------------
SOURCES = ("github",)                       # GitHub only, deliberately
PROJECT_STATES = ("watching", "paused", "disconnected", "error")
RUN_TRIGGERS = ("push", "heartbeat", "world", "manual", "initial")
RUN_STATES = ("queued", "running", "done", "failed", "cancelled")
AGENT_KINDS = ("fixed", "specialist")
AGENT_STATES = ("idle", "working", "dormant")
FINDING_STATES = ("open", "fixed", "accepted", "false_positive")
TIERS = ("Simple", "Moderate", "Complex", "Heavy")
MEMBERSHIP_ROLES = ("owner", "admin", "security_lead", "developer", "viewer")
NOTIFICATION_CHANNEL_KINDS = ("email", "slack", "discord", "teams", "webhook")
REPORT_KINDS = ("executive", "technical", "compliance", "repository")
REPORT_STATES = ("queued", "running", "done", "failed")


def one_of(column: str, values: tuple[str, ...]) -> str:
    """SQL IN-list that is correct for a single-element tuple and quotes the
    column, so names that collide with SQL keywords (``trigger``) are safe."""
    joined = ", ".join(f"'{v}'" for v in values)
    return f"`{column}` IN ({joined})"


class Org(Base):
    __tablename__ = "orgs"
    id: Mapped[uuid.UUID] = pk_uuid()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    gh_installation_id: Mapped[int | None] = mapped_column(BigInteger, index=True)
    gh_account_login: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = created_at()

    projects: Mapped[list["Project"]] = relationship(back_populates="org")
    memberships: Mapped[list["Membership"]] = relationship(back_populates="org", cascade="all, delete-orphan")


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint(one_of("source", SOURCES), name="source_valid"),
        CheckConstraint(one_of("state", PROJECT_STATES), name="state_valid"),
        UniqueConstraint("org_id", "gh_repo_id", name="uq_projects_org_repo"),
        Index("ix_projects_state", "state"),
    )
    id: Mapped[uuid.UUID] = pk_uuid()
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="github")
    origin: Mapped[str] = mapped_column(Text, nullable=False)        # owner/repo
    branch: Mapped[str] = mapped_column(String(200), default="main")
    gh_repo_id: Mapped[int | None] = mapped_column(BigInteger, index=True)
    gh_installation_id: Mapped[int | None] = mapped_column(BigInteger)
    is_private: Mapped[bool] = mapped_column(Boolean, default=True)
    default_branch: Mapped[str | None] = mapped_column(String(200))

    # ---- business context: the five things only a human can supply ---------
    revenue_supported: Mapped[float | None] = mapped_column(Numeric(16, 2))
    downtime_cost_hour: Mapped[float | None] = mapped_column(Numeric(14, 2))
    users_count: Mapped[int | None] = mapped_column(Integer)
    records_count: Mapped[int | None] = mapped_column(Integer)
    regimes: Mapped[list[str] | None] = mapped_column(JSON)
    eng_rate_hour: Mapped[float | None] = mapped_column(Numeric(10, 2))
    # Gate. While false the API refuses to emit a single money figure.
    context_complete: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # ---- survey output (Part 4) -------------------------------------------
    complexity_score: Mapped[int | None] = mapped_column(Integer)
    complexity_tier: Mapped[str | None] = mapped_column(String(20))
    crew_cap: Mapped[int | None] = mapped_column(Integer)
    signals: Mapped[dict | None] = mapped_column(JSON)
    languages: Mapped[list[str] | None] = mapped_column(JSON)
    dep_count: Mapped[int | None] = mapped_column(Integer)
    loc_count: Mapped[int | None] = mapped_column(Integer)

    state: Mapped[str] = mapped_column(String(20), default="watching", nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    org: Mapped[Org] = relationship(back_populates="projects")
    agents: Mapped[list["Agent"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    runs: Mapped[list["Run"]] = relationship(back_populates="project", cascade="all, delete-orphan")

    @property
    def missing_context(self) -> list[str]:
        need = {
            "revenue_supported": self.revenue_supported,
            "downtime_cost_hour": self.downtime_cost_hour,
            "users_count": self.users_count,
            "records_count": self.records_count,
            "regimes": self.regimes,
        }
        return [k for k, v in need.items() if v in (None, [], "")]


class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (
        UniqueConstraint("project_id", "slug", name="uq_agents_project_slug"),
        CheckConstraint(one_of("kind", AGENT_KINDS), name="kind_valid"),
        CheckConstraint(one_of("state", AGENT_STATES), name="state_valid"),
    )
    id: Mapped[uuid.UUID] = pk_uuid()
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)

    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    slug: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    wave: Mapped[int] = mapped_column(Integer, default=1)
    needs: Mapped[list[str]] = mapped_column(JSON, default=list)
    trigger_reason: Mapped[str | None] = mapped_column(Text)

    state: Mapped[str] = mapped_column(String(20), default="idle", nullable=False)
    runs_count: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    idle_runs: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = created_at()
    dormant_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(back_populates="agents")


class Run(Base):
    __tablename__ = "runs"
    __table_args__ = (
        CheckConstraint(one_of("trigger", RUN_TRIGGERS), name="trigger_valid"),
        CheckConstraint(one_of("state", RUN_STATES), name="state_valid"),
        Index("ix_runs_project_started", "project_id", "started_at"),
    )
    id: Mapped[uuid.UUID] = pk_uuid()
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)

    trigger: Mapped[str] = mapped_column(String(20), nullable=False)
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    commit_message: Mapped[str | None] = mapped_column(Text)
    pusher: Mapped[str | None] = mapped_column(String(200))
    changed_files: Mapped[list[str] | None] = mapped_column(JSON)
    full_sweep: Mapped[bool] = mapped_column(Boolean, default=False)

    # Populated for a connector-triggered run (see app.connectors.github.webhooks);
    # left NULL for a manual/legacy-GitHub-App run, exactly as before.
    branch: Mapped[str | None] = mapped_column(String(200))
    delivery_id: Mapped[str | None] = mapped_column(String(80))
    github_event_type: Mapped[str | None] = mapped_column(String(60))

    state: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    agents_woken: Mapped[list[str] | None] = mapped_column(JSON)

    findings_new: Mapped[int] = mapped_column(Integer, default=0)
    findings_closed: Mapped[int] = mapped_column(Integer, default=0)
    exposure_before: Mapped[float | None] = mapped_column(Numeric(16, 2))
    exposure_after: Mapped[float | None] = mapped_column(Numeric(16, 2))

    llm_cost_usd: Mapped[float] = mapped_column(Numeric(10, 6), default=0)
    scanner_seconds: Mapped[float] = mapped_column(Numeric(10, 2), default=0)

    queued_at: Mapped[datetime] = created_at()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(back_populates="runs")
    events: Mapped[list["RunEvent"]] = relationship(back_populates="run", cascade="all, delete-orphan")


class RunEvent(Base):
    """Append-only. This is exactly what the pixel floor replays."""
    __tablename__ = "run_events"
    __table_args__ = (Index("ix_run_events_run_seq", "run_id", "seq"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    agent_slug: Mapped[str | None] = mapped_column(String(40))
    event: Mapped[str] = mapped_column(String(30), nullable=False)   # woke|working|found|idle|hired|rested|wave|error
    message: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict | None] = mapped_column(JSON)

    run: Mapped[Run] = relationship(back_populates="events")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint", name="uq_findings_project_fingerprint"),
        CheckConstraint(one_of("state", FINDING_STATES), name="state_valid"),
        Index("ix_findings_project_state", "project_id", "state"),
        Index("ix_findings_score", "project_id", "context_score"),
    )
    id: Mapped[uuid.UUID] = pk_uuid()
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)

    # Stable across refactors: built from rule/package/symbol, never line number.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_slug: Mapped[str] = mapped_column(String(40), nullable=False)
    scanner: Mapped[str] = mapped_column(String(40), nullable=False)   # osv|semgrep|gitleaks|trivy|checkov

    title: Mapped[str] = mapped_column(Text, nullable=False)
    cve: Mapped[str | None] = mapped_column(String(40), index=True)
    cwe: Mapped[str | None] = mapped_column(String(40))
    rule_id: Mapped[str | None] = mapped_column(String(200))
    file: Mapped[str | None] = mapped_column(Text)
    line: Mapped[int | None] = mapped_column(Integer)
    package: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(String(80))
    fixed_version: Mapped[str | None] = mapped_column(String(80))

    # ---- enrichment (free public feeds) -----------------------------------
    cvss: Mapped[float | None] = mapped_column(Numeric(4, 2))
    epss: Mapped[float | None] = mapped_column(Numeric(6, 5))
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_maturity: Mapped[str | None] = mapped_column(String(80))

    # ---- our analysis ------------------------------------------------------
    reachable: Mapped[bool | None] = mapped_column(Boolean)
    reachability_conf: Mapped[float | None] = mapped_column(Numeric(4, 3))
    reachability_evidence: Mapped[str | None] = mapped_column(Text)
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    blast: Mapped[list[str] | None] = mapped_column(JSON)
    context_score: Mapped[int | None] = mapped_column(Integer)
    p_exploit: Mapped[float | None] = mapped_column(Numeric(6, 5))

    # ---- money: all nullable, all gated on project.context_complete --------
    impact_breakdown: Mapped[dict | None] = mapped_column(JSON)
    annual_loss: Mapped[float | None] = mapped_column(Numeric(16, 2))
    fix_hours: Mapped[float | None] = mapped_column(Numeric(8, 2))
    fix_cost: Mapped[float | None] = mapped_column(Numeric(14, 2))
    loss_per_hour: Mapped[float | None] = mapped_column(Numeric(14, 2))

    remediation: Mapped[dict | None] = mapped_column(JSON)

    introduced_commit: Mapped[str | None] = mapped_column(String(64))
    introduced_by: Mapped[str | None] = mapped_column(String(200))
    introduced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    first_seen_run: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    last_seen_run: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    first_seen_at: Mapped[datetime] = created_at()
    last_seen_at: Mapped[datetime] = updated_at()

    state: Mapped[str] = mapped_column(String(20), default="open", nullable=False)
    owner: Mapped[str | None] = mapped_column(String(200))
    note: Mapped[str | None] = mapped_column(Text)


class ExposureHistory(Base):
    """One row per project per day. The 90-day line is read from here, not recomputed."""
    __tablename__ = "exposure_history"
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True
    )
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    exposure: Mapped[float | None] = mapped_column(Numeric(16, 2))
    findings_open: Mapped[int] = mapped_column(Integer, default=0)
    findings_critical: Mapped[int] = mapped_column(Integer, default=0)


class AuditLog(Base):
    """Every model run, treatment decision and AI answer, with the state it saw."""
    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_org_ts", "org_id", "ts"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    org_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    project_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    actor: Mapped[str] = mapped_column(String(200), default="system")
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    state_hash: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict | None] = mapped_column(JSON)


# ==========================================================================
# Auth, tenancy, notifications, reports — added on top of the Part 0-3 schema
# above. Same conventions: pk_uuid(), one_of() CheckConstraints, nullable
# money/FKs where a row can legitimately predate the thing it would point to.
# ==========================================================================
class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = pk_uuid()
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = created_at()

    memberships: Mapped[list["Membership"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Membership(Base):
    """The tenancy join. Every org-scoped request resolves through this table."""
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "org_id", name="uq_memberships_user_org"),
        CheckConstraint(one_of("role", MEMBERSHIP_ROLES), name="role_valid"),
    )
    id: Mapped[uuid.UUID] = pk_uuid()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = created_at()

    user: Mapped[User] = relationship(back_populates="memberships")
    org: Mapped[Org] = relationship(back_populates="memberships")


class Invitation(Base):
    __tablename__ = "invitations"
    __table_args__ = (CheckConstraint(one_of("role", MEMBERSHIP_ROLES), name="role_valid"),)
    id: Mapped[uuid.UUID] = pk_uuid()
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    invited_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = created_at()


class Team(Base):
    __tablename__ = "teams"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_teams_org_name"),)
    id: Mapped[uuid.UUID] = pk_uuid()
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = created_at()


class TeamMembership(Base):
    __tablename__ = "team_memberships"
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)


class Notification(Base):
    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notifications_org_user", "org_id", "user_id"),)
    id: Mapped[uuid.UUID] = pk_uuid()
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(60), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    body: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict | None] = mapped_column(JSON)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at()


class NotificationChannel(Base):
    __tablename__ = "notification_channels"
    __table_args__ = (CheckConstraint(one_of("kind", NOTIFICATION_CHANNEL_KINDS), name="kind_valid"),)
    id: Mapped[uuid.UUID] = pk_uuid()
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)     # email address or webhook URL
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = created_at()


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint(one_of("kind", REPORT_KINDS), name="kind_valid"),
        CheckConstraint(one_of("status", REPORT_STATES), name="status_valid"),
        Index("ix_reports_org_created", "org_id", "created_at"),
    )
    id: Mapped[uuid.UUID] = pk_uuid()
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    file_path: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = created_at()
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[uuid.UUID] = pk_uuid()
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at()


class RevokedToken(Base):
    """JTI blacklist for logout. Rows are pruned once expires_at is in the past."""
    __tablename__ = "revoked_tokens"
    jti: Mapped[str] = mapped_column(String(32), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
