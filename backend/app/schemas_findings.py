"""Request/response shapes for the findings, risk, analytics, reports, and
notifications APIs — everything added on top of the Part 0-3 pricing schemas
in app/schemas.py."""
from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel


class FindingListItem(BaseModel):
    id: str
    project_id: str
    repo: str
    scanner: str
    title: str
    cve: str | None
    cwe: str | None
    package: str | None
    file: str | None
    cvss: float | None
    epss: float | None
    kev: bool
    context_score: int | None
    tier: str | None
    state: str
    annual_loss: float | None
    first_seen_at: datetime
    last_seen_at: datetime


class FindingListOut(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[FindingListItem]


class FindingDetailOut(BaseModel):
    id: str
    project_id: str
    repo: str
    fingerprint: str
    scanner: str
    agent_slug: str
    title: str
    cve: str | None
    cwe: str | None
    rule_id: str | None
    file: str | None
    line: int | None
    package: str | None
    version: str | None
    fixed_version: str | None
    cvss: float | None
    epss: float | None
    kev: bool
    exploit_maturity: str | None
    context_score: int | None
    tier: str | None
    state: str
    annual_loss: float | None
    fix_hours: float | None
    fix_cost: float | None
    loss_per_hour: float | None
    remediation: dict | None
    first_seen_run: str | None
    last_seen_run: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    owner: str | None
    note: str | None


class FindingStateUpdate(BaseModel):
    state: str
    note: str | None = None
    owner: str | None = None


# -------------------------------------------------------------------- risk --
class RiskFactorOut(BaseModel):
    name: str
    score: float
    weight_note: str


class OrgRiskOut(BaseModel):
    org_risk_score: float | None
    findings_open: int
    findings_critical: int
    total_exposure: float | None
    projects: list[dict]


class ProjectRiskOut(BaseModel):
    project_id: str
    context_score_avg: float | None
    context_score_max: int | None
    tier_distribution: dict[str, int]
    findings_open: int
    findings_critical: int
    exposure: float | None
    trend: list[dict]


# --------------------------------------------------------------- analytics --
class TimeseriesPoint(BaseModel):
    day: date
    value: float


class AnalyticsOut(BaseModel):
    findings_over_time: list[TimeseriesPoint]
    exposure_over_time: list[TimeseriesPoint]
    mttr_days: float | None
    sla_compliance_pct: float | None
    scanner_breakdown: dict[str, int]
    epss_distribution: dict[str, int]
    kev_count: int
    repo_comparison: list[dict]


# ------------------------------------------------------------------ reports --
class ReportCreate(BaseModel):
    kind: str
    project_id: str | None = None


class ReportOut(BaseModel):
    id: str
    org_id: str
    project_id: str | None
    kind: str
    status: str
    created_at: datetime
    finished_at: datetime | None


# ------------------------------------------------------------ notifications --
class NotificationOut(BaseModel):
    id: str
    kind: str
    title: str
    body: str | None
    read_at: datetime | None
    created_at: datetime


class NotificationChannelCreate(BaseModel):
    kind: str
    target: str


class NotificationChannelOut(BaseModel):
    id: str
    kind: str
    target: str
    enabled: bool
    created_at: datetime
