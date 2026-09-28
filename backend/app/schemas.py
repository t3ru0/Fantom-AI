"""Request and response shapes.

The important one is BusinessContextIn. Every field is optional so a user can
save progress, but `context_complete` only flips true when all five are present
— and nothing is priced until it does.
"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
KNOWN_REGIMES = ("DPDP", "GDPR", "PCI", "HIPAA", "RBI", "SOC2", "NONE")


# ---------------------------------------------------------------- projects --
class ProjectCreate(BaseModel):
    repo: str = Field(..., examples=["apex-fintech/paykit-api"],
                      description="owner/name — GitHub is the only supported source")
    branch: str = Field("main", max_length=200)
    installation_id: int | None = None

    @field_validator("repo")
    @classmethod
    def _repo_shape(cls, v: str) -> str:
        v = v.strip()
        if v.startswith(("http://", "https://")):
            raise ValueError(
                "give it as owner/repo, not a URL — we will not guess which part you meant"
            )
        if not REPO_RE.match(v):
            raise ValueError("must be owner/repo, e.g. apex-fintech/paykit-api")
        return v


class BusinessContextIn(BaseModel):
    """The five things no algorithm can derive, plus one that has a real default."""
    revenue_supported: float | None = Field(
        None, ge=0, description="Annual revenue this project supports, in USD")
    downtime_cost_hour: float | None = Field(
        None, ge=0, description="Cost of one hour of this project being down, in USD")
    users_count: int | None = Field(None, ge=0)
    records_count: int | None = Field(
        None, ge=0, description="Personal or regulated records this project can reach")
    regimes: list[str] | None = Field(
        None, description=f"Any of {', '.join(KNOWN_REGIMES)}")
    eng_rate_hour: float | None = Field(
        None, gt=0, description="Fully loaded engineer cost per hour. Defaults to 120 USD.")

    @field_validator("regimes")
    @classmethod
    def _known(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        bad = [r for r in v if not any(r.upper().startswith(k) for k in KNOWN_REGIMES)]
        if bad:
            raise ValueError(f"unknown regime(s): {', '.join(bad)}. "
                             f"Supported: {', '.join(KNOWN_REGIMES)}")
        return [r.upper() for r in v]


class ContextStatus(BaseModel):
    complete: bool
    missing: list[str]
    supplied: dict[str, object]
    why_it_matters: dict[str, str]
    effect: str


class ProjectOut(BaseModel):
    id: str
    repo: str
    branch: str
    state: str
    context_complete: bool
    missing_context: list[str]
    complexity_score: int | None = None
    complexity_tier: str | None = None
    findings_open: int = 0
    exposure: float | None = None          # null, never 0, when unpriced


# ---------------------------------------------------------------- pricing ---
class FindingIn(BaseModel):
    """Enough of a finding to price it, for the stateless preview endpoint."""
    scanner: Literal["osv", "gitleaks", "semgrep", "trivy", "checkov"] = "osv"
    title: str = "finding"
    cve: str | None = None
    cwe: str | None = None
    rule_id: str | None = None
    cvss: float | None = Field(None, ge=0, le=10)
    package: str | None = None
    version: str | None = None
    fixed_version: str | None = None
    file: str | None = None
    line: int | None = None
    direct: bool = True
    epss: float | None = Field(None, ge=0, le=1)
    kev: bool = False


class PricePreviewIn(BaseModel):
    context: BusinessContextIn
    finding: FindingIn


class ComponentOut(BaseModel):
    name: str
    amount: float
    basis: str


class EffortOut(BaseModel):
    build_hours: float
    loaded_hours: float
    cost: float
    change_risk: str
    basis: str
    sprint_share: float


class PriceOut(BaseModel):
    priced: bool
    context_missing: list[str] = []
    context_score: int | None = None
    tier: str | None = None
    sla: str | None = None
    if_it_happens: float | None = None
    annual_loss_upper_bound: float | None = None
    loss_per_hour: float | None = None
    p_wild_year: float | None = None
    p_here_year: float | None = None       # stays null until Parts 4-5
    components: list[ComponentOut] = []
    effort: EffortOut | None = None
    assumptions: list[str] = []
    note: str = ""
