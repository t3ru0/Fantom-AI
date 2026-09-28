"""Turning findings into money.

Rule zero, enforced by `BusinessContext.complete`: if the five business inputs
are not present, this module returns **None**. Not a default, not a sector
median, not an estimate — None. A finding without business context still ranks
perfectly by contextual score; it simply is not priced. Inventing a revenue
figure so the dashboard has something to show is the exact failure this product
exists to avoid.

Everything below is ordinary arithmetic. No model output ever becomes a figure.
Every coefficient that is a judgement call is listed in ASSUMPTIONS and is
surfaced to the user, because a number a CFO signs has to be one you can defend
line by line.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.config import settings
from app.scanners.base import RawFinding
from app.services.scoring import ScoreResult

# ===========================================================================
# Assumptions. Every one of these is a judgement, not a measurement, and the
# API returns this list alongside any priced figure.
# ===========================================================================
ASSUMPTIONS: dict[str, str] = {
    "incident_multiplier": (
        "Work done under incident conditions costs 3.2x the same work planned. "
        "Derived from the ratio of out-of-hours to planned engineering rates."
    ),
    "regulatory_per_record": (
        "Penalty per exposed record is a policy estimate per regime, capped. "
        "Actual enforcement varies enormously and settles below the statutory maximum."
    ),
    "churn_response": (
        "Customer loss after a disclosed breach is modelled as a fraction of "
        "users, scaled by how much regulated data the finding exposes."
    ),
    "brand_recovery": (
        "Brand and communications spend is modelled at 18% of churn plus penalty."
    ),
    "aggregation": (
        "Portfolio exposure aggregates rather than sums. Findings that reach the "
        "same records share one pool, so the worst single breach is taken instead "
        "of the total, and the result is capped at the revenue the project supports."
    ),
    "downtime_hours": (
        "Hours of outage per exploited finding is scaled from the contextual "
        "score, not measured. An availability finding on a tier-1 service is the "
        "case where this is most likely to be understated."
    ),
}

# ---------------------------------------------------------------------------
# Regulatory regimes. per_record is in USD; cap_usd is an absolute ceiling, and
# cap_revenue_pct (when set) caps against the project's own revenue instead.
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Regime:
    code: str
    name: str
    per_record: float
    cap_usd: float | None = None
    cap_revenue_pct: float | None = None


REGIMES: dict[str, Regime] = {
    "DPDP":   Regime("DPDP", "Digital Personal Data Protection Act 2023 (India)", 18.0, 30_000_000),
    "GDPR":   Regime("GDPR", "General Data Protection Regulation (EU)", 22.0, 24_000_000, 0.04),
    "PCI":    Regime("PCI", "PCI DSS 4.0", 12.0, 500_000),
    "HIPAA":  Regime("HIPAA", "HIPAA (US health data)", 45.0, 1_900_000),
    "RBI":    Regime("RBI", "RBI Cyber Security Framework (India)", 14.0, 12_000_000),
    "SOC2":   Regime("SOC2", "SOC 2 (contractual, not statutory)", 4.0, 250_000),
    "NONE":   Regime("NONE", "No regulated data in scope", 0.0, 0.0),
}


def resolve_regimes(codes: list[str] | None) -> list[Regime]:
    out = []
    for c in codes or []:
        key = re.sub(r"[^A-Z]", "", (c or "").upper())
        for k, r in REGIMES.items():
            if key.startswith(k):
                out.append(r)
                break
    return out or [REGIMES["NONE"]]


# ===========================================================================
# Business context — the five things only a human can supply.
# ===========================================================================
@dataclass(slots=True)
class BusinessContext:
    revenue_supported: float | None = None
    downtime_cost_hour: float | None = None
    users_count: int | None = None
    records_count: int | None = None
    regimes: list[str] | None = None
    eng_rate_hour: float | None = None            # optional; has a real default

    REQUIRED = ("revenue_supported", "downtime_cost_hour", "users_count",
                "records_count", "regimes")

    @property
    def missing(self) -> list[str]:
        out = []
        for f in self.REQUIRED:
            v = getattr(self, f)
            if v is None or v == "" or v == []:
                out.append(f)
        return out

    @property
    def complete(self) -> bool:
        return not self.missing

    @property
    def rate(self) -> float:
        return float(self.eng_rate_hour or settings.default_eng_rate_hour)


# ===========================================================================
# What a finding actually does when it is exploited.
# Derived from CWE where one exists, then from the rule id, then the scanner.
# ===========================================================================
@dataclass(frozen=True, slots=True)
class ImpactProfile:
    confidentiality: float        # 0-1, share of held records plausibly exposed
    integrity: float              # 0-1, ability to alter data or behaviour
    availability: float           # 0-1, ability to stop the service
    basis: str


CWE_PROFILE: dict[str, tuple[float, float, float]] = {
    # confidentiality, integrity, availability
    "CWE-89":  (0.85, 0.80, 0.20),   # SQL injection
    "CWE-95":  (0.90, 0.95, 0.70),   # code injection / eval
    "CWE-94":  (0.90, 0.95, 0.70),
    "CWE-78":  (0.85, 0.90, 0.70),   # OS command injection
    "CWE-502": (0.85, 0.90, 0.60),   # unsafe deserialisation
    "CWE-287": (0.80, 0.75, 0.15),   # improper authentication
    "CWE-798": (0.85, 0.80, 0.25),   # hardcoded credential
    "CWE-522": (0.75, 0.60, 0.10),
    "CWE-269": (0.70, 0.80, 0.35),   # privilege management
    "CWE-79":  (0.35, 0.45, 0.05),   # XSS
    "CWE-352": (0.10, 0.55, 0.05),   # CSRF
    "CWE-918": (0.55, 0.30, 0.15),   # SSRF
    "CWE-22":  (0.55, 0.25, 0.10),   # path traversal
    "CWE-400": (0.02, 0.05, 0.90),   # resource exhaustion / DoS
    "CWE-770": (0.02, 0.05, 0.85),
    "CWE-327": (0.45, 0.35, 0.05),   # broken crypto
    "CWE-295": (0.60, 0.55, 0.05),   # cert validation
    "CWE-1321": (0.40, 0.70, 0.35),  # prototype pollution
    "CWE-532": (0.55, 0.05, 0.02),   # sensitive data in logs
    "CWE-359": (0.70, 0.05, 0.02),   # PII exposure
    "CWE-338": (0.30, 0.45, 0.02),   # weak randomness
    "CWE-377": (0.20, 0.30, 0.10),
    "CWE-489": (0.50, 0.30, 0.10),   # debug enabled
    "CWE-617": (0.25, 0.45, 0.20),
    "CWE-732": (0.60, 0.35, 0.05),   # permissions
    "CWE-829": (0.55, 0.70, 0.20),   # untrusted dependency
    "CWE-693": (0.20, 0.20, 0.02),   # missing hardening
}
SECRET_PROFILE: dict[str, tuple[float, float, float]] = {
    "private-key":      (0.95, 0.90, 0.45),
    "aws-access-key":   (0.90, 0.85, 0.55),
    "db-uri-password":  (0.95, 0.85, 0.40),
    "github-pat":       (0.70, 0.85, 0.30),
    "github-fine-grained": (0.65, 0.80, 0.28),
    "stripe-live":      (0.55, 0.85, 0.15),
    "openai-key":       (0.15, 0.25, 0.05),
    "anthropic-key":    (0.15, 0.25, 0.05),
    "slack-token":      (0.45, 0.40, 0.10),
    "entropy-assignment": (0.40, 0.35, 0.12),
}
DEFAULT_PROFILE = (0.40, 0.35, 0.15)


def impact_profile(f: RawFinding) -> ImpactProfile:
    if f.scanner == "gitleaks" and f.rule_id in SECRET_PROFILE:
        c, i, a = SECRET_PROFILE[f.rule_id]
        return ImpactProfile(c, i, a, f"credential type {f.rule_id}")
    cwe = (f.cwe or "").upper().strip()
    if cwe in CWE_PROFILE:
        c, i, a = CWE_PROFILE[cwe]
        return ImpactProfile(c, i, a, f"weakness class {cwe}")
    c, i, a = DEFAULT_PROFILE
    return ImpactProfile(c, i, a, "no weakness class recorded — generic profile used")


# ===========================================================================
# Remediation effort. Derived, not typed in.
# ===========================================================================
SEMVER = re.compile(r"^\D*(\d+)(?:\.(\d+))?(?:\.(\d+))?")

CODE_RULE_HOURS: dict[str, float] = {
    "py.sql-injection": 8, "py.dynamic-exec": 12, "py.unsafe-deserialize": 16,
    "py.shell-injection": 8, "py.yaml-unsafe-load": 2, "py.weak-hash": 4,
    "py.tls-verify-disabled": 2, "py.insecure-temp": 2, "py.weak-random": 3,
    "py.assert-auth": 3, "py.debug-enabled": 1,
    "js.eval": 10, "js.new-function": 8, "js.child-process-interpolated": 8,
    "js.innerhtml": 5, "js.dangerously-set-html": 5, "js.jwt-none": 3,
    "js.sql-template": 8, "js.tls-disabled": 2, "js.math-random-token": 3,
    "go.sql-sprintf": 8, "go.command-injection": 8, "go.tls-skip-verify": 2,
    "go.weak-hash": 4,
}
SECRET_HOURS: dict[str, float] = {
    "private-key": 14, "aws-access-key": 10, "db-uri-password": 10,
    "github-pat": 6, "github-fine-grained": 6, "stripe-live": 8,
    "slack-token": 4, "openai-key": 3, "anthropic-key": 3, "npm-token": 5,
    "jwt": 3, "entropy-assignment": 3,
}


def _semver_jump(current: str | None, target: str | None) -> tuple[str, float]:
    """How far the upgrade is. A major bump is where the effort actually lives."""
    if not current or not target:
        return "unknown", 6.0
    a, b = SEMVER.match(current), SEMVER.match(target)
    if not a or not b:
        return "unknown", 6.0
    amaj, amin = int(a.group(1) or 0), int(a.group(2) or 0)
    bmaj, bmin = int(b.group(1) or 0), int(b.group(2) or 0)
    if bmaj > amaj:
        return "major", 12.0 + 4.0 * (bmaj - amaj - 1)
    if bmin > amin:
        return "minor", 4.0
    return "patch", 1.0


@dataclass(slots=True)
class Effort:
    build_hours: float
    loaded_hours: float
    cost: float
    change_risk: str
    basis: str

    @property
    def sprint_share(self) -> float:
        return self.loaded_hours / settings.sprint_hours


def estimate_effort(f: RawFinding, ctx: BusinessContext) -> Effort:
    """Build hours, then the overhead every real change carries."""
    if f.scanner == "osv":
        if not f.fixed_version:
            build, risk = 24.0, "High"
            basis = "no patched release exists — the dependency has to be replaced"
        else:
            kind, build = _semver_jump(f.version, f.fixed_version)
            risk = {"major": "High", "minor": "Medium", "patch": "Low",
                    "unknown": "Medium"}[kind]
            basis = f"{kind} version bump, {f.version} to {f.fixed_version}"
        if not f.extra.get("direct", True):
            build += 2.0
            basis += "; transitive, so the parent must be bumped too"
    elif f.scanner == "gitleaks":
        build = SECRET_HOURS.get(f.rule_id or "", 5.0)
        risk = "High" if build >= 10 else "Medium"
        basis = "revoke, rotate everything it reached, then purge from history"
        if f.extra.get("example_file"):
            build, risk = build * 0.4, "Low"
            basis = "appears to be an example file — confirm before rotating"
    else:
        build = CODE_RULE_HOURS.get(f.rule_id or "", 5.0)
        risk = "High" if build >= 10 else "Medium" if build >= 5 else "Low"
        basis = f"rule {f.rule_id} baseline"

    loaded = (build * (1 + settings.oh_review_multiple)
              + settings.oh_ship_hours + settings.oh_coord_hours)
    mult = {"High": 1.9, "Medium": 1.4, "Low": 1.05}[risk]
    return Effort(round(build, 1), round(loaded, 1),
                  round(loaded * ctx.rate * mult, 2), risk, basis)


# ===========================================================================
# The loss model.
# ===========================================================================
@dataclass(slots=True)
class LossComponent:
    name: str
    amount: float
    basis: str


@dataclass(slots=True)
class Money:
    if_it_happens: float
    components: list[LossComponent] = field(default_factory=list)
    effort: Effort | None = None
    p_wild_year: float | None = None
    annual_loss: float | None = None       # None while p_here is unknown
    loss_per_hour: float | None = None
    assumptions: list[str] = field(default_factory=list)
    note: str = ""


# Hours of outage by contextual tier, for the availability share of a finding.
DOWNTIME_BY_TIER = {4: 12.0, 3: 6.0, 2: 2.0, 1: 0.5}
CHURN_BY_TIER = {4: 0.030, 3: 0.015, 2: 0.006, 1: 0.002}


def regulatory_penalty(records_exposed: float, ctx: BusinessContext) -> tuple[float, str]:
    regimes = resolve_regimes(ctx.regimes)
    best, why = 0.0, "no regulated data in scope"
    for r in regimes:
        if r.per_record <= 0:
            continue
        raw = records_exposed * r.per_record
        cap = r.cap_usd if r.cap_usd is not None else float("inf")
        if r.cap_revenue_pct and ctx.revenue_supported:
            cap = min(cap, ctx.revenue_supported * r.cap_revenue_pct)
        amount = min(raw, cap)
        if amount > best:
            best = amount
            why = (f"{r.name}: {records_exposed:,.0f} records at ${r.per_record:.0f} "
                   f"each{', capped' if raw > cap else ''}")
    return best, why


def price(f: RawFinding, s: ScoreResult, ctx: BusinessContext) -> Money | None:
    """Returns None when business context is incomplete. That is the whole point."""
    if not ctx.complete:
        return None

    prof = impact_profile(f)
    tier = s.tier

    # --- what it costs if it happens -------------------------------------
    comps: list[LossComponent] = []

    down_h = DOWNTIME_BY_TIER[tier] * prof.availability
    if down_h > 0.01:
        amt = down_h * float(ctx.downtime_cost_hour or 0)
        comps.append(LossComponent(
            "Business interruption", amt,
            f"{down_h:.1f} h of outage at ${float(ctx.downtime_cost_hour or 0):,.0f}/h"))

    records_exposed = prof.confidentiality * float(ctx.records_count or 0)
    reg, reg_why = regulatory_penalty(records_exposed, ctx)
    if reg > 0:
        comps.append(LossComponent("Regulatory penalty", reg, reg_why))

    churn_rate = CHURN_BY_TIER[tier] * prof.confidentiality
    churn = churn_rate * float(ctx.revenue_supported or 0)
    if churn > 0:
        comps.append(LossComponent(
            "Customer churn", churn,
            f"{churn_rate:.2%} of ${float(ctx.revenue_supported or 0):,.0f} supported revenue"))

    ir = 18_000 + 9_000 * (prof.confidentiality + prof.integrity)
    comps.append(LossComponent("Incident response", ir,
                               "retainer call-off plus forensics, scaled by data involvement"))

    effort = estimate_effort(f, ctx)
    emergency = effort.build_hours * 3.2 * ctx.rate
    comps.append(LossComponent(
        "Emergency engineering", emergency,
        f"{effort.build_hours:.0f} h of planned work becomes "
        f"{effort.build_hours * 3.2:.0f} h under incident conditions"))

    brand = 0.18 * (churn + reg)
    if brand > 0:
        comps.append(LossComponent("Brand and communications", brand,
                                   "18% of churn plus penalty"))

    total = sum(c.amount for c in comps)

    # --- annualising -------------------------------------------------------
    # p_here is not computable yet (reachability and exposure are Parts 4-5), so
    # the world-probability is used and the result is labelled as an upper bound.
    p = s.p_wild_year
    annual = round(total * p, 2) if p is not None else None
    per_hour = round(annual / effort.loaded_hours, 2) if annual and effort.loaded_hours else None

    note = (
        "Annualised against the probability this flaw is exploited somewhere in the "
        "world, because reachability and internet exposure are not measured yet. "
        "Treat it as an upper bound; it will come down once those land."
    ) if p is not None else (
        "No published exploitation probability for this finding type, so only the "
        "cost-if-it-happens is given."
    )

    return Money(
        if_it_happens=round(total, 2),
        components=comps,
        effort=effort,
        p_wild_year=p,
        annual_loss=annual,
        loss_per_hour=per_hour,
        assumptions=[ASSUMPTIONS[k] for k in
                     ("downtime_hours", "regulatory_per_record", "churn_response",
                      "incident_multiplier", "brand_recovery")],
        note=note,
    )


# Components that all draw on the SAME pool. Your 180,000 records can only be
# exposed once; two findings that both reach them are not two breaches worth of
# penalty. Summing these across findings is the single easiest way to produce a
# number larger than the company.
SHARED_POOL = {"Regulatory penalty", "Customer churn", "Brand and communications"}
# These are genuinely separate events and do add up across incidents.
ADDITIVE = {"Business interruption", "Incident response", "Emergency engineering"}


def portfolio_from_rows(findings: list, revenue_supported: float | None = None) -> dict:
    """Same aggregation as `portfolio()`, for persisted `Finding` ORM rows
    instead of live `RawFinding`/`ScoreResult`/`Money` objects — the read APIs
    call this once a scan has already priced and stored findings, so re-scoring
    from scratch is not needed. Reads `impact_breakdown` (written by the
    orchestrator) rather than in-memory `Money.components`.
    """
    priced = [f for f in findings if f.impact_breakdown]
    if not priced:
        return {"priced": False, "exposure": None, "fix_cost": None,
                "loaded_hours": None, "sprints": None,
                "reason": "no priced findings yet - business context may be incomplete, "
                          "or no scan has run"}

    p_none = 1.0
    for f in priced:
        p = f.impact_breakdown.get("p_wild_year")
        if p:
            p_none *= (1 - p)
    p_any = 1 - p_none

    worst_shared, worst_from = 0.0, None
    for f in priced:
        shared = sum(c["amount"] for c in f.impact_breakdown.get("components", [])
                    if c["name"] in SHARED_POOL)
        if shared > worst_shared:
            worst_shared, worst_from = shared, (f.package or f.file or f.title)[:60]

    additive = sum(
        c["amount"] * (f.impact_breakdown.get("p_wild_year") or 0.0)
        for f in priced
        for c in f.impact_breakdown.get("components", []) if c["name"] in ADDITIVE
    )

    raw_exposure = worst_shared * p_any + additive
    cap = float(revenue_supported) if revenue_supported else None
    capped = bool(cap and raw_exposure > cap)
    exposure = min(raw_exposure, cap) if cap else raw_exposure

    hours = sum(float(f.fix_hours) for f in priced if f.fix_hours)
    cost = sum(float(f.fix_cost) for f in priced if f.fix_cost)
    naive = sum(float(f.annual_loss) for f in priced if f.annual_loss)

    return {
        "priced": True,
        "exposure": round(exposure, 2),
        "exposure_method": (
            "worst single breach against the shared record pool, weighted by the "
            "probability any finding is exploited, plus response costs that genuinely "
            "accumulate" + (", capped at the revenue this project supports" if capped else "")
        ),
        "naive_sum": round(naive, 2),
        "naive_sum_warning": (
            f"Adding every finding independently gives ${naive:,.0f}, which double-counts "
            f"the same records across {len(priced)} findings. It is reported only so the "
            f"difference is visible, and must not be used."
        ),
        "worst_single_breach": round(worst_shared, 2),
        "worst_single_breach_from": worst_from,
        "capped_at_revenue": capped,
        "fix_cost": round(cost, 2),
        "loaded_hours": round(hours, 1),
        "sprints": round(hours / settings.sprint_hours, 2),
        "findings_priced": len(priced),
        "findings_total": len(findings),
    }


def portfolio(priced: list[tuple[RawFinding, ScoreResult, "Money | None"]],
              ctx: BusinessContext | None = None) -> dict:
    """Aggregate, do not sum.

    Per-finding figures answer "what does this one cost me" and are the right
    basis for ranking. Adding them up answers nothing: 214 findings that each
    reach the same customer database do not mean 214 breaches. The aggregate
    therefore takes the worst case on the shared pool and adds only what really
    accumulates, then caps against the revenue the project supports.
    """
    with_money = [m for _, _, m in priced if m]
    if not with_money:
        return {"priced": False, "exposure": None, "fix_cost": None,
                "loaded_hours": None, "sprints": None,
                "reason": "business context incomplete - findings are ranked but not priced"}

    # P(at least one of these is exploited somewhere in the world this year)
    p_none = 1.0
    for m in with_money:
        if m.p_wild_year:
            p_none *= (1 - m.p_wild_year)
    p_any = 1 - p_none

    # Worst realistic single breach against the shared pool.
    worst_shared = 0.0
    worst_from = None
    for f, _, m in priced:
        if not m:
            continue
        shared = sum(c.amount for c in m.components if c.name in SHARED_POOL)
        if shared > worst_shared:
            worst_shared, worst_from = shared, (f.package or f.file or f.title)[:60]

    # Response costs accumulate, but only for findings likely enough to happen.
    additive = sum(
        c.amount * (m.p_wild_year or 0.0)
        for _, _, m in priced if m
        for c in m.components if c.name in ADDITIVE
    )

    raw_exposure = worst_shared * p_any + additive

    cap = None
    capped = False
    if ctx and ctx.revenue_supported:
        cap = float(ctx.revenue_supported)
        if raw_exposure > cap:
            capped = True
    exposure = min(raw_exposure, cap) if cap else raw_exposure

    hours = sum(m.effort.loaded_hours for m in with_money if m.effort)
    naive = sum(m.annual_loss or 0 for m in with_money)

    return {
        "priced": True,
        "exposure": round(exposure, 2),
        "exposure_method": (
            "worst single breach against the shared record pool, weighted by the "
            "probability any finding is exploited, plus response costs that genuinely "
            "accumulate" + (", capped at the revenue this project supports" if capped else "")
        ),
        "naive_sum": round(naive, 2),
        "naive_sum_warning": (
            f"Adding every finding independently gives ${naive:,.0f}, which double-counts "
            f"the same records across {len(with_money)} findings. It is reported only so the "
            f"difference is visible, and must not be used."
        ),
        "p_any_exploited": round(p_any, 4),
        "worst_single_breach": round(worst_shared, 2),
        "worst_single_breach_from": worst_from,
        "capped_at_revenue": capped,
        "fix_cost": round(sum(m.effort.cost for m in with_money if m.effort), 2),
        "loaded_hours": round(hours, 1),
        "sprints": round(hours / settings.sprint_hours, 2),
        "findings_priced": len(with_money),
        "findings_total": len(priced),
    }
