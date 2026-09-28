"""Contextual scoring.

CVSS answers "how bad is this flaw in the abstract". That is a property of the
flaw, not of your system, which is why a CVSS-ordered queue is usually the wrong
work order. This module answers "how bad is this flaw **here**".

Phase note, stated honestly: two of the five factors need information that does
not exist yet.

    exploitability   available now   (EPSS + KEV + CVSS + detector confidence)
    blast radius     available now   (direct vs transitive, production path)
    reachability     Part 5          (is the vulnerable symbol actually called)
    exposure         Part 4          (is this asset reachable from the internet)
    criticality      Part 3          (what does this project support)

Until those land, each contributes a neutral 1.0 and `ScoreResult.pending` names
what is missing. A score is never inflated by a factor we have not measured.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from app.enrich.epss import EpssScore, annualise
from app.enrich.kev import KevEntry
from app.scanners.base import RawFinding

# How "far along the road to a working exploit" each maturity signal is.
MATURITY = {
    "weaponised": 1.00,
    "public-exploit": 0.85,
    "misconfiguration": 0.80,   # nothing to weaponise; it is already true
    "trivial": 0.70,
    "proof-of-concept": 0.35,
    "local-only": 0.25,
    "none": 0.05,
}
SEVERITY_FALLBACK = {"CRITICAL": 0.80, "HIGH": 0.60, "MODERATE": 0.40,
                     "MEDIUM": 0.40, "LOW": 0.20}


@dataclass(slots=True)
class Factor:
    name: str
    value: float
    detail: str
    measured: bool = True


@dataclass(slots=True)
class ScoreResult:
    score: int                       # 0-100, the work-order number
    # EPSS answers "is this being exploited ANYWHERE", not "will it be exploited
    # against you". We keep the honest one and refuse to publish the other until
    # reachability and exposure exist to compute it.
    p_wild_30d: float = 0.0          # published EPSS, as published
    p_wild_year: float | None = None # annualised - still a world figure
    p_here_year: float | None = None # yours. None until Parts 4-5 land.
    p_note: str = ""
    factors: list[Factor] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)
    confidence: float = 0.5
    basis: str = "technical"         # becomes "contextual" once Parts 3-5 land

    @property
    def tier(self) -> int:
        return 4 if self.score >= 80 else 3 if self.score >= 60 else 2 if self.score >= 35 else 1

    @property
    def tier_name(self) -> str:
        return ["", "Low", "Medium", "High", "Critical"][self.tier]

    @property
    def sla(self) -> str:
        return {4: "24 hours", 3: "7 days", 2: "30 days", 1: "next cycle"}[self.tier]


def cvss_tier(cvss: float | None) -> int:
    if cvss is None:
        return 0
    return 4 if cvss >= 9 else 3 if cvss >= 7 else 2 if cvss >= 4 else 1


# ---------------------------------------------------------------------------
def _maturity_of(f: RawFinding, kev: KevEntry | None) -> tuple[float, str]:
    if kev:
        label = "weaponised"
        detail = f"on the CISA KEV catalogue since {kev.date_added}"
        if kev.ransomware:
            detail += "; used in known ransomware campaigns"
        return MATURITY[label], detail
    if f.scanner == "gitleaks":
        conf = float(f.extra.get("confidence", 0.7))
        return (MATURITY["misconfiguration"] * conf,
                f"credential is already present in the repository "
                f"({f.extra.get('detector', 'pattern')} detector, {conf:.0%} confidence)")
    if f.scanner == "semgrep":
        conf = float(f.extra.get("confidence", 0.6))
        return (MATURITY["trivial"] * conf,
                f"flaw is directly reachable in source ({conf:.0%} rule confidence)")
    return MATURITY["none"], "no exploit maturity signal"


def _exploitability(f: RawFinding, epss: EpssScore | None, kev: KevEntry | None) -> Factor:
    """Blend the three published signals. CVSS is the smallest term on purpose."""
    mat, mat_why = _maturity_of(f, kev)
    epss_p = epss.p30 if epss else 0.0
    cvss_n = (f.cvss / 10.0) if f.cvss else SEVERITY_FALLBACK.get(
        (f.severity_label or "").upper(), 0.35)

    e = 0.40 * max(epss_p, mat) + 0.30 * (1.0 if kev else 0.0) + 0.30 * cvss_n
    bits = [mat_why]
    if epss:
        bits.append(f"EPSS {epss.p30:.1%} in 30 days ({epss.band})")
    elif f.cve:
        bits.append("no EPSS score published for this CVE")
    if f.cvss:
        bits.append(f"CVSS {f.cvss:.1f}")
    return Factor("Exploitability", round(min(1.0, e), 4), " · ".join(bits))


def _blast(f: RawFinding) -> Factor:
    """What else this finding can reach. Measurable from the scanner output alone."""
    if f.scanner == "osv":
        direct = bool(f.extra.get("direct", True))
        v = 1.00 if direct else 0.78
        return Factor("Blast radius", v,
                      "a direct dependency of this project" if direct
                      else "a transitive dependency, pulled in by something else")
    if f.scanner == "gitleaks":
        example = bool(f.extra.get("example_file"))
        rule = f.rule_id or ""
        if rule in ("private-key", "aws-access-key", "db-uri-password", "github-pat"):
            v = 0.70 if example else 1.10      # these reach infrastructure, not one app
            why = "grants access to infrastructure beyond this repository"
        else:
            v = 0.60 if example else 0.95
            why = "scoped to one service or provider"
        if example:
            why += "; found in an example or fixture file"
        return Factor("Blast radius", v, why)
    path = (f.file or "").lower()
    if any(p in path for p in ("test", "spec", "mock", "fixture", "example", "docs/")):
        return Factor("Blast radius", 0.55, "sits in test or example code, not a shipped path")
    return Factor("Blast radius", 0.90, "sits on a shipped code path")


def _probability(f: RawFinding, epss: EpssScore | None,
                 kev: KevEntry | None) -> tuple[float, float | None, str]:
    """Returns (p_wild_30d, p_wild_year, note).

    Deliberately does NOT return a probability that you specifically get
    exploited. That needs reachability and internet exposure, neither of which
    is measured yet, so publishing one now would be a guess wearing a decimal
    point. The annual figure is also capped: independence across twelve periods
    is a modelling convenience, not a fact, and without the cap every finding
    above ~20% EPSS saturates to 100% and the column stops discriminating.
    """
    if epss:
        annual = min(0.95, annualise(epss.p30))
        note = (f"EPSS {epss.p30:.1%} in 30 days ({epss.band}); "
                f"{annual:.0%} somewhere in the world over a year")
        if kev:
            note += "; CISA records it already being exploited"
        return epss.p30, annual, note
    if kev:
        return 0.50, 0.90, "no EPSS score, but CISA records active exploitation in the wild"
    if f.scanner == "gitleaks":
        conf = float(f.extra.get("confidence", 0.7))
        return round(0.30 * conf, 4), None, (
            "a committed credential is readable by anyone with repository access; "
            "EPSS does not model credential leaks")
    return 0.0, None, "no published exploitation data for this finding type"


# ---------------------------------------------------------------------------
def score(f: RawFinding, epss: EpssScore | None = None,
          kev: KevEntry | None = None) -> ScoreResult:
    exploit = _exploitability(f, epss, kev)
    blast = _blast(f)

    pending: list[str] = []
    reach = Factor("Reachability", 1.0, "not yet analysed — assumed reachable", measured=False)
    expose = Factor("Internet exposure", 1.0, "unknown until the asset survey runs", measured=False)
    crit = Factor("Business criticality", 1.0, "unknown until business context is supplied", measured=False)
    pending = ["reachability (Part 5)", "internet exposure (Part 4)", "business criticality (Part 3)"]

    raw = exploit.value * reach.value * expose.value * crit.value * blast.value
    value = max(1, min(99, round(100 * math.pow(max(raw, 1e-6), 0.45))))

    p30, pyear, p_note = _probability(f, epss, kev)

    conf = 0.9 if (epss or kev) else 0.65 if f.scanner == "osv" else \
        float(f.extra.get("confidence", 0.6))

    return ScoreResult(
        score=value,
        p_wild_30d=p30,
        p_wild_year=pyear,
        p_here_year=None,          # requires reachability + exposure
        p_note=p_note,
        factors=[exploit, reach, expose, crit, blast,
                 Factor("Exploited in the wild", p30, p_note)],
        pending=pending,
        confidence=round(conf, 2),
        basis="technical",
    )


def score_all(findings: list[RawFinding], epss_map: dict[str, EpssScore],
              kev_catalog) -> list[tuple[RawFinding, ScoreResult]]:
    out = []
    for f in findings:
        e = epss_map.get((f.cve or "").upper()) if f.cve else None
        k = kev_catalog.get(f.cve) if f.cve else None
        out.append((f, score(f, e, k)))
    out.sort(key=lambda pair: -pair[1].score)
    return out


def disagreement(f: RawFinding, r: ScoreResult) -> int:
    """How many severity bands our score moved the finding from its CVSS band.
    Positive means we escalated, negative means we deprioritised."""
    c = cvss_tier(f.cvss)
    return 0 if not c else r.tier - c
