"""EPSS — Exploit Prediction Scoring System (FIRST.org).

This is the most important number in the product and the reason our probability
figures are defensible. EPSS is a published, peer-reviewed model that gives the
probability a CVE will be exploited **in the next 30 days**. It is not our guess.

The one thing we must get right is the conversion. EPSS is a 30-day probability;
everything downstream is annual. Treating 30-day as annual would understate risk
by roughly an order of magnitude at the low end.

    p_year = 1 - (1 - p30) ** (365/30)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

log = logging.getLogger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"
BATCH = 100                # the API caps the cve list; keep requests small
TIMEOUT = 25.0
PERIODS_PER_YEAR = 365 / 30


@dataclass(frozen=True, slots=True)
class EpssScore:
    cve: str
    p30: float             # probability of exploitation in the next 30 days
    percentile: float      # where it sits against every other scored CVE
    date: str

    @property
    def p_year(self) -> float:
        """Annualised. The compounding matters: 0.03 over 30 days is 0.31 a year."""
        return 1 - (1 - self.p30) ** PERIODS_PER_YEAR

    @property
    def band(self) -> str:
        if self.percentile >= 0.99:
            return "top 1%"
        if self.percentile >= 0.95:
            return "top 5%"
        if self.percentile >= 0.90:
            return "top 10%"
        return f"{self.percentile * 100:.0f}th percentile"


def annualise(p30: float) -> float:
    return 1 - (1 - max(0.0, min(1.0, p30))) ** PERIODS_PER_YEAR


def lookup(cves: list[str], client: httpx.Client | None = None) -> dict[str, EpssScore]:
    """CVE -> score. Missing CVEs simply do not appear; absence is not zero risk,
    it means EPSS has no model for that identifier yet."""
    wanted = sorted({c.upper() for c in cves if c and c.upper().startswith("CVE-")})
    if not wanted:
        return {}

    out: dict[str, EpssScore] = {}
    own = client is None
    client = client or httpx.Client(timeout=TIMEOUT, headers={"user-agent": "fantom/0.1"})
    try:
        for i in range(0, len(wanted), BATCH):
            chunk = wanted[i : i + BATCH]
            try:
                r = client.get(EPSS_API, params={"cve": ",".join(chunk), "limit": str(BATCH)})
                r.raise_for_status()
                body = r.json()
            except (httpx.HTTPError, ValueError) as exc:
                log.warning("EPSS lookup failed for %d CVEs: %s", len(chunk), exc)
                continue
            for row in body.get("data") or []:
                try:
                    out[row["cve"]] = EpssScore(
                        cve=row["cve"],
                        p30=float(row["epss"]),
                        percentile=float(row["percentile"]),
                        date=str(row.get("date", "")),
                    )
                except (KeyError, TypeError, ValueError):
                    continue
    finally:
        if own:
            client.close()

    log.info("EPSS: %d/%d CVEs scored", len(out), len(wanted))
    return out
