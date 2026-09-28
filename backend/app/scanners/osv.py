"""The Library Inspector.

Queries OSV (osv.dev) — the same database Google's own osv-scanner uses — in
batches, then resolves each hit to its full record for severity and fix version.

No API key, no rate limit worth worrying about, no binary to install.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from app.scanners.base import Package, RawFinding, ScanContext

log = logging.getLogger(__name__)

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_BYID = "https://api.osv.dev/v1/vulns/"
BATCH_SIZE = 200
DETAIL_WORKERS = 16       # osv.dev is a read API behind a CDN
TIMEOUT = 30.0


def _cvss_from(vuln: dict[str, Any]) -> tuple[float | None, str | None]:
    """Prefer a CVSS v3/v4 base score; fall back to a database severity label."""
    for sev in vuln.get("severity") or []:
        score = sev.get("score", "")
        if sev.get("type", "").startswith("CVSS") and score.startswith("CVSS:"):
            # "CVSS:3.1/AV:N/AC:L/... " — the numeric base score lives in the
            # database_specific block far more reliably than in the vector.
            break
    ds = vuln.get("database_specific") or {}
    label = ds.get("severity")
    score_val = None
    for sev in vuln.get("severity") or []:
        try:
            score_val = float(sev.get("score"))
            break
        except (TypeError, ValueError):
            continue
    if score_val is None and label:
        score_val = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0}.get(
            str(label).upper()
        )
    return score_val, label


def _fixed_version(vuln: dict[str, Any], pkg: Package) -> str | None:
    for aff in vuln.get("affected") or []:
        p = aff.get("package") or {}
        if p.get("name", "").lower() != pkg.name.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    return ev["fixed"]
    return None


def _cwe_from(vuln: dict[str, Any]) -> str | None:
    ds = vuln.get("database_specific") or {}
    ids = ds.get("cwe_ids") or []
    return ids[0] if ids else None


def _cve_from(vuln: dict[str, Any]) -> str | None:
    if str(vuln.get("id", "")).startswith("CVE-"):
        return vuln["id"]
    for a in vuln.get("aliases") or []:
        if str(a).startswith("CVE-"):
            return a
    return None


def query_batch(packages: list[Package], client: httpx.Client) -> dict[str, list[str]]:
    """package.key -> [vuln ids]. One request per BATCH_SIZE packages."""
    hits: dict[str, list[str]] = {}
    for i in range(0, len(packages), BATCH_SIZE):
        chunk = packages[i : i + BATCH_SIZE]
        payload = {
            "queries": [
                {"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}
                for p in chunk
            ]
        }
        try:
            r = client.post(OSV_BATCH, json=payload, timeout=TIMEOUT)
            r.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("OSV batch failed (%s) - %d packages unchecked", exc, len(chunk))
            continue
        for pkg, result in zip(chunk, r.json().get("results", []), strict=False):
            ids = [v["id"] for v in (result.get("vulns") or [])]
            if ids:
                hits[pkg.key] = ids
    return hits


def fetch_vulns(ids: set[str], client: httpx.Client) -> dict[str, dict]:
    """One GET per advisory, run concurrently.

    Sequentially this is the slowest step in the whole scan — 200+ advisories at
    ~0.3s each is over a minute, which would blow the push-cycle budget on its
    own. A small thread pool takes it to a few seconds; osv.dev is a CDN-backed
    read API and is happy with the concurrency.
    """
    out: dict[str, dict] = {}
    if not ids:
        return out

    def one(vid: str) -> tuple[str, dict | None]:
        try:
            r = client.get(OSV_BYID + vid, timeout=TIMEOUT)
            r.raise_for_status()
            return vid, r.json()
        except httpx.HTTPError as exc:
            log.warning("OSV detail failed for %s: %s", vid, exc)
            return vid, None

    with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
        for vid, doc in pool.map(one, sorted(ids)):
            if doc is not None:
                out[vid] = doc
    return out


def scan(ctx: ScanContext, packages: list[Package]) -> list[RawFinding]:
    """Dependencies -> findings. Returns [] rather than raising if OSV is down."""
    if not packages:
        return []

    limits = httpx.Limits(max_connections=DETAIL_WORKERS * 2, max_keepalive_connections=DETAIL_WORKERS)
    with httpx.Client(headers={"user-agent": "fantom/0.1 (+security scanner)"},
                      limits=limits, http2=False) as client:
        hits = query_batch(packages, client)
        if not hits:
            return []
        all_ids = {vid for ids in hits.values() for vid in ids}
        log.info("OSV: %d/%d packages affected, %d advisories", len(hits), len(packages), len(all_ids))
        details = fetch_vulns(all_ids, client)

    by_key = {p.key: p for p in packages}
    findings: list[RawFinding] = []
    for key, ids in hits.items():
        pkg = by_key[key]
        for vid in ids:
            v = details.get(vid)
            if not v:
                continue
            cvss, label = _cvss_from(v)
            fixed = _fixed_version(v, pkg)
            summary = v.get("summary") or (v.get("details") or "")[:200]
            findings.append(
                RawFinding(
                    scanner="osv",
                    agent_slug="lib",
                    title=summary or f"{pkg.name} {pkg.version} is affected by {vid}",
                    file=pkg.source_file,
                    package=pkg.name,
                    version=pkg.version,
                    fixed_version=fixed,
                    ecosystem=pkg.ecosystem,
                    cve=_cve_from(v),
                    cwe=_cwe_from(v),
                    rule_id=vid,
                    aliases=list(v.get("aliases") or []),
                    cvss=cvss,
                    severity_label=label,
                    summary=summary,
                    references=[r["url"] for r in (v.get("references") or []) if r.get("url")][:5],
                    remediation=(
                        [f"Upgrade {pkg.name} from {pkg.version} to {fixed} or later."]
                        if fixed
                        else [
                            f"No patched release of {pkg.name} exists yet. "
                            "Pin an alternative, or apply a compensating control and re-check weekly."
                        ]
                    ),
                    extra={"osv_id": vid, "direct": pkg.direct},
                )
            )
    return findings
