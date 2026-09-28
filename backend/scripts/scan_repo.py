"""Scan any public GitHub repository end to end, with nothing configured.

    python scripts/scan_repo.py owner/repo [--branch main] [--json out.json]
                                [--limit 20] [--only lib,secret,code]

Runs the whole Part 1 + Part 2 pipeline: clone, resolve dependencies, query OSV,
hunt secrets, analyse code, enrich with EPSS and CISA KEV, then score everything
contextually and show where that disagrees with CVSS.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    RULE, ARROW, ELLIPSIS, DOT = "─", "→", "…", "·"
except Exception:                      # noqa: BLE001
    RULE, ARROW, ELLIPSIS, DOT = "-", "->", "...", "*"

from app.enrich import epss as epss_mod                    # noqa: E402
from app.enrich import kev as kev_mod                      # noqa: E402
from app.scanners import code, lockfiles, osv, secrets     # noqa: E402
from app.scanners.base import ScanContext                  # noqa: E402
from app.services import repo as repo_svc                  # noqa: E402
from app.services.fingerprint import fingerprint           # noqa: E402
from app.services import money as money_svc                       # noqa: E402
from app.services.scoring import cvss_tier, disagreement, score_all  # noqa: E402

B, D, R = "\033[1m", "\033[2m", "\033[0m"
TIER_MARK = {4: "####", 3: "###.", 2: "##..", 1: "#..."}


def human(n: float) -> str:
    return f"{n:,.0f}" if n >= 1000 else f"{n:g}"


def main() -> int:
    ap = argparse.ArgumentParser(description="FANTOM - scan a public repo")
    ap.add_argument("repo", help="owner/name")
    ap.add_argument("--branch", default=None)
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--limit", type=int, default=15)
    ap.add_argument("--only", default="lib,secret,code",
                    help="comma list: lib, secret, code")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--context", metavar="JSON_FILE",
                    help="business context file; without it findings are ranked but not priced")
    ap.add_argument("--revenue", type=float, help="shortcut: annual revenue this project supports")
    ap.add_argument("--downtime", type=float, help="shortcut: cost of one hour of downtime")
    ap.add_argument("--users", type=int)
    ap.add_argument("--records", type=int)
    ap.add_argument("--regimes", default=None, help="comma list, e.g. DPDP,PCI")
    args = ap.parse_args()

    bctx = money_svc.BusinessContext()
    if args.context:
        raw_ctx = json.loads(Path(args.context).read_text(encoding="utf-8"))
        bctx = money_svc.BusinessContext(**{k: v for k, v in raw_ctx.items()
                                           if k in money_svc.BusinessContext.__slots__})
    for attr, val in (("revenue_supported", args.revenue), ("downtime_cost_hour", args.downtime),
                      ("users_count", args.users), ("records_count", args.records)):
        if val is not None:
            setattr(bctx, attr, val)
    if args.regimes:
        bctx.regimes = [r.strip().upper() for r in args.regimes.split(",") if r.strip()]

    if args.repo.count("/") != 1:
        print("repo must be owner/name", file=sys.stderr)
        return 2
    only = {s.strip() for s in args.only.split(",") if s.strip()}

    t0 = time.time()
    print(f"\n{B}FANTOM{R}  scanning {B}{args.repo}{R}")
    print(RULE * 86)

    findings = []
    try:
        with repo_svc.checkout(args.repo, args.branch, keep=args.keep) as (root, meta):
            print(f"  clone       {meta['commit'][:10]}  {meta['size_mb']} MB  {meta['clone_s']}s")
            ctx = ScanContext(root=root, repo=args.repo)

            # ---- dependencies -------------------------------------------------
            if "lib" in only:
                t = time.time()
                packages, files = lockfiles.collect_packages(root)
                if packages:
                    eco = Counter(p.ecosystem for p in packages)
                    print(f"  lockfiles   {len(files)} {DOT} {human(len(packages))} packages "
                          f"({', '.join(f'{k} {v}' for k, v in eco.most_common(3))})")
                    dep = osv.scan(ctx, packages)
                    findings += dep
                    print(f"  osv.dev     {len(dep)} advisories  ({time.time()-t:.1f}s)")
                else:
                    print(f"  lockfiles   {D}none committed - dependency findings unavailable, "
                          f"not guessed{R}")

            # ---- secrets ------------------------------------------------------
            if "secret" in only:
                t = time.time()
                sec = secrets.scan(ctx)
                findings += sec
                print(f"  secrets     {len(sec)} candidates  ({time.time()-t:.1f}s)")

            # ---- code ---------------------------------------------------------
            if "code" in only:
                t = time.time()
                langs = code.detect_languages(root)
                cf = code.scan(ctx)
                findings += cf
                top = ", ".join(f"{k} {v}" for k, v in
                                sorted(langs.items(), key=lambda x: -x[1])[:3])
                print(f"  code        {len(cf)} flaws in {top or 'no supported language'}  "
                      f"({time.time()-t:.1f}s)")
    except repo_svc.RepoTooLarge as exc:
        print(f"\n  refused: {exc}")
        return 1
    except repo_svc.RepoError as exc:
        print(f"\n  clone failed: {exc}")
        return 1

    if not findings:
        print("\n  Nothing found by the scanners that ran.")
        return 0

    # ---- enrichment -------------------------------------------------------
    t = time.time()
    cves = [f.cve for f in findings if f.cve]
    epss_map = epss_mod.lookup(cves) if cves else {}
    catalog = kev_mod.catalog()
    print(f"  epss        {len(epss_map)}/{len(set(cves))} CVEs scored")
    print(f"  cisa kev    {len(catalog)} catalogue entries, released {catalog.released or 'unknown'}"
          f"  ({time.time()-t:.1f}s)")

    scored = score_all(findings, epss_map, catalog)
    for f, _ in scored:
        f.extra["fingerprint"] = fingerprint(f)

    # One row per distinct finding. The same advisory hitting two installed
    # versions of a package is one thing to fix, not two things to read.
    best: dict[str, tuple] = {}
    seen_at: dict[str, set] = {}
    for f, r in scored:
        fp = f.extra["fingerprint"]
        seen_at.setdefault(fp, set()).add(f"{f.package or f.file} {f.version or ''}".strip())
        if fp not in best or r.score > best[fp][1].score:
            best[fp] = (f, r)
    unique = sorted(best.values(), key=lambda pair: -pair[1].score)

    # ---- summary ----------------------------------------------------------
    uniq = {f.extra["fingerprint"] for f, _ in scored}
    tiers = Counter(r.tier for _, r in scored)
    kev_hits = [f for f, _ in scored if catalog.contains(f.cve)]
    by_scanner = Counter(f.scanner for f, _ in scored)

    print(RULE * 86)
    print(f"\n{B}FINDINGS{R}  {len(scored)} raw {DOT} {len(uniq)} unique fingerprints {DOT} "
          f"{', '.join(f'{k} {v}' for k, v in by_scanner.most_common())}")
    print(f"          {B}{tiers[4]}{R} critical {DOT} {tiers[3]} high {DOT} "
          f"{tiers[2]} medium {DOT} {tiers[1]} low")
    if kev_hits:
        ransom = [f for f in kev_hits if (catalog.get(f.cve) or None) and catalog.get(f.cve).ransomware]
        print(f"          {B}{len(kev_hits)} are on the CISA KEV catalogue{R}"
              + (f" {DOT} {len(ransom)} used in ransomware campaigns" if ransom else ""))

    # ---- where we disagree with CVSS -------------------------------------
    moves = [(f, r, disagreement(f, r)) for f, r in scored if f.cvss]
    up = sorted([m for m in moves if m[2] > 0], key=lambda m: -m[2])[:3]
    down = sorted([m for m in moves if m[2] < 0], key=lambda m: m[2])[:3]
    if up or down:
        print(f"\n{B}WHERE THIS DISAGREES WITH CVSS{R}   {D}(band moves, not point moves){R}")
        for f, r, d in up:
            print(f"  {B}ESCALATED{R}  CVSS {f.cvss:.1f} {ARROW} {r.score}  "
                  f"[{['','Low','Med','High','Crit'][cvss_tier(f.cvss)]} {ARROW} {r.tier_name}]  "
                  f"{(f.package or f.file or '')[:34]}")
            print(f"             {D}{r.factors[0].detail[:80]}{R}")
        for f, r, d in down:
            print(f"  DEPRIORITISED  CVSS {f.cvss:.1f} {ARROW} {r.score}  "
                  f"[{['','Low','Med','High','Crit'][cvss_tier(f.cvss)]} {ARROW} {r.tier_name}]  "
                  f"{(f.package or f.file or '')[:34]}")
            print(f"             {D}{r.factors[0].detail[:80]}{R}")

    # ---- money ------------------------------------------------------------
    priced = [(f, r, money_svc.price(f, r, bctx)) for f, r in unique]
    book = money_svc.portfolio(priced, bctx)
    money_by_fp = {f.extra["fingerprint"]: m for f, _, m in priced if m}

    print(f"\n{B}MONEY{R}")
    if not book["priced"]:
        print(f"  {B}Not priced.{R} {book['reason']}")
        print(f"  Missing: {B}{', '.join(bctx.missing)}{R}")
        print(f"  {D}Supply them with --revenue --downtime --users --records --regimes,")
        print(f"  or a --context file. Nothing is guessed in their absence.{R}")
    else:
        print(f"  exposure                {B}${book['exposure']:,.0f}{R} / year"
              + (f"  {D}(capped at supported revenue){R}" if book["capped_at_revenue"] else ""))
        print(f"  {D}{book['exposure_method']}{R}")
        print(f"  worst single breach     ${book['worst_single_breach']:,.0f}"
              f"  {D}from {book['worst_single_breach_from']}{R}")
        print(f"  P(any exploited/yr)     {book['p_any_exploited']:.1%}")
        print(f"  cost to fix everything  ${book['fix_cost']:,.0f}"
              f"  ({book['loaded_hours']:,.0f} loaded hours {DOT} {book['sprints']} sprints)")
        print(f"  {D}{book['findings_priced']} of {book['findings_total']} findings priced{R}")
        print(f"  {D}naive sum would say ${book['naive_sum']:,.0f} - that double-counts the")
        print(f"  same records across every finding, so it is not used.{R}")
        # order by what each engineer hour buys
        best = sorted([(f, r, m) for f, r, m in priced if m and m.loss_per_hour],
                      key=lambda x: -x[2].loss_per_hour)[:3]
        if best:
            print(f"\n  {B}Best use of engineering time{R}")
            for f, r, m in best:
                what = f.package or f"{f.file}:{f.line}"
                print(f"    ${m.loss_per_hour:>9,.0f}/hour  {m.effort.loaded_hours:>5.0f} h  "
                      f"{what[:44]}")

    # ---- the work order ---------------------------------------------------
    print(f"\n{B}WORK ORDER{R}  {D}ranked by contextual score, not CVSS{R}\n")
    for i, (f, r) in enumerate(unique[: args.limit], start=1):
        places = seen_at.get(f.extra["fingerprint"], set())
        loc = f"{f.package} {f.version}" if f.package else f"{f.file}:{f.line}"
        if len(places) > 1:
            loc += f"  (+{len(places)-1} more version{'s' if len(places) > 2 else ''})"
        cvss_s = f"CVSS {f.cvss:.1f}" if f.cvss else "no CVSS"
        print(f"  {i:>2}. {B}{r.score:>2}{R} {TIER_MARK[r.tier]} {r.tier_name:<8} "
              f"{D}fix within {r.sla}{R}")
        print(f"      {f.title[:76]}")
        wild = f"exploited in the wild {r.p_wild_30d:.1%}/30d" if r.p_wild_30d else "no EPSS"
        print(f"      {loc[:70]}")
        print(f"      {D}{cvss_s} {DOT} {wild} {DOT} confidence {r.confidence:.0%}{R}")
        if f.extra.get("redacted"):
            print(f"      {D}value {f.extra['redacted']} - never stored in full{R}")
        print(f"      {D}{r.factors[-1].detail[:78]}{R}")
        m = money_by_fp.get(f.extra["fingerprint"])
        if m:
            ann = f"${m.annual_loss:,.0f}/yr" if m.annual_loss else "not annualised"
            print(f"      {B}{ann}{R}  {D}if it happens ${m.if_it_happens:,.0f} {DOT} "
                  f"fix {m.effort.loaded_hours:.0f} h / ${m.effort.cost:,.0f} {DOT} "
                  f"{m.effort.change_risk.lower()} risk{R}")
            top = sorted(m.components, key=lambda c: -c.amount)[:2]
            print(f"      {D}mostly {', '.join(f'{c.name.lower()} ${c.amount:,.0f}' for c in top)}{R}")
        print()

    if len(unique) > args.limit:
        print(f"  {ELLIPSIS} {len(unique)-args.limit} more (use --limit)\n")

    pend = unique[0][1].pending
    print(f"{D}  Scores are {B}technical{R}{D} for now. Still unmeasured: {', '.join(pend)}.")
    print(f"  Each contributes a neutral 1.0, so nothing here is inflated by a factor")
    print(f"  we have not measured. EPSS says how likely a flaw is to be exploited")
    print(f"  {B}somewhere in the world{R}{D} - not how likely you are to be breached. That")
    print(f"  second number needs reachability and exposure, so it is not published yet.{R}")

    if book["priced"]:
        print(f"{D}  Every figure above is arithmetic over inputs you supplied. The model's")
        print(f"  judgement calls are listed at GET /api/assumptions - five of them.{R}")

    if args.json_out:
        payload = [
            {
                "fingerprint": f.extra["fingerprint"], "scanner": f.scanner,
                "agent": f.agent_slug, "title": f.title, "file": f.file, "line": f.line,
                "package": f.package, "version": f.version, "fixed_version": f.fixed_version,
                "cve": f.cve, "cwe": f.cwe, "rule_id": f.rule_id, "cvss": f.cvss,
                "context_score": r.score, "tier": r.tier_name, "sla": r.sla,
                "p_wild_30d": round(r.p_wild_30d, 5),
                "p_wild_year": (round(r.p_wild_year, 5) if r.p_wild_year is not None else None),
                "p_here_year": None,
                "probability_note": r.p_note,
                "confidence": r.confidence,
                "kev": catalog.contains(f.cve),
                "epss": (epss_map.get((f.cve or "").upper()).p30
                         if f.cve and (f.cve or "").upper() in epss_map else None),
                "factors": [{"name": x.name, "value": x.value, "detail": x.detail,
                             "measured": x.measured} for x in r.factors],
                "remediation": f.remediation,
                "money": (None if not money_by_fp.get(f.extra["fingerprint"]) else {
                    "if_it_happens": money_by_fp[f.extra["fingerprint"]].if_it_happens,
                    "annual_loss_upper_bound": money_by_fp[f.extra["fingerprint"]].annual_loss,
                    "loss_per_hour": money_by_fp[f.extra["fingerprint"]].loss_per_hour,
                    "fix_cost": money_by_fp[f.extra["fingerprint"]].effort.cost,
                    "loaded_hours": money_by_fp[f.extra["fingerprint"]].effort.loaded_hours,
                    "components": [{"name": c.name, "amount": round(c.amount, 2),
                                    "basis": c.basis}
                                   for c in money_by_fp[f.extra["fingerprint"]].components],
                }),
            }
            for f, r in unique
        ]
        Path(args.json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\n  wrote {args.json_out}")

    print(f"\n  total {time.time()-t0:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
