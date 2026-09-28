"""Part 3 acceptance: business context, the loss model, and the gate.

The most important tests here are the ones that assert money is **absent**.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.enrich.epss import EpssScore
from app.main import app
from app.scanners.base import RawFinding
from app.services import money as M
from app.services.scoring import score

client = TestClient(app)

FULL = dict(revenue_supported=24_000_000, downtime_cost_hour=38_000,
            users_count=180_000, records_count=180_000, regimes=["DPDP", "PCI"])


def ctx(**over) -> M.BusinessContext:
    return M.BusinessContext(**{**FULL, **over})


def finding(cwe="CWE-89", cvss=7.5, scanner="osv", rule=None, **kw) -> RawFinding:
    return RawFinding(scanner=scanner, agent_slug="lib", title="t", cwe=cwe, cvss=cvss,
                      cve="CVE-2020-0001", package="p", version="1.0.0",
                      fixed_version="1.0.1", rule_id=rule,
                      extra={"direct": True, **kw})


def priced(f=None, c=None, epss=0.2):
    f = f or finding()
    r = score(f, EpssScore("CVE-2020-0001", epss, 0.8, "2026-09-10"))
    return f, r, M.price(f, r, c if c is not None else ctx())


# ======================================================== THE GATE ==========
def test_no_context_means_no_money():
    _, _, m = priced(c=M.BusinessContext())
    assert m is None


@pytest.mark.parametrize("drop", list(M.BusinessContext.REQUIRED))
def test_any_single_missing_field_blocks_pricing(drop):
    """Four of five is still not priced. There is no partial credit."""
    _, _, m = priced(c=ctx(**{drop: None}))
    assert m is None, f"pricing must be blocked when {drop} is absent"


def test_missing_names_exactly_what_is_absent():
    c = ctx(revenue_supported=None, regimes=None)
    assert set(c.missing) == {"revenue_supported", "regimes"}
    assert c.complete is False


def test_engineer_rate_is_the_one_field_with_a_real_default():
    c = ctx(eng_rate_hour=None)
    assert c.complete is True          # not required
    assert c.rate == 120.0


def test_zero_is_a_real_answer_not_a_missing_one():
    """A project with no regulated records is complete, not incomplete."""
    c = ctx(records_count=0, regimes=["NONE"])
    assert c.complete is True
    _, _, m = priced(c=c)
    assert m is not None
    assert not any(x.name == "Regulatory penalty" for x in m.components)


# ======================================================== AGGREGATION =======
def test_portfolio_does_not_sum_the_same_records_twice():
    """214 findings reaching one customer database is not 214 breaches."""
    rows = [priced(finding(), epss=0.2) for _ in range(30)]
    book = M.portfolio(rows, ctx())
    assert book["priced"] is True
    assert book["exposure"] < book["naive_sum"]
    # the aggregate must be near the worst single breach, not 30x it
    assert book["exposure"] < book["worst_single_breach"] * 4
    assert "double-counts" in book["naive_sum_warning"]


def test_portfolio_caps_at_revenue_supported():
    rows = [priced(finding(cwe="CWE-95"), epss=0.9) for _ in range(200)]
    book = M.portfolio(rows, ctx())
    assert book["exposure"] <= FULL["revenue_supported"]


def test_unpriced_portfolio_returns_nulls_not_zeros():
    rows = [priced(c=M.BusinessContext())]
    book = M.portfolio(rows, M.BusinessContext())
    assert book["priced"] is False
    assert book["exposure"] is None          # never 0.0
    assert book["fix_cost"] is None


# ======================================================== THE MODEL =========
def test_regulatory_penalty_respects_the_regime_cap():
    huge = ctx(records_count=100_000_000)
    amount, why = M.regulatory_penalty(100_000_000, huge)
    assert amount <= 30_000_000                # DPDP cap
    assert "capped" in why


def test_different_regimes_produce_different_penalties():
    a, _ = M.regulatory_penalty(10_000, ctx(regimes=["PCI"]))
    b, _ = M.regulatory_penalty(10_000, ctx(regimes=["HIPAA"]))
    assert b > a                               # HIPAA is dearer per record


def test_dos_finding_charges_downtime_not_records():
    _, _, m = priced(finding(cwe="CWE-400"))
    names = {c.name for c in m.components}
    assert "Business interruption" in names
    reg = next((c for c in m.components if c.name == "Regulatory penalty"), None)
    assert reg is None or reg.amount < 100_000   # availability flaw leaks little


def test_sql_injection_charges_records_not_downtime():
    _, _, m = priced(finding(cwe="CWE-89"))
    reg = next(c for c in m.components if c.name == "Regulatory penalty")
    assert reg.amount > 0


def test_components_sum_to_the_headline():
    _, _, m = priced()
    assert sum(c.amount for c in m.components) == pytest.approx(m.if_it_happens, rel=1e-6)


def test_annual_loss_is_the_headline_times_probability():
    f, r, m = priced(epss=0.2)
    assert m.annual_loss == pytest.approx(m.if_it_happens * r.p_wild_year, rel=1e-6)


def test_every_component_carries_its_basis():
    _, _, m = priced()
    assert all(c.basis for c in m.components)
    assert len(m.assumptions) >= 4


# ======================================================== EFFORT ============
def test_major_version_bump_costs_more_than_a_patch():
    c = ctx()
    patch = M.estimate_effort(finding(), c)                    # 1.0.0 -> 1.0.1
    major = M.estimate_effort(
        RawFinding(scanner="osv", agent_slug="lib", title="t", package="p",
                   version="1.0.0", fixed_version="4.0.0", extra={"direct": True}), c)
    assert major.build_hours > patch.build_hours
    assert major.change_risk == "High"


def test_no_patched_version_is_the_most_expensive_case():
    e = M.estimate_effort(
        RawFinding(scanner="osv", agent_slug="lib", title="t", package="p",
                   version="1.0.0", fixed_version=None, extra={"direct": True}), ctx())
    assert e.build_hours >= 24
    assert "replaced" in e.basis


def test_loaded_hours_always_exceed_build_hours():
    e = M.estimate_effort(finding(), ctx())
    assert e.loaded_hours > e.build_hours      # review + ship + coordinate
    assert 0 < e.sprint_share < 1


def test_example_file_secret_is_cheaper_to_deal_with():
    real = M.estimate_effort(
        RawFinding(scanner="gitleaks", agent_slug="secret", title="t",
                   rule_id="aws-access-key", extra={}), ctx())
    sample = M.estimate_effort(
        RawFinding(scanner="gitleaks", agent_slug="secret", title="t",
                   rule_id="aws-access-key", extra={"example_file": True}), ctx())
    assert sample.build_hours < real.build_hours


# ======================================================== IMPACT ============
def test_impact_profile_comes_from_the_weakness_class():
    assert M.impact_profile(finding(cwe="CWE-400")).availability > 0.8
    assert M.impact_profile(finding(cwe="CWE-89")).confidentiality > 0.8
    assert "CWE-89" in M.impact_profile(finding(cwe="CWE-89")).basis


def test_unknown_weakness_falls_back_and_says_so():
    p = M.impact_profile(finding(cwe="CWE-99999"))
    assert "generic" in p.basis


def test_credential_type_drives_the_secret_profile():
    key = RawFinding(scanner="gitleaks", agent_slug="secret", title="t",
                     rule_id="private-key", extra={})
    tok = RawFinding(scanner="gitleaks", agent_slug="secret", title="t",
                     rule_id="openai-key", extra={})
    assert M.impact_profile(key).confidentiality > M.impact_profile(tok).confidentiality


# ======================================================== API ===============
def test_preview_refuses_to_price_without_context():
    r = client.post("/api/price/preview", json={
        "context": {"revenue_supported": 1_000_000},
        "finding": {"scanner": "osv", "cve": "CVE-2020-0001", "cvss": 9.0,
                    "cwe": "CWE-89", "package": "p", "version": "1.0.0"},
    })
    assert r.status_code == 200
    b = r.json()
    assert b["priced"] is False
    assert b["if_it_happens"] is None
    assert b["annual_loss_upper_bound"] is None
    assert "downtime_cost_hour" in b["context_missing"]
    assert b["context_score"] > 0              # still ranked


def test_preview_prices_with_full_context():
    r = client.post("/api/price/preview", json={
        "context": FULL,
        "finding": {"scanner": "osv", "cve": "CVE-2020-0001", "cvss": 9.0,
                    "cwe": "CWE-89", "package": "p", "version": "1.0.0",
                    "fixed_version": "1.0.4", "epss": 0.3},
    })
    b = r.json()
    assert b["priced"] is True
    assert b["if_it_happens"] > 0
    assert b["effort"]["loaded_hours"] > 0
    assert b["p_here_year"] is None            # still not computable
    assert len(b["components"]) >= 3
    assert all(c["basis"] for c in b["components"])


def test_context_validate_explains_what_is_missing():
    r = client.post("/api/context/validate", json={"revenue_supported": 5_000_000})
    b = r.json()
    assert b["complete"] is False
    assert "records_count" in b["missing"]
    assert "records_count" in b["why_it_matters"]
    assert "NOT priced" in b["effect"]


def test_repo_url_is_rejected_with_a_useful_message():
    reg = client.post("/api/auth/register", json={
        "email": "repo-url-test@example.com", "password": "password123",
        "name": "Tester", "org_name": "Repo URL Test Co",
    })
    headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}
    r = client.post("/api/projects", json={"repo": "https://github.com/a/b"}, headers=headers)
    assert r.status_code == 422
    assert "owner/repo" in str(r.json())


def test_unknown_regime_is_rejected():
    r = client.post("/api/context/validate", json={"regimes": ["FAKELAW"]})
    assert r.status_code == 422


def test_assumptions_endpoint_lists_every_judgement_call():
    b = client.get("/api/assumptions").json()
    assert len(b["assumptions"]) >= 5
    assert "aggregation" in b["assumptions"]


def test_regimes_endpoint_flags_figures_as_estimates():
    b = client.get("/api/regimes").json()
    assert len(b["regimes"]) >= 6
    assert "estimates" in b["note"]
