"""Part 2 acceptance: scanners, enrichment and contextual scoring."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from app.enrich.epss import EpssScore, annualise
from app.enrich.kev import KevEntry
from app.scanners import code, secrets
from app.scanners.base import RawFinding, ScanContext
from app.services.scoring import cvss_tier, disagreement, score


# ============================================================ EPSS ==========
def test_epss_annualisation_compounds():
    """A 3% chance over 30 days is not a 3% chance over a year."""
    assert annualise(0.03) == pytest.approx(0.31, abs=0.02)
    assert annualise(0.0) == 0.0
    assert annualise(1.0) == 1.0


def test_epss_annual_always_exceeds_monthly():
    for p in (0.001, 0.01, 0.1, 0.5):
        assert annualise(p) > p


def test_epss_band_labels():
    assert EpssScore("CVE-1", 0.9, 0.995, "2026-09-10").band == "top 1%"
    assert EpssScore("CVE-2", 0.5, 0.96, "2026-09-10").band == "top 5%"
    assert "percentile" in EpssScore("CVE-3", 0.1, 0.42, "2026-09-10").band


# ============================================================ scoring =======
def osv_finding(cvss=None, cve="CVE-2020-0001", direct=True):
    return RawFinding(scanner="osv", agent_slug="lib", title="t", package="p",
                      version="1.0", ecosystem="npm", cve=cve, cvss=cvss,
                      rule_id="GHSA-x", extra={"direct": direct})


def test_kev_plus_high_epss_escalates_a_medium_cvss():
    """The product thesis: a CVSS 5.5 that is actually being exploited outranks
    a CVSS 9.5 that nobody has ever touched."""
    exploited = score(
        osv_finding(cvss=5.5),
        EpssScore("CVE-2020-0001", 0.84, 0.99, "2026-09-10"),
        KevEntry("CVE-2020-0001", "v", "p", "n", "2025-01-23", "2025-02-13", False, "patch"),
    )
    dormant = score(osv_finding(cvss=9.5), EpssScore("CVE-2020-0002", 0.005, 0.41, "2026-09-10"), None)
    assert exploited.score > dormant.score
    assert exploited.tier > dormant.tier
    assert disagreement(osv_finding(cvss=5.5), exploited) > 0     # escalated
    assert disagreement(osv_finding(cvss=9.5), dormant) < 0       # deprioritised


def test_transitive_dependency_scores_below_a_direct_one():
    e = EpssScore("CVE-2020-0001", 0.2, 0.8, "2026-09-10")
    assert score(osv_finding(cvss=7.5, direct=False), e).score < \
           score(osv_finding(cvss=7.5, direct=True), e).score


def test_probability_is_never_presented_as_yours():
    """We publish 'exploited somewhere in the wild', never 'you will be breached'."""
    r = score(osv_finding(cvss=7.5), EpssScore("CVE-2020-0001", 0.5, 0.9, "2026-09-10"))
    assert r.p_wild_30d == 0.5
    assert r.p_here_year is None          # needs reachability + exposure
    assert "world" in r.p_note


def test_annual_probability_does_not_saturate_to_certainty():
    r = score(osv_finding(cvss=7.5), EpssScore("CVE-2020-0001", 0.9, 0.99, "2026-09-10"))
    assert r.p_wild_year is not None and r.p_wild_year <= 0.95


def test_unmeasured_factors_are_declared_and_neutral():
    r = score(osv_finding(cvss=7.5))
    unmeasured = [f for f in r.factors if not f.measured]
    assert {f.name for f in unmeasured} == {"Reachability", "Internet exposure", "Business criticality"}
    assert all(f.value == 1.0 for f in unmeasured)      # neutral, never inflating
    assert len(r.pending) == 3
    assert r.basis == "technical"


def test_cvss_tier_boundaries():
    assert cvss_tier(9.0) == 4 and cvss_tier(8.9) == 3
    assert cvss_tier(7.0) == 3 and cvss_tier(6.9) == 2
    assert cvss_tier(None) == 0


def test_score_stays_in_range():
    for c in (None, 0.1, 5.0, 10.0):
        assert 1 <= score(osv_finding(cvss=c)).score <= 99


# ============================================================ secrets ======
def write(tmp: Path, rel: str, body: str) -> None:
    p = tmp / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body), encoding="utf-8")


def scan_secrets(tmp: Path):
    return secrets.scan(ScanContext(root=tmp, repo="t/t"))


def test_aws_key_detected_and_value_redacted(tmp_path):
    write(tmp_path, "cfg.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    found = scan_secrets(tmp_path)
    assert any(f.rule_id == "aws-access-key" for f in found)
    f = next(f for f in found if f.rule_id == "aws-access-key")
    # The value must never survive in full.
    assert "AKIAIOSFODNN7EXAMPLE" not in f.extra["redacted"]
    assert f.extra["redacted"].startswith("AKIA")
    assert "AKIAIOSFODNN7EXAMPLE" not in (f.summary or "")


def test_private_key_block_detected(tmp_path):
    write(tmp_path, "deploy/key.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n")
    assert any(f.rule_id == "private-key" for f in scan_secrets(tmp_path))


def test_placeholders_are_not_reported(tmp_path):
    write(tmp_path, "a.py", '''
        api_key = "your-api-key-here"
        password = "changeme"
        secret = "xxxxxxxxxxxxxxxxxxxx"
        token = "<YOUR_TOKEN>"
    ''')
    assert [f for f in scan_secrets(tmp_path) if f.extra.get("detector") == "entropy"] == []


def test_hash_digests_are_not_mistaken_for_secrets(tmp_path):
    write(tmp_path, "a.py", 'secret = "5d41402abc4b2a76b9719d911017c592"\n')   # md5
    assert [f for f in scan_secrets(tmp_path) if f.extra.get("detector") == "entropy"] == []


def test_lockfiles_are_skipped_entirely(tmp_path):
    write(tmp_path, "package-lock.json",
          '{"x":{"integrity":"sha512-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH=="}}')
    assert scan_secrets(tmp_path) == []


def test_example_files_are_downgraded_not_hidden(tmp_path):
    write(tmp_path, ".env.example", 'STRIPE = "sk_live_abcdefghij0123456789XY"\n')
    found = scan_secrets(tmp_path)
    assert found, "an example file should still be reported"
    assert found[0].extra["example_file"] is True
    assert found[0].extra["confidence"] < 0.7
    assert found[0].severity_label == "LOW"


# ============================================================ code =========
def scan_code(tmp: Path):
    return code.scan(ScanContext(root=tmp, repo="t/t"))


def test_sql_injection_across_lines_is_caught(tmp_path):
    """The real-world shape: build on one line, execute on another."""
    write(tmp_path, "dao.py", '''
        async def create(conn, name):
            q = ("INSERT INTO students (name) VALUES ('%(name)s')" % {'name': name})
            async with conn.cursor() as cur:
                await cur.execute(q)
    ''')
    found = scan_code(tmp_path)
    sqli = [f for f in found if f.rule_id == "py.sql-injection"]
    assert len(sqli) == 1
    assert "then executed here" in sqli[0].summary


def test_parameterised_query_is_not_flagged(tmp_path):
    write(tmp_path, "ok.py", '''
        async def get(conn, id_):
            async with conn.cursor() as cur:
                await cur.execute("SELECT * FROM users WHERE id = %s", (id_,))
    ''')
    assert [f for f in scan_code(tmp_path) if f.rule_id == "py.sql-injection"] == []


def test_taint_does_not_leak_between_functions(tmp_path):
    write(tmp_path, "two.py", '''
        def builder(name):
            q = "SELECT %s" % name
            return q

        def runner(conn, q):
            conn.execute(q)
    ''')
    assert [f for f in scan_code(tmp_path) if f.rule_id == "py.sql-injection"] == []


def test_eval_on_literal_is_ignored_but_on_variable_is_not(tmp_path):
    write(tmp_path, "e.py", '''
        def a():
            eval("1 + 1")

        def b(user_input):
            eval(user_input)
    ''')
    hits = [f for f in scan_code(tmp_path) if f.rule_id == "py.dynamic-exec"]
    assert len(hits) == 1


def test_yaml_safe_loader_is_accepted(tmp_path):
    write(tmp_path, "y.py", '''
        import yaml
        def a(s):
            yaml.load(s, Loader=yaml.SafeLoader)
        def b(s):
            yaml.load(s)
    ''')
    assert len([f for f in scan_code(tmp_path) if f.rule_id == "py.yaml-unsafe-load"]) == 1


def test_vendored_javascript_is_skipped(tmp_path):
    payload = "el.innerHTML = userValue;\n"
    write(tmp_path, "static/js/materialize.js", payload)
    write(tmp_path, "src/app.js", payload)
    files = {f.file for f in scan_code(tmp_path)}
    assert "src/app.js" in files
    assert "static/js/materialize.js" not in files


def test_go_insecure_skip_verify(tmp_path):
    write(tmp_path, "main.go", "cfg := &tls.Config{InsecureSkipVerify: true}\n")
    assert any(f.rule_id == "go.tls-skip-verify" for f in scan_code(tmp_path))


def test_comments_do_not_trigger_pattern_rules(tmp_path):
    write(tmp_path, "a.js", "// eval(userInput) is dangerous, do not do this\n")
    assert scan_code(tmp_path) == []


def test_unparseable_python_is_skipped_not_fatal(tmp_path):
    write(tmp_path, "broken.py", "def f(:\n   this is not python\n")
    assert scan_code(tmp_path) == []
