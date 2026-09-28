"""Part 1 acceptance.

The webhook tests are the important ones: signature verification is the only
thing standing between GitHub and anyone on the internet who would like us to
clone a repository of their choosing.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.integrations.github import webhook as wh
from app.main import app
from app.scanners import lockfiles
from app.scanners.base import RawFinding
from app.services.fingerprint import fingerprint

SECRET = "test-secret-value"
client = TestClient(app)


# --------------------------------------------------------------- signature --
def test_valid_signature_passes():
    body = b'{"zen":"Design for failure."}'
    wh.verify(body, wh.sign(body, SECRET), SECRET)          # must not raise


def test_tampered_body_rejected():
    body = b'{"repo":"good/repo"}'
    sig = wh.sign(body, SECRET)
    with pytest.raises(wh.BadSignature):
        wh.verify(b'{"repo":"evil/repo"}', sig, SECRET)


def test_missing_signature_rejected():
    with pytest.raises(wh.BadSignature, match="missing"):
        wh.verify(b"{}", None, SECRET)


def test_wrong_secret_rejected():
    body = b"{}"
    with pytest.raises(wh.BadSignature):
        wh.verify(body, wh.sign(body, "other-secret"), SECRET)


def test_unsupported_algorithm_rejected():
    with pytest.raises(wh.BadSignature, match="algorithm"):
        wh.verify(b"{}", "sha1=deadbeef", SECRET)


def test_empty_secret_rejected():
    body = b"{}"
    with pytest.raises(wh.BadSignature):
        wh.verify(body, wh.sign(body, ""), "")


def test_endpoint_rejects_unsigned_delivery():
    r = client.post("/webhooks/github", content=b"{}", headers={"x-github-event": "ping"})
    assert r.status_code in (401, 503)
    assert r.json()["error"] in ("bad_signature", "webhook_not_configured")


# ------------------------------------------------------------ push parsing --
PUSH = {
    "ref": "refs/heads/main",
    "before": "a" * 40,
    "after": "b" * 40,
    "deleted": False,
    "pusher": {"name": "k.mehta"},
    "repository": {"id": 42, "full_name": "apex/paykit-api",
                   "default_branch": "main", "private": True},
    "installation": {"id": 99},
    "head_commit": {"message": "bump grpc\n\nlong body"},
    "commits": [
        {"added": ["go.mod"], "modified": ["internal/x.go"], "removed": []},
        {"added": [], "modified": ["go.mod"], "removed": ["old.go"]},
    ],
}


def test_parse_push_collects_unique_changed_files():
    ev = wh.parse_push(PUSH)
    assert ev.repo == "apex/paykit-api"
    assert ev.branch == "main"
    assert ev.installation_id == 99
    assert ev.commit_message == "bump grpc"          # first line only
    assert ev.changed_files == ["go.mod", "internal/x.go", "old.go"]
    assert ev.is_default_branch is True
    assert ev.should_scan is True


def test_tag_push_is_not_scanned():
    ev = wh.parse_push({**PUSH, "ref": "refs/tags/v1.0.0"})
    assert ev.should_scan is False


def test_branch_deletion_is_not_scanned():
    ev = wh.parse_push({**PUSH, "deleted": True})
    assert ev.should_scan is False


# --------------------------------------------------------------- lockfiles --
def test_package_lock_v2():
    text = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root"},
            "node_modules/lodash": {"name": "lodash", "version": "4.17.15"},
            "node_modules/a/node_modules/ms": {"name": "ms", "version": "0.7.1"},
        },
    })
    pkgs = lockfiles.parse_package_lock(text, "package-lock.json")
    got = {(p.name, p.version, p.ecosystem) for p in pkgs}
    assert ("lodash", "4.17.15", "npm") in got
    assert ("ms", "0.7.1", "npm") in got


def test_requirements_only_takes_pinned_versions():
    text = "django==3.2.4\nrequests>=2.0\n# comment\nflask==2.0.1  # trailing\n-r other.txt\n"
    pkgs = lockfiles.parse_requirements(text, "requirements.txt")
    assert {(p.name, p.version) for p in pkgs} == {("django", "3.2.4"), ("flask", "2.0.1")}


def test_go_mod_strips_the_v_prefix():
    text = "module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/net v0.7.0 // indirect\n)\n"
    pkgs = lockfiles.parse_go_mod(text, "go.mod")
    by = {p.name: p for p in pkgs}
    assert by["github.com/gin-gonic/gin"].version == "1.9.0"
    assert by["golang.org/x/net"].direct is False


def test_malformed_lockfile_returns_empty_not_crash():
    assert lockfiles.parse_package_lock("{not json", "package-lock.json") == []
    assert lockfiles.parse_composer_lock("<<<", "composer.lock") == []


# ------------------------------------------------------------- fingerprint --
def _osv(pkg="ejs", ver="1.0.0", rule="GHSA-3w5v-p54c-f74x", file="package-lock.json"):
    return RawFinding(scanner="osv", agent_slug="lib", title="t", package=pkg,
                      version=ver, ecosystem="npm", rule_id=rule, file=file)


def test_fingerprint_survives_a_version_bump():
    """Same advisory, still-vulnerable newer version — the same finding, still ageing."""
    assert fingerprint(_osv(ver="1.0.0")) == fingerprint(_osv(ver="0.8.8"))


def test_fingerprint_survives_a_moved_lockfile():
    assert fingerprint(_osv(file="package-lock.json")) == fingerprint(_osv(file="ui/package-lock.json"))


def test_fingerprint_differs_per_advisory_and_package():
    assert fingerprint(_osv(rule="GHSA-aaaa")) != fingerprint(_osv(rule="GHSA-bbbb"))
    assert fingerprint(_osv(pkg="ejs")) != fingerprint(_osv(pkg="lodash"))


def test_code_fingerprint_ignores_line_number_but_not_file():
    a = RawFinding(scanner="semgrep", agent_slug="flaw_py", title="t",
                   rule_id="py.sqli", file="app/db.py", line=10)
    b = RawFinding(scanner="semgrep", agent_slug="flaw_py", title="t",
                   rule_id="py.sqli", file="app/db.py", line=884)
    c = RawFinding(scanner="semgrep", agent_slug="flaw_py", title="t",
                   rule_id="py.sqli", file="app/other.py", line=10)
    assert fingerprint(a) == fingerprint(b)       # a reformat must not resurrect it
    assert fingerprint(a) != fingerprint(c)


def test_fingerprint_is_hex_sha256():
    fp = fingerprint(_osv())
    assert len(fp) == 64 and all(c in "0123456789abcdef" for c in fp)
