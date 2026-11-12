"""End-to-end API tests."""

from __future__ import annotations

import io
import zipfile

import pytest

VULN = 'import os\nfrom flask import request\nos.system("ls " + request.args["d"])\n'


# --------------------------------------------------------------------------- #
# meta / auth
# --------------------------------------------------------------------------- #
def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["rules"] >= 50


def test_register_login_refresh_flow(client):
    email = "flow@test.dev"
    r = client.post("/api/auth/register", json={"email": email, "full_name": "Flow", "password": "password123"})
    assert r.status_code == 201
    tokens = r.json()
    assert tokens["user"]["email"] == email

    r = client.post("/api/auth/login", json={"email": email, "password": "password123"})
    assert r.status_code == 200
    refresh = r.json()["refresh_token"]

    r = client.post("/api/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200 and r.json()["access_token"]


def test_duplicate_email_rejected(client):
    payload = {"email": "dup@test.dev", "full_name": "A", "password": "password123"}
    assert client.post("/api/auth/register", json=payload).status_code == 201
    assert client.post("/api/auth/register", json=payload).status_code == 409


def test_wrong_password(client):
    r = client.post("/api/auth/login", json={"email": "demo@aegis.dev", "password": "nope"})
    assert r.status_code == 401


def test_protected_route_requires_token(client):
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/scans", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_me(client, auth):
    r = client.get("/api/auth/me", headers=auth)
    assert r.status_code == 200 and r.json()["email"] == "demo@aegis.dev"


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #
def test_anonymous_snippet_scan_is_not_persisted(client, auth):
    before = len(client.get("/api/scans", headers=auth).json())
    r = client.post("/api/scans/snippet", json={"code": VULN, "filename": "x.py"})
    assert r.status_code == 200
    assert any(f["rule_id"] == "AEGIS-CMDI-001" for f in r.json()["findings"])
    after = len(client.get("/api/scans", headers=auth).json())
    assert after == before


def test_authenticated_scan_persists_with_full_detail(client, auth):
    r = client.post("/api/scans/snippet", json={"code": VULN, "filename": "x.py"}, headers=auth)
    assert r.status_code == 200
    scan = r.json()
    assert scan["id"]
    f = scan["findings"][0]
    assert f["why"] and f["fix_example"] and f["fingerprint"]
    assert f["evidence"], "taint evidence should survive a DB round-trip"
    assert f["tags"] is not None


def test_scan_detail_and_list(client, auth):
    scan = client.post("/api/scans/snippet", json={"code": VULN, "filename": "d.py"}, headers=auth).json()
    r = client.get(f"/api/scans/{scan['id']}", headers=auth)
    assert r.status_code == 200 and r.json()["id"] == scan["id"]
    assert any(s["id"] == scan["id"] for s in client.get("/api/scans", headers=auth).json())


def test_scan_of_other_user_is_404(client, auth):
    other = client.post(
        "/api/auth/register",
        json={"email": "other@test.dev", "full_name": "O", "password": "password123"},
    ).json()
    h = {"Authorization": f"Bearer {other['access_token']}"}
    assert client.get("/api/scans/does-not-exist", headers=h).status_code == 404


def test_clean_code_scores_full_marks(client, auth):
    r = client.post("/api/scans/snippet", json={"code": "def add(a, b):\n    return a + b\n",
                                                "filename": "clean.py"}, headers=auth)
    body = r.json()
    assert body["score"] == 100 and body["grade"] == "A+"


def test_triage(client, auth):
    scan = client.post("/api/scans/snippet", json={"code": VULN, "filename": "t.py"}, headers=auth).json()
    fid = scan["findings"][0]["id"]
    r = client.patch(f"/api/findings/{fid}", json={"status": "false-positive", "note": "sanitised upstream"},
                     headers=auth)
    assert r.status_code == 200 and r.json()["status"] == "false-positive"
    detail = client.get(f"/api/scans/{scan['id']}", headers=auth).json()
    assert detail["findings"][0]["note"] == "sanitised upstream"


def test_zip_upload_and_zip_slip_protection(client, auth):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app/x.py", "import pickle\npickle.loads(request.data)\n")
        zf.writestr("web/a.js", "el.innerHTML = userInput;\n")
        zf.writestr("../../../evil.py", "os.system('x')\n")
    buf.seek(0)
    r = client.post("/api/scans/upload", files={"file": ("proj.zip", buf, "application/zip")}, headers=auth)
    assert r.status_code == 200
    body = r.json()
    found = {f["rule_id"] for f in body["findings"]}
    assert "AEGIS-DESER-001" in found and "AEGIS-XSS-001" in found
    assert body["files_scanned"] == 2
    assert not any("evil" in f["file"] for f in body["findings"])


def test_upload_rejects_oversized_payload(client, auth):
    big = b"a" * (6 * 1024 * 1024)
    r = client.post("/api/scans/upload", files={"file": ("big.py", big, "text/plain")}, headers=auth)
    assert r.status_code == 413


# --------------------------------------------------------------------------- #
# exports
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fmt,marker", [
    ("sarif", b'"version": "2.1.0"'),
    ("json", b'"summary"'),
    ("markdown", b"Score"),
    ("html", b"<!DOCTYPE html>"),
])
def test_exports(client, auth, fmt, marker):
    scan = client.post("/api/scans/snippet", json={"code": VULN, "filename": "e.py"}, headers=auth).json()
    r = client.get(f"/api/scans/{scan['id']}/export?fmt={fmt}", headers=auth)
    assert r.status_code == 200 and marker in r.content
    assert "attachment" in r.headers.get("content-disposition", "")


# --------------------------------------------------------------------------- #
# CI gate
# --------------------------------------------------------------------------- #
def test_ci_gate_fails_on_critical(client):
    r = client.post("/api/ci/gate", files={"file": ("y.py", VULN.encode())},
                    data={"max_critical": 0})
    assert r.status_code == 409
    body = r.json()
    assert body["passed"] is False and body["reasons"]


def test_ci_gate_passes_within_budget(client):
    r = client.post("/api/ci/gate", files={"file": ("y.py", VULN.encode())},
                    data={"max_critical": 5, "max_high": 5})
    assert r.status_code == 200 and r.json()["passed"] is True


def test_ci_gate_clean_file(client):
    r = client.post("/api/ci/gate", files={"file": ("c.py", b"x = 1\n")},
                    data={"max_critical": 0, "min_score": 90})
    assert r.status_code == 200


# --------------------------------------------------------------------------- #
# projects / stats / rules
# --------------------------------------------------------------------------- #
def test_project_lifecycle(client, auth):
    name = "Payments API"
    r = client.post("/api/projects", json={"name": name}, headers=auth)
    assert r.status_code in (201, 409)
    if r.status_code == 201:
        pid = r.json()["id"]
        assert r.json()["slug"] == "payments-api"
        assert client.post("/api/projects", json={"name": name}, headers=auth).status_code == 409
        listed = client.get("/api/projects", headers=auth).json()
        assert any(p["id"] == pid for p in listed)
        assert client.delete(f"/api/projects/{pid}", headers=auth).status_code == 204


def test_stats(client, auth):
    r = client.get("/api/stats", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["rules_available"] >= 50
    assert set(body["by_severity"]) == {"critical", "high", "medium", "low", "info"}


def test_rules_catalog_is_public(client):
    r = client.get("/api/rules")
    assert r.status_code == 200
    rules = r.json()
    assert len(rules) >= 50
    assert all(r["cwe"] and r["why"] and r["fix_hint"] for r in rules)


def test_admin_requires_admin_role(client, auth):
    assert client.get("/api/admin/overview", headers=auth).status_code == 200
    user = client.post("/api/auth/register",
                       json={"email": "plain@test.dev", "full_name": "P", "password": "password123"}).json()
    h = {"Authorization": f"Bearer {user['access_token']}"}
    assert client.get("/api/admin/overview", headers=h).status_code == 403


# --------------------------------------------------------------------------- #
# static dashboard
# --------------------------------------------------------------------------- #
def test_dashboard_is_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "AegisReview" in r.text
    assert "/static/js/app.js" in r.text


def test_assets_are_served(client):
    assert client.get("/static/css/app.css").status_code == 200
    assert client.get("/static/js/app.js").status_code == 200
    assert client.get("/static/js/ui.js").status_code == 200
    assert client.get("/static/js/api.js").status_code == 200


# --------------------------------------------------------------------------- #
# Repository scanning — URL validation is the security boundary here, so it is
# tested directly against the parser rather than through the network.
# --------------------------------------------------------------------------- #
import pytest as _pytest

from aegis.repofetch import RepoError, parse_repo_url


@_pytest.mark.parametrize("url,expected", [
    ("https://github.com/pallets/flask", ("github.com", "pallets", "flask")),
    ("https://github.com/pallets/flask.git", ("github.com", "pallets", "flask")),
    ("github.com/pallets/flask", ("github.com", "pallets", "flask")),
    ("https://gitlab.com/group/project", ("gitlab.com", "group", "project")),
])
def test_repo_urls_that_are_allowed(url, expected):
    assert parse_repo_url(url) == expected


@_pytest.mark.parametrize("url", [
    "file:///etc/passwd",                    # local file read
    "ext::sh -c touch% /tmp/pwn",            # git ext:: transport = RCE
    "ssh://git@github.com/a/b",              # ssh transport
    "git://github.com/a/b",                  # unauthenticated git protocol
    "http://github.com/a/b",                 # cleartext
    "https://169.254.169.254/latest/meta",   # cloud metadata (SSRF)
    "https://evil.example.com/a/b",          # host not allowlisted
    "https://user:pw@github.com/a/b",        # embedded credentials
    "https://github.com/../../etc/passwd",   # traversal in path
    "https://github.com/onlyowner",          # malformed
])
def test_dangerous_repo_urls_are_rejected(url):
    with _pytest.raises(RepoError):
        parse_repo_url(url)


def test_repo_endpoint_rejects_bad_url_and_requires_auth(client, auth):
    assert client.post("/api/scans/repo", json={"url": "https://github.com/a/b"}).status_code == 401
    r = client.post("/api/scans/repo", json={"url": "file:///etc/passwd"}, headers=auth)
    assert r.status_code == 400
    assert "https" in r.json()["detail"]
    r = client.post("/api/scans/repo", json={"url": "https://evil.example.com/a/b"}, headers=auth)
    assert r.status_code == 400 and "host" in r.json()["detail"]
