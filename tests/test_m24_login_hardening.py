"""M24: login_detect hardened for real-world auth — cookie sessions, CSRF-guarded
logins, and form-encoded bodies, detected AND replayed at scan time.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx

from heretic.config import Accounts, Config, CsrfSpec, LoginSpec, Role, Scope
from heretic.core.login_detect import detect_login
from heretic.core.session_mgr import SessionManager

_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.sig"


# ---- detection: cookie session --------------------------------------------

def _cookie_login(req: httpx.Request) -> httpx.Response:
    if req.url.path == "/login" and req.method == "POST":
        body = json.loads(req.content or b"{}")
        if body.get("username") and body.get("password"):
            return httpx.Response(200, headers={"set-cookie": "sessionid=sess-abc; Path=/; HttpOnly"},
                                  json={"ok": True})                 # session cookie, no body token
        return httpx.Response(401, json={})
    return httpx.Response(404, json={})


def test_detect_cookie_session():
    spec = detect_login("http://web.local", "alice", "pw", transport=httpx.MockTransport(_cookie_login))
    assert spec is not None
    assert spec["token_field"] == "cookie:sessionid"
    assert spec["auth_header"] == "Cookie: sessionid={token}"
    assert "username" in spec["cred_fields"]


# ---- detection: CSRF-guarded login (Laravel/Angular XSRF cookie) ----------

def _csrf_login():
    def h(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if req.method == "GET" and p in ("/login", "/"):
            return httpx.Response(200, headers={"set-cookie": "XSRF-TOKEN=csrf-xyz; Path=/"},
                                  text="<html>login</html>")
        if req.method == "POST" and p == "/api/login":
            if req.headers.get("x-xsrf-token") == "csrf-xyz":
                body = json.loads(req.content or b"{}")
                if body.get("email"):
                    return httpx.Response(200, json={"token": _JWT})
            return httpx.Response(419, json={"error": "CSRF token mismatch"})   # Laravel 419
        return httpx.Response(404, json={})
    return h


def test_detect_csrf_guarded_login():
    spec = detect_login("http://lara.local", "a@x", "pw", transport=httpx.MockTransport(_csrf_login()))
    assert spec is not None
    assert spec["csrf"] and spec["csrf"]["source"] == "cookie:XSRF-TOKEN"
    assert spec["csrf"]["header"] == "X-XSRF-TOKEN"
    assert spec["token_field"] == "token"


# ---- detection: form-encoded login ----------------------------------------

def _form_login(req: httpx.Request) -> httpx.Response:
    if req.url.path == "/login" and req.method == "POST":
        if "application/x-www-form-urlencoded" in req.headers.get("content-type", ""):
            data = parse_qs(req.content.decode())
            if data.get("username") and data.get("password"):
                return httpx.Response(200, headers={"set-cookie": "session=s1; Path=/"}, text="ok")
        return httpx.Response(400, text="bad")
    return httpx.Response(404, text="nf")


def test_detect_form_encoded_login():
    spec = detect_login("http://old.local", "bob", "pw", transport=httpx.MockTransport(_form_login))
    assert spec is not None
    assert spec["content_type"] == "form"
    assert spec["token_field"] == "cookie:session"


# ---- scan-time replay: CSRF pre-fetch + cookie-session auth end to end -----

def _csrf_cookie_app():
    def h(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if req.method == "GET" and p == "/csrf-seed":
            return httpx.Response(200, headers={"set-cookie": "XSRF-TOKEN=tok9; Path=/"})
        if req.method == "POST" and p == "/api/login":
            if req.headers.get("x-xsrf-token") == "tok9" and json.loads(req.content or b"{}").get("email"):
                return httpx.Response(200, headers={"set-cookie": "session=SESS1; Path=/"}, json={"ok": True})
            return httpx.Response(419, json={})
        if req.method == "GET" and p == "/api/me":
            if "session=SESS1" in req.headers.get("cookie", ""):
                return httpx.Response(200, json={"id": 1, "email": "a@x"})
            return httpx.Response(401, json={})
        return httpx.Response(404, json={})
    return h


def test_scan_time_csrf_and_cookie_login():
    cfg = Config(
        url="http://app.local", model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000, scope=Scope(allow=["app.local"]), classes=["bola"], chain=False,
        accounts_path=Path("accounts.yaml"),
        accounts=Accounts(
            login=LoginSpec(url="/api/login", token_field="cookie:session",
                            auth_header="Cookie: session={token}",
                            csrf=CsrfSpec(fetch_url="/csrf-seed", source="cookie:XSRF-TOKEN",
                                          header="X-XSRF-TOKEN")),
            roles=[Role(name="guest", creds=None),
                   Role(name="userA", creds={"email": "a@x", "password": "pw"})]))
    sm = SessionManager(cfg, transport=httpx.MockTransport(_csrf_cookie_app()))
    sm.login_all()
    assert not sm.login_errors                              # CSRF + cookie login succeeded
    assert "userA" in sm.roles()
    assert sm.get_as("userA", "/api/me").status_code == 200  # session cookie replayed as a header
    sm.close()
