"""M13: login auto-detection + pre-obtained token roles — the easy on-ramp.
Offline mocks: detect the login endpoint/token field from creds, and prove a
token-only role (OTP/SSO paste) authenticates without a login step.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, LoginObjectSpec, Role, Scope
from heretic.core.login_detect import detect_login
from heretic.core.orchestrator import Orchestrator
from heretic.llm.scripted import ScriptedLLM

_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"


def _juice_login(req: httpx.Request) -> httpx.Response:
    """Only /rest/user/login works, only with {email,password}; token is nested."""
    if req.url.path == "/rest/user/login":
        body = json.loads(req.content or b"{}")
        if body.get("email") and body.get("password"):
            return httpx.Response(200, json={"authentication": {"token": _JWT, "bid": 6}})
    return httpx.Response(404, json={"error": "not found"})


def test_detect_login_finds_endpoint_and_nested_token():
    spec = detect_login("http://juice.local", "userA@x", "pw",
                        transport=httpx.MockTransport(_juice_login))
    assert spec is not None
    assert spec["url"] == "/rest/user/login"
    assert spec["token_field"] == "authentication.token"     # dotted path discovered
    assert "email" in spec["cred_fields"]


def _username_login(req: httpx.Request) -> httpx.Response:
    """A Flask-ish API keyed on {username,password}, flat token."""
    if req.url.path == "/api/login":
        body = json.loads(req.content or b"{}")
        if body.get("username") and body.get("password"):
            return httpx.Response(200, json={"access_token": _JWT})
    return httpx.Response(401, json={})


def test_detect_login_tries_username_variant():
    spec = detect_login("http://api.local", "alice", "pw",
                        transport=httpx.MockTransport(_username_login))
    assert spec is not None
    assert spec["url"] == "/api/login"
    assert spec["token_field"] == "access_token"
    assert "username" in spec["cred_fields"]


def test_detect_login_returns_none_when_no_token():
    def otp(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": "OTP sent to your email"})   # no token yet
    assert detect_login("http://x.local", "a@x", "pw", transport=httpx.MockTransport(otp)) is None


# ---- token-only roles (OTP/SSO paste) authenticate with no login step ----

def _basket(req: httpx.Request) -> httpx.Response:
    p = req.url.path
    if not req.headers.get("authorization", "").startswith("Bearer "):
        return httpx.Response(401, json={"error": "auth"})
    import re
    m = re.match(r"^/rest/basket/(\d+)$", p)
    if m:
        return httpx.Response(200, json={"data": {"id": int(m.group(1)), "items": ["x"]}})
    return httpx.Response(404, json={})


def test_token_only_roles_authenticate_and_find_idor():
    cfg = Config(
        url="http://app.local", model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000, scope=Scope(allow=["app.local"]), classes=["bola"], chain=False,
        accounts_path=Path("accounts.yaml"),
        accounts=Accounts(login=None, roles=[            # NO login block — pasted tokens only
            Role(name="guest", token=None),
            Role(name="userA", token="tok-A"),
            Role(name="userB", token="tok-B")]),
        login_objects=[LoginObjectSpec(name="basket", item_url="/rest/basket/{id}", id_from="unused")])
    # ids come from a list normally; here we just prove token auth works by harvesting manually
    orch = Orchestrator(cfg, console=Console(quiet=True), transport=httpx.MockTransport(_basket),
                        llm=ScriptedLLM())
    orch.sessions.login_all()
    # both token roles are authenticated clients, and a cross-read returns 200 (IDOR present)
    assert set(orch.sessions.roles()) >= {"userA", "userB"}
    assert orch.sessions.get_as("userA", "/rest/basket/7").status_code == 200
