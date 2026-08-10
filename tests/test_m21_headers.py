"""M21: RoE-wide headers (program-attribution like `BUGCROWD: handle`) are sent on
every request — required by many real bug-bounty programs."""
from __future__ import annotations

from pathlib import Path

import httpx

from heretic.config import Accounts, Config, LoginSpec, Role, Scope
from heretic.core.session_mgr import SessionManager


def _cfg(headers: dict) -> Config:
    return Config(
        url="http://app.local", model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000, scope=Scope(allow=["app.local"]), headers=headers,
        accounts_path=Path("accounts.yaml"),
        accounts=Accounts(login=LoginSpec(url="/login", token_field="token"),
                          roles=[Role(name="userA", creds={"email": "a@x", "password": "x"})]))


def test_roe_headers_sent_on_every_request():
    seen: list[dict] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({k: v for k, v in req.headers.items()})
        if req.url.path == "/login":
            return httpx.Response(200, json={"token": "t"})
        return httpx.Response(200, json={"ok": True})

    s = SessionManager(_cfg({"BUGCROWD": "syco7", "X-Correlation-Id": "bc-1"}),
                       transport=httpx.MockTransport(handler))
    s.login_all()
    s.get_as("userA", "/api/thing")
    s.close()

    # the attribution header rides on the login request AND every scan request
    assert all(h.get("bugcrowd") == "syco7" for h in seen)
    assert all(h.get("x-correlation-id") == "bc-1" for h in seen)


def test_auth_header_overrides_but_roe_headers_remain():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/login":
            return httpx.Response(200, json={"token": "tok"})
        assert req.headers.get("bugcrowd") == "syco7"           # attribution present
        assert req.headers.get("authorization") == "Bearer tok"  # auth still set
        return httpx.Response(200, json={})

    s = SessionManager(_cfg({"BUGCROWD": "syco7"}), transport=httpx.MockTransport(handler))
    s.login_all()
    s.get_as("userA", "/api/thing")
    s.close()
