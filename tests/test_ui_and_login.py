"""Menu UI banner + login-failure robustness (no more crashing on a 401)."""
from __future__ import annotations

import io
from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, LoginSpec, Role, Scope
from heretic.core.session_mgr import SessionManager
from heretic.ui import _MENU, banner


def test_login_failure_does_not_crash_and_is_recorded():
    def h(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/login":
            return httpx.Response(401, json={"error": "bad creds"})
        return httpx.Response(404, json={})

    cfg = Config(url="http://t.local", model="fake", engagement="t", authorized_by="a@b",
                 signed=True, scope=Scope(allow=["t.local"]), max_rate_rps=100000,
                 accounts_path=Path("x"),
                 accounts=Accounts(login=LoginSpec(url="/login", token_field="token"),
                                   roles=[Role(name="userA", creds={"email": "a@b", "password": "x"})]))
    sm = SessionManager(cfg, transport=httpx.MockTransport(h))
    sm.login_all()                                   # must NOT raise
    assert ("userA", "HTTP 401") in sm.login_errors
    assert "guest" in sm.roles() and "userA" not in sm.roles()


def test_banner_shows_author_and_github():
    c = Console(file=io.StringIO(), width=90)
    banner(c)
    out = c.file.getvalue()
    assert "SYCO7" in out and "github.com/SYCO7" in out
    assert "Business-Logic Vulnerability Agent" in out


def test_menu_has_all_actions():
    names = {name for _, name, _ in _MENU}
    assert {"Doctor", "Scan", "Live-check", "Benchmark", "Export", "Keys", "Quit"} <= names
