"""M10: login-response id harvest — reach owned ids the app hands you at login
(Juice Shop's basket `bid`) so the differential BOLA oracle can test cross-reads.
Offline: a mock that mints a per-user bid at login and lets any user read any basket.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, LoginObjectSpec, LoginSpec, Role, Scope
from heretic.core.orchestrator import Orchestrator
from heretic.llm.scripted import ScriptedLLM

_QUIET = Console(quiet=True)


def _handler(req: httpx.Request) -> httpx.Response:
    p = req.url.path
    if p == "/rest/user/login":
        email = json.loads(req.content or b"{}").get("email", "")
        bid = "6" if "userA" in email else "7"                       # per-user basket id
        who = email.split("@")[0]
        return httpx.Response(200, json={"authentication": {"token": f"tok-{who}", "bid": bid}})
    m = re.match(r"^/rest/basket/(\d+)$", p)
    if m:
        if not req.headers.get("authorization", "").startswith("Bearer tok-"):
            return httpx.Response(401, json={"error": "auth"})
        bid = m.group(1)                                             # IDOR: ANY authed user reads ANY basket
        return httpx.Response(200, json={"status": "success",
                                         "data": {"id": int(bid), "Products": [{"name": f"item-{bid}"}]}})
    return httpx.Response(404, json={})


def _cfg() -> Config:
    return Config(
        url="http://juice.local", model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000, scope=Scope(allow=["juice.local"]), classes=["bola"], chain=True,
        accounts_path=Path("accounts.yaml"),
        accounts=Accounts(
            login=LoginSpec(url="/rest/user/login", method="POST", token_field="authentication.token"),
            roles=[Role(name="guest", creds=None),
                   Role(name="userA", creds={"email": "userA@x", "password": "x"}),
                   Role(name="userB", creds={"email": "userB@x", "password": "x"})]),
        login_objects=[LoginObjectSpec(name="basket", item_url="/rest/basket/{id}",
                                       id_from="authentication.bid")])


def test_login_harvest_confirms_basket_idor():
    orch = Orchestrator(_cfg(), console=_QUIET, transport=httpx.MockTransport(_handler),
                        llm=ScriptedLLM())
    findings = orch.run()
    bola = [f for f in findings if f.bug_class == "bola"]
    # userA (bid 6) and userB (bid 7) each read the other's basket -> two confirmed IDORs
    assert len(bola) == 2
    assert all("basket" in f.title for f in bola)


def test_login_harvest_no_false_positive_when_scoped():
    """If baskets are per-user (each user only reads their own), nothing is confirmed."""
    def safe(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p == "/rest/user/login":
            email = json.loads(req.content or b"{}").get("email", "")
            bid = "6" if "userA" in email else "7"
            return httpx.Response(200, json={"authentication": {"token": f"tok-{bid}", "bid": bid}})
        m = re.match(r"^/rest/basket/(\d+)$", p)
        if m:
            tok = req.headers.get("authorization", "").removeprefix("Bearer tok-")
            if tok != m.group(1):                                   # only the owner may read
                return httpx.Response(403, json={"error": "forbidden"})
            return httpx.Response(200, json={"data": {"id": int(m.group(1))}})
        return httpx.Response(404, json={})

    orch = Orchestrator(_cfg(), console=_QUIET, transport=httpx.MockTransport(safe), llm=ScriptedLLM())
    assert [f for f in orch.run() if f.bug_class == "bola"] == []
