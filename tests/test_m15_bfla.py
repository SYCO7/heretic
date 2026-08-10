"""M15: Broken Function-Level Authorization oracle. Confirms an admin function that
is open to guests, or reachable by a regular user; leaves properly-gated ones alone.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, LoginSpec, Role, Scope
from heretic.core.orchestrator import Orchestrator
from heretic.llm.scripted import ScriptedLLM


def _handler(req: httpx.Request) -> httpx.Response:
    p = req.url.path
    if p == "/login":
        who = json.loads(req.content or b"{}").get("email", "").split("@")[0]
        return httpx.Response(200, json={"token": f"tok-{who}"})
    authed = req.headers.get("authorization", "").startswith("Bearer tok-")
    if p == "/rest/admin/application-configuration":            # OPEN admin function (guest reaches)
        return httpx.Response(200, json={"config": {"secretKey": "x"}})
    if p == "/admin/users":                                     # guest denied, regular user reaches
        return httpx.Response(200, json={"users": [1, 2]}) if authed else httpx.Response(401, json={})
    if p == "/console":                                         # properly gated: userA forbidden
        return httpx.Response(403, json={}) if authed else httpx.Response(401, json={})
    return httpx.Response(404, json={})


def _cfg() -> Config:
    return Config(
        url="http://app.local", model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000, scope=Scope(allow=["app.local"]), classes=["bfla"], chain=False,
        accounts_path=Path("accounts.yaml"),
        accounts=Accounts(login=LoginSpec(url="/login", token_field="token"),
                          roles=[Role(name="guest", creds=None),
                                 Role(name="userA", creds={"email": "userA@x", "password": "x"})]))


def test_bfla_confirms_open_and_reachable_admin_functions():
    orch = Orchestrator(_cfg(), console=Console(quiet=True), transport=httpx.MockTransport(_handler),
                        llm=ScriptedLLM())
    found = {f.invariant_id: f for f in orch.run() if f.bug_class == "bfla"}

    # 1) admin config open to unauthenticated callers
    open_admin = found["BFLA:/rest/admin/application-configuration"]
    assert "unauthenticated" in open_admin.title
    assert open_admin.proof["reached_by"] == "guest"

    # 2) regular user reaches an /admin function (guest denied, strong marker)
    esc = found["BFLA:/admin/users"]
    assert "regular user reaches" in esc.title
    assert esc.proof["userA_status"] == 200 and esc.proof["guest_status"] == 401


def test_bfla_leaves_properly_gated_functions_alone():
    orch = Orchestrator(_cfg(), console=Console(quiet=True), transport=httpx.MockTransport(_handler),
                        llm=ScriptedLLM())
    flagged = {f.invariant_id for f in orch.run() if f.bug_class == "bfla"}
    assert "BFLA:/console" not in flagged                       # userA gets 403 — access control holds
