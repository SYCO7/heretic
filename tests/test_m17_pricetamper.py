"""M17: deterministic price tampering via negative quantity. A cart endpoint that
accepts and reflects a negative quantity is confirmed; one that clamps it is not.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, LoginSpec, Role, Scope
from heretic.core.orchestrator import Orchestrator
from heretic.core.pricetamper import reflects_negative_quantity
from heretic.llm.scripted import ScriptedLLM


def test_reflects_negative_quantity_helper():
    assert reflects_negative_quantity({"data": {"quantity": -100}}) == ("quantity", -100)
    assert reflects_negative_quantity({"data": {"qty": 5}}) is None
    assert reflects_negative_quantity({"items": [{"quantity": -3}]}) == ("quantity", -3)
    assert reflects_negative_quantity({"paid": True}) is None            # bool is not a negative qty


def _vuln(req: httpx.Request) -> httpx.Response:
    if req.url.path == "/login":
        return httpx.Response(200, json={"authentication": {"token": "tok-a", "bid": 6}})
    if req.url.path == "/api/BasketItems":
        body = json.loads(req.content or b"{}")
        q = body.get("quantity", body.get("qty"))
        return httpx.Response(201, json={"data": {"id": 10, "quantity": q}})    # trusts client quantity
    return httpx.Response(404, json={})


def _safe(req: httpx.Request) -> httpx.Response:
    if req.url.path == "/login":
        return httpx.Response(200, json={"authentication": {"token": "tok-a", "bid": 6}})
    if req.url.path == "/api/BasketItems":
        return httpx.Response(201, json={"data": {"id": 10, "quantity": 1}})    # clamps to 1
    return httpx.Response(404, json={})


def _cfg(mode: str = "live") -> Config:
    return Config(
        url="http://shop.local", model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000, scope=Scope(allow=["shop.local"]), classes=["price_tamper"],
        mode=mode, destructive_allowed=["*"], chain=False, accounts_path=Path("accounts.yaml"),
        accounts=Accounts(login=LoginSpec(url="/login", token_field="authentication.token"),
                          roles=[Role(name="guest", creds=None),
                                 Role(name="userA", creds={"email": "a@x", "password": "x"})]))


def _run(handler, mode="live"):
    orch = Orchestrator(_cfg(mode), console=Console(quiet=True), transport=httpx.MockTransport(handler),
                        llm=ScriptedLLM())
    return [f for f in orch.run() if f.bug_class == "price_tamper"]


def test_negative_quantity_is_confirmed():
    pt = _run(_vuln)
    assert len(pt) == 1
    assert pt[0].proof["oracle"] == "reflected_negative_quantity"
    assert pt[0].proof["field"] == "quantity" and pt[0].proof["value"] == -100


def test_clamped_quantity_is_not_flagged():
    assert _run(_safe) == []                                             # server clamped → no FP


def test_pricetamper_gated_in_dry_run():
    assert _run(_vuln, mode="dry-run") == []                            # state-changing → skipped
