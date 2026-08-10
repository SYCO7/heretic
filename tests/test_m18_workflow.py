"""M18: deterministic workflow bypass. A checkout that returns an order confirmation
without any payment step is confirmed; an error / gated checkout is not.
"""
from __future__ import annotations

from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, LoginSpec, Role, Scope
from heretic.core.orchestrator import Orchestrator
from heretic.core.workflow import order_confirmation, reflects_state
from heretic.llm.scripted import ScriptedLLM


def test_helpers():
    assert order_confirmation({"orderConfirmation": "abc"}) == ("orderConfirmation", "abc")
    assert order_confirmation({"status": "error"}) is None
    assert reflects_state({"data": {"status": "paid"}}, "status", "paid")
    assert reflects_state({"data": {"paid": True}}, "paid", True)
    assert not reflects_state({"data": {"status": "pending"}}, "status", "paid")


def _vuln(req: httpx.Request) -> httpx.Response:
    if req.url.path == "/login":
        return httpx.Response(200, json={"authentication": {"token": "tok-a", "bid": 6}})
    if req.url.path == "/rest/basket/6/checkout":                  # order placed, no payment enforced
        return httpx.Response(200, json={"orderConfirmation": "075e-f76920285e298d49"})
    return httpx.Response(404, json={})


def _safe(req: httpx.Request) -> httpx.Response:
    if req.url.path == "/login":
        return httpx.Response(200, json={"authentication": {"token": "tok-a", "bid": 6}})
    if req.url.path == "/rest/basket/6/checkout":                  # requires payment first
        return httpx.Response(400, json={"error": "payment required"})
    return httpx.Response(404, json={})


def _cfg(mode: str = "live") -> Config:
    return Config(
        url="http://shop.local", model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000, scope=Scope(allow=["shop.local"]), classes=["workflow_bypass"],
        mode=mode, destructive_allowed=["*"], chain=False, accounts_path=Path("accounts.yaml"),
        accounts=Accounts(login=LoginSpec(url="/login", token_field="authentication.token"),
                          roles=[Role(name="guest", creds=None),
                                 Role(name="userA", creds={"email": "a@x", "password": "x"})]))


def _run(handler, mode="live"):
    orch = Orchestrator(_cfg(mode), console=Console(quiet=True), transport=httpx.MockTransport(handler),
                        llm=ScriptedLLM())
    return [f for f in orch.run() if f.bug_class == "workflow_bypass"]


def test_unpaid_checkout_is_confirmed():
    wf = _run(_vuln)
    assert len(wf) == 1
    assert wf[0].proof["oracle"] == "unpaid_finalization"
    assert wf[0].proof["path"] == "/rest/basket/6/checkout"


def test_gated_checkout_is_not_flagged():
    assert _run(_safe) == []                                       # payment enforced → no FP


def test_workflow_gated_in_dry_run():
    assert _run(_vuln, mode="dry-run") == []                       # state-changing → skipped
