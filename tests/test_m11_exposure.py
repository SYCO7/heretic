"""M11: excessive-data-exposure oracle. A private list endpoint that returns records
owned by multiple users is a leak; a public catalog (no owner field) or a genuinely
per-user list must NOT be flagged. Offline mock covering all three.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, LoginSpec, ObjectSpec, Role, Scope
from heretic.core.exposure import owner_of
from heretic.core.orchestrator import Orchestrator
from heretic.llm.scripted import ScriptedLLM

_QUIET = Console(quiet=True)


def _handler(req: httpx.Request) -> httpx.Response:
    p = req.url.path
    if p == "/login":
        who = json.loads(req.content or b"{}").get("email", "").split("@")[0]
        return httpx.Response(200, json={"token": f"tok-{who}"})
    authed = req.headers.get("authorization", "").startswith("Bearer tok-")
    if p == "/api/BasketItems":                                  # LEAK: mixed owners, private
        if not authed:
            return httpx.Response(401, json={"error": "auth"})
        return httpx.Response(200, json={"data": [
            {"id": 1, "BasketId": 6}, {"id": 2, "BasketId": 7}, {"id": 3, "BasketId": 6}]})
    if p == "/api/Products":                                     # PUBLIC catalog: no owner field
        return httpx.Response(200, json={"data": [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]})
    if p == "/api/MyOrders":                                     # SAFE: single owner
        if not authed:
            return httpx.Response(401, json={"error": "auth"})
        return httpx.Response(200, json={"data": [{"id": 1, "UserId": 6}, {"id": 2, "UserId": 6}]})
    if p == "/api/Users":                                        # LEAK: PII exposed WITHOUT auth
        return httpx.Response(200, json={"data": [{"id": 1, "email": "a@x.com"},
                                                  {"id": 2, "email": "b@x.com"}]})
    if p == "/api/Reviews":                                      # SAFE public catalog: no PII
        return httpx.Response(200, json={"data": [{"id": 1, "stars": 5}, {"id": 2, "stars": 4}]})
    if re.match(r"^/api/\w+/\d+$", p):
        return httpx.Response(200, json={"data": {"id": 1}})
    return httpx.Response(404, json={})


def _obj(n: str, u: str) -> ObjectSpec:
    return ObjectSpec(name=n, list_url=u, item_url=u + "/{id}", id_field="id", list_path="data")


def _cfg() -> Config:
    return Config(
        url="http://shop.local", model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000, scope=Scope(allow=["shop.local"]),
        classes=["excessive_data_exposure"], chain=False, accounts_path=Path("accounts.yaml"),
        accounts=Accounts(login=LoginSpec(url="/login", token_field="token"),
                          roles=[Role(name="guest", creds=None),
                                 Role(name="userA", creds={"email": "userA@x", "password": "x"}),
                                 Role(name="userB", creds={"email": "userB@x", "password": "x"})]),
        objects=[_obj("basketitem", "/api/BasketItems"), _obj("product", "/api/Products"),
                 _obj("myorder", "/api/MyOrders"), _obj("user", "/api/Users"),
                 _obj("review", "/api/Reviews")])


def test_owner_of_detection():
    assert owner_of({"id": 1, "BasketId": 6}) == "6"
    assert owner_of({"id": 1, "UserId": 9}) == "9"
    assert owner_of({"id": 1, "name": "widget"}) is None        # no owner field


def test_private_comingled_list_is_flagged():
    orch = Orchestrator(_cfg(), console=_QUIET, transport=httpx.MockTransport(_handler),
                        llm=ScriptedLLM())
    ede = {f.invariant_id: f for f in orch.run() if f.bug_class == "excessive_data_exposure"}
    f = ede["EDE:basketitem"]                                    # the private co-mingled list
    assert "leaks all users' records" in f.title
    assert f.proof["distinct_owners"] == 2                       # BasketId 6 and 7
    assert f.proof["guest_status"] == 401                        # private data


def test_public_catalog_and_scoped_list_are_not_flagged():
    orch = Orchestrator(_cfg(), console=_QUIET, transport=httpx.MockTransport(_handler),
                        llm=ScriptedLLM())
    flagged = {f.invariant_id for f in orch.run() if f.bug_class == "excessive_data_exposure"}
    assert "EDE:product" not in flagged                         # public, no owner field
    assert "EDE:myorder" not in flagged                         # single owner — properly scoped
    assert "EDE:review" not in flagged                          # public, but no PII/secret fields


def test_public_pii_leak_is_flagged():
    """A public endpoint exposing emails without authentication is a leak."""
    orch = Orchestrator(_cfg(), console=_QUIET, transport=httpx.MockTransport(_handler),
                        llm=ScriptedLLM())
    ede = [f for f in orch.run() if f.invariant_id == "EDE:user"]
    assert len(ede) == 1
    assert "email" in ede[0].title
    assert ede[0].proof["oracle"] == "public_sensitive_exposure"
    assert ede[0].proof["guest_status"] == 200
