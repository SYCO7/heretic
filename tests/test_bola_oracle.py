"""End-to-end M1 test: the differential Oracle must catch a real BOLA, ignore a
properly-authorized endpoint, and NOT flag a public resource (false-positive
control). Runs entirely on an in-process mock target — no network.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, LoginSpec, ObjectSpec, Role, Scope
from heretic.core.models import Severity
from heretic.core.orchestrator import Orchestrator

# ---- mock target ------------------------------------------------------
# order:   VULNERABLE — any authenticated caller can read any order (BOLA)
# profile: SAFE       — only the owner (or admin) may read
# catalog: PUBLIC     — everyone incl. guest can read (must NOT be flagged)

ORDERS_BY_ROLE = {"userA": [{"id": "1001"}], "userB": [{"id": "1002"}], "admin": [{"id": "1003"}]}
ORDER_DATA = {
    "1001": {"id": "1001", "owner": "userA", "card": "4111-1111-A"},
    "1002": {"id": "1002", "owner": "userB", "card": "4111-1111-B"},
    "1003": {"id": "1003", "owner": "admin", "card": "4111-1111-ADM"},
}
PROFILES_BY_ROLE = {"userA": [{"id": "pA"}], "userB": [{"id": "pB"}]}
PROFILE_OWNER = {"pA": "userA", "pB": "userB"}
PROFILE_DATA = {"pA": {"id": "pA", "ssn": "111-11"}, "pB": {"id": "pB", "ssn": "222-22"}}
CATALOG_BY_ROLE = {"userA": [{"id": "catA"}], "userB": [{"id": "catB"}]}
CATALOG_DATA = {"catA": {"id": "catA", "name": "Widget A"}, "catB": {"id": "catB", "name": "Widget B"}}


def _caller(request: httpx.Request) -> str:
    auth = request.headers.get("authorization", "")
    return auth[len("Bearer tok-"):] if auth.startswith("Bearer tok-") else "guest"


def handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    caller = _caller(request)

    if path == "/api/auth/login":
        email = json.loads(request.content).get("email", "")
        return httpx.Response(200, json={"token": f"tok-{email.split('@')[0]}"})

    # collection endpoints (auth required)
    if path == "/api/orders":
        return _authed(caller, {"orders": ORDERS_BY_ROLE.get(caller, [])})
    if path == "/api/profile":
        return _authed(caller, {"profiles": PROFILES_BY_ROLE.get(caller, [])})
    if path == "/api/catalog":
        return _authed(caller, {"items": CATALOG_BY_ROLE.get(caller, [])})

    # item endpoints
    if m := re.match(r"^/api/orders/(.+)$", path):
        if caller == "guest":
            return httpx.Response(401, json={"error": "auth required"})
        data = ORDER_DATA.get(m.group(1))
        return httpx.Response(200, json=data) if data else httpx.Response(404, json={})
    if m := re.match(r"^/api/profile/(.+)$", path):
        pid = m.group(1)
        owner = PROFILE_OWNER.get(pid)
        if owner is None:
            return httpx.Response(404, json={})
        if caller in (owner, "admin"):
            return httpx.Response(200, json=PROFILE_DATA[pid])
        return httpx.Response(403, json={"error": "forbidden"})
    if m := re.match(r"^/api/catalog/(.+)$", path):
        data = CATALOG_DATA.get(m.group(1))
        return httpx.Response(200, json=data) if data else httpx.Response(404, json={})

    return httpx.Response(404, json={"error": "not found"})


def _authed(caller: str, body: dict) -> httpx.Response:
    if caller == "guest":
        return httpx.Response(401, json={"error": "auth required"})
    return httpx.Response(200, json=body)


# ---- config builder ---------------------------------------------------

def _cfg() -> Config:
    return Config(
        url="http://app.local",
        model="none",
        engagement="test",
        authorized_by="tester@test",
        signed=True,
        scope=Scope(allow=["app.local"]),
        max_rate_rps=1000,            # avoid real sleeps in tests
        classes=["bola"],
        accounts_path=Path("accounts.yaml"),
        accounts=Accounts(
            login=LoginSpec(url="/api/auth/login", token_field="token"),
            roles=[
                Role(name="guest", creds=None),
                Role(name="userA", creds={"email": "userA@test.local", "password": "x"}),
                Role(name="userB", creds={"email": "userB@test.local", "password": "x"}),
                Role(name="admin", creds={"email": "admin@test.local", "password": "x"}),
            ],
        ),
        objects=[
            ObjectSpec(name="order",   list_url="/api/orders",  item_url="/api/orders/{id}",  id_field="id", list_path="orders"),
            ObjectSpec(name="profile", list_url="/api/profile", item_url="/api/profile/{id}", id_field="id", list_path="profiles"),
            ObjectSpec(name="catalog", list_url="/api/catalog", item_url="/api/catalog/{id}", id_field="id", list_path="items"),
        ],
    )


def _run():
    orch = Orchestrator(_cfg(), console=Console(quiet=True), transport=httpx.MockTransport(handler))
    return orch.run()


# ---- tests ------------------------------------------------------------

def test_finds_all_and_only_bola_orders():
    findings = _run()
    # 1001->userB, 1002->userA, 1003->userA&userB  == 4 confirmed BOLA on orders
    assert len(findings) == 4
    assert all(f.bug_class == "bola" for f in findings)
    assert all("order" in f.title for f in findings)
    assert all(f.severity == Severity.HIGH for f in findings)


def test_safe_endpoint_not_flagged():
    assert not any("profile" in f.title for f in _run())


def test_public_resource_not_flagged_false_positive():
    # catalog is public (guest sees it) — the Oracle's public-resource control must drop it
    assert not any("catalog" in f.title for f in _run())


def test_specific_cross_user_read_confirmed():
    findings = _run()
    titles = {f.title for f in findings}
    assert any("userB reads userA's order #1001" in t for t in titles)
    assert any("userA reads admin's order #1003" in t for t in titles)


def test_proof_bundle_is_populated():
    f = next(f for f in _run() if "1001" in f.title)
    assert f.proof["oracle"] == "cross_session_diff"
    assert f.proof["reproduced"] is True
    assert f.proof["similarity"] >= 0.85
    assert f.proof["poc"]           # reproducible request sequence attached
