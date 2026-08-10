"""A self-contained vulnerable mock app + ground truth, for the built-in benchmark.

Covers every implemented bug class with BOTH a vulnerable and a safe/public
variant, so the run measures detection (recall) AND false-positive suppression
(precision) together — entirely offline.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
from rich.console import Console

from ..config import Accounts, Config, LoginSpec, ObjectSpec, Role, Scope
from ..core.orchestrator import Orchestrator
from ..llm.scripted import ScriptedLLM

# ---- mutable state (reset per run) ------------------------------------
_MASS: dict[str, str] = {}
_ORDERS2: dict[str, dict] = {}


def _reset() -> None:
    _MASS.clear()
    _ORDERS2.clear()
    _ORDERS2.update({"o100": {"paid": False, "shipped": False}})


# BOLA data: userA owns 1001, userB owns 1002 (admin owns none)
_ORDERS_BY_ROLE = {"userA": [{"id": "1001"}], "userB": [{"id": "1002"}], "admin": []}
_ORDER_DATA = {
    "1001": {"id": "1001", "owner": "userA", "card": "4111-A"},
    "1002": {"id": "1002", "owner": "userB", "card": "4111-B"},
}
_PROFILES_BY_ROLE = {"userA": [{"id": "pA"}], "userB": [{"id": "pB"}]}      # SAFE object
_PROFILE_OWNER = {"pA": "userA", "pB": "userB"}
_PROFILE_DATA = {"pA": {"id": "pA", "ssn": "111"}, "pB": {"id": "pB", "ssn": "222"}}
_CATALOG_BY_ROLE = {"userA": [{"id": "catA"}], "userB": [{"id": "catB"}]}   # PUBLIC object
_CATALOG_DATA = {"catA": {"id": "catA", "name": "A"}, "catB": {"id": "catB", "name": "B"}}


# SPA shell + JS bundle — the frontend's API calls, as a spec-less target would ship them.
# Item routes use template literals (${...}) exactly like a real Angular/React service.
_INDEX_HTML = (
    "<!doctype html><html><head><title>shop</title></head>"
    '<body><app-root></app-root><script src="/static/app.js"></script></body></html>'
)
_APP_JS = """
const base = "";
export const api = {
  orders:  () => fetch(base + "/api/orders"),
  order:   (id) => fetch(`/api/orders/${id}`),
  profile: () => http.get("/api/profile"),
  aProfile:(pid) => http.get(`/api/profile/${pid}`),
  catalog: () => axios.get('/api/catalog'),
  aItem:   (cid) => axios.get(`/api/catalog/${cid}`),
  checkout:(b) => http.post("/api/checkout", b),
};
"""

# OpenAPI 3 doc the mock publishes — discovery parses this to find list/item endpoints
_OPENAPI = {
    "openapi": "3.0.0",
    "paths": {
        "/api/orders": {"get": {}}, "/api/orders/{id}": {"get": {}},
        "/api/profile": {"get": {}}, "/api/profile/{id}": {"get": {}},
        "/api/catalog": {"get": {}}, "/api/catalog/{id}": {"get": {}},
        "/api/checkout": {"post": {}},
    },
}


def _caller(request: httpx.Request) -> str:
    auth = request.headers.get("authorization", "")
    return auth[len("Bearer tok-"):] if auth.startswith("Bearer tok-") else "guest"


def handler(request: httpx.Request) -> httpx.Response:
    path, caller = request.url.path, _caller(request)
    body = {}
    if request.content:
        try:
            body = json.loads(request.content)
        except Exception:
            body = {}

    # ---- SPA shell + JS bundle (lets JS-route discovery work spec-less) ----
    if path in ("/", "/index.html"):
        return httpx.Response(200, text=_INDEX_HTML, headers={"content-type": "text/html"})
    if path == "/static/app.js":
        return httpx.Response(200, text=_APP_JS, headers={"content-type": "application/javascript"})

    # ---- OpenAPI spec (lets autonomous discovery infer the objects) ----
    if path in ("/openapi.json", "/v3/api-docs"):
        return httpx.Response(200, json=_OPENAPI)

    if path == "/api/auth/login":
        return httpx.Response(200, json={"token": f"tok-{body.get('email','').split('@')[0]}"})

    # ---- BOLA: orders (VULN), profile (SAFE), catalog (PUBLIC) ----
    if path == "/api/orders":
        return _authed(caller, {"orders": _ORDERS_BY_ROLE.get(caller, [])})
    if path == "/api/profile":
        return _authed(caller, {"profiles": _PROFILES_BY_ROLE.get(caller, [])})
    if path == "/api/catalog":
        return _authed(caller, {"items": _CATALOG_BY_ROLE.get(caller, [])})
    # (BOLA item endpoints are matched LAST, after the explicit routes below, so
    #  the generic /api/profile/{id} regex does not swallow /api/profile/update etc.)

    # ---- price tampering ----
    if path == "/api/checkout":
        return httpx.Response(200, json={"order_id": "o1", "charged": body.get("price")})  # VULN
    if path == "/api/checkout_safe":
        return httpx.Response(200, json={"order_id": "o1", "charged": 100})                # SAFE

    # ---- mass assignment ----
    if path == "/api/profile/update":
        _MASS[caller] = body.get("role", "user")            # VULN: stores role
        return httpx.Response(200, json={"ok": True})
    if path == "/api/profile/me":
        return httpx.Response(200, json={"role": _MASS.get(caller, "user")})
    if path == "/api/profile_safe/update":
        return httpx.Response(200, json={"ok": True})        # SAFE: ignores role
    if path == "/api/profile_safe/me":
        return httpx.Response(200, json={"role": "user"})

    # ---- workflow bypass ----
    if m := re.match(r"^/api/orders2/([^/]+)$", path):
        o = _ORDERS2.get(m.group(1))
        return httpx.Response(200, json={"id": m.group(1), **o}) if o else httpx.Response(404, json={})
    if m := re.match(r"^/api/orders2/([^/]+)/ship$", path):
        if m.group(1) in _ORDERS2:
            _ORDERS2[m.group(1)]["shipped"] = True           # VULN: ships unpaid
        return httpx.Response(200, json={"ok": True})

    # ---- sub-resource item endpoint (only reachable via list->detail probing) ----
    if re.match(r"^/api/orders/([^/]+)/status$", path):
        return httpx.Response(200, json={"status": "open"})

    # ---- BOLA item endpoints (matched last): orders (VULN), profile (SAFE), catalog (PUBLIC) ----
    if m := re.match(r"^/api/orders/([^/]+)$", path):
        if caller == "guest":
            return httpx.Response(401, json={"error": "auth"})
        d = _ORDER_DATA.get(m.group(1))                      # VULN: any authed caller
        return httpx.Response(200, json=d) if d else httpx.Response(404, json={})
    if m := re.match(r"^/api/profile/([^/]+)$", path):
        owner = _PROFILE_OWNER.get(m.group(1))
        if owner is None:
            return httpx.Response(404, json={})
        if caller in (owner, "admin"):
            return httpx.Response(200, json=_PROFILE_DATA[m.group(1)])
        return httpx.Response(403, json={"error": "forbidden"})   # SAFE
    if m := re.match(r"^/api/catalog/([^/]+)$", path):
        d = _CATALOG_DATA.get(m.group(1))
        return httpx.Response(200, json=d) if d else httpx.Response(404, json={})  # PUBLIC

    return httpx.Response(404, json={"error": "not found"})


def _authed(caller: str, body: dict) -> httpx.Response:
    return httpx.Response(401, json={"error": "auth"}) if caller == "guest" else httpx.Response(200, json=body)


# ---- scripted LLM (offline brain) -------------------------------------
_INTENT = {
    "app_type": "shop", "entities": ["order", "profile"], "roles": ["userA", "admin"],
    "workflows": [{"name": "checkout", "steps": ["price", "pay", "ship"]}],
    "invariants": [
        {"id": "INV-P", "rule": "price computed server-side", "bug_class": "price_tamper"},
        {"id": "INV-M", "rule": "role not user-settable", "bug_class": "mass_assignment"},
        {"id": "INV-W", "rule": "shipping requires payment", "bug_class": "workflow_bypass"},
    ],
}
_HYPOTHESES = [
    {"invariant_id": "INV-P", "bug_class": "price_tamper", "description": "tamper price on /api/checkout",
     "request_sequence": [{"method": "POST", "url": "/api/checkout", "as": "userA", "body": {"price": 1}}],
     "expected_safe": "charged == 100", "oracle": "invariant_assertion",
     "assertion": {"field": "charged", "expected_value": 100, "tampered_value": 1}},
    {"invariant_id": "INV-P", "bug_class": "price_tamper", "description": "tamper price on /api/checkout_safe (safe)",
     "request_sequence": [{"method": "POST", "url": "/api/checkout_safe", "as": "userA", "body": {"price": 1}}],
     "expected_safe": "charged == 100", "oracle": "invariant_assertion",
     "assertion": {"field": "charged", "expected_value": 100, "tampered_value": 1}},
    {"invariant_id": "INV-M", "bug_class": "mass_assignment", "description": "set role=admin via /api/profile/update",
     "request_sequence": [{"method": "POST", "url": "/api/profile/update", "as": "userA", "body": {"role": "admin"}}],
     "expected_safe": "role not settable", "oracle": "invariant_assertion",
     "assertion": {"field": "role", "equals": "admin"}, "state_probe": {"url": "/api/profile/me", "as": "userA"}},
    {"invariant_id": "INV-M", "bug_class": "mass_assignment", "description": "set role=admin via /api/profile_safe/update (safe)",
     "request_sequence": [{"method": "POST", "url": "/api/profile_safe/update", "as": "userA", "body": {"role": "admin"}}],
     "expected_safe": "role not settable", "oracle": "invariant_assertion",
     "assertion": {"field": "role", "equals": "admin"}, "state_probe": {"url": "/api/profile_safe/me", "as": "userA"}},
    {"invariant_id": "INV-W", "bug_class": "workflow_bypass", "description": "ship o100 before payment",
     "request_sequence": [{"method": "POST", "url": "/api/orders2/o100/ship", "as": "userA"}],
     "expected_safe": "cannot ship unpaid", "oracle": "state_delta_judge",
     "state_probe": {"url": "/api/orders2/o100", "as": "userA"}, "invariant_rule": "shipping requires payment"},
]


def _judge_fn(system: str, user: str) -> dict:
    after = (json.loads(user).get("after") or {})
    violated = after.get("shipped") is True and after.get("paid") is False
    return {"verdict": violated, "why": "shipped while unpaid" if violated else "ok", "confidence": 0.9}


# ---- ground truth: the bugs that SHOULD be reported -------------------
GROUND_TRUTH = [
    {"bug_class": "bola", "match": "userB reads userA's order #1001"},
    {"bug_class": "bola", "match": "userA reads userB's order #1002"},
    {"bug_class": "price_tamper", "match": "tamper price on /api/checkout"},
    {"bug_class": "mass_assignment", "match": "role=admin via /api/profile/update"},
    {"bug_class": "workflow_bypass", "match": "ship o100 before payment"},
    # M4 chains composed from the primitives above:
    {"bug_class": "chain", "match": "Account takeover"},        # bola + mass_assignment
    {"bug_class": "chain", "match": "Financial fraud"},         # price_tamper + workflow_bypass
    {"bug_class": "chain", "match": "Bulk data exfiltration"},  # 2x bola
]


def _cfg() -> Config:
    return Config(
        url="http://bench.local", model="fake", engagement="builtin-benchmark",
        authorized_by="benchmark@heretic", signed=True, scope=Scope(allow=["bench.local"]),
        mode="live", max_rate_rps=100000, destructive_allowed=["*"], chain=True,
        classes=["bola", "price_tamper", "mass_assignment", "workflow_bypass"],
        accounts_path=Path("accounts.yaml"),
        accounts=Accounts(
            login=LoginSpec(url="/api/auth/login", token_field="token"),
            roles=[Role(name="guest", creds=None),
                   Role(name="userA", creds={"email": "userA@x", "password": "x"}),
                   Role(name="userB", creds={"email": "userB@x", "password": "x"}),
                   Role(name="admin", creds={"email": "admin@x", "password": "x"})],
        ),
        objects=[
            ObjectSpec(name="order", list_url="/api/orders", item_url="/api/orders/{id}", id_field="id", list_path="orders"),
            ObjectSpec(name="profile", list_url="/api/profile", item_url="/api/profile/{id}", id_field="id", list_path="profiles"),
            ObjectSpec(name="catalog", list_url="/api/catalog", item_url="/api/catalog/{id}", id_field="id", list_path="items"),
        ],
    )


def build_orchestrator(console: Console | None = None, trace=None, memory=None,
                       engagement=None) -> Orchestrator:
    """Construct the offline benchmark orchestrator (ScriptedLLM + mock transport)."""
    _reset()
    llm = ScriptedLLM(intent=_INTENT, hypotheses=_HYPOTHESES, judge_fn=_judge_fn)
    return Orchestrator(_cfg(), console=console or Console(quiet=True),
                        transport=httpx.MockTransport(handler), llm=llm,
                        trace=trace, memory=memory, engagement=engagement)


def run_builtin(console: Console | None = None):
    """Run the offline benchmark. Returns (findings, GROUND_TRUTH)."""
    return build_orchestrator(console=console).run(), GROUND_TRUTH
