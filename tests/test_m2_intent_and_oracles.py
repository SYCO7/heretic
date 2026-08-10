"""M2 offline end-to-end: intent model (ScriptedLLM) + Oracle 1 (assertion) for
price-tampering & mass-assignment + Oracle 3 (state-delta judge + refuters) for
workflow-bypass. Each class has a VULNERABLE and a SAFE endpoint; the Oracle must
confirm the vuln and drop the safe one. No network.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, LoginSpec, Role, Scope
from heretic.core.models import Severity
from heretic.core.orchestrator import Orchestrator
from heretic.llm.scripted import ScriptedLLM

# ---- mutable mock state (reset per run) -------------------------------
MASS_STATE: dict[str, str] = {}
ORDERS2: dict[str, dict] = {}


def _reset():
    MASS_STATE.clear()
    ORDERS2.clear()
    ORDERS2.update({"o100": {"paid": False, "shipped": False},
                    "o200": {"paid": False, "shipped": False}})


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

    if path == "/api/auth/login":
        return httpx.Response(200, json={"token": f"tok-{body.get('email','').split('@')[0]}"})

    # price tampering
    if path == "/api/checkout":                       # VULN: trusts client price
        return httpx.Response(200, json={"order_id": "o1", "charged": body.get("price")})
    if path == "/api/checkout_safe":                  # SAFE: server price
        return httpx.Response(200, json={"order_id": "o1", "charged": 100})

    # mass assignment
    if path == "/api/profile/update":                 # VULN: stores role
        MASS_STATE[caller] = body.get("role", "user")
        return httpx.Response(200, json={"ok": True})
    if path == "/api/profile/me":
        return httpx.Response(200, json={"name": "x", "role": MASS_STATE.get(caller, "user")})
    if path == "/api/profile_safe/update":            # SAFE: ignores role
        return httpx.Response(200, json={"ok": True})
    if path == "/api/profile_safe/me":
        return httpx.Response(200, json={"name": "x", "role": "user"})

    # workflow bypass
    if m := re.match(r"^/api/orders2/([^/]+)$", path):
        o = ORDERS2.get(m.group(1))
        return httpx.Response(200, json={"id": m.group(1), **o}) if o else httpx.Response(404, json={})
    if m := re.match(r"^/api/orders2/([^/]+)/ship$", path):     # VULN: ships unpaid
        oid = m.group(1)
        if oid in ORDERS2:
            ORDERS2[oid]["shipped"] = True
        return httpx.Response(200, json={"ok": True})
    if m := re.match(r"^/api/orders2/([^/]+)/ship_safe$", path):  # SAFE: requires payment
        oid = m.group(1)
        if not ORDERS2.get(oid, {}).get("paid"):
            return httpx.Response(400, json={"error": "unpaid"})
        ORDERS2[oid]["shipped"] = True
        return httpx.Response(200, json={"ok": True})

    return httpx.Response(404, json={"error": "not found"})


# ---- scripted LLM outputs ---------------------------------------------

INTENT = {
    "app_type": "shop", "entities": ["order", "profile", "item"], "roles": ["userA", "admin"],
    "workflows": [{"name": "checkout", "steps": ["price", "pay", "ship"]}],
    "invariants": [
        {"id": "INV-P", "rule": "price computed server-side", "bug_class": "price_tamper"},
        {"id": "INV-M", "rule": "role is not user-settable", "bug_class": "mass_assignment"},
        {"id": "INV-W", "rule": "shipping requires completed payment", "bug_class": "workflow_bypass"},
    ],
}

HYPOTHESES = [
    # price: vuln -> confirm, safe -> drop
    {"invariant_id": "INV-P", "bug_class": "price_tamper", "description": "tamper price on /api/checkout",
     "request_sequence": [{"method": "POST", "url": "/api/checkout", "as": "userA", "body": {"item_id": "i1", "price": 1}}],
     "expected_safe": "charged equals server price 100", "oracle": "invariant_assertion",
     "assertion": {"field": "charged", "expected_value": 100, "tampered_value": 1}, "state_probe": None},
    {"invariant_id": "INV-P", "bug_class": "price_tamper", "description": "tamper price on /api/checkout_safe",
     "request_sequence": [{"method": "POST", "url": "/api/checkout_safe", "as": "userA", "body": {"item_id": "i1", "price": 1}}],
     "expected_safe": "charged equals server price 100", "oracle": "invariant_assertion",
     "assertion": {"field": "charged", "expected_value": 100, "tampered_value": 1}, "state_probe": None},
    # mass assignment: vuln -> confirm, safe -> drop
    {"invariant_id": "INV-M", "bug_class": "mass_assignment", "description": "set role=admin via /api/profile/update",
     "request_sequence": [{"method": "POST", "url": "/api/profile/update", "as": "userA", "body": {"name": "x", "role": "admin"}}],
     "expected_safe": "role cannot be set by user", "oracle": "invariant_assertion",
     "assertion": {"field": "role", "equals": "admin"}, "state_probe": {"url": "/api/profile/me", "as": "userA"}},
    {"invariant_id": "INV-M", "bug_class": "mass_assignment", "description": "set role=admin via /api/profile_safe/update",
     "request_sequence": [{"method": "POST", "url": "/api/profile_safe/update", "as": "userA", "body": {"name": "x", "role": "admin"}}],
     "expected_safe": "role cannot be set by user", "oracle": "invariant_assertion",
     "assertion": {"field": "role", "equals": "admin"}, "state_probe": {"url": "/api/profile_safe/me", "as": "userA"}},
    # workflow bypass: vuln -> confirm (Oracle 3), safe -> drop
    {"invariant_id": "INV-W", "bug_class": "workflow_bypass", "description": "ship o100 before payment",
     "request_sequence": [{"method": "POST", "url": "/api/orders2/o100/ship", "as": "userA"}],
     "expected_safe": "cannot ship an unpaid order", "oracle": "state_delta_judge",
     "state_probe": {"url": "/api/orders2/o100", "as": "userA"}, "invariant_rule": "shipping requires completed payment"},
    {"invariant_id": "INV-W", "bug_class": "workflow_bypass", "description": "ship o200 before payment (safe endpoint)",
     "request_sequence": [{"method": "POST", "url": "/api/orders2/o200/ship_safe", "as": "userA"}],
     "expected_safe": "cannot ship an unpaid order", "oracle": "state_delta_judge",
     "state_probe": {"url": "/api/orders2/o200", "as": "userA"}, "invariant_rule": "shipping requires completed payment"},
]


def judge_fn(system: str, user: str) -> dict:
    """Real judgment over the after-state: shipped while unpaid == violation."""
    after = (json.loads(user).get("after") or {})
    violated = after.get("shipped") is True and after.get("paid") is False
    return {"verdict": violated, "why": "shipped while unpaid" if violated else "ok", "confidence": 0.9}


def _cfg(mode: str = "live") -> Config:
    return Config(
        url="http://app.local", model="fake", engagement="test", authorized_by="tester@test",
        signed=True, scope=Scope(allow=["app.local"]), mode=mode, max_rate_rps=1000,
        destructive_allowed=["*"], classes=["price_tamper", "mass_assignment", "workflow_bypass"],
        accounts_path=Path("accounts.yaml"),
        accounts=Accounts(
            login=LoginSpec(url="/api/auth/login", token_field="token"),
            roles=[Role(name="guest", creds=None),
                   Role(name="userA", creds={"email": "userA@test.local", "password": "x"}),
                   Role(name="admin", creds={"email": "admin@test.local", "password": "x"})],
        ),
        objects=[],
    )


def _run(mode: str = "live"):
    _reset()
    llm = ScriptedLLM(intent=INTENT, hypotheses=HYPOTHESES, judge_fn=judge_fn)
    orch = Orchestrator(_cfg(mode), console=Console(quiet=True),
                        transport=httpx.MockTransport(handler), llm=llm)
    return orch.run()


# ---- tests ------------------------------------------------------------

def test_confirms_one_per_class_drops_safe():
    findings = _run()
    classes = sorted(f.bug_class for f in findings)
    assert classes == ["mass_assignment", "price_tamper", "workflow_bypass"]
    # no confirmed finding targets a *_safe endpoint
    assert not any("safe" in f.proof["poc"][0]["url"] for f in findings)


def test_severities():
    by_class = {f.bug_class: f.severity for f in _run()}
    assert by_class["mass_assignment"] == Severity.CRITICAL
    assert by_class["price_tamper"] == Severity.HIGH
    assert by_class["workflow_bypass"] == Severity.HIGH


def test_price_assertion_proof():
    f = next(f for f in _run() if f.bug_class == "price_tamper")
    assert f.proof["oracle"] == "invariant_assertion"
    assert f.proof["observed"] == 1                      # server charged the client value
    assert f.proof["expected_server_value"] == 100


def test_workflow_used_judge_and_survived_refuters():
    f = next(f for f in _run() if f.bug_class == "workflow_bypass")
    assert f.proof["oracle"] == "state_delta_judge"
    assert f.proof["after"]["shipped"] is True and f.proof["after"]["paid"] is False
    assert f.proof["refuter_genuine"] >= 2          # M3: perspective-diverse panel of 3
    assert f.proof["confidence"] >= 0.5


def test_dry_run_gate_skips_state_changing():
    # dry-run must NOT fire any state-changing test -> zero findings
    assert _run(mode="dry-run") == []
