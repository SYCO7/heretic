"""M28: Ownership Provenance Differential (OPD) — HERETIC's own algorithm.
Deterministic provenance-purity metric that quantifies a leak from the actual
ownership tokens (no `owner` field required), and enriches confirmed findings.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, LoginSpec, ObjectSpec, Role, Scope
from heretic.core.orchestrator import Orchestrator
from heretic.core.provenance import OwnershipMap, opd_proof, purity, signature
from heretic.llm.scripted import ScriptedLLM

# ---- the algorithm, in isolation ------------------------------------------

def _omap() -> OwnershipMap:
    return OwnershipMap.build(
        identities={"userA": {"alice@x.com"}, "userB": {"bob@x.com"}},
        owned={"order": {"userA": {"ord-1001"}, "userB": {"ord-2002"}}})


def test_ambiguous_and_short_tokens_dropped():
    omap = OwnershipMap.build(identities={"userA": {"1", "admin", "alice@x.com"},
                                          "userB": {"1", "bob@x.com"}}, owned={})
    toks = omap.token_role
    assert "1" not in toks and "admin" not in toks     # short / noise / shared → dropped
    assert toks["alice@x.com"] == "userA" and toks["bob@x.com"] == "userB"


def test_purity_flags_foreign_data():
    omap = _omap()
    # userB's session shows userA's order + email → foreign provenance
    payload = {"order": {"id": "ord-1001", "buyer": "alice@x.com"}}
    sig = signature(payload, omap)
    own, foreign, p = purity(sig, viewer="userB")
    assert own == 0 and foreign == 2 and p == 0.0       # pure foreign → leak

    # userA seeing its own order → clean
    _own2, foreign2, p2 = purity(signature(payload, omap), viewer="userA")
    assert foreign2 == 0 and p2 == 1.0


def test_opd_proof_shape():
    ev = opd_proof({"buyer": "alice@x.com", "id": "ord-1001"}, _omap(), viewer="userB")
    assert ev["foreign_tokens"] == 2 and ev["purity"] == 0.0
    assert ev["leaked_owners"] == ["userA"]
    assert opd_proof({"buyer": "alice@x.com"}, None, "userB") is None   # no map → no evidence


# ---- wired: a live BOLA finding carries OPD evidence ----------------------

_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.sig"


def _app(req: httpx.Request) -> httpx.Response:
    auth = req.headers.get("authorization", "")
    if req.url.path == "/login":
        email = json.loads(req.content or b"{}").get("email", "")
        return httpx.Response(200, json={"token": f"tok-{email}", "id": email})
    if req.url.path == "/api/orders":                    # each user's own order id
        if "alice@x.com" in auth:
            return httpx.Response(200, json=[{"id": "ord-1001"}])
        if "bob@x.com" in auth:
            return httpx.Response(200, json=[{"id": "ord-2002"}])
        return httpx.Response(401, json=[])
    if req.url.path.startswith("/api/orders/"):          # VULN: any user reads any order (BOLA)
        oid = req.url.path.rsplit("/", 1)[1]
        owner = "alice@x.com" if oid == "ord-1001" else "bob@x.com"
        if auth.startswith("Bearer "):
            return httpx.Response(200, json={"id": oid, "buyer": owner, "total": 42})
        return httpx.Response(401, json={})
    return httpx.Response(404, json={})


def test_bola_finding_carries_provenance():
    cfg = Config(
        url="http://shop.local", model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000, scope=Scope(allow=["shop.local"]), classes=["bola"],
        mode="dry-run", chain=False, accounts_path=Path("accounts.yaml"),
        accounts=Accounts(login=LoginSpec(url="/login", token_field="token"),
                          roles=[Role(name="guest", creds=None),
                                 Role(name="userA", creds={"email": "alice@x.com", "password": "p"}),
                                 Role(name="userB", creds={"email": "bob@x.com", "password": "p"})]),
        objects=[ObjectSpec(name="order", list_url="/api/orders", item_url="/api/orders/{id}", id_field="id")])

    orch = Orchestrator(cfg, console=Console(quiet=True),
                        transport=httpx.MockTransport(_app), llm=ScriptedLLM())
    findings = [f for f in orch.run() if f.bug_class == "bola"]
    assert findings, "expected a BOLA finding"
    prov = [f.proof.get("provenance") for f in findings if f.proof.get("provenance")]
    assert prov, "BOLA finding should carry OPD provenance evidence"
    assert prov[0]["foreign_tokens"] >= 1 and prov[0]["purity"] < 1.0
