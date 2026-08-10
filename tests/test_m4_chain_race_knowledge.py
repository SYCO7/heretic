"""M4: chaining, race/TOCTOU parallel-fire, RAG-lite knowledge, report polish.
All offline.
"""
from __future__ import annotations

import threading
from pathlib import Path

import httpx
from rich.console import Console

from heretic.benchmark import run_builtin
from heretic.config import Accounts, Config, LoginSpec, RaceSpec, Role, Scope
from heretic.core.knowledge import KnowledgeBase
from heretic.core.models import Severity
from heretic.core.orchestrator import Orchestrator
from heretic.report.render import _as_markdown, render

# ---- chaining ---------------------------------------------------------

def test_chains_compose_from_confirmed_primitives():
    findings, _ = run_builtin()
    chains = {f.title: f for f in findings if f.bug_class == "chain"}
    assert {"Account takeover", "Financial fraud", "Bulk data exfiltration"} <= set(chains)
    takeover = chains["Account takeover"]
    assert takeover.severity == Severity.CRITICAL
    assert takeover.impact                       # business impact narrative present
    assert takeover.chained_from                 # references the underlying primitives
    assert takeover.proof["confidence"] == 1.0   # grounded in confirmed primitives


# ---- race / TOCTOU ----------------------------------------------------

_USED = set()
_LOCK = threading.Lock()


def _race_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/api/auth/login":
        return httpx.Response(200, json={"token": "tok-userA"})
    if path == "/api/coupon/redeem":                     # VULN: no enforcement
        return httpx.Response(200, json={"ok": True})
    if path == "/api/coupon/redeem_safe":                # SAFE: atomic single-use
        with _LOCK:
            if "c" in _USED:
                return httpx.Response(409, json={"ok": False})
            _USED.add("c")
            return httpx.Response(200, json={"ok": True})
    return httpx.Response(404, json={})


def _race_cfg() -> Config:
    return Config(
        url="http://race.local", model="fake", engagement="race", authorized_by="t@t",
        signed=True, scope=Scope(allow=["race.local"]), mode="live", max_rate_rps=100000,
        max_parallel=8, destructive_allowed=["*"], classes=["race_condition"],
        accounts_path=Path("accounts.yaml"),
        accounts=Accounts(login=LoginSpec(url="/api/auth/login", token_field="token"),
                          roles=[Role(name="guest", creds=None),
                                 Role(name="userA", creds={"email": "userA@x", "password": "x"})]),
        races=[
            RaceSpec(name="coupon", url="/api/coupon/redeem", parallel=8, expect_max_success=1),
            RaceSpec(name="coupon_safe", url="/api/coupon/redeem_safe", parallel=8, expect_max_success=1),
        ],
    )


def test_race_detects_missing_atomicity_and_drops_safe():
    _USED.clear()
    orch = Orchestrator(_race_cfg(), console=Console(quiet=True),
                        transport=httpx.MockTransport(_race_handler))
    findings = orch.run()
    assert len(findings) == 1                             # vuln confirmed, safe dropped
    f = findings[0]
    assert f.bug_class == "race_condition"
    assert f.proof["success_count"] > f.proof["expect_max"]
    assert "coupon" in f.title


# ---- RAG-lite knowledge ----------------------------------------------

def test_knowledge_base_retrieval():
    kb = KnowledgeBase.load()
    hits = kb.retrieve("bola", "swap object identifiers uuid", k=2)
    assert hits and len(hits) <= 2
    assert any("identifier" in h.lower() or "swap" in h.lower() for h in hits)
    assert kb.retrieve("no_such_class") == []


def test_knowledge_ranks_by_query_terms():
    kb = KnowledgeBase.load()
    top = kb.retrieve("mass_assignment", "read the object back to confirm", k=1)
    assert top and "read" in top[0].lower()


# ---- report polish ----------------------------------------------------

def test_html_report_has_chain_impact_and_poc(tmp_path):
    findings, _ = run_builtin()
    out = tmp_path / "report.html"
    render(findings, fmt="table", html_path=out, console=Console(quiet=True))
    doc = out.read_text()
    assert "HERETIC" in doc and "CRITICAL" in doc
    assert "Account takeover" in doc
    assert "Business impact" in doc            # chain impact rendered
    assert "Proof of concept" in doc


def test_markdown_includes_impact_and_chained_from():
    findings, _ = run_builtin()
    md = _as_markdown(findings)
    assert "Business impact" in md and "Chained from" in md and "Confidence" in md
