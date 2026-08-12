"""M22: deterministic coupon abuse. A single-use coupon the server accepts more
than `max_uses` times (redeemed sequentially) is confirmed; one the server
rejects after the first redemption is not. State-changing → gated in dry-run.
"""
from __future__ import annotations

from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, CouponSpec, LoginSpec, Role, Scope
from heretic.core.coupon import build_coupon_hypotheses
from heretic.core.orchestrator import Orchestrator
from heretic.llm.scripted import ScriptedLLM


def _vuln(req: httpx.Request) -> httpx.Response:
    if req.url.path == "/login":
        return httpx.Response(200, json={"token": "tok-a"})
    if req.url.path == "/api/coupon/apply":
        return httpx.Response(200, json={"discount": 10, "applied": True})     # accepts every redemption
    return httpx.Response(404, json={})


def _safe() -> "callable":
    """A server that enforces single-use: first redemption 200, all later ones 409."""
    seen = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/login":
            return httpx.Response(200, json={"token": "tok-a"})
        if req.url.path == "/api/coupon/apply":
            seen["n"] += 1
            if seen["n"] == 1:
                return httpx.Response(200, json={"discount": 10, "applied": True})
            return httpx.Response(409, json={"error": "coupon already used"})
        return httpx.Response(404, json={})

    return handler


def _cfg(mode: str = "live") -> Config:
    return Config(
        url="http://shop.local", model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000, scope=Scope(allow=["shop.local"]), classes=["coupon_abuse"],
        mode=mode, destructive_allowed=["*"], chain=False, accounts_path=Path("accounts.yaml"),
        accounts=Accounts(login=LoginSpec(url="/login", token_field="token"),
                          roles=[Role(name="guest", creds=None),
                                 Role(name="userA", creds={"email": "a@x", "password": "x"})]),
        coupons=[CouponSpec(name="welcome10", url="/api/coupon/apply", code="WELCOME10",
                            success_field="applied", max_uses=1)])


def _run(handler, mode="live"):
    orch = Orchestrator(_cfg(mode), console=Console(quiet=True),
                        transport=httpx.MockTransport(handler), llm=ScriptedLLM())
    return [f for f in orch.run() if f.bug_class == "coupon_abuse"]


def test_builder_emits_one_probe_per_spec():
    hyps = build_coupon_hypotheses(_cfg())
    assert len(hyps) == 1
    h = hyps[0]
    assert h.invariant_id == "COUPON:welcome10"
    assert h.meta["reps"] == 2                          # max_uses(1) + 1
    assert h.meta["body"]["code"] == "WELCOME10"


def test_reused_coupon_is_confirmed():
    c = _run(_vuln)
    assert len(c) == 1
    assert c[0].proof["oracle"] == "sequential_redemption_count"
    assert c[0].proof["success_count"] == 2 and c[0].proof["max_uses"] == 1
    assert c[0].proof["code"] == "WELCOME10"


def test_single_use_enforced_is_not_flagged():
    assert _run(_safe()) == []                          # server rejected the 2nd redemption → no FP


def test_coupon_gated_in_dry_run():
    assert _run(_vuln, mode="dry-run") == []            # state-changing → skipped without live mode
