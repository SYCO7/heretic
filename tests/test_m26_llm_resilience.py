"""M26: a flaky/unreachable LLM must not sink the whole scan. When the LLM phase
errors, the mechanical (deterministic) findings already confirmed survive and the
run completes with a clear message instead of crashing.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, LoginSpec, ObjectSpec, Role, Scope
from heretic.core.orchestrator import Orchestrator
from heretic.llm.base import LLM, LLMError


class _DeadLLM(LLM):
    """A backend that always fails — simulates a rate-limited / unreachable free tier."""
    name = "dead"
    context_tokens = 1000

    def complete(self, system: str, user: str, *, json: bool = False,
                 reasoning: bool = False, tag: str = "") -> str:
        raise LLMError("dead: HTTP 503 after retries")

    def judge(self, system: str, user: str, *, tag: str = "") -> dict:
        return {"verdict": False, "why": "dead", "confidence": 0.0}


def _bola_app(req: httpx.Request) -> httpx.Response:
    auth = req.headers.get("authorization", "")
    if req.url.path == "/login":
        email = json.loads(req.content or b"{}").get("email", "")
        return httpx.Response(200, json={"token": f"tok-{email}"})
    if req.url.path == "/orders":                            # each user owns one order id
        if "a@x" in auth:
            return httpx.Response(200, json=[{"id": 1}])
        if "b@x" in auth:
            return httpx.Response(200, json=[{"id": 2}])
        return httpx.Response(401, json=[])
    m = re.match(r"^/orders/(\d+)$", req.url.path)
    if m and auth.startswith("Bearer "):                     # VULN: any authed user reads any order
        return httpx.Response(200, json={"id": int(m.group(1)), "secret": "xyz"})
    return httpx.Response(404, json={})


def test_dead_llm_keeps_mechanical_findings():
    cfg = Config(
        url="http://shop.local", model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000, scope=Scope(allow=["shop.local"]),
        classes=["bola", "price_tamper"],                    # price_tamper pulls in the (dead) LLM phase
        mode="dry-run", chain=False, accounts_path=Path("accounts.yaml"),
        accounts=Accounts(login=LoginSpec(url="/login", token_field="token"),
                          roles=[Role(name="guest", creds=None),
                                 Role(name="userA", creds={"email": "a@x", "password": "p"}),
                                 Role(name="userB", creds={"email": "b@x", "password": "p"})]),
        objects=[ObjectSpec(name="order", list_url="/orders", item_url="/orders/{id}", id_field="id")])

    orch = Orchestrator(cfg, console=Console(quiet=True),
                        transport=httpx.MockTransport(_bola_app), llm=_DeadLLM())
    findings = orch.run()                                    # must NOT raise despite the dead LLM

    assert any(f.bug_class == "bola" for f in findings)      # mechanical BOLA survived the LLM outage
