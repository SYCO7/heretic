"""M16: deterministic mass-assignment at registration. A signup endpoint that accepts
and reflects a client-supplied `role`/`isAdmin` is confirmed; one that ignores it is not.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, LoginSpec, Role, Scope
from heretic.core.massassign import reflects
from heretic.core.orchestrator import Orchestrator
from heretic.llm.scripted import ScriptedLLM


def test_reflects_helper():
    assert reflects({"data": {"role": "admin"}}, "role", "admin")
    assert reflects({"user": {"isAdmin": True}}, "isAdmin", True)
    assert not reflects({"data": {"role": "customer"}}, "role", "admin")


def _vuln(req: httpx.Request) -> httpx.Response:
    """VULN: /api/Users echoes whatever role you send (mass assignment)."""
    if req.url.path == "/api/Users":
        body = json.loads(req.content or b"{}")
        return httpx.Response(201, json={"data": {"id": 1, "email": body.get("email"),
                                                  "role": body.get("role", "customer")}})
    return httpx.Response(404, json={})


def _safe(req: httpx.Request) -> httpx.Response:
    """SAFE: role is always customer, ignoring the client."""
    if req.url.path == "/api/Users":
        body = json.loads(req.content or b"{}")
        return httpx.Response(201, json={"data": {"id": 1, "email": body.get("email"),
                                                  "role": "customer"}})
    return httpx.Response(404, json={})


def _cfg() -> Config:
    return Config(
        url="http://shop.local", model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000, scope=Scope(allow=["shop.local"]), classes=["mass_assignment"],
        mode="live", destructive_allowed=["*"], chain=False, accounts_path=Path("accounts.yaml"),
        accounts=Accounts(login=LoginSpec(url="/login", token_field="token"),
                          roles=[Role(name="guest", creds=None)]))


def _run(handler):
    orch = Orchestrator(_cfg(), console=Console(quiet=True), transport=httpx.MockTransport(handler),
                        llm=ScriptedLLM())
    return [f for f in orch.run() if f.bug_class == "mass_assignment"]


def test_reflected_role_is_confirmed():
    ma = _run(_vuln)
    assert len(ma) == 1
    assert "role" in ma[0].title
    assert ma[0].proof["oracle"] == "reflected_privileged_field"
    assert ma[0].proof["field"] == "role" and ma[0].proof["value"] == "admin"


def test_ignored_privileged_field_is_not_flagged():
    assert _run(_safe) == []                                # role stays customer → no false positive


def test_registration_probe_gated_in_dry_run():
    cfg = _cfg()
    cfg.mode = "dry-run"                                    # state-changing → must be skipped
    orch = Orchestrator(cfg, console=Console(quiet=True), transport=httpx.MockTransport(_vuln),
                        llm=ScriptedLLM())
    assert [f for f in orch.run() if f.bug_class == "mass_assignment"] == []
