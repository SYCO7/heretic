"""M14: owner-field-aware harvest — the real-world BOLA enabler. Many apps leak a
full list to every user (so "who fetched it" tells you nothing), but each record
carries an owner field. HERETIC attributes ownership from that field, turning a
leaky list into a confirmable ownership-BOLA. Offline mock modelled on VAmPI books.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, LoginSpec, ObjectSpec, Role, Scope
from heretic.core.orchestrator import Orchestrator
from heretic.llm.scripted import ScriptedLLM

# LEAKY list: every user sees ALL books, but each record names its owner in `user`.
_BOOKS = [{"book_title": "b1", "user": "name1"}, {"book_title": "b2", "user": "name2"}]


def _handler(req: httpx.Request) -> httpx.Response:
    p = req.url.path
    if p == "/users/v1/login":
        u = json.loads(req.content or b"{}").get("username", "")
        return httpx.Response(200, json={"auth_token": f"tok-{u}"})
    if not req.headers.get("authorization", "").startswith("Bearer tok-"):
        return httpx.Response(401, json={"error": "auth"})
    if p == "/books/v1":
        return httpx.Response(200, json={"Books": _BOOKS})          # everyone sees all books
    m = re.match(r"^/books/v1/([^/]+)$", p)
    if m:                                                            # IDOR: any user reads any book's secret
        owner = next((b["user"] for b in _BOOKS if b["book_title"] == m.group(1)), "?")
        return httpx.Response(200, json={"book_title": m.group(1), "owner": owner, "secret": f"s-{m.group(1)}"})
    return httpx.Response(404, json={})


def _cfg() -> Config:
    return Config(
        url="http://vampi.local", model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000, scope=Scope(allow=["vampi.local"]), classes=["bola"], chain=False,
        accounts_path=Path("accounts.yaml"),
        accounts=Accounts(
            login=LoginSpec(url="/users/v1/login", method="POST", token_field="auth_token"),
            roles=[Role(name="guest", creds=None),
                   Role(name="userA", creds={"username": "name1", "password": "pass1"}),
                   Role(name="userB", creds={"username": "name2", "password": "pass2"})]),
        objects=[ObjectSpec(name="book", list_url="/books/v1", item_url="/books/v1/{id}",
                            id_field="book_title", list_path="Books")])


def test_owner_field_turns_leaky_list_into_confirmed_bola():
    orch = Orchestrator(_cfg(), console=Console(quiet=True), transport=httpx.MockTransport(_handler),
                        llm=ScriptedLLM())
    # ownership attributed by the `user` field: name1 owns b1, name2 owns b2 (non-overlapping)
    orch.sessions.login_all()
    owned, _obs = orch.sessions.recon(_cfg().objects)
    assert owned["book"] == {"userA": {"b1"}, "userB": {"b2"}}

    bola = [f for f in orch.run() if f.bug_class == "bola"]
    assert len(bola) == 2                                           # both cross-reads confirmed
    assert all("book" in f.title for f in bola)
