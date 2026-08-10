"""M9: harden autonomous object-pairing across diverse API shapes.

Two real vulnerable targets have schemes that break naive pairing:

  * OWASP Juice Shop — list responses wrap the array in `{status, data:[...]}`, and
    resources are Capitalised (`/api/Products/{id}`, `/api/Users/{id}`).
  * VAmPI — items are keyed on STRING ids (`/users/v1/{username}`,
    `/books/v1/{book_title}`), the objects carry no numeric `id`, and paths are
    versioned (`/users/v1`).

These mocks reproduce those exact shapes so pairing is verified offline.
"""
from __future__ import annotations

import re
from pathlib import Path

import httpx
from rich.console import Console

from heretic.config import Accounts, Config, DiscoverySpec, LoginSpec, Role, Scope
from heretic.core.discovery import Discoverer
from heretic.core.session_mgr import SessionManager

_QUIET = Console(quiet=True)


def _cfg(url: str, host: str) -> Config:
    return Config(
        url=url, model="fake", engagement="t", authorized_by="t@t", signed=True,
        max_rate_rps=100000,                                # no throttle in tests
        scope=Scope(allow=[host]), accounts_path=Path("accounts.yaml"),
        accounts=Accounts(
            login=LoginSpec(url="/login", token_field="token"),
            roles=[Role(name="guest", creds=None),
                   Role(name="userA", creds={"email": "a@x", "password": "x"}),
                   Role(name="userB", creds={"email": "b@x", "password": "x"})]),
        discovery=DiscoverySpec(enabled=True, js=False, browser=False, detail_probe=True))


def _discover(handler, url="http://t.local", host="t.local"):
    cfg = _cfg(url, host)
    s = SessionManager(cfg, transport=httpx.MockTransport(handler))
    s.login_all()
    res = Discoverer(s, cfg, console=_QUIET).discover()
    s.close()
    return {o.name: o for o in res.objects}


# ---- OWASP Juice Shop shape ------------------------------------------

_JUICE_SPEC = {"openapi": "3.0.0", "paths": {
    "/api/Products": {"get": {}}, "/api/Products/{id}": {"get": {}},
    "/api/Users": {"get": {}}, "/api/Users/{id}": {"get": {}}}}
_PRODUCTS = [{"id": 1, "name": "Apple"}, {"id": 2, "name": "Banana"}]
_JUSERS = [{"id": 1, "email": "a@juice"}, {"id": 2, "email": "b@juice"}]


def _juice(req: httpx.Request) -> httpx.Response:
    p = req.url.path
    if p == "/login":
        return httpx.Response(200, json={"token": "t"})
    if p == "/openapi.json":
        return httpx.Response(200, json=_JUICE_SPEC)
    if p == "/api/Products":
        return httpx.Response(200, json={"status": "success", "data": _PRODUCTS})   # data wrapper
    if p == "/api/Users":
        return httpx.Response(200, json={"status": "success", "data": _JUSERS})
    if re.match(r"^/api/Products/\d+$", p):
        return httpx.Response(200, json={"status": "success", "data": {"id": 1, "name": "x"}})
    if re.match(r"^/api/Users/\d+$", p):
        return httpx.Response(200, json={"status": "success", "data": {"id": 1, "email": "x"}})
    return httpx.Response(404, json={})


def test_juice_shop_data_wrapper_and_capitalised_models():
    objs = _discover(_juice)
    assert {"product", "user"} <= set(objs)                 # names normalised + lowercased
    prod = objs["product"]
    assert prod.list_url == "/api/Products"
    assert prod.item_url == "/api/Products/{id}"
    assert prod.id_field == "id"
    assert prod.list_path == "data"                         # unwrapped the {status,data:[...]} envelope


# ---- VAmPI shape (string ids, versioned paths, no numeric id) --------

_VAMPI_SPEC = {"openapi": "3.0.0", "paths": {
    "/users/v1": {"get": {}}, "/users/v1/{username}": {"get": {}},
    "/books/v1": {"get": {}}, "/books/v1/{book_title}": {"get": {}}}}
_VUSERS = [{"username": "name1", "email": "e1"}, {"username": "name2", "email": "e2"}]
_VBOOKS = [{"book_title": "bookA", "secret": "s1"}, {"book_title": "bookB", "secret": "s2"}]


def _vampi(req: httpx.Request) -> httpx.Response:
    p = req.url.path
    if p == "/login":
        return httpx.Response(200, json={"token": "t"})
    if p == "/openapi.json":
        return httpx.Response(200, json=_VAMPI_SPEC)
    if p == "/users/v1":
        return httpx.Response(200, json={"users": _VUSERS})
    if p == "/books/v1":
        return httpx.Response(200, json={"Books": _VBOOKS})
    m = re.match(r"^/users/v1/([^/]+)$", p)
    if m and m.group(1) in ("name1", "name2"):
        return httpx.Response(200, json={"username": m.group(1), "email": "e"})
    m = re.match(r"^/books/v1/([^/]+)$", p)
    if m and m.group(1) in ("bookA", "bookB"):
        return httpx.Response(200, json={"book_title": m.group(1), "secret": "s"})
    return httpx.Response(404, json={})


def test_vampi_string_ids_and_versioned_paths():
    objs = _discover(_vampi)
    assert {"user", "book"} <= set(objs)                    # not "v1" — version segment skipped in naming
    user = objs["user"]
    assert user.list_url == "/users/v1"
    assert user.item_url == "/users/v1/{id}"                # {username} normalised to {id}
    assert user.id_field == "username"                      # keyed on username, NOT email
    assert user.list_path == "users"
    book = objs["book"]
    assert book.id_field == "book_title"                    # string title id
    assert book.list_path == "Books"


def test_vampi_prefers_username_over_email_via_detail_probe():
    """The user object has both username and email; only /users/v1/<username> returns 200,
    so the prober must keep `username` — proving id-field disambiguation on string ids."""
    objs = _discover(_vampi)
    assert objs["user"].id_field == "username"
