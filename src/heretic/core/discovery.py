"""Autonomous attack-surface discovery (M8) — find the endpoints yourself.

The biggest limit of the earlier milestones: the operator had to hand-write the
`objects:` block in roe.yaml (which list/item endpoints to test for BOLA). This
module removes that step. Read-only, scope-gated, and it feeds the same pipeline:

  1. OpenAPI / Swagger — probe the well-known spec paths; if the app publishes a
     schema, parse every path+method out of it (the richest, cleanest source).
  2. Light JSON crawl — GET a seed set as an authenticated role and pull path-like
     strings out of the responses (HATEOAS links, nested resource URLs).
  3. Object inference — for every `GET /base/{id}` item endpoint, find its sibling
     list endpoint, FETCH it, inspect the returned array, and detect the id field.
     That yields ready-to-attack ObjectSpecs with no human input.

Everything here is GET-only and passes through cfg.assert_in_scope — discovery can
never touch an out-of-scope host or perform a state change.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import Config, DiscoverySpec, ObjectSpec

# response keys that commonly hold an object's identifier, best-first. Strong numeric/uuid
# ids first, then human-key ids (VAmPI keys users on `username`, books on `book_title`).
_ID_KEYS = ["id", "uuid", "_id", "guid", "pk", "slug", "username", "user_id",
            "name", "title", "book_title", "number", "email"]
# strings that look like an API path (leading slash, path-ish chars)
_PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./{}]+$")
_TEMPLATED = re.compile(r"\{[^/}]+\}")

# JS/HTML scraping
_SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
# quoted tokens (path may be relative — SPAs strip the leading slash + service prefix)
_JS_TOKEN = re.compile(r"""["'`]([A-Za-z0-9_./${}\-]{3,200})["'`]""")
_JS_TEMPLATE = re.compile(r"\$\{[^}]+\}")

# wordlist brute-force (opt-in). Kept deliberately small + generic.
_WORDLIST = [
    "api", "api/users", "api/user", "api/orders", "api/order", "api/products",
    "api/product", "api/cart", "api/account", "api/accounts", "api/profile",
    "api/me", "api/v1", "api/v2", "rest", "graphql", "api/admin", "api/coupons",
    "api/invoices", "api/transactions",
]
# resource words crossed with every discovered path-prefix
_RESOURCES = [
    "users", "user", "orders", "order", "products", "product", "items", "item",
    "accounts", "account", "profile", "profiles", "cart", "coupons", "invoices",
    "transactions", "vehicles", "vehicle", "mechanic", "reports", "posts",
    "comments", "me", "list", "all",
]


@dataclass
class DiscoveryResult:
    objects: list[ObjectSpec] = field(default_factory=list)     # inferred BOLA targets
    endpoints: list[dict[str, Any]] = field(default_factory=list)  # {method, path} for the intent model
    spec_paths: list[str] = field(default_factory=list)         # which OpenAPI specs were found
    crawled: int = 0
    js_assets: int = 0                                          # JS bundles fetched + scraped
    probes: int = 0                                            # wordlist paths probed
    browser_reqs: int = 0                                      # distinct XHRs captured by the browser


class Discoverer:
    def __init__(self, sessions: Any, cfg: Config, console: Any = None,
                 spec: DiscoverySpec | None = None) -> None:
        self.s = sessions
        self.cfg = cfg
        self.console = console
        self.spec = spec or cfg.discovery
        # rotate through authenticated roles; fall back to guest
        self._roles = [r for r in self.s.roles() if r != "guest"] or ["guest"]
        self._spa_routes: set[str] = set()                  # frontend routes for the browser pass

    # ---- public entrypoint --------------------------------------------

    def discover(self) -> DiscoveryResult:
        res = DiscoveryResult()
        endpoints: dict[tuple[str, str], dict[str, Any]] = {}

        def merge(eps: list[dict[str, Any]], overwrite: bool = False) -> None:
            for ep in eps:
                key = (ep["method"], ep["path"])
                if overwrite:
                    endpoints[key] = ep
                else:
                    endpoints.setdefault(key, ep)

        merge(self._from_openapi(res), overwrite=True)
        if self.spec.js:
            merge(self._from_js(res))                       # SPA bundles → real API routes
        merge(self._from_crawl(res))
        if self.spec.browser:
            merge(self._from_browser(res))                  # headless XHR capture (dynamic URLs)
        if self.spec.wordlist:
            merge(self._from_wordlist(res, endpoints))      # brute-force common paths (opt-in)
        if self.spec.detail_probe:
            merge(self._from_details(res, endpoints))       # list -> detail with real ids

        res.endpoints = list(endpoints.values())
        res.objects = self._infer_objects(res.endpoints)
        return res

    # ---- 1. OpenAPI / Swagger -----------------------------------------

    def _from_openapi(self, res: DiscoveryResult) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for path in self.spec.openapi:
            doc = self._get_json(path)
            if not isinstance(doc, dict) or "paths" not in doc:
                continue
            res.spec_paths.append(path)
            base = (doc.get("basePath") or "").rstrip("/")          # swagger 2.0
            for raw_path, methods in (doc.get("paths") or {}).items():
                if not isinstance(methods, dict):
                    continue
                full = base + raw_path if raw_path.startswith("/") else f"{base}/{raw_path}"
                for method in methods:
                    if method.lower() in ("get", "post", "put", "patch", "delete"):
                        out.append({"method": method.upper(), "path": full, "src": "openapi"})
        return out

    # ---- 2. light JSON crawl ------------------------------------------

    def _from_crawl(self, res: DiscoveryResult) -> list[dict[str, Any]]:
        seen: set[str] = set()
        found: dict[str, dict[str, Any]] = {}
        # seed from "/", explicit seeds, and any list endpoints the RoE already knows —
        # so on a HATEOAS API the crawl expands outward from real resource responses.
        obj_seeds = [o.list_url for o in self.cfg.objects]
        queue = ["/", *self.spec.seeds, *obj_seeds]
        role = self._roles[0]
        while queue and res.crawled < self.spec.max_pages:
            path = queue.pop(0)
            if path in seen or _TEMPLATED.search(path):
                continue
            seen.add(path)
            body = self._get_json(path, role=role)
            if body is None:
                continue
            res.crawled += 1
            found.setdefault(path, {"method": "GET", "path": path, "src": "crawl"})
            for p in _extract_paths(body):
                if p not in seen:
                    found.setdefault(p, {"method": "GET", "path": p, "src": "crawl"})
                    if not _TEMPLATED.search(p):
                        queue.append(p)
        return list(found.values())

    # ---- 2b. JS-route extraction (spec-less SPA support) --------------

    def _from_js(self, res: DiscoveryResult) -> list[dict[str, Any]]:
        """Fetch the SPA shell, pull its <script> bundles, and regex the API routes the
        frontend calls out of the JS — the way to map a target that ships no OpenAPI.
        Fragments that omit the service prefix are resolved by probing (crAPI-style)."""
        role = self._roles[0]
        html = self._get_text("/", role) or self._get_text("/index.html", role)
        assets = _script_srcs(html) if html else []
        paths: set[str] = set(_extract_js_paths(html) if html else [])
        for src in assets:
            if res.js_assets >= self.spec.max_js:
                break
            js = self._get_text(_to_path(src), role)
            if js is None:
                continue
            res.js_assets += 1
            paths |= _extract_js_paths(js)
            self._spa_routes |= _extract_routes(js)         # frontend routes for the browser pass
        if html:
            self._spa_routes |= _extract_routes(html)
        return self._resolve_prefixes(paths, res)

    # ---- 2d. headless-browser XHR capture (dynamic URLs) --------------

    def _from_browser(self, res: DiscoveryResult) -> list[dict[str, Any]]:
        """Drive the SPA as an authenticated role in a real headless browser and record the
        XHRs it fires — catching item-by-id URLs built at runtime that no static scrape sees."""
        from . import browser as B
        ok, hint = B.available()
        if not ok:
            if self.console:
                self.console.print(f"  [yellow]browser capture skipped[/] — {hint}")
            return []
        headers, token = self.s.role_auth(self._roles[0])
        headers = {**self.cfg.headers, **headers}         # include RoE attribution headers
        routes = [*sorted(self._spa_routes), *self.spec.browser_routes]
        creds = next((r.creds for r in self.cfg.accounts.roles
                      if r.name == self._roles[0] and r.creds), None)
        cap = B.BrowserCapture(self.cfg.url, headers=headers, token=token, creds=creds,
                               login_path=self.spec.browser_login,
                               wait_ms=self.spec.browser_wait_ms, clicks=self.spec.browser_clicks,
                               storage_keys=self.spec.storage_keys,
                               in_scope=self.cfg.assert_in_scope)
        try:
            eps = cap.capture(routes)
        except Exception as e:                              # a browser failure must not kill discovery
            if self.console:
                self.console.print(f"  [yellow]browser capture failed[/] ({type(e).__name__})")
            return []
        res.browser_reqs = len(eps)
        return eps

    def _resolve_prefixes(self, paths: set[str], res: DiscoveryResult) -> list[dict[str, Any]]:
        """A JS fragment like `api/shop/orders` may live under `/workshop/api/shop/orders`.
        Probe each static fragment across the service prefixes; learn which prefixes are
        live, then apply them to the templated item routes (which can't be probed blind)."""
        static = sorted(p for p in paths if not _TEMPLATED.search(p))
        templated = sorted(p for p in paths if _TEMPLATED.search(p))
        good: set[str] = set()
        working: set[str] = set()
        for p in static:
            for pre in self.spec.service_prefixes:
                if res.probes >= self.spec.max_probes:
                    break
                full = (pre + p) if pre else p
                if full in good:
                    continue
                st = self._status(full)
                res.probes += 1
                if st is not None and st != 404:        # 200/401/403/405 => the path exists
                    good.add(full)
                    working.add(pre)
                    break
        for p in templated:                             # apply the prefixes that worked
            for pre in (working or {""}):
                good.add((pre + p) if pre else p)
        return [{"method": "GET", "path": p, "src": "js"} for p in sorted(good)]

    # ---- 2c. wordlist brute-force (opt-in, noisy) ---------------------

    def _from_wordlist(self, res: DiscoveryResult, known: dict) -> list[dict[str, Any]]:
        """Probe common API paths, plus each discovered path-prefix crossed with a small
        resource wordlist. Records anything that isn't a plain 404. GET-only, capped."""
        prefixes = {""} | {_prefix(p) for (_m, p) in known}
        candidates: list[str] = list(dict.fromkeys([*_WORDLIST, *self.spec.extra_paths]))
        for pre in sorted(prefixes):
            for word in _RESOURCES:
                candidates.append(f"{pre}/{word}")
        out: list[dict[str, Any]] = []
        seen = {p for (_m, p) in known}
        for cand in dict.fromkeys(candidates):
            if res.probes >= self.spec.max_probes:
                break
            cand = "/" + cand.lstrip("/")
            if cand in seen or _TEMPLATED.search(cand):
                continue
            seen.add(cand)
            status = self._status(cand)
            if status is None:
                continue
            res.probes += 1
            if status != 404:                              # 200/401/403/405 => the path exists
                out.append({"method": "GET", "path": cand, "src": "wordlist", "status": status})
        return out

    # ---- 2e. targeted list -> detail probing (real ids) --------------

    def _from_details(self, res: DiscoveryResult, known: dict) -> list[dict[str, Any]]:
        """For each discovered list endpoint: fetch it, take a REAL id, and probe the item
        and sub-resource URLs with that id. This recovers `/thing/{id}` and
        `/thing/{id}/location` — the item endpoints BOLA needs — deterministically."""
        lists = [p for (m, p) in known if m == "GET" and not _TEMPLATED.search(p)]
        lists += [o.list_url for o in self.cfg.objects]
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for lst in dict.fromkeys(lists):
            item0 = _first_item(self._get_json(lst))
            if item0 is None:
                continue
            # candidate (id_field, value) pairs — an object often has both `id` and `uuid`;
            # only the one the endpoint actually keys on returns 200, so we learn which.
            pairs = [(k, str(item0[k])) for k in _ID_KEYS if item0.get(k) is not None]
            if not pairs:
                continue
            parent = lst.rsplit("/", 1)[0] if "/" in lst.lstrip("/") else lst
            for base in dict.fromkeys([lst, parent]):
                pref = None                                 # id field learned to work for this base
                for tmpl in ["{b}/{v}", *[f"{{b}}/{{v}}/{s}" for s in self.spec.detail_subs]]:
                    if res.probes >= self.spec.max_probes:
                        break
                    order = sorted(pairs, key=lambda p: p[0] != pref)   # try the learned field first
                    hit = None
                    for fld, val in order:
                        if res.probes >= self.spec.max_probes:
                            break
                        st = self._status(tmpl.format(b=base, v=val))
                        res.probes += 1
                        if st == 200:
                            hit = (fld, val)
                            pref = fld
                            break
                        if st is not None and st != 404 and hit is None:
                            hit = (fld, val)                # exists but not readable (401/403/405)
                    if hit:
                        fld, val = hit
                        item = tmpl.format(b=base, v=val).replace(val, "{id}", 1)
                        if item not in seen:
                            seen.add(item)
                            out.append({"method": "GET", "path": item, "src": "detail", "id_field": fld})
        return out

    # ---- 3. active object inference (the BOLA-ready part) -------------

    def _infer_objects(self, endpoints: list[dict[str, Any]]) -> list[ObjectSpec]:
        gets = [e["path"] for e in endpoints if e["method"] == "GET"]
        static = {p for p in gets if not _TEMPLATED.search(p)}
        # id-field hints learned by detail-probing (which field actually returned 200)
        hints = {e["path"]: e["id_field"] for e in endpoints if e.get("id_field")}
        objects: list[ObjectSpec] = []
        used_names: set[str] = set()

        paired: set[str] = set()
        for item in gets:
            if len(_TEMPLATED.findall(item)) != 1:
                continue                                    # want exactly one {id} segment
            base, param = _item_base(item)
            if base is None:
                continue
            # try each plausible list endpoint until one actually returns a collection —
            # so an action endpoint like `/vehicle/add_vehicle` can't masquerade as the list.
            for list_url in self._list_candidates(base, static):
                if list_url in paired:
                    continue
                payload = self._get_json(list_url)
                detected, list_path = _detect_id_field(payload, param)
                id_field = hints.get(item) or detected     # the field proven to resolve wins
                if id_field is None:
                    continue
                paired.add(list_url)
                objects.append(ObjectSpec(
                    name=_object_name(base, used_names), list_url=list_url,
                    item_url=_TEMPLATED.sub("{id}", item),  # normalise {vehicleId} -> {id}
                    id_field=id_field, list_path=list_path))
                break
        return objects

    def _list_candidates(self, base: str, static: set[str]) -> list[str]:
        """Ordered list-endpoint guesses for an item base — collection-shaped ones first,
        so the real list wins over sibling action endpoints."""
        ordered: list[str] = []
        for cand in (base, base + "s", base + "es", base + "/mine", base + "/list"):
            if cand in static and cand not in ordered:
                ordered.append(cand)
        # direct children of base, plural/collection-looking ones first
        children = [p for p in static if p.startswith(base + "/") and "/" not in p[len(base) + 1:]]
        children.sort(key=lambda p: (not p.rstrip("/").endswith("s"), p))
        for p in children:
            if p not in ordered:
                ordered.append(p)
        return ordered

    # ---- helpers ------------------------------------------------------

    def _get_json(self, path: str, role: str | None = None) -> Any:
        resp = self._fetch(path, role)
        if resp is not None and resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                return None
        return None

    def _get_text(self, path: str, role: str | None = None) -> str | None:
        resp = self._fetch(path, role)
        if resp is not None and resp.status_code == 200:
            return resp.text
        return None

    def _status(self, path: str, role: str | None = None) -> int | None:
        resp = self._fetch(path, role)
        return resp.status_code if resp is not None else None

    def _fetch(self, path: str, role: str | None = None) -> httpx.Response | None:
        try:
            self.cfg.assert_in_scope(self.s.abs(path))      # hard scope gate — never leave scope
        except SystemExit:
            return None
        for r in ([role] if role else self._roles):
            try:
                return self.s.get_as(r, path)
            except httpx.HTTPError:
                continue
        return None


# ---- module-level helpers ---------------------------------------------

def _extract_paths(obj: Any, out: set[str] | None = None) -> set[str]:
    """Pull path-like strings out of a JSON body (HATEOAS links / nested URLs)."""
    out = set() if out is None else out
    if isinstance(obj, str):
        s = obj
        if s.startswith("http"):
            m = re.match(r"^https?://[^/]+(/.*)$", s)
            s = m.group(1) if m else ""
        if s and _PATH_RE.match(s) and len(s) < 200:
            out.add(s.split("?")[0])
    elif isinstance(obj, dict):
        for v in obj.values():
            _extract_paths(v, out)
    elif isinstance(obj, list):
        for v in obj[:50]:
            _extract_paths(v, out)
    return out


_ROUTE_RE = re.compile(r"^/[a-z][a-z0-9\-]*(?:/[a-z0-9\-]+){0,2}$")


def _extract_routes(text: str) -> set[str]:
    """Frontend (non-API) SPA router paths, to visit in the headless-browser pass."""
    out: set[str] = set()
    for raw in _JS_TOKEN.findall(text or ""):
        tok = raw.split("?")[0]
        low = tok.lower()
        if "api" in low or "." in tok or "{" in tok:
            continue
        if _ROUTE_RE.match(tok):
            out.add(tok)
    return out


def _script_srcs(html: str) -> list[str]:
    return _SCRIPT_SRC.findall(html or "")


def _to_path(src: str) -> str:
    """Normalise a script src (absolute URL or relative) to a leading-slash path."""
    if src.startswith("http"):
        m = re.match(r"^https?://[^/]+(/.*)$", src)
        return m.group(1) if m else "/"
    return src if src.startswith("/") else "/" + src


def _extract_js_paths(text: str) -> set[str]:
    """Regex API routes out of JS/HTML source. Keeps path-like strings that look like API
    endpoints (contain 'api' or a /vN segment), normalising `${x}`->`{id}`. Relative
    fragments get a leading slash; a trailing-slash concatenation base (`api/orders/`)
    yields both the list (`/api/orders`) and its item template (`/api/orders/{id}`)."""
    out: set[str] = set()
    for raw in _JS_TOKEN.findall(text or ""):
        tok = _JS_TEMPLATE.sub("{id}", raw).split("?")[0].strip()
        low = tok.lower()
        if "/" not in tok or " " in tok:
            continue
        if "api/" not in low and "/api" not in low and not re.search(r"/v\d", tok):
            continue                                        # only API-ish routes, not frontend router paths
        p = tok if tok.startswith("/") else "/" + tok
        if "//" in p[1:] or len(p) < 4:
            continue
        if p.endswith("/"):                                 # `.../orders/` + id concatenation site
            base = p.rstrip("/")
            out.update({base, base + "/{id}"})
        else:
            out.add(p)
    return out


def _prefix(path: str) -> str:
    """Parent directory of a path (templated + empty segments dropped), for crossing
    with the resource wordlist. `/a/b/{id}/loc` -> `/a/b`."""
    parts = [p for p in path.split("?")[0].split("/") if p and "{" not in p]
    return "/" + "/".join(parts[:-1]) if len(parts) > 1 else ""


def _item_base(item_path: str) -> tuple[str | None, str | None]:
    """`/api/orders/{id}` -> ('/api/orders', 'id'); `/v/{vid}/loc` -> ('/v', 'vid')."""
    m = _TEMPLATED.search(item_path)
    if not m:
        return None, None
    param = m.group(0)[1:-1]
    base = item_path[:m.start()].rstrip("/")
    return (base or None), param


def _detect_id_field(payload: Any, param: str) -> tuple[str | None, str | None]:
    """Given a list response, return (id_field, list_path). Actively inspects items."""
    list_path = None
    data = payload
    if isinstance(data, dict):
        arrays = [(k, v) for k, v in data.items() if isinstance(v, list)]
        if arrays:
            list_path, data = arrays[0]
    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        return None, None
    item = data[0]
    # prefer a key matching the URL param, then common id keys, then any *id/*name/*title key
    candidates = [param, param.rstrip("Ss"), *_ID_KEYS]
    for key in candidates:
        if key and key in item:
            return key, list_path
    for key in item:
        if key.lower().endswith(("id", "uuid", "name", "title", "key")):
            return key, list_path
    return None, None


def _first_item(payload: Any) -> dict | None:
    """The first object in a list response (unwrapping a `{key: [...]}` collection)."""
    data = payload
    if isinstance(data, dict):
        arrays = [v for v in data.values() if isinstance(v, list)]
        data = arrays[0] if arrays else None
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data[0]
    return None


def _sample_id(payload: Any) -> str | None:
    """Pull one concrete id out of a list response, for detail probing."""
    item = _first_item(payload)
    if item is None:
        return None
    for key in _ID_KEYS:
        if item.get(key) is not None:
            return str(item[key])
    return None


_SKIP_SEG = {"api", "rest", "v1", "v2", "v3", "v4", "backend", "identity", "community", "workshop"}


def _object_name(base: str, used: set[str]) -> str:
    # last meaningful segment — skip version / gateway segments so `/users/v1` -> "user"
    segs = [s for s in base.strip("/").split("/")
            if s and s.lower() not in _SKIP_SEG and not re.fullmatch(r"v\d+", s.lower())]
    name = (segs[-1] if segs else "object").rstrip("s").lower() or "object"
    stem, i = name, 2
    while name in used:
        name = f"{stem}{i}"
        i += 1
    used.add(name)
    return name
