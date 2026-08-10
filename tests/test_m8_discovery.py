"""M8: autonomous attack-surface discovery — OpenAPI parse + active object
inference. Proves the tool finds its own BOLA targets with NO hand-written
`objects:` block. Offline (mock transport + published OpenAPI spec).
"""
from __future__ import annotations

import httpx
from rich.console import Console

from heretic.benchmark import fixtures as F
from heretic.core.browser import available as browser_available
from heretic.core.browser import is_api, templatize
from heretic.core.discovery import (
    Discoverer,
    _detect_id_field,
    _extract_js_paths,
    _extract_routes,
    _item_base,
    _prefix,
    _sample_id,
    _script_srcs,
    _to_path,
)
from heretic.core.orchestrator import Orchestrator
from heretic.core.session_mgr import SessionManager
from heretic.llm.scripted import ScriptedLLM

_QUIET = Console(quiet=True)


def _sessions():
    cfg = F._cfg()
    s = SessionManager(cfg, transport=httpx.MockTransport(F.handler))
    s.login_all()
    return s, cfg


# ---- unit: the inference primitives ----------------------------------

def test_item_base_parsing():
    assert _item_base("/api/orders/{id}") == ("/api/orders", "id")
    assert _item_base("/identity/vehicle/{vehicleId}/location") == ("/identity/vehicle", "vehicleId")
    assert _item_base("/api/orders") == (None, None)


def test_id_field_detection_from_list_body():
    assert _detect_id_field({"orders": [{"id": "1001"}]}, "id") == ("id", "orders")
    assert _detect_id_field([{"uuid": "x"}], "vehicleId") == ("uuid", None)
    assert _detect_id_field({"data": []}, "id") == (None, None)


# ---- OpenAPI-driven discovery ----------------------------------------

def test_discovery_parses_openapi_and_infers_objects():
    s, cfg = _sessions()
    res = Discoverer(s, cfg, console=_QUIET).discover()

    assert res.spec_paths                                   # found the published spec
    assert len(res.endpoints) >= 6                          # all documented paths
    names = {o.name for o in res.objects}
    assert {"order", "profile", "catalog"} <= names         # inferred every list/item pair

    order = next(o for o in res.objects if o.name == "order")
    assert order.list_url == "/api/orders"
    assert order.item_url == "/api/orders/{id}"             # {id} normalised, ready for .format(id=...)
    assert order.id_field == "id"
    assert order.list_path == "orders"                      # detected the array wrapper key


def test_discovery_respects_scope_gate():
    """Out-of-scope fetches return nothing rather than firing off-scope."""
    s, cfg = _sessions()
    d = Discoverer(s, cfg, console=_QUIET)
    cfg.scope.allow = ["nowhere.invalid"]                   # nothing is in scope now
    assert d._get_json("/api/orders") is None               # gate blocks the fetch, no crash


# ---- end-to-end: autonomous BOLA with NO hand-written objects --------

def _autonomous_orchestrator() -> Orchestrator:
    cfg = F._cfg()
    cfg.objects = []                                        # operator supplied NOTHING
    cfg.discovery.enabled = True                            # discover the surface instead
    F._reset()
    llm = ScriptedLLM(intent=F._INTENT, hypotheses=F._HYPOTHESES, judge_fn=F._judge_fn)
    return Orchestrator(cfg, console=_QUIET, transport=httpx.MockTransport(F.handler), llm=llm)


def test_autonomous_run_matches_hand_tuned_result():
    findings = _autonomous_orchestrator().run()
    bola = [f for f in findings if f.bug_class == "bola"]
    # discovery inferred the order object on its own → the two BOLAs are still found,
    # and the safe profile / public catalog are still correctly dropped (no new FP)
    assert len(bola) == 2
    assert len(findings) == 8                               # identical to the hand-configured benchmark


# ---- JS-route extraction (spec-less SPA support) ---------------------

def test_js_scraping_primitives():
    html = '<html><script src="/static/app.js"></script><script src="https://x.test/b.js"></script></html>'
    assert _script_srcs(html) == ["/static/app.js", "https://x.test/b.js"]
    assert _to_path("https://x.test/static/app.js") == "/static/app.js"
    assert _to_path("assets/app.js") == "/assets/app.js"
    assert _prefix("/identity/api/v2/vehicle/{id}/location") == "/identity/api/v2/vehicle"

    js = 'fetch("/api/orders"); http.get(`/api/orders/${id}`); const x="/login"; go("/api/v2/cars")'
    paths = _extract_js_paths(js)
    assert "/api/orders" in paths                           # plain list route
    assert "/api/orders/{id}" in paths                      # template literal → {id}
    assert "/api/v2/cars" in paths                          # /vN route kept
    assert "/login" not in paths                            # non-api frontend route filtered out


def test_discovery_from_js_only_infers_objects():
    """With OpenAPI disabled, the JS bundle alone yields the BOLA-ready objects."""
    s, cfg = _sessions()
    cfg.discovery.openapi = []                              # force the JS path to do the work
    cfg.discovery.js = True
    res = Discoverer(s, cfg, console=_QUIET).discover()

    assert res.js_assets >= 1                               # fetched + scraped the bundle
    assert not res.spec_paths                               # no OpenAPI was used
    names = {o.name for o in res.objects}
    assert {"order", "profile", "catalog"} <= names         # inferred purely from JS routes


# ---- wordlist brute-force probe --------------------------------------

def test_wordlist_probe_finds_reachable_paths():
    s, cfg = _sessions()
    cfg.objects = []                                       # isolate the wordlist (no crawl seeds)
    cfg.discovery.openapi = []
    cfg.discovery.js = False
    cfg.discovery.wordlist = True
    res = Discoverer(s, cfg, console=_QUIET).discover()

    assert res.probes > 0                                   # it actually probed
    hit = {e["path"] for e in res.endpoints if e.get("src") == "wordlist"}
    assert "/api/orders" in hit                             # found a real path by brute force
    # a 404-only path is never recorded
    assert all(e.get("status", 200) != 404 for e in res.endpoints if e.get("src") == "wordlist")


# ---- headless-browser XHR capture (pure logic) -----------------------

def test_templatize_collapses_ids():
    assert templatize("/api/v2/vehicle/3aa99fc5-240e-495a-8424-dda9a897fefb/location") == \
        "/api/v2/vehicle/{id}/location"
    assert templatize("/api/orders/1001") == "/api/orders/{id}"
    assert templatize("/api/orders/all") == "/api/orders/all"       # non-id segment kept
    assert templatize("/identity/api/v2/user/abcdef0123456789abcdef01") == \
        "/identity/api/v2/user/{id}"                                # mongo-style id
    # crAPI-style ids: VIN, base62 token, and the SPA's null placeholder
    assert templatize("/workshop/api/merchant/service_requests/12HCUB1NGTP5L42TM") == \
        "/workshop/api/merchant/service_requests/{id}"
    assert templatize("/community/api/v2/community/posts/g7ee6n3FJkzK7H7FMZYN6h") == \
        "/community/api/v2/community/posts/{id}"
    assert templatize("/workshop/api/shop/orders/null") == "/workshop/api/shop/orders/{id}"
    assert templatize("/workshop/api/mechanic/service_requests") == \
        "/workshop/api/mechanic/service_requests"                   # word segment kept, not an id


def test_is_api_filter():
    assert is_api("/identity/api/v2/vehicle/{id}/location")
    assert is_api("/rest/v3/orders")
    assert not is_api("/dashboard")


def test_extract_routes_finds_frontend_paths():
    js = '{"/dashboard":1,"/shop":2,"/api/orders":3,"/main.js":4,"/vehicle-service":5}'
    routes = _extract_routes(js)
    assert "/dashboard" in routes and "/shop" in routes and "/vehicle-service" in routes
    assert "/api/orders" not in routes                      # api routes are not frontend routes
    assert "/main.js" not in routes                         # asset files excluded


def test_browser_available_returns_tuple():
    ok, hint = browser_available()
    assert isinstance(ok, bool)
    assert ok or hint                                       # if unavailable, a hint is provided


# ---- targeted list->detail probing -----------------------------------

def test_sample_id_pulls_a_real_id():
    assert _sample_id({"orders": [{"id": "1001"}, {"id": "1002"}]}) == "1001"
    assert _sample_id([{"uuid": "abc"}]) == "abc"
    assert _sample_id({"orders": []}) is None


def test_detail_probe_discovers_subresource_item_endpoint():
    """A `/orders/{id}/status` sub-resource is invisible to static scraping — only
    following the list to a detail with a real id finds it."""
    s, cfg = _sessions()
    cfg.discovery.openapi = []
    cfg.discovery.js = False
    cfg.discovery.detail_probe = True
    res = Discoverer(s, cfg, console=_QUIET).discover()

    detail = {e["path"] for e in res.endpoints if e.get("src") == "detail"}
    assert "/api/orders/{id}/status" in detail              # sub-resource recovered via real id
    assert "/api/orders/{id}" in detail                     # the plain item endpoint too
