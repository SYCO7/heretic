"""Config loading + the authorization gate.

THIS MODULE IS A SECURITY BOUNDARY. It refuses to run without a valid, signed
RoE, and exposes scope checks the orchestrator MUST call before every action.
The LLM cannot bypass these — they are plain code. See docs/07-GUARDRAILS.md.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

ALL_CLASSES = [
    "bola", "bfla", "excessive_data_exposure", "price_tamper", "workflow_bypass",
    "mass_assignment", "coupon_abuse", "race_condition", "auth_flow",
]


# ---- accounts (test identities) ---------------------------------------

class CsrfSpec(BaseModel):
    """How to defeat a CSRF-guarded login: GET `fetch_url` first (persisting cookies),
    read the token from `source`, then replay it on the login request as a header
    and/or a body field. Covers Angular/Laravel (XSRF cookie), Django/Rails (hidden
    input), and SPA meta-tag patterns."""
    fetch_url: str = "/"                             # page/endpoint that seeds the token
    source: str = "cookie:XSRF-TOKEN"               # cookie:NAME | meta:NAME | input:NAME | json:dotted
    header: str | None = "X-XSRF-TOKEN"           # send the token in this request header
    field: str | None = None                      # and/or in this login-body field


class LoginSpec(BaseModel):
    url: str
    method: str = "POST"
    token_field: str = "token"                       # json field, dotted, or "cookie:NAME"
    auth_header: str = "Authorization: Bearer {token}"
    content_type: str = "json"                       # json | form  (form = application/x-www-form-urlencoded)
    csrf: CsrfSpec | None = None                   # optional CSRF pre-fetch (None = none needed)


class Role(BaseModel):
    name: str
    creds: dict[str, Any] | None = None           # None = unauthenticated (guest)
    token: str | None = None                      # pre-obtained bearer token — skips login
                                                  # (for OTP/MFA/SSO: paste the token from the browser)


class Accounts(BaseModel):
    login: LoginSpec | None = None
    roles: list[Role] = Field(default_factory=list)


# ---- object specs (what to harvest + test for BOLA) -------------------

class ObjectSpec(BaseModel):
    """A per-object resource. Roles fetch `list_url` to harvest the ids they own,
    then non-owners are tested against `item_url` for BOLA."""
    name: str
    list_url: str                                    # role fetches own -> harvest ids
    item_url: str                                    # templated with {id}, cross-role test
    id_field: str = "id"                             # dotted path to id within a list item
    list_path: str | None = None                  # dotted path to the array in the list response


class LoginObjectSpec(BaseModel):
    """An object whose per-role OWNED id comes from the login response, not a list
    endpoint (e.g. Juice Shop hands you your basket id as `authentication.bid`).
    Pairs that id with `item_url` so the differential BOLA oracle can test cross-reads."""
    name: str
    item_url: str                                    # templated with {id}
    id_from: str                                     # dotted path in the login JSON -> this role's id


class RaceSpec(BaseModel):
    """A race-condition / TOCTOU probe: fire `parallel` identical requests and
    confirm that no more than `expect_max_success` succeed (atomic enforcement)."""
    name: str
    url: str
    method: str = "POST"
    body: dict[str, Any] | None = None
    as_role: str = "userA"
    parallel: int = 10
    expect_max_success: int = 1                      # e.g. single-use coupon
    success_status: int = 200
    success_field: str | None = None              # optional dotted field that marks success


class CouponSpec(BaseModel):
    """A coupon-abuse probe: redeem the SAME single-use code `max_uses`+1 times
    SEQUENTIALLY and confirm the server does not accept it more than `max_uses`
    times (single-use / per-user limit enforced server-side). Sibling to RaceSpec —
    RaceSpec fires concurrently (TOCTOU), this one redeems in series (missing
    idempotency / reuse). State-changing → live-gated."""
    name: str
    url: str                                         # the coupon-apply / redeem endpoint
    code: str                                        # the single-use coupon code
    method: str = "POST"
    code_field: str = "code"                         # body field carrying the code
    body: dict[str, Any] | None = None            # extra body merged with the code field
    as_role: str = "userA"
    max_uses: int = 1                                # allowed successful redemptions (single-use = 1)
    success_status: int = 200
    success_field: str | None = None              # optional dotted field that marks a redemption


# ---- scope + config ----------------------------------------------------

class Scope(BaseModel):
    allow: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


# well-known OpenAPI / Swagger locations, probed in order
_DEFAULT_OPENAPI = [
    "/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs", "/api-docs",
    "/swagger/v1/swagger.json", "/api/openapi.json", "/api-docs/swagger.json",
]


class DiscoverySpec(BaseModel):
    """Autonomous attack-surface discovery (read-only). Auto-enabled when `objects`
    is empty so the tool can find its own BOLA targets."""
    enabled: bool = False
    openapi: list[str] = Field(default_factory=lambda: list(_DEFAULT_OPENAPI))
    seeds: list[str] = Field(default_factory=list)   # extra paths to crawl from
    max_pages: int = 40
    js: bool = True                                  # extract API routes from SPA JS bundles
    max_js: int = 10                                 # cap JS assets fetched
    wordlist: bool = False                           # brute-force a path wordlist (noisy; opt-in)
    max_probes: int = 400                            # cap probe budget (JS-resolve + wordlist + detail)
    extra_paths: list[str] = Field(default_factory=list)   # user-supplied candidate paths
    # list->detail: fetch each list endpoint, take a real id, probe item + sub-resource URLs
    # with it. This is what recovers `/thing/{id}` and `/thing/{id}/location` for BOLA.
    detail_probe: bool = True
    detail_subs: list[str] = Field(default_factory=lambda: [
        "location", "details", "detail", "view", "info", "status", "report", "profile",
    ])
    # service-routing prefixes to try when a JS fragment omits it (microservice proxies
    # like crAPI mount services under /identity, /community, /workshop). "" tried first.
    service_prefixes: list[str] = Field(default_factory=lambda: [
        "", "/api", "/identity", "/community", "/workshop", "/rest", "/backend",
    ])
    # headless-browser XHR capture — drive the SPA and observe the requests it fires,
    # catching dynamically-built item URLs (e.g. /vehicle/{id}/location) that no static
    # scrape can see. Opt-in: needs playwright + a chromium binary.
    browser: bool = False
    browser_routes: list[str] = Field(default_factory=list)   # extra SPA routes to visit
    browser_login: str = "/login"                             # SPA login route to drive the form on
    browser_wait_ms: int = 2500
    browser_clicks: int = 20                                  # bounded interaction per route (0 = off)
    storage_keys: list[str] = Field(default_factory=lambda: [
        "token", "access_token", "jwt", "id_token", "auth_token", "crapi.token", "user",
    ])


class Config(BaseModel):
    url: str
    model: str
    engagement: str
    authorized_by: str
    signed: bool
    scope: Scope
    mode: str = "dry-run"                             # dry-run | live
    max_rate_rps: int = 5
    max_parallel: int = 3
    headers: dict[str, str] = Field(default_factory=dict)   # sent on EVERY request (e.g. program-attribution)
    destructive_allowed: list[str] = Field(default_factory=list)
    classes: list[str] = Field(default_factory=lambda: list(ALL_CLASSES))
    accounts_path: Path
    accounts: Accounts = Field(default_factory=Accounts)
    objects: list[ObjectSpec] = Field(default_factory=list)
    login_objects: list[LoginObjectSpec] = Field(default_factory=list)
    races: list[RaceSpec] = Field(default_factory=list)
    coupons: list[CouponSpec] = Field(default_factory=list)
    chain: bool = False                              # compose confirmed primitives into higher-impact chains
    iterate: int = 0                                 # feedback loop: mutate+retry a failed logic test up to N times
    discovery: DiscoverySpec = Field(default_factory=DiscoverySpec)   # autonomous endpoint discovery
    models: dict[str, str] = Field(default_factory=dict)   # per-phase model overrides (used when model == "auto")

    # ---- the security boundary ----------------------------------------

    def assert_in_scope(self, target: str) -> None:
        """Called before EVERY request. Hard-stops on out-of-scope / excluded target."""
        host = urlparse(target).hostname or target
        for pat in self.scope.exclude:
            if fnmatch.fnmatch(target, pat) or fnmatch.fnmatch(host, pat):
                _die(f"BLOCKED: '{target}' matches an exclude rule ('{pat}').")
        if any(_scope_match(target, host, pat) for pat in self.scope.allow):
            return
        _die(f"BLOCKED: '{target}' is not in the scope allowlist.")

    def is_destructive_allowed(self, action_class: str) -> bool:
        """Destructive actions are blocked unless pre-authorized in the RoE."""
        return action_class in self.destructive_allowed


def _scope_match(url: str, host: str, pat: str) -> bool:
    if fnmatch.fnmatch(host, pat) or fnmatch.fnmatch(url, pat):
        return True
    # "*.example.com" should also cover the apex "example.com"
    if pat.startswith("*.") and host == pat[2:]:
        return True
    # CIDR pattern, e.g. 10.10.0.0/24
    try:
        if ipaddress.ip_address(host) in ipaddress.ip_network(pat, strict=False):
            return True
    except ValueError:
        pass
    return False


def load_config(
    roe: Path,
    accounts: Path,
    url: str,
    model: str,
    classes: list[str] | None = None,
    mode: str | None = None,
    chain: bool | None = None,
    discover: bool | None = None,
) -> Config:
    """Load + validate config. Enforces the authorization gate before returning."""
    if not roe.exists():
        _die(f"RoE file not found: {roe}")
    gate = yaml.safe_load(roe.read_text()) or {}

    # ---- AUTHORIZATION GATE -------------------------------------------
    if not gate.get("signed", False):
        _die("RoE is not signed (signed: true required). Refusing to run.")
    if not gate.get("authorized_by"):
        _die("RoE has no 'authorized_by'. Refusing to run.")
    if not gate.get("scope", {}).get("allow"):
        _die("RoE scope.allow is empty. Refusing to run open-scope.")
    if not accounts.exists():
        _die(f"accounts file not found: {accounts}")

    acct = Accounts(**(yaml.safe_load(accounts.read_text()) or {}))
    objects = [ObjectSpec(**o) for o in gate.get("objects", [])]
    login_objects = [LoginObjectSpec(**o) for o in gate.get("login_objects", [])]
    races = [RaceSpec(**r) for r in gate.get("races", [])]
    coupons = [CouponSpec(**c) for c in gate.get("coupons", [])]

    discovery = DiscoverySpec(**(gate.get("discovery") or {}))
    # auto-enable discovery when the operator gave no objects, or forced it via --discover
    if discover or (discover is None and not objects):
        discovery.enabled = True

    cfg = Config(
        url=url,
        model=model,
        engagement=gate.get("engagement", ""),
        authorized_by=gate["authorized_by"],
        signed=True,
        scope=Scope(**gate.get("scope", {})),
        mode=(mode or gate.get("mode", "dry-run")),
        max_rate_rps=gate.get("max_rate_rps", 5),
        max_parallel=gate.get("max_parallel", 3),
        headers=gate.get("headers", {}),
        destructive_allowed=gate.get("destructive_allowed", []),
        classes=(classes or gate.get("classes") or list(ALL_CLASSES)),
        accounts_path=accounts,
        accounts=acct,
        objects=objects,
        login_objects=login_objects,
        races=races,
        coupons=coupons,
        chain=(chain if chain is not None else gate.get("chain", False)),
        discovery=discovery,
        models=gate.get("models", {}),
    )

    cfg.assert_in_scope(url)                          # the target itself must be in scope
    if cfg.mode == "live":
        _warn_live(cfg)
    return cfg


def _die(msg: str) -> None:
    print(f"\n[HERETIC] {msg}\n", file=sys.stderr)
    raise SystemExit(2)


def _warn_live(cfg: Config) -> None:
    print(
        f"[HERETIC] LIVE mode on '{cfg.url}'. Destructive actions allowed: "
        f"{cfg.destructive_allowed or 'none'}. Authorized by {cfg.authorized_by}.",
        file=sys.stderr,
    )
