"""Headless-browser XHR capture (M8.2) — observe what the SPA actually fires.

Static scraping misses URLs the frontend builds at runtime (`base + '/vehicle/' +
id + '/location'`). This module drives a real headless Chromium through the app's
routes as an authenticated role and records every XHR/fetch it makes, then collapses
concrete ids back into `{id}` templates — recovering exactly the item-by-id endpoints
that BOLA needs and that no static analysis can see.

Read-only navigation. Opt-in (needs `playwright` + a chromium binary):
    pip install playwright && python -m playwright install chromium
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _is_id_seg(seg: str) -> bool:
    """Does this path segment look like a concrete identifier (to collapse into {id})?"""
    low = seg.lower()
    if low in ("null", "undefined"):
        return True                                   # SPA fired with an unset id placeholder
    if seg.isdigit() or _UUID.match(seg):
        return True                                   # numeric id / uuid
    if re.fullmatch(r"[0-9a-fA-F]{16,}", seg):
        return True                                   # long hex / mongo id
    if len(seg) >= 10 and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg):
        return True                                   # VIN / base62 token (letters + digits)
    return len(seg) >= 20 and seg.isalnum()           # long opaque token
# default SPA routes to visit if the caller has none of its own
_DEFAULT_ROUTES = [
    "/", "/dashboard", "/shop", "/orders", "/past-orders", "/profile", "/my-profile",
    "/vehicles", "/forum", "/mechanic-dashboard", "/vehicle-service-dashboard",
]


def available() -> tuple[bool, str]:
    """(usable, hint). False if playwright isn't importable."""
    try:
        import playwright  # noqa: F401
        return True, ""
    except ImportError:
        return False, "pip install playwright && python -m playwright install chromium"


def templatize(path: str) -> str:
    """`/api/v2/vehicle/3aa9…/location` -> `/api/v2/vehicle/{id}/location`."""
    return "/".join("{id}" if _is_id_seg(seg) else seg for seg in path.split("/"))


def is_api(path: str) -> bool:
    low = path.lower()
    return "/api" in low or bool(re.search(r"/v\d", path))


class BrowserCapture:
    def __init__(self, base_url: str, *, headers: dict[str, str] | None = None,
                 token: str | None = None, creds: dict | None = None, login_path: str = "/login",
                 wait_ms: int = 2500, clicks: int = 20, storage_keys: list[str] | None = None,
                 in_scope=None) -> None:
        self.base = base_url.rstrip("/")
        self.host = urlparse(self.base).netloc
        self.headers = headers or {}
        self.token = token
        self.creds = creds                               # {"email"/"username", "password"} for form login
        self.login_path = login_path
        self.wait_ms = wait_ms
        self.clicks = clicks
        self.storage_keys = storage_keys or ["token", "access_token", "jwt"]
        self.in_scope = in_scope                         # optional callable(url) -> raises if off-scope

    def capture(self, routes: list[str] | None = None, *, max_routes: int = 12) -> list[dict]:
        from playwright.sync_api import sync_playwright

        routes = list(dict.fromkeys((routes or []) + _DEFAULT_ROUTES))[:max_routes]  # bound runtime
        seen: set[tuple[str, str]] = set()

        def on_request(req) -> None:
            u = urlparse(req.url)
            if u.netloc and u.netloc != self.host:       # same-origin only
                return
            path = templatize(u.path)
            if is_api(path):
                seen.add((req.method.upper(), path))

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            ctx = browser.new_context(extra_http_headers=self.headers)
            if self.token:                               # seed the token so authed views render
                setters = ";".join(f"localStorage.setItem({json.dumps(k)},{json.dumps(self.token)})"
                                   for k in self.storage_keys)
                ctx.add_init_script(setters)
            page = ctx.new_page()
            page.on("request", on_request)
            self._login(page)                            # drive the login form (best-effort)
            for route in routes:
                url = self.base + (route if route.startswith("/") else "/" + route)
                if self.in_scope is not None:
                    try:
                        self.in_scope(url)               # scope gate — skip off-scope routes
                    except SystemExit:
                        continue
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    page.wait_for_timeout(self.wait_ms)
                    self._interact(page)                 # click around to trigger lazy item XHRs
                except Exception:
                    continue                             # a slow/blank route must not abort the run
            browser.close()

        return [{"method": m, "path": pth, "src": "browser"} for (m, pth) in sorted(seen)]

    def _login(self, page) -> None:
        """Best-effort generic form login: find the password field, the email field, submit."""
        if not self.creds:
            return
        user = self.creds.get("email") or self.creds.get("username") or self.creds.get("user")
        pw = self.creds.get("password")
        if not (user and pw):
            return
        try:
            page.goto(self.base + self.login_path, wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(1200)
            pwd = page.query_selector("input[type=password]")
            email = (page.query_selector("input[type=email]")
                     or page.query_selector("input[placeholder*='mail' i],input[placeholder*='user' i],"
                                            "input[id*='email' i],input[name*='email' i],input[name*='user' i]")
                     or page.query_selector("input[type=text]"))
            if not (pwd and email):
                return
            email.fill(str(user))
            pwd.fill(str(pw))
            btn = (page.query_selector("button[type=submit]")
                   or page.query_selector("button:has-text('Login'),button:has-text('Log in'),"
                                          "button:has-text('Sign in'),button:has-text('Log In')"))
            if btn:
                btn.click(timeout=4000)
            else:
                pwd.press("Enter")
            page.wait_for_timeout(self.wait_ms)
        except Exception:
            return                                       # login is best-effort; capture proceeds regardless

    def _interact(self, page) -> None:
        """Click a bounded number of elements to trigger lazily-loaded item XHRs."""
        if self.clicks <= 0:
            return
        done = 0
        for sel in ("[class*='vehicle' i]", "[class*='card' i]", "[class*='order' i]",
                    "[role=button]", "button", "a"):
            for el in page.query_selector_all(sel):
                if done >= self.clicks:
                    return
                try:
                    el.click(timeout=1000, no_wait_after=True)
                    done += 1
                    page.wait_for_timeout(350)
                except Exception:
                    continue
