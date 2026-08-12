"""Login auto-detection — the easy on-ramp, hardened for real-world auth.

Given a base URL and one set of credentials, this discovers everything
`accounts.yaml` needs — endpoint, method, where the session lives, credential
shape — across the auth mechanisms real apps actually use:

  1. JSON token / JWT in the body          (APIs, SPAs)            -> token_field + Bearer
  2. Session cookie set on login           (Django/Rails/PHP/Express) -> token_field "cookie:NAME"
  3. CSRF-guarded login                     (Laravel/Angular/Rails)  -> pre-fetch + replay the token
  4. Form-encoded bodies                    (classic server apps)    -> content_type "form"

Read-only: it only POSTs the credentials the user supplied, to their own target,
plus a GET to seed a CSRF token. The returned spec is what both the connect wizard
and the scan-time login (`SessionManager._login`) consume — so what is detected is
exactly what is replayed.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote

import httpx

from .http import join

# common login endpoints, most-specific first
LOGIN_PATHS = [
    "/api/auth/login", "/rest/user/login", "/identity/api/auth/login", "/users/v1/login",
    "/api/login", "/api/v1/login", "/api/v1/auth/login", "/auth/login", "/login",
    "/api/users/login", "/api/session", "/session", "/api/token", "/oauth/token", "/signin",
    "/api/signin", "/api/account/login",
]
# response keys that hold an auth token, best-first
_TOKEN_KEYS = ["token", "access_token", "accesstoken", "accessToken", "jwt", "id_token",
               "idToken", "authToken", "auth_token", "authtoken", "sessionToken", "apiToken"]
_JWT = re.compile(r"^ey[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.")   # a JSON Web Token value

# --- session-cookie detection -----------------------------------------------
# a Set-Cookie whose name looks like a server session (not a CSRF/tracking cookie)
_SESSION_COOKIE_HINTS = ["sessionid", "session", "sessid", "connect.sid", "jsessionid",
                         "phpsessid", "laravel_session", "_session", "sid", "auth", "authtoken"]
_NOT_SESSION = ["csrf", "xsrf", "_ga", "_gid", "consent", "locale", "lang", "timezone"]

# --- CSRF pre-fetch ----------------------------------------------------------
_CSRF_FETCH_PATHS = ["/sanctum/csrf-cookie", "/api/csrf", "/csrf", "/api/auth/csrf",
                     "/login", "/", "/index.html"]
_CSRF_COOKIE_NAMES = ["XSRF-TOKEN", "csrftoken", "csrf_token", "CSRF-TOKEN", "_csrf"]
# header a given CSRF cookie is conventionally echoed back in
_CSRF_COOKIE_HEADER = {"xsrf-token": "X-XSRF-TOKEN", "csrftoken": "X-CSRFToken",
                       "csrf-token": "X-CSRF-Token", "csrf_token": "X-CSRF-Token",
                       "_csrf": "X-CSRF-Token"}
_META_CSRF = re.compile(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)', re.I)
_INPUT_CSRF = re.compile(
    r'<input[^>]+name=["\'](_csrf|csrf_token|authenticity_token|csrfmiddlewaretoken)["\']'
    r'[^>]+value=["\']([^"\']+)', re.I)


def _cred_bodies(identity: str, password: str, phone: str | None) -> list[dict]:
    """Credential shapes to try — apps name the identity field differently."""
    bodies = [{"email": identity, "password": password},
              {"username": identity, "password": password},
              {"user": identity, "password": password},
              {"login": identity, "password": password},
              {"identifier": identity, "password": password}]
    if phone:
        bodies.append({"phone": phone, "password": password})
        bodies.append({"phoneNumber": phone, "password": password})
    return bodies


def _find_token(obj: Any, prefix: str = "") -> tuple[str, str] | None:
    """(token value, dotted path) — prefer an explicit token key, then any JWT-shaped value."""
    if isinstance(obj, dict):
        for key in _TOKEN_KEYS:                          # explicit token keys win
            if isinstance(obj.get(key), str) and obj[key]:
                return obj[key], f"{prefix}{key}"
        for k, v in obj.items():                         # else recurse
            hit = _find_token(v, f"{prefix}{k}.")
            if hit:
                return hit
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hit = _find_token(v, f"{prefix}{i}.")
            if hit:
                return hit
    elif isinstance(obj, str) and _JWT.match(obj):
        return obj, prefix.rstrip(".")
    return None


def _session_cookie(resp: httpx.Response) -> str | None:
    """Name of the session cookie a login response set (excluding CSRF/tracking cookies)."""
    best: str | None = None
    for name, _ in resp.cookies.items():
        low = name.lower()
        if any(bad in low for bad in _NOT_SESSION):
            continue
        if any(hint in low for hint in _SESSION_COOKIE_HINTS):
            return name                                  # a strong session-cookie name — take it
        best = best or name                              # otherwise remember the first plausible one
    return best


def extract_csrf(resp: httpx.Response, source: str) -> str | None:
    """Pull a CSRF token out of a seeded response per `source`:
    cookie:NAME | meta:NAME | input:NAME | json:dotted."""
    kind, _, name = source.partition(":")
    if kind == "cookie":
        val = resp.cookies.get(name)
        return unquote(val) if val else None            # Laravel/Angular URL-encode the XSRF cookie
    text = resp.text or ""
    if kind == "meta":
        m = _META_CSRF.search(text)
        return m.group(1) if m else None
    if kind == "input":
        m = _INPUT_CSRF.search(text)
        return m.group(2) if m else None
    if kind == "json":
        try:
            cur: Any = resp.json()
        except ValueError:
            return None
        for part in name.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        return str(cur) if cur is not None else None
    return None


def _discover_csrf(client: httpx.Client, base_url: str) -> dict | None:
    """GET candidate pages to seed + locate a CSRF token. Returns a csrf spec
    {fetch_url, source, header, field} the login can replay, or None."""
    for path in _CSRF_FETCH_PATHS:
        try:
            resp = client.get(join(base_url, path))
        except httpx.HTTPError:
            continue
        # 1) a CSRF cookie was set (Angular/Laravel/Rails double-submit)
        for cname in _CSRF_COOKIE_NAMES:
            if resp.cookies.get(cname):
                header = _CSRF_COOKIE_HEADER.get(cname.lower(), "X-CSRF-Token")
                return {"fetch_url": path, "source": f"cookie:{cname}", "header": header, "field": None}
        # 2) a <meta name="csrf-token"> tag (Rails/SPA)
        if _META_CSRF.search(resp.text or ""):
            return {"fetch_url": path, "source": "meta:csrf-token",
                    "header": "X-CSRF-Token", "field": None}
        # 3) a hidden <input> CSRF field (Django/classic server-rendered form)
        mi = _INPUT_CSRF.search(resp.text or "")
        if mi:
            return {"fetch_url": path, "source": f"input:{mi.group(1)}",
                    "header": "X-CSRF-Token", "field": mi.group(1)}
    return None


def _post(client: httpx.Client, url: str, body: dict, content_type: str,
          csrf: dict | None = None, token: str | None = None) -> httpx.Response | None:
    """One login attempt with the given body encoding + optional resolved CSRF token."""
    headers: dict[str, str] = {}
    send_body = dict(body)
    if csrf and token:
        if csrf.get("header"):
            headers[csrf["header"]] = token
        if csrf.get("field"):
            send_body[csrf["field"]] = token
    try:
        if content_type == "form":
            return client.post(url, data=send_body, headers=headers)
        return client.post(url, json=send_body, headers=headers)
    except httpx.HTTPError:
        return None


def _success(resp: httpx.Response | None) -> tuple[str, str] | None:
    """(token_field, auth_header) if a login response proves authentication — a body
    token/JWT (Bearer) or a session cookie (Cookie header). Else None."""
    if resp is None or resp.status_code not in (200, 201, 204):
        return None
    try:
        data = resp.json()
    except ValueError:
        data = None
    if data is not None:
        hit = _find_token(data)
        if hit:
            return hit[1], "Authorization: Bearer {token}"
    cookie = _session_cookie(resp)
    if cookie:
        return f"cookie:{cookie}", f"Cookie: {cookie}={{token}}"
    return None


def detect_login(base_url: str, identity: str, password: str, *, phone: str | None = None,
                 transport: httpx.BaseTransport | None = None,
                 paths: list[str] | None = None) -> dict | None:
    """Probe login routes with `identity`/`password`. Returns the login spec on success:
    {url, method, token_field, auth_header, content_type, cred_fields, csrf, otp_hint}
    — or None if nothing authenticated. Tries plain JSON first (fast for APIs/labs),
    then form-encoded, then a CSRF pre-fetch + replay for guarded logins."""
    client = httpx.Client(transport=transport, timeout=12.0, follow_redirects=True)
    try:
        # pass 1: plain JSON, then form — the common, unguarded case (APIs, labs)
        for content_type in ("json", "form"):
            for path in (paths or LOGIN_PATHS):
                url = join(base_url, path)
                for body in _cred_bodies(identity, password, phone):
                    resp = _post(client, url, body, content_type, None)
                    ok = _success(resp)
                    if ok:
                        # otp_hint reflects the MATCHED login response only — never an
                        # unrelated 4xx/5xx error page that happens to say "verify".
                        return _spec(path, ok, body, content_type, None, _looks_otp(resp))

        # pass 2: CSRF-guarded login — seed a token, then replay it
        csrf = _discover_csrf(client, base_url)
        if csrf is not None:
            for content_type in ("json", "form"):
                for path in (paths or LOGIN_PATHS):
                    url = join(base_url, path)
                    for body in _cred_bodies(identity, password, phone):
                        try:
                            seed = client.get(join(base_url, csrf["fetch_url"]))   # (re)seed token
                        except httpx.HTTPError:
                            continue
                        token = extract_csrf(seed, csrf["source"])
                        resp = _post(client, url, body, content_type, csrf, token)
                        ok = _success(resp)
                        if ok:
                            return _spec(path, ok, body, content_type, csrf, _looks_otp(resp))
    finally:
        client.close()
    return None


def _spec(path: str, ok: tuple[str, str], body: dict, content_type: str,
          csrf: dict | None, otp: bool) -> dict:
    token_field, auth_header = ok
    return {"url": path, "method": "POST", "token_field": token_field, "auth_header": auth_header,
            "content_type": content_type, "cred_fields": list(body), "csrf": csrf, "otp_hint": otp}


def _looks_otp(resp: httpx.Response) -> bool:
    return _otp_hint(_safe_json(resp))


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return resp.text


def _otp_hint(data: Any) -> bool:
    """Does the response smell like it wants a second (OTP/MFA) step?"""
    blob = str(data).lower()
    return any(w in blob for w in ("otp", "mfa", "2fa", "one-time", "verification code", "verify"))
