"""Login auto-detection — the easy on-ramp.

The user should not have to know their app's login endpoint or where the token
lives in the response. Given a base URL and one set of credentials, this probes
the common login routes with the common credential field-names, and — on the first
that returns an auth token — reports the endpoint, method, credential shape, and the
dotted path to the token. That's everything `accounts.yaml` needs, discovered for you.

Read-only: it only POSTs the credentials the user supplied, to their own target.
"""
from __future__ import annotations

import re
from typing import Any

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


def detect_login(base_url: str, identity: str, password: str, *, phone: str | None = None,
                 transport: httpx.BaseTransport | None = None,
                 paths: list[str] | None = None) -> dict | None:
    """Probe login routes with `identity`/`password`. Returns the login spec on success:
    {url, method, token_field, cred_fields, otp_hint} — or None if nothing authenticated."""
    client = httpx.Client(transport=transport, timeout=12.0, follow_redirects=True)
    try:
        for path in (paths or LOGIN_PATHS):
            for body in _cred_bodies(identity, password, phone):
                try:
                    r = client.post(join(base_url, path), json=body)
                except httpx.HTTPError:
                    continue
                if r.status_code not in (200, 201):
                    continue
                try:
                    data = r.json()
                except ValueError:
                    continue
                hit = _find_token(data)
                if hit:
                    return {"url": path, "method": "POST", "token_field": hit[1],
                            "cred_fields": list(body), "otp_hint": _otp_hint(data)}
    finally:
        client.close()
    return None


def _otp_hint(data: Any) -> bool:
    """Does the login response smell like it wants a second (OTP/MFA) step?"""
    blob = str(data).lower()
    return any(w in blob for w in ("otp", "mfa", "2fa", "one-time", "verification code", "verify"))
