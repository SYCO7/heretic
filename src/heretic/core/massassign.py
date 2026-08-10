"""Deterministic mass-assignment at registration (OWASP API #6) — mechanical.

The LLM hypothesis engine can *propose* mass-assignment tests, but it guesses which
endpoint and often misses. This detector is deterministic: it finds the account-
creation endpoint, learns a working registration body, then re-registers with a
privileged field injected (`role: admin`, `isAdmin: true`, …). It confirms ONLY if
the response reflects the injected privileged value — so an app that ignores the
field is never flagged. State-changing (it creates throwaway accounts): live-gated.
"""
from __future__ import annotations

import time
from typing import Any

from ..config import Config
from .models import Hypothesis

# path fragments / built-ins that mark an account-creation endpoint
_REGISTER_MARKERS = ["register", "signup", "sign-up", "/users", "/user", "/account", "/accounts"]
_BUILTIN = [
    "/api/Users", "/rest/user/register", "/users/v1/register", "/register", "/signup",
    "/api/register", "/api/auth/register", "/api/users", "/api/account/register", "/api/v1/users",
    "/api/v1/register", "/auth/signup",
]
# privileged (field, value) pairs to inject at signup, best-first
PRIV_FIELDS: list[tuple[str, Any]] = [
    ("role", "admin"), ("role", "administrator"), ("isAdmin", True), ("is_admin", True),
    ("admin", True), ("isAdministrator", True), ("accountType", "admin"), ("type", "admin"),
    ("verified", True), ("emailVerified", True), ("membership", "premium"),
]


def register_endpoints(cfg: Config, endpoints: list) -> list[str]:
    paths: set[str] = set(_BUILTIN)
    for ep in endpoints:
        path = ep.get("path") if isinstance(ep, dict) else ep
        low = (path or "").lower()
        if path and "{" not in path and any(m in low for m in _REGISTER_MARKERS):
            paths.add(path)
    return sorted(paths)


def build_massassign_hypotheses(cfg: Config, endpoints: list) -> list[Hypothesis]:
    """One deterministic registration mass-assignment check over all candidate endpoints."""
    return [Hypothesis(
        invariant_id="MASS:registration",
        bug_class="mass_assignment",
        description="account registration accepts a client-supplied privileged field",
        request_sequence=[],
        expected_safe="registration must ignore client-supplied role/privilege fields",
        as_roles=["guest"],
        meta={"register_paths": register_endpoints(cfg, endpoints)},
    )]


def creds(n: int) -> tuple[str, str, str]:
    """Unique (email, username, password) per attempt so registrations don't collide."""
    stamp = f"{int(time.monotonic() * 1000)}{n}"
    return f"heretic{stamp}@ma.test", f"heretic{stamp}", "H3retic!Pass23"


def body_shapes(email: str, user: str, pw: str) -> list[dict]:
    return [
        {"email": email, "password": pw, "passwordRepeat": pw},
        {"username": user, "password": pw, "email": email},
        {"email": email, "password": pw},
        {"username": user, "password": pw},
    ]


def reflects(obj: Any, field: str, value: Any) -> bool:
    """Does the response echo `field == value` anywhere (recursively)?"""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() == field.lower():
                if isinstance(value, bool):
                    if v is True or str(v).lower() == "true":
                        return True
                elif str(v).lower() == str(value).lower():
                    return True
            if reflects(v, field, value):
                return True
    elif isinstance(obj, list):
        return any(reflects(x, field, value) for x in obj)
    return False
