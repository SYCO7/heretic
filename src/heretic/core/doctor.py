"""Preflight checks (M6) — is HERETIC ready to run live?

Verifies the selected model's API key is present (or that it's a local/offline
backend), and optionally that the target is reachable. Pure logic; the HTTP
probe is injected so this is testable offline.
"""
from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from ..llm.backends import REGISTRY
from ..llm.router import DEFAULT_PROFILE


def _key_check(model_id: str, env: dict[str, str], prefix: str = "") -> dict[str, Any]:
    if model_id.startswith("ollama:"):
        return {"name": f"{prefix}{model_id}", "ok": True, "detail": "no API key needed (local Ollama)"}
    spec = REGISTRY.get(model_id)
    if spec is None:
        return {"name": f"{prefix}{model_id}", "ok": False, "detail": "unknown backend id"}
    key = spec.get("key_env")
    if spec.get("scripted") or not key:
        return {"name": f"{prefix}{model_id}", "ok": True, "detail": "no API key needed (local/offline)"}
    present = bool(env.get(key))
    return {"name": f"{prefix}{model_id}", "ok": present,
            "detail": f"{key} is set" if present else f"missing — export {key}"}


def preflight(
    model: str,
    url: str | None = None,
    env: dict[str, str] | None = None,
    probe: Callable[[str], int] | None = None,
) -> list[dict[str, Any]]:
    env = dict(os.environ) if env is None else env
    checks: list[dict[str, Any]] = []

    if model == "auto":
        for role, model_id in DEFAULT_PROFILE.items():
            checks.append(_key_check(model_id, env, prefix=f"{role} → "))
    else:
        checks.append(_key_check(model, env))

    if url and probe is not None:
        try:
            code = probe(url)
            checks.append({"name": f"target {url}", "ok": 100 <= code < 600, "detail": f"HTTP {code}"})
        except Exception as e:
            checks.append({"name": f"target {url}", "ok": False, "detail": f"unreachable: {e}"})

    return checks
