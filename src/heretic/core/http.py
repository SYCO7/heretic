"""Scope-checked, rate-limited HTTP client — one per role/identity.

Every request passes the config scope gate BEFORE it leaves the process, and is
throttled to cfg.max_rate_rps. A transport can be injected for tests
(httpx.MockTransport), so the whole engine is exercisable with no network.
"""
from __future__ import annotations

import time
from typing import Any

import httpx

from ..config import Config


def join(base: str, url: str) -> str:
    """Resolve a possibly-relative URL against the target base."""
    if url.startswith(("http://", "https://")):
        return url
    return base.rstrip("/") + "/" + url.lstrip("/")


class RoleClient:
    """HTTP client bound to one identity (its auth header/cookies)."""

    def __init__(
        self,
        cfg: Config,
        role: str,
        headers: dict[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.cfg = cfg
        self.role = role
        self._min_interval = 1.0 / max(cfg.max_rate_rps, 1)
        self._last = 0.0
        self.client = httpx.Client(
            headers=headers or {},
            timeout=15.0,
            transport=transport,
            follow_redirects=True,
        )

    def request(self, method: str, url: str, json: Any = None) -> httpx.Response:
        full = join(self.cfg.url, url)
        self.cfg.assert_in_scope(full)               # GATE — never bypass
        self._throttle()
        return self.client.request(method.upper(), full, json=json)

    def get(self, url: str) -> httpx.Response:
        return self.request("GET", url)

    def _throttle(self) -> None:
        gap = time.monotonic() - self._last
        if gap < self._min_interval:
            time.sleep(self._min_interval - gap)
        self._last = time.monotonic()

    def close(self) -> None:
        self.client.close()
