"""Broken Function-Level Authorization (BFLA, OWASP API #5) — mechanical, read-only.

An administrative function that the wrong role can reach. Two deterministic patterns:

  1. an admin-marked endpoint reachable by GUEST (no auth) — an admin function open to
     anyone (critical);
  2. an admin-marked endpoint that guest is denied but a REGULAR user reaches — a
     privilege-escalation gap (high).

Candidates come from discovery (endpoints whose path looks administrative) plus a small
built-in admin-path list. GET-only, so it never changes state.
"""
from __future__ import annotations

from ..config import Config
from .models import Hypothesis

# path fragments that mark an administrative / privileged function
ADMIN_MARKERS = ["/admin", "/administrator", "/manage", "/management", "/internal",
                 "/superuser", "/moderator", "/actuator", "/console", "/_debug",
                 "/backend/admin", "/api/admin", "/staff", "/root"]
# strong markers — an admin function beyond doubt (used when there's no admin role to corroborate)
STRONG_MARKERS = {"/admin", "/administrator", "/internal", "/superuser", "/moderator",
                  "/actuator", "/console"}
# always-probe admin paths (in case discovery didn't surface them)
_BUILTIN = [
    "/rest/admin/application-configuration", "/admin", "/api/admin", "/admin/users",
    "/manage", "/actuator", "/actuator/env", "/console", "/internal",
]


def is_admin_path(path: str) -> bool:
    low = path.lower()
    return any(m in low for m in ADMIN_MARKERS)


def has_strong_marker(path: str) -> bool:
    low = path.lower()
    return any(m in low for m in STRONG_MARKERS)


def build_bfla_hypotheses(cfg: Config, endpoints: list) -> list[Hypothesis]:
    """One check per admin-marked GET endpoint (discovered + built-in)."""
    paths: list[str] = list(_BUILTIN)
    for ep in endpoints:
        path = ep.get("path") if isinstance(ep, dict) else ep
        method = ep.get("method", "GET") if isinstance(ep, dict) else "GET"
        if method == "GET" and path and "{" not in path and is_admin_path(path):
            paths.append(path)

    hyps: list[Hypothesis] = []
    seen: set[str] = set()
    for path in paths:
        if path in seen or not is_admin_path(path):
            continue
        seen.add(path)
        hyps.append(Hypothesis(
            invariant_id=f"BFLA:{path}",
            bug_class="bfla",
            description=f"non-admin reaches admin function {path}",
            request_sequence=[{"method": "GET", "url": path, "as": "userA"}],
            expected_safe=f"only an administrator may reach {path}; other callers get 401/403",
            as_roles=["userA", "admin", "guest"],
            meta={"path": path},
        ))
    return hyps
