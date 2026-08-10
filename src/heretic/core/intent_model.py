"""Phase 2 — build the business-intent model + extract invariants.

Feeds the observed traffic to a large-context LLM (Nemotron 3 / Gemini, both 1M
ctx) and gets back structured intent + the invariants to attack. Invariants are
the heart of the whole tool — everything downstream is "break invariant X, then
prove it broke."
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..llm.base import LLM
from .models import Invariant

SYSTEM = """You are a senior application-security architect analysing a web
application's observed HTTP traffic (endpoints, params, roles, sample responses).
Infer the application's BUSINESS INTENT and output STRICT JSON:

{
  "app_type": "...",
  "entities": ["..."],
  "roles": ["..."],
  "workflows": [{"name": "...", "steps": ["..."]}],
  "invariants": [
    {"id": "INV-1",
     "rule": "<a business rule the app assumes but may fail to enforce>",
     "bug_class": "bola|price_tamper|workflow_bypass|mass_assignment|coupon_abuse|race_condition|auth_flow",
     "checkable": "<optional: how to verify it, e.g. 'charged == catalog price'>"}
  ]
}

Focus on invariants an attacker would try to break (server-side price, object
ownership, workflow ordering, non-settable privileged fields). Be concrete. JSON only."""


@dataclass
class IntentModel:
    app_type: str = ""
    entities: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    workflows: list[dict] = field(default_factory=list)
    invariants: list[Invariant] = field(default_factory=list)


class IntentModeler:
    def __init__(self, llm: LLM) -> None:
        self.llm = llm

    def build(self, observation) -> IntentModel:
        payload = json.dumps({"endpoints": observation.endpoints}, default=str)[:120_000]
        raw = self.llm.complete(SYSTEM, payload, json=True, tag="intent_model")
        try:
            d = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return IntentModel()
        invs = [
            Invariant(
                id=i.get("id", f"INV-{n}"),
                rule=i.get("rule", ""),
                bug_class=i.get("bug_class", ""),
                checkable=i.get("checkable"),
            )
            for n, i in enumerate(d.get("invariants", []), 1)
        ]
        return IntentModel(
            app_type=d.get("app_type", ""),
            entities=d.get("entities", []),
            roles=d.get("roles", []),
            workflows=d.get("workflows", []),
            invariants=invs,
        )
