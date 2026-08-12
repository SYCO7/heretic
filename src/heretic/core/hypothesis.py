"""Phase 3 — generate concrete tests that try to violate each invariant.

BOLA is mechanical (see bola.py). The state-changing classes here are LLM-driven:
given the invariants + observed endpoints, the model proposes concrete, replayable
tests, each tagged with which Oracle proves it and the assertion/probe it needs.
"""
from __future__ import annotations

import json
from typing import Any

from ..llm.base import LLM
from .intent_model import IntentModel
from .models import Hypothesis

# classes generated here (BOLA is handled mechanically in bola.py)
LLM_CLASSES = {"price_tamper", "workflow_bypass", "mass_assignment", "coupon_abuse", "auth_flow"}

SYSTEM = """You are a penetration tester. Given business-logic INVARIANTS and the
observed ENDPOINTS of an app, produce concrete tests that try to VIOLATE each
invariant. Output STRICT JSON: a list of tests, each:

{
  "invariant_id": "INV-2",
  "bug_class": "price_tamper|mass_assignment|workflow_bypass|coupon_abuse|auth_flow",
  "description": "short human description",
  "request_sequence": [
    {"method": "POST", "url": "/api/checkout", "as": "userA", "body": {"item_id": "i1", "price": 1}}
  ],
  "expected_safe": "what a correct app does (the invariant holding)",
  "oracle": "invariant_assertion | state_delta_judge",
  "assertion": {"field": "charged", "expected_value": 100, "tampered_value": 1},
       // for invariant_assertion. Use {"field": "role", "equals": "admin"} for reflected fields.
  "state_probe": {"url": "/api/orders/1", "as": "userA"},   // GET before+after; null if none
  "invariant_rule": "shipping requires completed payment"    // for state_delta_judge
}

Only emit tests you can concretely construct from the observed endpoints. JSON only."""


class HypothesisEngine:
    def __init__(self, llm: LLM, kb: Any = None, memory: Any = None) -> None:
        self.llm = llm
        self.kb = kb                                  # optional RAG-lite KnowledgeBase
        self.memory = memory                          # optional PatternMemory (self-improvement)

    def generate(self, model: IntentModel, observation, classes: list[str],
                 known_paths: list[str] | None = None) -> list[Hypothesis]:
        wanted = [i for i in model.invariants if i.bug_class in classes and i.bug_class in LLM_CLASSES]
        if not wanted:
            return []
        knowledge, learned = {}, {}
        for i in wanted:
            if self.kb is not None:
                knowledge[i.bug_class] = self.kb.retrieve(i.bug_class, i.rule, k=3)
            if self.memory is not None:
                hints = self.memory.recall(i.bug_class, k=3)
                if hints:
                    learned[i.bug_class] = hints
        payload = json.dumps({
            "invariants": [
                {"id": i.id, "rule": i.rule, "bug_class": i.bug_class, "checkable": i.checkable}
                for i in wanted
            ],
            "endpoints": observation.endpoints,
            "attack_patterns": knowledge,             # grounded tradecraft (RAG-lite)
            "learned_patterns": learned,              # from past engagements (self-improvement)
            # anti-hallucination: on regeneration, the ONLY endpoints allowed
            "allowed_endpoints": (known_paths or [])[:300],
        }, default=str)[:120_000]

        system = SYSTEM
        if known_paths:
            system += ("\n\nGROUNDING: use ONLY endpoints from allowed_endpoints — a previous attempt "
                       "invented paths that do not exist. Do NOT invent endpoints; if no allowed endpoint "
                       "fits an invariant, omit that test.")
        raw = self.llm.complete(system, payload, json=True, tag="hypotheses")
        try:
            arr = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []
        if isinstance(arr, dict):
            arr = arr.get("tests") or arr.get("hypotheses") or []

        out: list[Hypothesis] = []
        for h in arr:
            bc = h.get("bug_class")
            if bc not in classes or bc not in LLM_CLASSES:
                continue
            seq = h.get("request_sequence", []) or []
            out.append(Hypothesis(
                invariant_id=h.get("invariant_id", ""),
                bug_class=bc,
                description=h.get("description", ""),
                request_sequence=seq,
                expected_safe=h.get("expected_safe", ""),
                as_roles=[s.get("as") for s in seq if isinstance(s, dict) and s.get("as")],
                meta={
                    "oracle": h.get("oracle"),
                    "assertion": h.get("assertion"),
                    "state_probe": h.get("state_probe"),
                    "invariant_rule": h.get("invariant_rule"),
                },
            ))
        return out
