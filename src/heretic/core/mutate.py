"""Feedback-loop mutations (M2+ enhancement) — turn a one-shot test into an experiment.

A logic-class hypothesis that the Oracle does NOT confirm on the first try is often
*almost* right: the tampered value was wrong, the privileged field had a different
name, or the workflow steps needed a different order. When `--iterate N` is set, the
orchestrator asks this module for up to N mutated variants of a failed hypothesis and
retries each — reading the response and adjusting the input, instead of giving up.

Deterministic and offline (no LLM, no extra cost). Each variant keeps its Oracle meta
(assertion / probe) consistent with the mutated request so the proof stays sound.
"""
from __future__ import annotations

import copy

from .models import Hypothesis

# privileged (field, value) pairs to try for mass assignment, common across frameworks
_PRIV_FIELDS = [
    ("role", "admin"), ("isAdmin", True), ("is_admin", True), ("admin", True),
    ("membership", "premium"), ("account_type", "admin"), ("is_staff", True),
]
# under-pay candidates for price tampering
_PRICE_VALUES = [1, 0, 0.01, -1, 0.0]
_PRICE_FIELDS = ("price", "amount", "total", "cost", "unit_price", "subtotal")


def mutations(hyp: Hypothesis, limit: int) -> list[Hypothesis]:
    """Return up to `limit` mutated variants of a failed hypothesis (may be empty)."""
    if limit <= 0:
        return []
    if hyp.bug_class == "price_tamper":
        out = _price(hyp)
    elif hyp.bug_class == "mass_assignment":
        out = _mass(hyp)
    elif hyp.bug_class == "workflow_bypass":
        out = _workflow(hyp)
    elif hyp.bug_class == "coupon_abuse":
        out = _coupon(hyp)
    else:
        out = []
    return out[:limit]


def _last_body_step(seq: list[dict]) -> int:
    """Index of the last request that carries a JSON body (the one we tamper)."""
    for i in range(len(seq) - 1, -1, -1):
        if isinstance(seq[i], dict) and isinstance(seq[i].get("body"), dict):
            return i
    return -1


def _price(hyp: Hypothesis) -> list[Hypothesis]:
    a = dict(hyp.meta.get("assertion") or {})
    field = a.get("field")
    seq = hyp.request_sequence or []
    idx = _last_body_step(seq)
    if idx < 0:
        return []
    body = seq[idx]["body"]
    target = field if field in body else next((f for f in _PRICE_FIELDS if f in body), None)
    if target is None:
        return []
    out = []
    for val in _PRICE_VALUES:
        v = copy.deepcopy(hyp)
        v.request_sequence[idx]["body"][target] = val
        v.meta = {**hyp.meta, "assertion": {**a, "field": a.get("field", target), "tampered_value": val}}
        v.description = f"{hyp.description} [mutate {target}={val}]"
        out.append(v)
    return out


def _mass(hyp: Hypothesis) -> list[Hypothesis]:
    seq = hyp.request_sequence or []
    idx = _last_body_step(seq)
    if idx < 0:
        # no body to inject into — synthesize one on the first request
        idx = 0 if seq else -1
    if idx < 0:
        return []
    out = []
    for field, value in _PRIV_FIELDS:
        v = copy.deepcopy(hyp)
        step = v.request_sequence[idx]
        step.setdefault("body", {})
        step["body"][field] = value
        v.meta = {**hyp.meta, "assertion": {"field": field, "equals": value},
                  "state_probe": hyp.meta.get("state_probe")}
        v.description = f"{hyp.description} [mutate set {field}={value}]"
        out.append(v)
    return out


def _workflow(hyp: Hypothesis) -> list[Hypothesis]:
    seq = hyp.request_sequence or []
    out = []
    if len(seq) >= 2:
        rev = copy.deepcopy(hyp)
        rev.request_sequence = list(reversed(rev.request_sequence))
        rev.description = f"{hyp.description} [mutate reorder steps]"
        out.append(rev)
        skip = copy.deepcopy(hyp)
        skip.request_sequence = skip.request_sequence[1:]     # skip the prerequisite (e.g. payment)
        skip.description = f"{hyp.description} [mutate skip first step]"
        out.append(skip)
    return out


def _coupon(hyp: Hypothesis) -> list[Hypothesis]:
    seq = hyp.request_sequence or []
    if not seq:
        return []
    out = []
    for reps in (2, 3):
        v = copy.deepcopy(hyp)
        v.request_sequence = [copy.deepcopy(seq[0]) for _ in range(reps)]
        v.description = f"{hyp.description} [mutate replay x{reps}]"
        out.append(v)
    return out
