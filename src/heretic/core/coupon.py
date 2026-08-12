"""Deterministic coupon abuse (mechanical) — single-use / limit reuse.

A single-use coupon should be accepted at most `max_uses` times. This detector
redeems the SAME code `max_uses`+1 times SEQUENTIALLY (not concurrently — that is
`race_condition`) and confirms a bug ONLY if the server accepted it more than the
allowed number of times. Because the invariant is a plain count, the proof is
deterministic and low-FP: an app that rejects the second redemption is never
flagged. Driven by the RoE `coupons:` block (like `races:`). State-changing (it
redeems a real code): live-gated.
"""
from __future__ import annotations

from typing import Any

from ..config import Config, CouponSpec
from .models import Hypothesis


def _body(spec: CouponSpec) -> dict[str, Any]:
    """The redemption body — the code field plus any extra body the RoE supplied."""
    body = dict(spec.body or {})
    body.setdefault(spec.code_field, spec.code)
    return body


def build_coupon_hypotheses(cfg: Config) -> list[Hypothesis]:
    hyps: list[Hypothesis] = []
    for spec in cfg.coupons:
        reps = max(spec.max_uses, 0) + 1                 # one more redemption than allowed
        body = _body(spec)
        hyps.append(Hypothesis(
            invariant_id=f"COUPON:{spec.name}",
            bug_class="coupon_abuse",
            description=f"redeem single-use coupon '{spec.code}' {reps}x in series at {spec.url} "
                        f"(allow ≤{spec.max_uses})",
            request_sequence=[{"method": spec.method, "url": spec.url,
                               "as": spec.as_role, "body": body}],
            expected_safe=f"the coupon '{spec.code}' is accepted at most {spec.max_uses} time(s)",
            as_roles=[spec.as_role],
            meta={
                "coupon": True, "as": spec.as_role, "method": spec.method, "url": spec.url,
                "body": body, "reps": reps, "max_uses": spec.max_uses, "code": spec.code,
                "success_status": spec.success_status, "success_field": spec.success_field,
            },
        ))
    return hyps
