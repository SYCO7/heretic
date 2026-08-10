"""Race-condition / TOCTOU hypotheses (M4) — mechanical, from RoE `races:` specs.

Each spec fires `parallel` identical requests concurrently; the Oracle confirms a
bug when more than `expect_max_success` succeed (missing atomic enforcement, e.g.
single-use coupon redeemed many times, double-spend). State-changing → gated
behind live mode + authorization (see orchestrator).
"""
from __future__ import annotations

from ..config import Config
from .models import Hypothesis


def build_race_hypotheses(cfg: Config) -> list[Hypothesis]:
    hyps: list[Hypothesis] = []
    for spec in cfg.races:
        parallel = min(spec.parallel, max(cfg.max_parallel, 1))     # respect the RoE parallel cap
        hyps.append(Hypothesis(
            invariant_id=f"RACE:{spec.name}",
            bug_class="race_condition",
            description=f"{parallel}x parallel {spec.method} {spec.url} (allow ≤{spec.expect_max_success})",
            request_sequence=[{"method": spec.method, "url": spec.url, "as": spec.as_role, "body": spec.body}],
            expected_safe=f"at most {spec.expect_max_success} of {parallel} concurrent requests succeed",
            as_roles=[spec.as_role],
            meta={
                "race": True, "parallel": parallel, "as": spec.as_role,
                "method": spec.method, "url": spec.url, "body": spec.body,
                "expect_max_success": spec.expect_max_success,
                "success_status": spec.success_status, "success_field": spec.success_field,
            },
        ))
    return hyps
