"""M19: anti-hallucination. Grounding detects LLM-invented endpoints; the state-delta
judge cannot confirm a violation when nothing actually changed.
"""
from __future__ import annotations

from heretic.core.grounding import dedup, ground_hypotheses, is_grounded, known_paths, norm_path
from heretic.core.models import Hypothesis
from heretic.core.oracle import Oracle
from heretic.llm.scripted import ScriptedLLM

# ---- endpoint grounding ----------------------------------------------

def test_norm_and_known_paths():
    assert norm_path("http://x/api/Orders/1234") == "/api/orders/{id}"
    known = known_paths(["/api/orders", "/api/orders/{id}", "/api/users/{id}"])
    assert is_grounded("/api/orders/99", known)                 # id collapses to {id}
    assert is_grounded("/api/orders", known)
    assert not is_grounded("/api/invented/thing", known)        # hallucinated


def _hyp(cls, url):
    return Hypothesis(invariant_id="i", bug_class=cls, description="d",
                      request_sequence=[{"method": "POST", "url": url, "as": "userA"}],
                      expected_safe="", meta={})


def test_ground_hypotheses_splits_real_from_invented():
    known = known_paths(["/api/checkout", "/api/profile/update"])
    hyps = [_hyp("price_tamper", "/api/checkout"),          # real
            _hyp("mass_assignment", "/api/profile/update"),  # real
            _hyp("workflow_bypass", "/api/ship-now")]        # invented
    grounded, hallucinated = ground_hypotheses(hyps, known)
    assert [h.bug_class for h in grounded] == ["price_tamper", "mass_assignment"]
    assert [h.bug_class for h in hallucinated] == ["workflow_bypass"]


def test_dedup():
    hyps = [_hyp("price_tamper", "/api/checkout"), _hyp("price_tamper", "/api/checkout")]
    assert len(dedup(hyps)) == 1


# ---- judge grounding: no state change => no violation ----------------

def _wf_hyp():
    return Hypothesis(invariant_id="INV-W", bug_class="workflow_bypass", description="ship before pay",
                      request_sequence=[{"method": "POST", "url": "/ship", "as": "userA"}],
                      expected_safe="pay first",
                      meta={"oracle": "state_delta_judge", "invariant_rule": "payment precedes shipping",
                            "state_probe": {"url": "/order", "as": "userA"}})


def _result(before, after):
    from heretic.core.models import TestResult
    return TestResult(hypothesis=_wf_hyp(), responses={},
                      state_before={"json": before}, state_after={"json": after})


def test_judge_cannot_confirm_without_a_state_change():
    """A judge that ALWAYS says 'violated' must still be dropped when nothing changed."""
    always_yes = ScriptedLLM(judge_fn=lambda s, u: {"verdict": True, "why": "hallucinated", "confidence": 0.9})
    oracle = Oracle(judge_llm=always_yes, refute_llm=always_yes)
    same = {"shipped": False, "paid": False}
    v = oracle.verify(_wf_hyp(), _result(same, dict(same)))
    assert not v.confirmed                                       # no delta → ungrounded verdict dropped


def test_judge_confirms_on_a_real_state_change():
    always_yes = ScriptedLLM(judge_fn=lambda s, u: {"verdict": True, "why": "shipped unpaid", "confidence": 0.9})
    oracle = Oracle(judge_llm=always_yes, refute_llm=always_yes)
    v = oracle.verify(_wf_hyp(), _result({"shipped": False, "paid": False},
                                         {"shipped": True, "paid": False}))
    assert v.confirmed                                          # state changed → judge trusted (+ refuter panel)
