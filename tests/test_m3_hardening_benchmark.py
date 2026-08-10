"""M3: Oracle hardening (refuter panel, confidence) + the precision/recall
benchmark harness. All offline.
"""
from __future__ import annotations

import json

import httpx
from rich.console import Console

from heretic.benchmark import fixtures as F
from heretic.benchmark import run_builtin
from heretic.core.benchmark import score
from heretic.core.models import Finding, Severity
from heretic.core.orchestrator import Orchestrator
from heretic.llm.scripted import ScriptedLLM

# ---- benchmark harness ------------------------------------------------

def test_builtin_benchmark_is_perfect_on_mock():
    findings, gt = run_builtin()
    m = score(findings, gt)
    assert (m.tp, m.fp, m.fn) == (8, 0, 0)          # 5 primitives + 3 M4 chains
    assert m.precision == 1.0 and m.recall == 1.0 and m.fp_rate == 0.0


def test_score_flags_a_false_positive():
    findings, gt = run_builtin()
    bogus = Finding(title="BOLA — nonexistent bug", invariant_id="x", bug_class="bola",
                    severity=Severity.HIGH, expected="", observed="", proof={})
    m = score([*findings, bogus], gt)
    assert m.fp == 1 and m.fp_rate > 0.0
    assert "nonexistent" in m.fps[0]


def test_score_flags_a_missed_bug():
    findings, gt = run_builtin()
    without_price = [f for f in findings if f.bug_class != "price_tamper"]
    m = score(without_price, gt)
    assert m.fn >= 1 and m.recall < 1.0


# ---- Oracle hardening: adversarial panel ------------------------------

def _workflow_only_run(judge_fn):
    """Run just the workflow-bypass hypothesis against the mock, with a custom judge."""
    F._reset()
    cfg = F._cfg()
    cfg.classes = ["workflow_bypass"]
    cfg.objects = []                       # isolate: skip BOLA harvest
    intent = {"invariants": [{"id": "INV-W", "rule": "shipping requires payment",
                              "bug_class": "workflow_bypass"}]}
    hyps = [{"invariant_id": "INV-W", "bug_class": "workflow_bypass",
             "description": "ship o100 before payment",
             "request_sequence": [{"method": "POST", "url": "/api/orders2/o100/ship", "as": "userA"}],
             "expected_safe": "cannot ship unpaid", "oracle": "state_delta_judge",
             "state_probe": {"url": "/api/orders2/o100", "as": "userA"},
             "invariant_rule": "shipping requires payment"}]
    llm = ScriptedLLM(intent=intent, hypotheses=hyps, judge_fn=judge_fn)
    orch = Orchestrator(cfg, console=Console(quiet=True),
                        transport=httpx.MockTransport(F.handler), llm=llm)
    return orch.run()


def test_refuter_panel_kills_finding_the_skeptics_reject():
    def judge(system, user):
        after = json.loads(user).get("after") or {}
        violated = after.get("shipped") is True and after.get("paid") is False
        if "refute" in system.lower():          # skeptics veto it
            return {"verdict": False, "why": "skeptic refutes"}
        return {"verdict": bool(violated), "why": "primary judge"}
    # primary judge confirms, but the panel refutes -> dropped
    assert _workflow_only_run(judge) == []


def test_finding_survives_when_panel_agrees():
    findings = _workflow_only_run(F._judge_fn)   # panel agrees with primary judge
    assert len(findings) == 1
    assert findings[0].proof["confidence"] >= 0.5


# ---- confidence on deterministic proofs -------------------------------

def test_deterministic_finding_has_full_confidence():
    findings, _ = run_builtin()
    price = next(f for f in findings if f.bug_class == "price_tamper")
    assert price.proof["confidence"] == 1.0      # deterministic oracle, no panel
