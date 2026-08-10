"""M7: resumable engagements (SQLite checkpoint), the feedback-loop mutation
engine, and the shared auto-flow helper. All offline (mock transport + ScriptedLLM).
"""
from __future__ import annotations

import httpx
from rich.console import Console

from heretic.benchmark import fixtures as F
from heretic.core.chain import Chainer
from heretic.core.engagement import EngagementStore, finding_from_dict, finding_to_dict
from heretic.core.models import Hypothesis, Severity
from heretic.core.mutate import mutations
from heretic.core.orchestrator import Orchestrator
from heretic.llm.scripted import ScriptedLLM

_QUIET = Console(quiet=True)


# ---- engagement checkpoint + resume ----------------------------------

def test_engagement_persists_primitives_and_marks_complete(tmp_path):
    db = tmp_path / "eng.db"
    store = EngagementStore(db)
    store.start(F._cfg(), roe="roe.yaml", accounts="accounts.yaml")
    findings = F.build_orchestrator(engagement=store).run()
    store.close()

    meta, saved, done = EngagementStore(db).load()
    # 5 confirmed primitives are checkpointed; the 3 chains are NOT (they are derived)
    assert len(saved) == 5
    assert all(f.bug_class != "chain" for f in saved)
    assert meta["completed"] is True
    # every class in the run is marked done
    assert {"bola", "price_tamper", "mass_assignment", "workflow_bypass"} <= done
    # in-memory run still returns the full 8 (5 primitives + 3 chains)
    assert len(findings) == 8


def test_finding_serialization_roundtrip():
    src = next(f for f in F.build_orchestrator().run() if f.bug_class == "mass_assignment")
    clone = finding_from_dict(finding_to_dict(src))
    assert clone.title == src.title
    assert clone.severity is Severity.CRITICAL          # enum survives the round-trip
    assert clone.proof == src.proof


def test_resume_rechains_saved_primitives(tmp_path):
    """The resume path: reload saved primitives, then re-chain over the merged set."""
    db = tmp_path / "eng.db"
    store = EngagementStore(db)
    store.start(F._cfg(), roe="roe.yaml", accounts="accounts.yaml")
    F.build_orchestrator(engagement=store).run()
    store.close()

    _meta, saved, _done = EngagementStore(db).load()
    chains = Chainer(None).chain(saved, None)
    titles = {c.title for c in chains}
    # 2 BOLA + mass + price + workflow compose into all three chains
    assert titles == {"Account takeover", "Financial fraud", "Bulk data exfiltration"}


# ---- feedback-loop mutations -----------------------------------------

def test_mutations_are_bounded_and_nondestructive():
    h = Hypothesis("INV-1", "price_tamper", "checkout",
                   [{"method": "POST", "url": "/api/checkout", "as": "userA", "body": {"price": 100}}],
                   "server recomputes", meta={"oracle": "invariant_assertion",
                                              "assertion": {"field": "charged", "expected_value": 100}})
    variants = mutations(h, 2)
    assert len(variants) == 2                            # limit respected
    assert h.request_sequence[0]["body"]["price"] == 100   # original untouched (deep copy)
    # each variant keeps the assertion consistent with the value it actually sends
    for v in variants:
        sent = v.request_sequence[0]["body"]["price"]
        assert v.meta["assertion"]["tampered_value"] == sent


def test_mutations_cover_each_logic_class():
    mass = mutations(Hypothesis("i", "mass_assignment", "d",
                     [{"method": "POST", "url": "/u", "as": "userA", "body": {}}], "", meta={}), 3)
    assert mass and all("equals" in v.meta["assertion"] for v in mass)

    wf = mutations(Hypothesis("i", "workflow_bypass", "d",
                   [{"method": "POST", "url": "/pay"}, {"method": "POST", "url": "/ship"}], "", meta={}), 5)
    assert len(wf) == 2                                  # reorder + skip-first

    coupon = mutations(Hypothesis("i", "coupon_abuse", "d",
                       [{"method": "POST", "url": "/c", "body": {"code": "X"}}], "", meta={}), 5)
    assert [len(v.request_sequence) for v in coupon] == [2, 3]   # replay x2, x3

    # non-mutatable class yields nothing
    assert mutations(Hypothesis("i", "bola", "d", [], "", meta={}), 3) == []


def _price_orchestrator(iterate: int) -> Orchestrator:
    """A single price-tamper hypothesis that HOLDS at price=100 but breaks when mutated."""
    cfg = F._cfg()
    cfg.classes = ["price_tamper"]
    cfg.iterate = iterate
    intent = {"invariants": [{"id": "INV-P", "rule": "price computed server-side", "bug_class": "price_tamper"}]}
    hyps = [{"invariant_id": "INV-P", "bug_class": "price_tamper", "description": "tamper checkout",
             "request_sequence": [{"method": "POST", "url": "/api/checkout", "as": "userA", "body": {"price": 100}}],
             "expected_safe": "charged == 100", "oracle": "invariant_assertion",
             "assertion": {"field": "charged", "expected_value": 100, "tampered_value": 100}}]
    llm = ScriptedLLM(intent=intent, hypotheses=hyps, judge_fn=F._judge_fn)
    return Orchestrator(cfg, console=_QUIET, transport=httpx.MockTransport(F.handler), llm=llm)


def test_feedback_loop_turns_a_drop_into_a_confirm():
    # price=100 satisfies the invariant → nothing found without the feedback loop
    assert _price_orchestrator(iterate=0).run() == []
    # with --iterate, a mutated price (1/0/0.01) breaks it → confirmed
    found = _price_orchestrator(iterate=3).run()
    assert [f.bug_class for f in found] == ["price_tamper"]
    assert "mutate" in found[0].title            # the confirming finding came from a mutated retry
