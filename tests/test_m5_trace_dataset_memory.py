"""M5: trace logging, distillation dataset export, and the self-improvement
pattern memory. All offline.
"""
from __future__ import annotations

import json

from heretic.benchmark import fixtures as F
from heretic.core.dataset import build_finetune_examples, to_chat, to_jsonl
from heretic.core.memory import PatternMemory
from heretic.core.trace import TraceStore

# ---- trace logging ----------------------------------------------------

def test_trace_records_confirmed_and_dropped():
    ts = TraceStore()
    F.build_orchestrator(trace=ts).run()
    # every executed primitive test is logged (6 BOLA + 5 logic + 1 mechanical mass-assign
    # + 1 mechanical price-tamper probe, both drop on the mock); chains aren't executed
    assert len(ts.records) == 13
    assert any(r["confirmed"] for r in ts.records)
    assert any(not r["confirmed"] for r in ts.records)
    # confirmed primitives == 5 (2 BOLA + price + mass + workflow)
    assert len(ts.confirmed()) == 5
    for r in ts.confirmed():
        assert r["oracle"] and r["confidence"] is not None


def test_trace_persists_and_reloads(tmp_path):
    path = tmp_path / "run.trace.jsonl"
    ts = TraceStore(path)
    F.build_orchestrator(trace=ts).run()
    reloaded = TraceStore.load(path)
    assert len(reloaded.records) == len(ts.records)
    assert len(reloaded.confirmed()) == 5


# ---- distillation dataset --------------------------------------------

def test_dataset_export_shape():
    ts = TraceStore()
    F.build_orchestrator(trace=ts).run()
    examples = build_finetune_examples(ts.records)
    assert len(examples) == 5                         # one per confirmed primitive
    for e in examples:
        assert set(e) == {"instruction", "input", "output"}
        assert json.loads(e["input"]) is not None and json.loads(e["output"]) is not None   # valid JSON

    # JSONL round-trips
    lines = to_jsonl(examples).splitlines()
    assert len(lines) == 5 and all(json.loads(x) for x in lines)

    # chat format for SFT/QLoRA trainers
    chat = to_chat(examples)
    assert chat[0]["messages"][0]["role"] == "system"
    assert chat[0]["messages"][-1]["role"] == "assistant"


# ---- self-improvement memory -----------------------------------------

def test_memory_learns_and_recalls():
    findings = F.build_orchestrator().run()
    mem = PatternMemory()
    added = mem.learn(findings)
    # 4 distinct patterns: BOLA:order (both bola share it), price, mass, workflow; chains skipped
    assert added == 4
    assert mem.recall("bola")                         # remembers BOLA patterns
    assert mem.recall("price_tamper")
    assert mem.recall("no_such_class") == []


def test_memory_persists_roundtrip(tmp_path):
    findings = F.build_orchestrator().run()
    path = tmp_path / "memory.jsonl"
    mem = PatternMemory(path=path)
    mem.learn(findings)
    reloaded = PatternMemory.load(path)
    assert len(reloaded.records) == 4
    # re-learning the same findings adds nothing (dedup by bug_class+invariant)
    assert reloaded.learn(findings) == 0


def test_memory_feeds_hypothesis_engine_without_error():
    # a run WITH memory present should still work end-to-end (learned hints injected)
    mem = PatternMemory()
    first = F.build_orchestrator(memory=mem).run()
    assert len(first) == 8                            # 5 primitives + 3 chains, unchanged
    assert len(mem.records) == 4                      # 4 distinct patterns learned
