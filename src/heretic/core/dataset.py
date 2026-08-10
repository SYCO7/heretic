"""Turn confirmed attack traces into fine-tune examples (M5).

This is the "build your own AI for free" path from docs/04-LLM-BACKENDS.md:
generate reasoning traces with a strong free model, log the ones the Oracle
CONFIRMED, then distil/LoRA a small local Nemotron Nano on them → a private,
specialised business-logic model that runs offline.

Outputs Alpaca-style records (instruction/input/output) or OpenAI chat format.
"""
from __future__ import annotations

import json
from typing import Any

_INSTRUCTION = (
    "You are HERETIC, a business-logic vulnerability oracle. Given an application context "
    "and a business INVARIANT the app assumes but may not enforce, produce a concrete, "
    "replayable HTTP test that VIOLATES that invariant, name the oracle that proves it "
    "(cross_session_diff | invariant_assertion | state_delta_judge | parallel_success_count), "
    "and state the proof. Never claim a finding without proof. "
    'Output STRICT JSON only: {"test": [<request objects>], "oracle": "<oracle>", "proof": "<evidence>"}.'
)


def build_finetune_examples(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One example per CONFIRMED trace record."""
    examples: list[dict[str, Any]] = []
    for r in records:
        if not r.get("confirmed"):
            continue
        examples.append({
            "instruction": _INSTRUCTION,
            "input": json.dumps({
                "bug_class": r.get("bug_class"),
                "invariant": r.get("invariant_id"),
                "expected_safe": r.get("expected_safe"),
            }, default=str),
            "output": json.dumps({
                "test": r.get("request_sequence"),
                "oracle": r.get("oracle"),
                "proof": r.get("observed"),
            }, default=str),
        })
    return examples


def to_jsonl(examples: list[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(e, default=str) for e in examples)


def to_chat(examples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """OpenAI/Nemotron chat-format for SFT/QLoRA trainers."""
    return [{
        "messages": [
            {"role": "system", "content": e["instruction"]},
            {"role": "user", "content": e["input"]},
            {"role": "assistant", "content": e["output"]},
        ]
    } for e in examples]
