"""Engagement trace log (M5). Records every executed hypothesis + its verdict to
JSONL. Two uses:
  1. audit trail (see docs/07-GUARDRAILS.md — every action is logged), and
  2. raw material for distillation / LoRA (see core/dataset.py) — the confirmed
     traces become training examples for a private specialist model.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class TraceStore:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def add(self, record: dict[str, Any]) -> None:
        self.records.append(record)
        if self.path:
            with self.path.open("a") as fh:
                fh.write(json.dumps(record, default=str) + "\n")

    def record_verdict(self, hyp: Any, verdict: Any) -> None:
        f = verdict.finding
        self.add({
            "bug_class": hyp.bug_class,
            "invariant_id": hyp.invariant_id,
            "description": hyp.description,
            "request_sequence": hyp.request_sequence,
            "expected_safe": hyp.expected_safe,
            "confirmed": bool(verdict.confirmed),
            "reason": verdict.reason,
            "title": f.title if f else "",
            "observed": f.observed if f else "",
            "oracle": (f.proof.get("oracle") if f else None),
            "confidence": (f.proof.get("confidence") if f else None),
        })

    def confirmed(self) -> list[dict[str, Any]]:
        return [r for r in self.records if r.get("confirmed")]

    @classmethod
    def load(cls, path: Path | str) -> TraceStore:
        ts = cls()
        p = Path(path)
        if p.exists():
            for line in p.read_text().splitlines():
                line = line.strip()
                if line:
                    ts.records.append(json.loads(line))
        return ts
