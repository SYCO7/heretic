"""Pattern memory (M5) — the self-improvement loop.

After each engagement, the winning (Oracle-confirmed) hypothesis shapes are
remembered per bug class and persisted. On the next run they are fed back into
the hypothesis prompt as learned few-shot hints, so HERETIC gets better at a
target family the more it sees it. Deterministic, local JSONL — no training
required for the loop itself (that's the optional distil step in dataset.py).
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


class PatternMemory:
    def __init__(self, records: list[dict] | None = None, path: Path | str | None = None) -> None:
        self.records = records or []
        self.path = Path(path) if path else None

    @classmethod
    def load(cls, path: Path | str) -> PatternMemory:
        p = Path(path)
        recs: list[dict] = []
        if p.exists():
            for line in p.read_text().splitlines():
                line = line.strip()
                if line:
                    recs.append(json.loads(line))
        return cls(recs, path)

    def learn(self, findings: list[Finding]) -> int:
        """Record confirmed primitive patterns not already known. Returns count added."""
        seen = {(r["bug_class"], r["invariant"]) for r in self.records}
        added = 0
        for f in findings:
            if f.bug_class == "chain":
                continue
            key = (f.bug_class, f.invariant_id)
            if key in seen:
                continue
            seen.add(key)
            rec = {"bug_class": f.bug_class, "invariant": f.invariant_id,
                   "pattern": f.title, "poc": f.proof.get("poc")}
            self.records.append(rec)
            added += 1
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a") as fh:
                    fh.write(json.dumps(rec, default=str) + "\n")
        return added

    def recall(self, bug_class: str, k: int = 3) -> list[str]:
        return [r["pattern"] for r in self.records if r["bug_class"] == bug_class][:k]

    def save(self, path: Path | str) -> None:
        Path(path).write_text("\n".join(json.dumps(r, default=str) for r in self.records))
