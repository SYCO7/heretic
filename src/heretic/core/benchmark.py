"""Precision / recall / false-positive scoring against ground truth.

The FP-rate is the number HERETIC lives or dies by (see docs/03-ORACLE.md).
This runs against known targets every build so a regression that starts
reporting garbage is caught immediately.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from rich.table import Table

from .models import Finding


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    fps: list[str] = field(default_factory=list)         # titles of false positives
    missed: list[dict] = field(default_factory=list)     # ground-truth items not found

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def fp_rate(self) -> float:
        """Share of REPORTED findings that are false (the number the win condition targets)."""
        return self.fp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def score(findings: list[Finding], ground_truth: list[dict[str, Any]]) -> Metrics:
    """A finding matches a ground-truth item when the bug_class is equal and the
    item's `match` substring appears in the finding title. Each GT item matches
    at most one finding."""
    matched = [False] * len(ground_truth)
    fps: list[str] = []
    for f in findings:
        idx = next(
            (i for i, g in enumerate(ground_truth)
             if not matched[i] and g["bug_class"] == f.bug_class and g["match"] in f.title),
            None,
        )
        if idx is None:
            fps.append(f.title)
        else:
            matched[idx] = True
    tp = sum(matched)
    return Metrics(
        tp=tp, fp=len(fps), fn=len(ground_truth) - tp,
        fps=fps,
        missed=[g for i, g in enumerate(ground_truth) if not matched[i]],
    )


def scoreboard(m: Metrics, *, threshold: float = 0.10) -> Table:
    t = Table(title="HERETIC benchmark", show_header=False)
    t.add_column("metric")
    t.add_column("value", justify="right")
    t.add_row("true positives", str(m.tp))
    t.add_row("false positives", str(m.fp))
    t.add_row("false negatives (missed)", str(m.fn))
    t.add_row("precision", f"{m.precision:.0%}")
    t.add_row("recall", f"{m.recall:.0%}")
    gate = "PASS" if m.fp_rate < threshold else "FAIL"
    color = "green" if gate == "PASS" else "red"
    t.add_row("false-positive rate", f"[{color}]{m.fp_rate:.0%} (gate <{threshold:.0%}: {gate})[/]")
    t.add_row("F1", f"{m.f1:.2f}")
    return t
