"""Anti-hallucination: ground the LLM's output against reality.

The LLM (intent model + hypothesis engine) can hallucinate — invent endpoints or
fields that do not exist. HERETIC's design already limits the damage (a hallucinated
endpoint 404s → the Oracle drops it), but that wastes requests and, worse, a hallucinated
JUDGE verdict could reach a report. This module makes hallucination detectable and
self-correcting:

  1. every hypothesis is checked against the REAL discovered surface — a request URL that
     isn't a known path is flagged as hallucinated;
  2. when hallucinations are found, the hypotheses are regenerated with the real endpoint
     list as a hard constraint (detect → restructure → retry);
  3. the hallucination rate is measured and logged, so the tool reports on its own honesty.

(The judge-verdict guard — a state-delta cannot be confirmed if nothing actually changed —
lives in oracle.py, where the before/after state is available.)
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .browser import templatize
from .models import Hypothesis


def norm_path(url: str) -> str:
    """Normalise a URL to a comparable path pattern: strip host/query, collapse ids to {id}."""
    path = urlparse(url).path or url
    return templatize(path).rstrip("/").lower() or "/"


def known_paths(paths: Any) -> set[str]:
    """The set of real path patterns from discovery + recon + configured objects."""
    return {norm_path(p) for p in paths if p}


def is_grounded(url: str, known: set[str]) -> bool:
    return norm_path(url) in known


def ground_hypotheses(hyps: list[Hypothesis], known: set[str]) -> tuple[list[Hypothesis], list[Hypothesis]]:
    """Split hypotheses into (grounded, hallucinated) by whether every request URL is real."""
    grounded: list[Hypothesis] = []
    hallucinated: list[Hypothesis] = []
    for h in hyps:
        urls = [s.get("url") for s in (h.request_sequence or []) if isinstance(s, dict) and s.get("url")]
        (grounded if urls and all(is_grounded(u, known) for u in urls) else hallucinated).append(h)
    return grounded, hallucinated


def dedup(hyps: list[Hypothesis]) -> list[Hypothesis]:
    """Drop duplicate hypotheses (same class + URL sequence)."""
    seen: set[tuple] = set()
    out: list[Hypothesis] = []
    for h in hyps:
        key = (h.bug_class, tuple(s.get("url", "") for s in (h.request_sequence or []) if isinstance(s, dict)))
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out
