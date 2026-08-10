"""ScriptedLLM — deterministic offline backend for tests and no-key dev runs.

Routes by the `tag` passed at each call site. Feed it the intent-model JSON and
hypotheses JSON you want returned, and a judge function for Oracle 3. Nothing
touches the network, so the whole M2 pipeline is exercisable offline.
"""
from __future__ import annotations

from collections.abc import Callable

from .base import LLM


class ScriptedLLM(LLM):
    name = "scripted"
    context_tokens = 1_000_000

    def __init__(
        self,
        intent: dict | None = None,
        hypotheses: list | None = None,
        judge_fn: Callable[[str, str], dict] | None = None,
    ) -> None:
        self._intent = intent or {}
        self._hypotheses = hypotheses or []
        self._judge_fn = judge_fn

    def complete(self, system: str, user: str, *, json: bool = False,
                 reasoning: bool = False, tag: str = "") -> str:
        import json as _json
        if tag == "intent_model":
            return _json.dumps(self._intent)
        if tag == "hypotheses":
            return _json.dumps(self._hypotheses)
        return "{}"

    def judge(self, system: str, user: str, *, tag: str = "") -> dict:
        if self._judge_fn is not None:
            return self._judge_fn(system, user)
        return {"verdict": False, "why": "no judge scripted", "confidence": 0.0}
