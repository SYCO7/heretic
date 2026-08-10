"""Per-phase model routing (the ADK win, without giving up the deterministic core).

Different agents want different models:
  - intent modelling + oracle judge  -> the smart one   (Nemotron Super via free NIM)
  - hypothesis / chain narrative      -> the cheap one    (Nemotron Nano, local Ollama)
  - refuter panel                     -> a DIVERSE voice  (DeepSeek-R1 free) so the
                                         skeptics fail differently from the judge

The router just resolves a role -> LLM backend. It supports three modes:
  - single(llm)          every role uses one model (offline ScriptedLLM, or `--model X`)
  - from_profile(...)    per-role backends, lazily built, with graceful fallback
  - empty()              no backend available -> engine runs mechanical checks only

Control flow stays in the deterministic orchestrator; the router only picks brains.
"""
from __future__ import annotations

from collections.abc import Callable

from .backends import get_backend
from .base import LLM

# role -> backend id (keys in llm/backends.py REGISTRY). Roles: intent, hypothesis, judge, refute, chain.
DEFAULT_PROFILE: dict[str, str] = {
    "intent": "nemotron-super",
    "hypothesis": "nemotron-nano",
    "judge": "nemotron-super",
    "refute": "openrouter-r1",
    "chain": "nemotron-nano",
}


class LLMRouter:
    def __init__(self) -> None:
        self._single: LLM | None = None
        self._by_role: dict[str, LLM | None] = {}
        self._fallback: LLM | None = None

    @classmethod
    def single(cls, llm: LLM) -> LLMRouter:
        r = cls()
        r._single = llm
        return r

    @classmethod
    def empty(cls) -> LLMRouter:
        return cls()

    @classmethod
    def from_profile(cls, profile: dict[str, str],
                     factory: Callable[[str], LLM] = get_backend) -> LLMRouter:
        r = cls()
        cache: dict[str, LLM | None] = {}
        for role, model_id in profile.items():
            if model_id not in cache:
                try:
                    cache[model_id] = factory(model_id)          # lazy; missing key -> None
                except Exception:
                    cache[model_id] = None
            r._by_role[role] = cache[model_id]
        r._fallback = next((b for b in cache.values() if b is not None), None)
        return r

    def for_role(self, role: str) -> LLM | None:
        if self._single is not None:
            return self._single
        b = self._by_role.get(role)
        return b if b is not None else self._fallback     # fall back to any working backend

    def any(self) -> bool:
        return self._single is not None or self._fallback is not None

    def describe(self) -> str:
        if self._single is not None:
            return f"single:{self._single.name}"
        return ", ".join(f"{r}={b.name if b else '—'}" for r, b in self._by_role.items()) or "none"
