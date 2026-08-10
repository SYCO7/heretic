"""Provider-agnostic LLM interface. Backends implement this; the engine only
depends on this. Never let provider specifics leak into core/.

`tag` labels the call site (e.g. "intent_model", "hypotheses", "judge") so
offline/scripted backends can route deterministically. Real backends may ignore
it (or use it for logging).
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class LLM(ABC):
    name: str
    context_tokens: int

    @abstractmethod
    def complete(self, system: str, user: str, *, json: bool = False,
                 reasoning: bool = False, tag: str = "") -> str:
        """Single-shot completion. `json=True` requests strict JSON;
        `reasoning=True` enables deep chain-of-thought (Nemotron toggle) for
        hard hypothesis/oracle steps."""
        ...

    @abstractmethod
    def judge(self, system: str, user: str, *, tag: str = "") -> dict:
        """Structured verdict for the Oracle. Returns
        {"verdict": bool, "why": str, "confidence": float}."""
        ...

    def embed(self, text: str) -> list[float]:  # optional; RAG uses local embeddings by default
        raise NotImplementedError
