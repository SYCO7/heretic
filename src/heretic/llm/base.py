"""Provider-agnostic LLM interface. Backends implement this; the engine only
depends on this. Never let provider specifics leak into core/.

`tag` labels the call site (e.g. "intent_model", "hypotheses", "judge") so
offline/scripted backends can route deterministically. Real backends may ignore
it (or use it for logging).
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class LLMError(RuntimeError):
    """A backend call failed after retries (network, rate-limit, bad key, outage).
    Raised with a human-readable message so callers can degrade gracefully — the
    scan keeps its mechanical findings instead of crashing on a flaky free-tier API."""


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
