"""RAG-lite knowledge base — bundled attack-pattern corpus + a stdlib keyword
retriever. No external vector DB, no embedding model, no network: it just grounds
the hypothesis prompt with relevant tradecraft per bug class. A real Chroma-backed
RAG can drop in behind the same `retrieve()` interface later.
"""
from __future__ import annotations

from pathlib import Path

import yaml

_DEFAULT = Path(__file__).resolve().parent.parent / "knowledge" / "patterns.yaml"
_STOP = {"a", "an", "the", "to", "of", "and", "or", "is", "be", "not", "by", "on", "in", "for"}


class KnowledgeBase:
    def __init__(self, data: dict[str, list[str]]) -> None:
        self.data = data

    @classmethod
    def load(cls, path: Path | None = None) -> KnowledgeBase:
        try:
            return cls(yaml.safe_load((path or _DEFAULT).read_text()) or {})
        except (OSError, yaml.YAMLError):
            return cls({})

    def retrieve(self, bug_class: str, query: str = "", k: int = 3) -> list[str]:
        items = self.data.get(bug_class, [])
        if not query or len(items) <= k:
            return items[:k]
        terms = {t for t in query.lower().split() if t not in _STOP}
        ranked = sorted(items, key=lambda s: -len(terms & set(s.lower().split())))
        return ranked[:k]
