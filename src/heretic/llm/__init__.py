"""Pluggable LLM backends. See docs/04-LLM-BACKENDS.md.

get_backend("nemotron-super") -> NVIDIA NIM free API
get_backend("gemini-flash")   -> Google free API (1M ctx)
get_backend("groq")           -> Groq free
get_backend("ollama:nemotron-nano") -> fully local / private
"""
from __future__ import annotations

from .backends import get_backend

__all__ = ["get_backend"]
