"""Model auto-selection + Ollama automation.

The point: users should never have to memorise `--model nemotron-super`. HERETIC
detects what's actually usable on this machine — hosted keys (NVIDIA / Gemini /
Groq / OpenRouter) and any locally-pulled Ollama models — and picks the best one
itself. A saved preference (HERETIC_MODEL) always wins; otherwise `best_available()`
chooses. Bigger local models can be pulled straight from the menu.
"""
from __future__ import annotations

import os
import subprocess

import httpx

# preferred hosted backends, best-first: (id, human label, key env var)
_HOSTED = [
    ("nemotron-super", "Nemotron Super 120B — NVIDIA free API (recommended)", "NVIDIA_API_KEY"),
    ("gemini-flash", "Gemini 2.5 Flash — 1M context", "GEMINI_API_KEY"),
    ("groq", "Llama 3.3 70B — Groq", "GROQ_API_KEY"),
    ("openrouter-r1", "DeepSeek R1 — OpenRouter free", "OPENROUTER_API_KEY"),
]
_OLLAMA_TAGS = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/") + "/api/tags"


def ollama_running(timeout: float = 2.0) -> bool:
    try:
        return httpx.get(_OLLAMA_TAGS, timeout=timeout).status_code == 200
    except httpx.HTTPError:
        return False


def ollama_models() -> list[dict]:
    """Locally-pulled models as [{name, size}], largest first (best default)."""
    try:
        r = httpx.get(_OLLAMA_TAGS, timeout=3.0)
        r.raise_for_status()
        models = r.json().get("models", [])
    except (httpx.HTTPError, ValueError):
        return []
    out = [{"name": m.get("name", ""), "size": int(m.get("size", 0))} for m in models if m.get("name")]
    return sorted(out, key=lambda m: -m["size"])


def ollama_pull(model: str) -> bool:
    """Pull a model via the ollama CLI (streams progress to the terminal)."""
    try:
        return subprocess.run(["ollama", "pull", model], check=False).returncode == 0
    except FileNotFoundError:
        return False


def available() -> list[dict]:
    """Every backend HERETIC could use, with readiness — for the menu picker."""
    rows: list[dict] = []
    for mid, label, env in _HOSTED:
        rows.append({"id": mid, "label": label, "ready": bool(os.getenv(env)),
                     "kind": "hosted", "note": "" if os.getenv(env) else f"set {env}"})
    if ollama_running():
        for m in ollama_models():
            gb = m["size"] / 1e9
            rows.append({"id": f"ollama:{m['name']}", "label": f"{m['name']} — local, private ({gb:.1f} GB)",
                         "ready": True, "kind": "local", "note": ""})
    else:
        rows.append({"id": "ollama", "label": "Ollama (local, private) — not running",
                     "ready": False, "kind": "local", "note": "start `ollama serve` + pull a model"})
    rows.append({"id": "fake", "label": "Offline — no LLM (BOLA + data-exposure only)",
                 "ready": True, "kind": "offline", "note": ""})
    return rows


def best_available() -> str:
    """The best usable model id, no user input required."""
    for mid, _label, env in _HOSTED:
        if os.getenv(env):
            return mid
    if ollama_running():
        models = ollama_models()
        if models:
            return f"ollama:{models[0]['name']}"       # largest local model
    return "fake"                                      # offline fallback (mechanical checks still run)


def resolve(model: str | None) -> str:
    """Turn a possibly-unset --model into a concrete backend id.

    'auto-detect' / None -> saved HERETIC_MODEL, else best_available(). An explicit
    id (including 'auto' for per-phase routing) is returned unchanged."""
    if model and model not in ("auto-detect", "auto-select"):
        return model
    saved = os.getenv("HERETIC_MODEL")
    if saved:
        return saved
    return best_available()
