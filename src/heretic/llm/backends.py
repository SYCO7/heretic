"""Concrete LLM backends. All free-tier. Everything except Gemini speaks the
OpenAI-compatible `/chat/completions` API, so one httpx-based client covers
Nemotron (NVIDIA NIM), Groq, OpenRouter, and Ollama by swapping base_url + model.
No SDK dependency — just httpx. ScriptedLLM ("fake") runs offline.

Keys via env: NVIDIA_API_KEY, GEMINI_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY.
Ollama needs no key. Use `ollama:<model>` for ANY locally-pulled model
(e.g. `ollama:qwen2.5:3b`, `ollama:nemotron-3-nano`).
"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx

from .base import LLM
from .scripted import ScriptedLLM

OLLAMA_BASE = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/") + "/v1"

NVIDIA_BASE = "https://integrate.api.nvidia.com/v1"

REGISTRY: dict[str, dict] = {
    "nemotron-super": {  # NVIDIA free API — brain: intent model + oracle judge
        "base_url": NVIDIA_BASE,
        "model": "nvidia/nemotron-3-super-120b-a12b", "key_env": "NVIDIA_API_KEY", "ctx": 1_000_000,
    },
    "nemotron-nano": {   # cheap workhorse + the open-weights finetune target
        "base_url": NVIDIA_BASE,
        "model": "nvidia/nemotron-3-nano-30b-a3b", "key_env": "NVIDIA_API_KEY", "ctx": 1_000_000,
    },
    "nemotron-ultra": {  # strongest (550B) — use only if free credits allow
        "base_url": NVIDIA_BASE,
        "model": "nvidia/nemotron-3-ultra-550b-a55b", "key_env": "NVIDIA_API_KEY", "ctx": 1_000_000,
    },
    "ollama:nemotron-nano": {   # fully local — private, for real targets (needs the model pulled)
        "base_url": OLLAMA_BASE, "model": "nemotron-3-nano", "key_env": None, "ctx": 1_000_000,
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile", "key_env": "GROQ_API_KEY", "ctx": 128_000,
    },
    "openrouter-r1": {   # free DeepSeek-R1 — a diverse 2nd opinion for the refuter panel
        "base_url": "https://openrouter.ai/api/v1",
        "model": "deepseek/deepseek-r1:free", "key_env": "OPENROUTER_API_KEY", "ctx": 128_000,
    },
    "gemini-flash": {"gemini": True, "model": "gemini-2.5-flash",
                     "key_env": "GEMINI_API_KEY", "ctx": 1_000_000},
    "fake": {"scripted": True, "model": "scripted", "ctx": 1_000_000},
}


class OpenAICompatLLM(LLM):
    """httpx client for any OpenAI-compatible /chat/completions endpoint."""

    def __init__(self, spec: dict) -> None:
        self.name = spec["model"]
        self.context_tokens = spec["ctx"]
        self._spec = spec

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        key_env = self._spec.get("key_env")
        if key_env and os.getenv(key_env):
            h["Authorization"] = f"Bearer {os.getenv(key_env)}"
        return h

    def complete(self, system: str, user: str, *, json: bool = False,
                 reasoning: bool = False, tag: str = "") -> str:
        body: dict[str, Any] = {
            "model": self._spec["model"], "temperature": 0,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }
        if json:
            body["response_format"] = {"type": "json_object"}
        url = self._spec["base_url"].rstrip("/") + "/chat/completions"
        r = httpx.post(url, headers=self._headers(), json=body, timeout=180.0)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"] or ""

    def judge(self, system: str, user: str, *, tag: str = "") -> dict:
        raw = self.complete(system, user, json=True, tag=tag)
        try:
            d = json.loads(_strip_fences(raw))
        except Exception:
            return {"verdict": False, "why": "unparseable judge output", "confidence": 0.0}
        verdict = bool(d.get("verdict", d.get("is_violation", False)))
        return {"verdict": verdict, "why": d.get("why", ""),
                "confidence": float(d.get("confidence", 0.5))}


class GeminiLLM(LLM):
    """Google Gemini — 1M context, ideal for Phase-2 whole-app modeling."""

    def __init__(self, spec: dict) -> None:
        self.name = spec["model"]
        self.context_tokens = spec["ctx"]
        self._spec = spec
        self._client = None

    def _c(self):
        if self._client is None:
            from google import genai  # lazy
            self._client = genai.Client(api_key=os.getenv(self._spec["key_env"], ""))
        return self._client

    def complete(self, system: str, user: str, *, json: bool = False,
                 reasoning: bool = False, tag: str = "") -> str:
        cfg: dict[str, Any] = {"system_instruction": system, "temperature": 0}
        if json:
            cfg["response_mime_type"] = "application/json"
        resp = self._c().models.generate_content(model=self._spec["model"], contents=user, config=cfg)
        return resp.text or ""

    def judge(self, system: str, user: str, *, tag: str = "") -> dict:
        raw = self.complete(system, user, json=True, tag=tag)
        try:
            d = json.loads(_strip_fences(raw))
        except Exception:
            return {"verdict": False, "why": "unparseable judge output", "confidence": 0.0}
        return {"verdict": bool(d.get("verdict", False)), "why": d.get("why", ""),
                "confidence": float(d.get("confidence", 0.5))}


def _strip_fences(text: str) -> str:
    """Some models wrap JSON in ```json fences — strip them."""
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[-1].rsplit("```", 1)[0]
    return t.strip()


def get_backend(model_id: str) -> LLM:
    spec = REGISTRY.get(model_id)
    if spec is None:
        if model_id.startswith("ollama:"):        # ollama:<any-locally-pulled-model>
            spec = {"base_url": OLLAMA_BASE, "model": model_id.split(":", 1)[1],
                    "key_env": None, "ctx": 128_000}
        else:
            raise ValueError(f"unknown model '{model_id}'. known: {', '.join(REGISTRY)} (or ollama:<model>)")
    if spec.get("scripted"):
        return ScriptedLLM()
    if spec.get("gemini"):
        if spec.get("key_env") and not os.getenv(spec["key_env"]):
            raise OSError(f"set {spec['key_env']} for backend '{model_id}'")
        return GeminiLLM(spec)
    if spec.get("key_env") and not os.getenv(spec["key_env"]):
        raise OSError(f"set {spec['key_env']} for backend '{model_id}'")
    return OpenAICompatLLM(spec)
