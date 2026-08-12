"""Concrete LLM backends. All free-tier. Everything except Gemini speaks the
OpenAI-compatible `/chat/completions` API, so one httpx-based client covers
Nemotron (NVIDIA NIM), Groq, OpenRouter, and Ollama by swapping base_url + model.
No SDK dependency — just httpx. ScriptedLLM ("fake") runs offline.

Robustness (why real free-tier backends don't fall over):
  - retry with backoff on rate-limits / 5xx / transient network errors
  - reasoning-model support: fall back to `reasoning_content` when `content` is
    empty (Nemotron/R1 style), so the answer is never silently dropped
  - tolerant JSON: strip ``` fences and recover the first JSON object if a model
    wraps its verdict in prose — the Oracle never crashes on a chatty judge

Keys via env: NVIDIA_API_KEY, GEMINI_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY.
Ollama needs no key. Use `ollama:<model>` for ANY locally-pulled model
(e.g. `ollama:qwen2.5:3b`, `ollama:nemotron-3-nano`).
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx

from .base import LLM
from .scripted import ScriptedLLM

OLLAMA_BASE = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/") + "/v1"

NVIDIA_BASE = "https://integrate.api.nvidia.com/v1"

_MAX_RETRIES = 3
_RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}

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

    def __init__(self, spec: dict, transport: httpx.BaseTransport | None = None) -> None:
        self.name = spec["model"]
        self.context_tokens = spec["ctx"]
        self._spec = spec
        self._retry_backoff = 0.75                       # seconds, scaled by attempt (tests set 0)
        self._client = httpx.Client(timeout=180.0, transport=transport)

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        key_env = self._spec.get("key_env")
        if key_env and os.getenv(key_env):
            h["Authorization"] = f"Bearer {os.getenv(key_env)}"
        return h

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        """POST with retry/backoff on rate-limits, 5xx, and transient network errors."""
        url = self._spec["base_url"].rstrip("/") + "/chat/completions"
        last_err: Exception | None = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                r = self._client.post(url, headers=self._headers(), json=body)
            except httpx.HTTPError as e:                  # timeout / connection reset / DNS
                last_err = e
            else:
                if r.status_code not in _RETRYABLE_STATUS:
                    r.raise_for_status()
                    return r.json()
                last_err = httpx.HTTPStatusError(
                    f"retryable HTTP {r.status_code}", request=r.request, response=r)
            if attempt < _MAX_RETRIES and self._retry_backoff:
                time.sleep(self._retry_backoff * attempt)
        raise last_err or RuntimeError("LLM request failed")

    def complete(self, system: str, user: str, *, json: bool = False,
                 reasoning: bool = False, tag: str = "") -> str:
        body: dict[str, Any] = {
            "model": self._spec["model"], "temperature": 0,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }
        if json:
            body["response_format"] = {"type": "json_object"}
        if self._spec.get("max_tokens"):
            body["max_tokens"] = self._spec["max_tokens"]
        return _content(self._post(body))

    def judge(self, system: str, user: str, *, tag: str = "") -> dict:
        return _judge_from(self.complete(system, user, json=True, tag=tag))


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
        return _judge_from(self.complete(system, user, json=True, tag=tag))


# ---- response parsing helpers -----------------------------------------------

def _content(data: dict[str, Any]) -> str:
    """The assistant text — falling back to `reasoning_content` when a reasoning
    model leaves `content` empty (Nemotron/DeepSeek-R1), so we never drop the answer."""
    try:
        msg = data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError):
        return ""
    return (msg.get("content") or msg.get("reasoning_content") or "")


def _strip_fences(text: str) -> str:
    """Some models wrap JSON in ```json fences — strip them."""
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[-1].rsplit("```", 1)[0]
    return t.strip()


def _first_json_object(t: str) -> str | None:
    """Best-effort: the first brace-balanced {...} block (a chatty model wrapping
    its verdict in prose). Ignores braces-in-strings, which is fine for verdict JSON."""
    start = t.find("{")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(t)):
        if t[i] == "{":
            depth += 1
        elif t[i] == "}":
            depth -= 1
            if depth == 0:
                return t[start:i + 1]
    return None


def _parse_json(raw: str) -> Any:
    t = _strip_fences(raw)
    try:
        return json.loads(t)
    except Exception:
        block = _first_json_object(t)
        if block:
            try:
                return json.loads(block)
            except Exception:
                return None
    return None


def _judge_from(raw: str) -> dict:
    d = _parse_json(raw)
    if not isinstance(d, dict):
        return {"verdict": False, "why": "unparseable judge output", "confidence": 0.0}
    verdict = bool(d.get("verdict", d.get("is_violation", False)))
    try:
        confidence = float(d.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    return {"verdict": verdict, "why": d.get("why", ""), "confidence": confidence}


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
