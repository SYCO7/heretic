"""M25: LLM backend robustness — retry/backoff on transient errors, reasoning-model
`reasoning_content` fallback, and tolerant JSON recovery from a chatty judge.
All offline via httpx.MockTransport (no network, no key).
"""
from __future__ import annotations

import httpx

from heretic.llm.backends import OpenAICompatLLM
from heretic.llm.base import LLMError

_SPEC = {"base_url": "http://llm.local/v1", "model": "m", "ctx": 1000, "key_env": None}


def _llm(handler) -> OpenAICompatLLM:
    llm = OpenAICompatLLM(_SPEC, transport=httpx.MockTransport(handler))
    llm._retry_backoff = 0                                  # no real sleeps in tests
    return llm


def test_retries_then_succeeds():
    state = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] < 3:                                  # 503 twice, then 200
            return httpx.Response(503, json={"error": "busy"})
        return httpx.Response(200, json={"choices": [{"message": {"content": "hello"}}]})

    assert _llm(h).complete("s", "u") == "hello"
    assert state["n"] == 3                                  # it actually retried


def test_reasoning_content_fallback():
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [
            {"message": {"content": "", "reasoning_content": "the real answer"}}]})

    assert _llm(h).complete("s", "u") == "the real answer"


def test_judge_recovers_json_from_prose():
    def h(req: httpx.Request) -> httpx.Response:
        txt = 'Sure! My verdict:\n```json\n{"verdict": true, "why": "leak", "confidence": 0.9}\n```'
        return httpx.Response(200, json={"choices": [{"message": {"content": txt}}]})

    v = _llm(h).judge("s", "u")
    assert v["verdict"] is True and v["confidence"] == 0.9 and v["why"] == "leak"


def test_judge_unparseable_defaults_to_not_a_bug():
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "no json at all"}}]})

    v = _llm(h).judge("s", "u")
    assert v["verdict"] is False                            # conservative: never confirm on garbage


def test_gives_up_with_clear_error():
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "down"})

    try:
        _llm(h).complete("s", "u")
        raised = False
    except LLMError as e:
        raised = True
        assert "HTTP 503" in str(e)                         # human-readable, names the model + reason
    assert raised                                           # surfaces the failure, doesn't hang/loop


def test_judge_degrades_on_outage():
    """A dead backend must not crash the Oracle — the judge returns 'not a bug'."""
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    v = _llm(h).judge("s", "u")
    assert v["verdict"] is False and v["confidence"] == 0.0
