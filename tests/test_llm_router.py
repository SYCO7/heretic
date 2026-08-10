"""Per-phase model routing: single / profile / fallback / empty modes. Offline —
uses stub backends, never the network.
"""
from __future__ import annotations

from heretic.llm.router import DEFAULT_PROFILE, LLMRouter


class _Stub:
    def __init__(self, name): self.name = name


def test_single_routes_every_role_to_one_model():
    llm = _Stub("scripted")
    r = LLMRouter.single(llm)
    assert r.any()
    for role in ("intent", "hypothesis", "judge", "refute", "chain"):
        assert r.for_role(role) is llm


def test_profile_routes_each_role_to_its_model():
    built = {}

    def factory(model_id):
        built.setdefault(model_id, _Stub(model_id))
        return built[model_id]

    r = LLMRouter.from_profile(DEFAULT_PROFILE, factory=factory)
    assert r.for_role("intent").name == "nemotron-super"
    assert r.for_role("hypothesis").name == "nemotron-nano"
    assert r.for_role("refute").name == "openrouter-r1"
    # same model id is instantiated once and shared (judge reuses intent's Super)
    assert r.for_role("judge") is r.for_role("intent")


def test_profile_falls_back_when_a_backend_is_unavailable():
    def factory(model_id):
        if model_id == "openrouter-r1":
            raise OSError("no OPENROUTER_API_KEY")   # refuter model missing
        return _Stub(model_id)

    r = LLMRouter.from_profile(DEFAULT_PROFILE, factory=factory)
    assert r.any()
    # refute's own backend failed -> falls back to a working one (not None)
    assert r.for_role("refute") is not None
    assert r.for_role("refute").name != "openrouter-r1"


def test_empty_router_when_nothing_available():
    def factory(model_id):
        raise OSError("no keys at all")

    r = LLMRouter.from_profile(DEFAULT_PROFILE, factory=factory)
    assert not r.any()
    assert r.for_role("intent") is None       # engine will run mechanical checks only


def test_describe():
    assert "single:" in LLMRouter.single(_Stub("x")).describe()
    assert LLMRouter.empty().describe() == "none"
