"""Live-validation harness: profile runner + ground-truth scoring + doctor
preflight. Offline — a mock target stands in for a real one.
"""
from __future__ import annotations

import json
import re

import httpx
import yaml
from rich.console import Console

from heretic.core.doctor import preflight
from heretic.core.livecheck import load_ground_truth, run_profile

# ---- a tiny vulnerable mock target (BOLA on orders) -------------------

def _handler(request: httpx.Request) -> httpx.Response:
    p = request.url.path
    auth = request.headers.get("authorization", "")
    caller = auth[len("Bearer tok-"):] if auth.startswith("Bearer tok-") else "guest"
    if p == "/api/login":
        email = json.loads(request.content).get("email", "")
        return httpx.Response(200, json={"token": f"tok-{email.split('@')[0]}"})
    if p == "/api/orders":
        if caller == "guest":
            return httpx.Response(401, json={})
        owned = {"userA": [{"id": "1001"}], "userB": [{"id": "1002"}]}.get(caller, [])
        return httpx.Response(200, json={"orders": owned})
    if m := re.match(r"^/api/orders/(.+)$", p):
        if caller == "guest":
            return httpx.Response(401, json={})
        d = {"1001": {"id": "1001", "owner": "userA"},
             "1002": {"id": "1002", "owner": "userB"}}.get(m.group(1))
        return httpx.Response(200, json=d) if d else httpx.Response(404, json={})
    return httpx.Response(404, json={})


def _write_profile(tmp):
    (tmp / "roe.yaml").write_text(yaml.safe_dump({
        "engagement": "t", "authorized_by": "a@b", "signed": True, "max_rate_rps": 100000,
        "scope": {"allow": ["lc.local"]}, "mode": "dry-run", "classes": ["bola"],
        "objects": [{"name": "order", "list_url": "/api/orders",
                     "item_url": "/api/orders/{id}", "id_field": "id", "list_path": "orders"}],
    }))
    (tmp / "accounts.yaml").write_text(yaml.safe_dump({
        "login": {"url": "/api/login", "token_field": "token"},
        "roles": [{"name": "guest", "creds": None},
                  {"name": "userA", "creds": {"email": "userA@x", "password": "x"}},
                  {"name": "userB", "creds": {"email": "userB@x", "password": "x"}}],
    }))
    (tmp / "ground_truth.yaml").write_text(yaml.safe_dump({"ground_truth": [
        {"bug_class": "bola", "match": "userB reads userA's order #1001"},
        {"bug_class": "bola", "match": "userA reads userB's order #1002"},
    ]}))


def test_run_profile_scores_against_ground_truth(tmp_path):
    _write_profile(tmp_path)
    _findings, m = run_profile(tmp_path, url="http://lc.local", model="fake", chain=False,
                               transport=httpx.MockTransport(_handler), console=Console(quiet=True))
    assert (m.tp, m.fp, m.fn) == (2, 0, 0)
    assert m.precision == 1.0 and m.recall == 1.0 and m.fp_rate == 0.0


def test_run_profile_detects_a_missed_bug(tmp_path):
    _write_profile(tmp_path)
    # add a ground-truth item the mock can't satisfy -> recall drops (honest scoring)
    gt = yaml.safe_load((tmp_path / "ground_truth.yaml").read_text())
    gt["ground_truth"].append({"bug_class": "bola", "match": "order #9999"})
    (tmp_path / "ground_truth.yaml").write_text(yaml.safe_dump(gt))
    _, m = run_profile(tmp_path, url="http://lc.local", model="fake", chain=False,
                       transport=httpx.MockTransport(_handler), console=Console(quiet=True))
    assert m.fn == 1 and m.recall < 1.0


def test_load_ground_truth_accepts_dict_or_list(tmp_path):
    (tmp_path / "a.yaml").write_text("ground_truth:\n  - {bug_class: bola, match: x}\n")
    (tmp_path / "b.yaml").write_text("- {bug_class: bola, match: y}\n")
    assert load_ground_truth(tmp_path / "a.yaml") == [{"bug_class": "bola", "match": "x"}]
    assert load_ground_truth(tmp_path / "b.yaml") == [{"bug_class": "bola", "match": "y"}]


# ---- doctor preflight -------------------------------------------------

def test_preflight_key_present_and_missing():
    assert preflight("nemotron-super", env={"NVIDIA_API_KEY": "k"})[0]["ok"]
    assert not preflight("nemotron-super", env={})[0]["ok"]


def test_preflight_local_and_offline_need_no_key():
    assert preflight("ollama:nemotron-nano", env={})[0]["ok"]
    assert preflight("fake", env={})[0]["ok"]


def test_preflight_auto_lists_each_role():
    checks = preflight("auto", env={"NVIDIA_API_KEY": "k"})   # openrouter key missing
    names = [c["name"] for c in checks]
    assert any("intent" in n for n in names) and any("refute" in n for n in names)
    assert any(not c["ok"] for c in checks)                   # refute backend flagged missing


def test_preflight_probes_target():
    ok = preflight("fake", url="http://x.local", env={}, probe=lambda u: 200)
    assert any(c["name"].startswith("target") and c["ok"] for c in ok)
    down = preflight("fake", url="http://x.local", env={}, probe=lambda u: (_ for _ in ()).throw(OSError("refused")))
    assert any(c["name"].startswith("target") and not c["ok"] for c in down)
