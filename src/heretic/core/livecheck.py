"""Live validation (M6) — run HERETIC against a REAL target and score it against
ground truth. This is the machine that turns "drop an API key" into a real
precision/recall/FP number.

A *target profile* is a directory with:
    roe.yaml            scope + objects/races + classes
    accounts.yaml       test identities
    ground_truth.yaml   the bugs that SHOULD be found (list of {bug_class, match})

`heretic livecheck --profile targets/crapi -u https://crapi.local --model auto`
runs the real scan, then scores confirmed findings vs ground truth. Offline-
testable: inject a transport + llm.
"""
from __future__ import annotations

from pathlib import Path

import httpx
import yaml
from rich.console import Console

from ..config import load_config
from .benchmark import Metrics, score
from .orchestrator import Orchestrator


def load_ground_truth(path: Path | str) -> list[dict]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    if isinstance(data, dict):
        data = data.get("ground_truth", [])
    return list(data)


def run_profile(
    profile_dir: Path | str,
    url: str,
    model: str = "nemotron-super",
    *,
    transport: httpx.BaseTransport | None = None,
    llm=None,
    console: Console | None = None,
    chain: bool = True,
    trace=None,
) -> tuple[list, Metrics]:
    """Run a target profile and score it. Returns (findings, metrics)."""
    d = Path(profile_dir)
    cfg = load_config(roe=d / "roe.yaml", accounts=d / "accounts.yaml",
                      url=url, model=model, chain=chain)
    orch = Orchestrator(cfg, console=console or Console(), transport=transport, llm=llm, trace=trace)
    findings = orch.run()
    ground_truth = load_ground_truth(d / "ground_truth.yaml")
    return findings, score(findings, ground_truth)
