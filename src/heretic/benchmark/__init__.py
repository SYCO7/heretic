"""Built-in offline benchmark: a mock target with known bugs + ground truth,
runnable with no network and no API key (ScriptedLLM). Used by `heretic bench`
and the test suite to measure precision/recall/FP every build."""
from __future__ import annotations

from .fixtures import GROUND_TRUTH, run_builtin

__all__ = ["GROUND_TRUTH", "run_builtin"]
