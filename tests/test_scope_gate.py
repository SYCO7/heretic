"""The scope gate is a security boundary — test it first, test it hard.
These are the tests that must pass before any network capability is added."""
from __future__ import annotations

import pytest

from heretic.config import Config, Scope


def _cfg(allow, exclude=None):
    return Config(
        url="https://crapi.local", model="ollama:nemotron-nano",
        engagement="test", authorized_by="me@test", signed=True,
        scope=Scope(allow=allow, exclude=exclude or []),
        accounts_path=__import__("pathlib").Path("accounts.yaml"),
    )


def test_in_scope_allowed():
    _cfg(["*.crapi.local"]).assert_in_scope("https://api.crapi.local/x")  # no raise


def test_out_of_scope_blocked():
    with pytest.raises(SystemExit):
        _cfg(["*.crapi.local"]).assert_in_scope("https://evil.example.com")


def test_exclude_wins_over_allow():
    with pytest.raises(SystemExit):
        _cfg(["*.crapi.local"], ["*/admin/delete*"]).assert_in_scope(
            "https://crapi.local/admin/delete/1")


def test_destructive_blocked_by_default():
    assert _cfg(["*.crapi.local"]).is_destructive_allowed("place_order") is False
