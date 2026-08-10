"""Shared data models passed between phases."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Endpoint:
    method: str
    path: str
    params: dict[str, Any] = field(default_factory=dict)
    seen_as_roles: list[str] = field(default_factory=list)


@dataclass
class Invariant:
    """A business rule the app assumes but may not enforce. The thing to break."""
    id: str                       # "INV-1"
    rule: str                     # "an order is readable only by its owner"
    bug_class: str                # "bola"
    checkable: str | None = None  # optional machine-checkable assertion


@dataclass
class Hypothesis:
    """A concrete attempt to violate one invariant."""
    invariant_id: str
    bug_class: str
    description: str              # "userA GET /order/{userB_order_id}"
    request_sequence: list[dict]  # ordered requests to replay
    expected_safe: str           # what SHOULD happen if the app is correct
    as_roles: list[str] = field(default_factory=list)  # identities to fire from
    meta: dict[str, Any] = field(default_factory=dict)  # class-specific extras (owner/attacker/url...)


@dataclass
class TestResult:
    hypothesis: Hypothesis
    responses: dict[str, Any]     # per-role response(s)
    state_before: dict[str, Any] = field(default_factory=dict)
    state_after: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A CONFIRMED, Oracle-proven business-logic bug."""
    title: str
    invariant_id: str
    bug_class: str
    severity: Severity
    expected: str
    observed: str
    proof: dict[str, Any]         # oracle evidence + reproducible PoC
    remediation: str = ""
    impact: str = ""              # business impact (esp. for chained findings)
    chained_from: list[str] = field(default_factory=list)
