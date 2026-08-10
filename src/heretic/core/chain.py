"""Phase 6 — chain confirmed primitives into higher-impact attacks.

A single confirmed bug is a primitive. The real value is the chain: IDOR (read
others' data) + mass-assignment (set is_admin) -> full account takeover.

Design: chains are built ONLY from already-Oracle-confirmed primitives, so a
chain inherits their confirmation — it introduces no new false positives and
needs no extra requests. Rules are deterministic; an LLM (if present) only writes
the business-impact narrative.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .models import Finding, Severity


def _by_class(findings: list[Finding], cls: str) -> list[Finding]:
    return [f for f in findings if f.bug_class == cls]


@dataclass
class ChainRule:
    name: str
    title: str
    severity: Severity
    impact: str
    remediation: str
    match: Callable[[list[Finding]], list[Finding] | None]


def _takeover(F: list[Finding]) -> list[Finding] | None:
    bola, mass = _by_class(F, "bola"), _by_class(F, "mass_assignment")
    return [bola[0], mass[0]] if bola and mass else None


def _fraud(F: list[Finding]) -> list[Finding] | None:
    price, wf = _by_class(F, "price_tamper"), _by_class(F, "workflow_bypass")
    return [price[0], wf[0]] if price and wf else None


def _bulk_exfil(F: list[Finding]) -> list[Finding] | None:
    bola = _by_class(F, "bola")
    return bola if len(bola) >= 2 else None


RULES: list[ChainRule] = [
    ChainRule(
        "account_takeover", "Account takeover", Severity.CRITICAL,
        "Read a victim's object via broken object-level authorization, then escalate "
        "privileges via mass assignment — full account/tenant takeover.",
        "Fix both object-level authZ and field whitelisting; audit for privilege escalation.",
        _takeover),
    ChainRule(
        "financial_fraud", "Financial fraud", Severity.CRITICAL,
        "Under-pay via price tampering and/or obtain goods by bypassing the payment "
        "step — direct financial loss.",
        "Recompute price server-side and enforce payment before fulfilment.",
        _fraud),
    ChainRule(
        "bulk_data_exfiltration", "Bulk data exfiltration", Severity.HIGH,
        "Multiple broken object-level authorizations allow enumerating and exfiltrating "
        "other users' records at scale.",
        "Enforce object-level authorization uniformly and add per-object access auditing.",
        _bulk_exfil),
]


class Chainer:
    def __init__(self, llm: Any = None) -> None:
        self.llm = llm

    def chain(self, confirmed: list[Finding], model: Any = None) -> list[Finding]:
        """Return higher-impact chain findings composed from confirmed primitives."""
        primitives = [f for f in confirmed if f.bug_class != "chain"]
        chains: list[Finding] = []
        for rule in RULES:
            parts = rule.match(primitives)
            if not parts:
                continue
            chains.append(Finding(
                title=rule.title,
                invariant_id=f"CHAIN:{rule.name}",
                bug_class="chain",
                severity=rule.severity,
                expected="individual findings should not compose into higher-impact attacks",
                observed=self._narrative(rule, parts),
                proof={"oracle": "chain_composition", "confidence": 1.0,
                       "chained_from": [p.title for p in parts]},
                remediation=rule.remediation,
                impact=rule.impact,
                chained_from=[p.invariant_id for p in parts],
            ))
        return chains

    def _narrative(self, rule: ChainRule, parts: list[Finding]) -> str:
        return f"{rule.impact} Composed from: " + "; ".join(p.title for p in parts) + "."
