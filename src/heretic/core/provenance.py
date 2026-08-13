"""Ownership Provenance Differential (OPD) — HERETIC's own algorithm.

A novel, deterministic evidence metric for access-control violations, original to
this project. Existing BOLA/exposure heuristics look for a response FIELD named
`owner`/`user`. OPD needs no such label: it tracks the concrete ownership TOKENS
that provably belong to each identity — its login identifiers plus the object ids
it owns — and measures the *provenance purity* of any response:

    purity(response, viewer) = own_tokens / (own_tokens + foreign_tokens)

A response served to `viewer` that carries tokens owned by another identity has
purity < 1 → foreign data leaked. This unifies two bug classes under one number:

  - BOLA           — an item response whose tokens belong to a different owner.
  - data exposure  — a list response co-mingling several owners' tokens.

and catches leaks where ownership is unlabeled (no `owner` field), which the
field-based oracles cannot see. OPD is deterministic and additive: it enriches an
already-Oracle-confirmed finding with quantified provenance evidence — it never
manufactures a finding, so it cannot raise the false-positive rate.

Design notes:
  - Tokens shorter than 3 chars or on a small noise list are dropped, so common
    values ("1", "true", "admin") never masquerade as ownership evidence.
  - Matching is whole-value equality against the strings walked out of the JSON
    (not blind substring search), keeping precision high.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

# values too common/ambiguous to be ownership evidence
_NOISE = {"true", "false", "null", "none", "guest", "admin", "user", "users",
          "name", "email", "password", "id", "role", "customer"}
_MIN_TOKEN = 3


@dataclass
class OwnershipMap:
    """token value -> the role that provably owns it."""
    token_role: dict[str, str] = field(default_factory=dict)

    @classmethod
    def build(cls, identities: dict[str, set[str]],
              owned: dict[str, dict[str, set[str]]]) -> OwnershipMap:
        """From per-role login identifiers + per-object owned ids, build the map.
        First owner of a token wins (stable), so a value shared by two roles — i.e.
        not actually owner-distinguishing — is not treated as strong evidence."""
        m: dict[str, str] = {}
        shared: set[str] = set()

        def add(role: str, raw: Any) -> None:
            tok = str(raw).strip()
            if len(tok) < _MIN_TOKEN or tok.lower() in _NOISE:
                return
            if tok in m and m[tok] != role:
                shared.add(tok)                     # owned by >1 role → drop as ambiguous
            else:
                m.setdefault(tok, role)

        for role, toks in (identities or {}).items():
            for t in toks:
                add(role, t)
        for _obj, per_role in (owned or {}).items():
            for role, ids in per_role.items():
                for t in ids:
                    add(role, t)
        for t in shared:
            m.pop(t, None)
        return cls(m)

    def __bool__(self) -> bool:
        return bool(self.token_role)


def _walk_values(obj: Any, out: list[str]) -> list[str]:
    """Every scalar value in a JSON structure, as strings (bounded)."""
    if isinstance(obj, bool):
        return out
    if isinstance(obj, (str, int, float)):
        out.append(str(obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            _walk_values(v, out)
    elif isinstance(obj, list):
        for v in obj[:1000]:
            _walk_values(v, out)
    return out


def signature(payload: Any, omap: OwnershipMap) -> Counter:
    """Counter{owning_role: number of that role's tokens present in `payload`}."""
    sig: Counter = Counter()
    if not omap:
        return sig
    values = set(_walk_values(payload, []))
    for tok, role in omap.token_role.items():
        if tok in values:                            # whole-value match, not substring
            sig[role] += 1
    return sig


def purity(sig: Counter, viewer: str) -> tuple[int, int, float]:
    """(own_tokens, foreign_tokens, purity_score) for `viewer`."""
    own = sig.get(viewer, 0)
    foreign = sum(n for r, n in sig.items() if r != viewer)
    total = own + foreign
    return own, foreign, (own / total if total else 1.0)


def foreign_owners(sig: Counter, viewer: str) -> list[str]:
    return sorted(r for r, n in sig.items() if r != viewer and n > 0)


def opd_proof(payload: Any, omap: OwnershipMap | None, viewer: str) -> dict | None:
    """Provenance evidence block for a finding, or None if OPD sees nothing.
    Attach to a confirmed finding's proof; never used to confirm on its own."""
    if not omap:
        return None
    sig = signature(payload, omap)
    own, foreign, p = purity(sig, viewer)
    if own == 0 and foreign == 0:
        return None
    return {
        "own_tokens": own,
        "foreign_tokens": foreign,
        "purity": round(p, 3),
        "leaked_owners": foreign_owners(sig, viewer),
    }
