"""BOLA / IDOR hypothesis generation (M1) — mechanical, no LLM required.

Given the ids each role OWNS (harvested by the session manager), build one test
per (object, owner, attacker, id): a non-owner tries to read the owner's object.
The differential Oracle decides if the attempt actually succeeded.

FP controls baked in here:
  - `admin` is never an attacker (it may legitimately access everything).
  - `guest` is never an attacker (handled separately as the public-resource baseline).
  - an id owned by BOTH owner and attacker is skipped (ambiguous ownership).
"""
from __future__ import annotations

from ..config import Config
from .models import Hypothesis

# roles that must not be treated as attackers for BOLA
NON_ATTACKER_ROLES = {"guest", "admin"}


def build_bola_hypotheses(
    cfg: Config,
    owned: dict[str, dict[str, set[str]]],
) -> list[Hypothesis]:
    hyps: list[Hypothesis] = []
    role_names = [r.name for r in cfg.accounts.roles]

    for spec in cfg.objects:
        per_role = owned.get(spec.name, {})
        for owner, owner_ids in per_role.items():
            for attacker in role_names:
                if attacker == owner or attacker in NON_ATTACKER_ROLES:
                    continue
                attacker_ids = per_role.get(attacker, set())
                for oid in sorted(owner_ids):
                    if oid in attacker_ids:                 # ambiguous ownership -> skip
                        continue
                    url = spec.item_url.format(id=oid)
                    hyps.append(Hypothesis(
                        invariant_id=f"BOLA:{spec.name}",
                        bug_class="bola",
                        description=f"{attacker} accesses {owner}'s {spec.name} #{oid}",
                        request_sequence=[{"method": "GET", "url": url, "as": attacker}],
                        expected_safe=(
                            f"{attacker} (not the owner) should receive 401/403/404 — "
                            f"never {owner}'s {spec.name} data"
                        ),
                        as_roles=[owner, attacker, "guest"],
                        meta={
                            "item_url": url,
                            "owner_role": owner,
                            "attacker_role": attacker,
                            "object": spec.name,
                            "id": oid,
                        },
                    ))
    return hyps
