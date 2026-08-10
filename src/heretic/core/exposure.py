"""Excessive Data Exposure oracle (M11) — mechanical, read-only, no LLM.

BOLA is about reading ONE other user's object by id. Excessive data exposure is
worse and different: a "list" endpoint hands EVERY authenticated user the whole
pool of everyone's records (Juice Shop's `/api/BasketItems`, `/api/Users`, …).

Detection is deterministic and FP-guarded: a finding is confirmed only when a
single authenticated caller's list carries an owner field taking >= 2 distinct
values (co-mingled owners) AND the endpoint is private (guest is denied) — so a
public catalog with no owner field, or a genuinely per-user list, is never flagged.
"""
from __future__ import annotations

from ..config import Config
from .models import Hypothesis

# record keys that identify who OWNS the record
OWNER_KEYS = {
    "userid", "user_id", "owner", "ownerid", "owner_id", "user", "email", "useremail",
    "user_email", "username", "createdby", "author", "basketid", "bid", "account", "accountid",
}


def build_exposure_hypotheses(cfg: Config) -> list[Hypothesis]:
    """One check per distinct list endpoint the engagement knows about."""
    hyps: list[Hypothesis] = []
    seen: set[str] = set()
    for spec in cfg.objects:
        if spec.list_url in seen:
            continue
        seen.add(spec.list_url)
        hyps.append(Hypothesis(
            invariant_id=f"EDE:{spec.name}",
            bug_class="excessive_data_exposure",
            description=f"list {spec.list_url} returns other users' {spec.name} records",
            request_sequence=[{"method": "GET", "url": spec.list_url, "as": "userA"}],
            expected_safe=f"{spec.list_url} returns only the caller's own {spec.name} records",
            as_roles=["userA", "userB", "guest"],
            meta={"list_url": spec.list_url, "object": spec.name, "list_path": spec.list_path},
        ))
    return hyps


def owner_of(record: dict) -> str | None:
    """The record's owner value, from the first owner-identifying key present."""
    if not isinstance(record, dict):
        return None
    for key, val in record.items():
        if key.lower() in OWNER_KEYS and val is not None:
            return str(val)
    return None


def _norm(s: str) -> str:
    return s.lower().replace("_", "").replace("-", "")


# always a leak if exposed without auth, even in one record
_SECRET = {_norm(x) for x in (
    "password", "passwordhash", "pwd", "secret", "token", "auth_token", "apikey", "ssn",
    "creditcard", "cardnumber", "cvv", "cvc", "passport", "nationalid", "privatekey", "pin")}
# personally-identifiable — a leak when a PUBLIC endpoint lists many people's
_PII = {_norm(x) for x in ("email", "mail", "phone", "phonenumber", "mobile", "address",
                           "dob", "dateofbirth", "birthdate")}


def sensitive_fields(record: dict) -> tuple[set[str], set[str]]:
    """(secret fields, PII fields) present with a value in a record."""
    secret: set[str] = set()
    pii: set[str] = set()
    if not isinstance(record, dict):
        return secret, pii
    for key, val in record.items():
        if val in (None, "", [], {}):
            continue
        n = _norm(key)
        if n in _SECRET:
            secret.add(key)
        elif n in _PII:
            pii.add(key)
    return secret, pii
