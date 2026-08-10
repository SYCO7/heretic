"""Phase 5 — the Oracle. THE MOAT. See docs/03-ORACLE.md.

A business-logic bug throws no error and returns 200 OK, so the Oracle must
PROVE an invariant was violated. Two layers:

  RAW ORACLES (produce a candidate):
    - Oracle 2 (cross-session differential)  -> BOLA          [deterministic]
    - Oracle 1 (invariant assertion)          -> price/mass    [deterministic]
    - Oracle 3 (state-delta judge)            -> workflow      [LLM]

  HARDENING (M3 — promote or drop the candidate):
    - re-run confirmation for read-only tests (reproducibility)
    - perspective-diverse refuter panel for LLM-judged findings (refute-or-promote)
    - a confidence score on every proof bundle

Design choice: LLM refuters may NOT overturn a DETERMINISTIC proof — a fuzzy
model must not veto arithmetic/access-diff evidence. Only LLM-judged findings
face the adversarial panel. The whole tool's value is this module's
false-positive rate. Target < 10%.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any

from .models import Finding, Hypothesis, Severity, TestResult

# thresholds
_SIM_MATCH = 0.85
_MIN_BODY_LEN = 3
N_REFUTERS = 3                 # perspective-diverse skeptics for LLM findings

_SEVERITY = {
    "bola": Severity.HIGH, "price_tamper": Severity.HIGH,
    "mass_assignment": Severity.CRITICAL, "workflow_bypass": Severity.HIGH,
    "coupon_abuse": Severity.MEDIUM, "race_condition": Severity.HIGH,
    "excessive_data_exposure": Severity.HIGH, "bfla": Severity.HIGH,
}
_REMEDIATION = {
    "price_tamper": "Compute price/total server-side from the catalog; never trust client-supplied amounts.",
    "mass_assignment": "Whitelist writable fields; reject privileged fields (role, is_admin, balance) on binding.",
    "workflow_bypass": "Enforce workflow state transitions server-side; verify prerequisites before each step.",
    "coupon_abuse": "Enforce single-use/limits atomically server-side.",
    "race_condition": "Make check-then-act atomic (DB constraints, locks, idempotency keys) to prevent double-spend.",
    "excessive_data_exposure": "Scope list queries to the authenticated user; filter records by owner "
                               "server-side and never return other users' rows.",
    "bfla": "Enforce role checks server-side on every administrative endpoint; deny by default and "
            "verify the caller's privilege, not just that they are authenticated.",
}

_JUDGE_SYS = (
    "You are a strict application-security oracle. Given a business INVARIANT and the "
    "system STATE before and after an action, decide if the invariant was VIOLATED. "
    'Output STRICT JSON: {"verdict": true|false, "why": "...", "confidence": 0..1}. '
    "verdict=true ONLY if the after-state clearly breaks the invariant."
)
_REFUTE_SYS = (
    "You are a skeptical reviewer trying to REFUTE a claimed business-logic violation. "
    "Default to NOT a bug. Decide if this is a GENUINE violation. "
    'Output STRICT JSON: {"verdict": true|false, "why": "...", "confidence": 0..1}. '
    "verdict=true means genuine violation; be conservative. "
)
# each refuter gets a distinct lens so the panel catches different failure modes
_REFUTE_LENSES = [
    "Lens: is the after-state simply the app's intended, authorized behavior?",
    "Lens: could the actor be legitimately permitted this action by role or ownership?",
    "Lens: is this a flaky or coincidental result that would not reproduce deterministically?",
]


@dataclass
class Verdict:
    confirmed: bool
    reason: str = ""
    finding: Finding | None = None


class Oracle:
    def __init__(self, judge_llm: Any = None, refute_llm: Any = None) -> None:
        self.judge_llm = judge_llm                     # Oracle 3 state-delta judge
        self.refute_llm = refute_llm if refute_llm is not None else judge_llm  # refuter panel

    def verify(
        self,
        hyp: Hypothesis,
        result: TestResult,
        model: Any = None,
        reexec: Callable[[Hypothesis], TestResult] | None = None,
    ) -> Verdict:
        cand = self._raw_verify(hyp, result)
        if not cand.confirmed:
            return cand
        return self._harden(hyp, result, cand, reexec)

    # ---- raw oracles ---------------------------------------------------

    def _raw_verify(self, hyp: Hypothesis, result: TestResult) -> Verdict:
        if hyp.bug_class == "bola":
            return self._verify_bola(hyp, result)
        if hyp.bug_class == "race_condition":
            return self._verify_race(hyp, result)
        if hyp.bug_class == "excessive_data_exposure":
            return self._verify_exposure(hyp, result)
        if hyp.bug_class == "bfla":
            return self._verify_bfla(hyp, result)
        oracle = (hyp.meta or {}).get("oracle")
        if oracle == "invariant_assertion":
            return self._verify_assertion(hyp, result)
        if oracle == "state_delta_judge":
            return self._verify_state_delta(hyp, result)
        return Verdict(False, reason=f"no oracle for class '{hyp.bug_class}' / '{oracle}'")

    # ---- M3 hardening: promote-or-drop --------------------------------

    def _harden(self, hyp, result, cand: Verdict, reexec) -> Verdict:
        finding = cand.finding
        assert finding is not None

        # 1. re-run confirmation for read-only tests (BOLA) — reproducibility
        if reexec is not None and _readonly(hyp):
            if not self._raw_verify(hyp, reexec(hyp)).confirmed:
                return Verdict(False, "failed re-run — not reproducible (flaky)")
            finding.proof["reproduced"] = True

        # 2. adversarial refuter panel — LLM-judged findings only
        if self.refute_llm is not None and finding.proof.get("oracle") == "state_delta_judge":
            votes = self._refute_panel(hyp, result)          # True = genuine
            genuine, n = sum(votes), len(votes)
            finding.proof["refuter_votes"] = votes
            finding.proof["refuter_genuine"] = genuine
            if genuine <= n // 2:
                return Verdict(False, f"refuted by adversarial panel ({n - genuine}/{n} skeptics)")
            finding.proof["confidence"] = round(genuine / n, 2) if n else 1.0
        else:
            finding.proof.setdefault("confidence", 1.0)      # deterministic proof

        return Verdict(True, cand.reason, finding)

    def _refute_panel(self, hyp: Hypothesis, result: TestResult) -> list[bool]:
        payload = _state_payload(hyp, result)
        votes: list[bool] = []
        for lens in _REFUTE_LENSES[:N_REFUTERS]:
            v = self.refute_llm.judge(_REFUTE_SYS + lens, payload, tag="refute")
            votes.append(bool(v.get("verdict")))
        return votes

    # ---- Oracle 2: cross-session differential (BOLA) ------------------

    def _verify_bola(self, hyp: Hypothesis, result: TestResult) -> Verdict:
        r = result.responses
        owner, attacker = r["owner"], r["attacker"]
        rerun = r.get("attacker_rerun")
        guest = r.get("guest")

        if owner["status"] != 200 or not _nontrivial(owner):
            return Verdict(False, "owner has no resource at this id")
        if attacker["status"] != 200:
            return Verdict(False, f"attacker denied ({attacker['status']}) — access control holds")
        sim = _similarity(attacker, owner)
        if sim < _SIM_MATCH:
            return Verdict(False, f"attacker 200 but different data (sim={sim:.2f})")
        if rerun is not None and (rerun["status"] != 200 or _similarity(rerun, owner) < _SIM_MATCH):
            return Verdict(False, "did not reproduce on re-run (flaky)")
        if guest is not None and guest["status"] == 200 and _similarity(guest, owner) >= _SIM_MATCH:
            return Verdict(False, "public resource (guest sees identical data) — not BOLA")

        m = hyp.meta
        return Verdict(True, "cross-session differential confirms BOLA", finding=_finding(
            hyp,
            title=f"BOLA — {m['attacker_role']} reads {m['owner_role']}'s {m['object']} #{m['id']}",
            observed=f"{m['attacker_role']} received {m['owner_role']}'s {m['object']} "
                     f"(HTTP 200, body similarity {sim:.2f})",
            proof={"oracle": "cross_session_diff", "similarity": round(sim, 3),
                   "owner_status": owner["status"], "attacker_status": attacker["status"],
                   "guest_status": (guest or {}).get("status"),
                   "poc": hyp.request_sequence, "reproduced": True},
        ))

    # ---- race / TOCTOU: parallel success count ------------------------

    def _verify_race(self, hyp: Hypothesis, result: TestResult) -> Verdict:
        r = result.responses
        succ, exp, n = r["success_count"], r["expect_max"], r["parallel"]
        if succ <= exp:
            return Verdict(False, f"{succ}/{n} succeeded ≤ {exp} — atomic enforcement holds")
        return Verdict(True, "parallel fire exceeded the allowed successes", finding=_finding(
            hyp, title=f"race_condition — {hyp.description}",
            observed=f"{succ} of {n} concurrent requests succeeded (expected ≤{exp}) — missing atomic enforcement",
            proof={"oracle": "parallel_success_count", "success_count": succ, "parallel": n,
                   "expect_max": exp, "poc": hyp.request_sequence}))

    # ---- broken function-level authorization (admin function, wrong role) ---

    def _verify_bfla(self, hyp: Hypothesis, result: TestResult) -> Verdict:
        from .bfla import has_strong_marker

        r = result.responses
        path = hyp.meta["path"]
        guest, ua, admin = r.get("guest"), r.get("userA"), r.get("admin")

        def reaches(snap):
            if snap is None or snap["status"] not in (200, 201) or not _nontrivial(snap):
                return False
            # a SPA serves index.html for unknown routes — that's the frontend, not an admin FUNCTION
            return not (snap.get("json") is None and _looks_html(snap.get("body", "")))

        # pattern 1: an admin function open to UNAUTHENTICATED callers — critical
        if reaches(guest):
            return Verdict(True, "admin function reachable without authentication", finding=_finding(
                hyp, title=f"bfla — admin function {path} is exposed to unauthenticated users",
                observed=f"guest (no auth) received HTTP {guest['status']} from the admin endpoint {path}",
                proof={"oracle": "function_level_access", "path": path, "guest_status": guest["status"],
                       "reached_by": "guest", "poc": hyp.request_sequence}))

        # pattern 2: a regular user reaches an admin function guest is denied — needs corroboration
        if reaches(ua):
            admin_ok = reaches(admin)
            if admin_ok or has_strong_marker(path):
                by = "matches an admin function admin can reach" if admin_ok else "path is an admin function"
                return Verdict(True, "regular user reaches an admin function", finding=_finding(
                    hyp, title=f"bfla — regular user reaches admin function {path}",
                    observed=f"userA (non-admin) received HTTP {ua['status']} from {path} "
                             f"while guest is denied ({(guest or {}).get('status')}); {by}",
                    proof={"oracle": "function_level_access", "path": path, "userA_status": ua["status"],
                           "guest_status": (guest or {}).get("status"),
                           "admin_status": (admin or {}).get("status"), "poc": hyp.request_sequence}))
            return Verdict(False, "reachable by a user but no admin role / strong marker to corroborate")
        return Verdict(False, "regular user cannot reach it — access control holds")

    # ---- excessive data exposure: co-mingled owners in a private list ---

    def _verify_exposure(self, hyp: Hypothesis, result: TestResult) -> Verdict:
        from .exposure import owner_of, sensitive_fields

        r = result.responses
        a = r.get("userA")
        if not a or a["status"] != 200:
            return Verdict(False, "list not accessible to userA")
        obj, url, lp = hyp.meta["object"], hyp.meta["list_url"], hyp.meta.get("list_path")
        guest = r.get("guest")

        # --- public endpoint: leak if it exposes secrets/PII WITHOUT auth ---
        if guest is not None and guest["status"] == 200 and _nontrivial(guest):
            grecords = _records(guest.get("json"), lp)
            secret: set[str] = set()
            pii: set[str] = set()
            for rec in grecords:
                s, p = sensitive_fields(rec)
                secret |= s
                pii |= p
            if secret or (pii and len(grecords) >= 2):       # secrets leak on sight; PII needs a list
                fields = sorted(secret | pii)
                return Verdict(True, "public endpoint exposes sensitive data", finding=_finding(
                    hyp, title=f"excessive_data_exposure — {obj} exposes {', '.join(fields)} to unauthenticated users",
                    observed=f"guest (no auth) read {len(grecords)} {obj} record(s) exposing "
                             f"{', '.join(fields)} at {url}",
                    proof={"oracle": "public_sensitive_exposure", "fields": fields,
                           "record_count": len(grecords), "guest_status": 200, "poc": hyp.request_sequence}))
            return Verdict(False, "public endpoint with no sensitive fields — not a leak")

        # --- private endpoint: leak if one user's list carries many owners ---
        records = _records(a.get("json"), lp)
        if len(records) < 2:
            return Verdict(False, "fewer than 2 records — nothing to co-mingle")
        owners = {o for o in (owner_of(rec) for rec in records) if o is not None}
        if len(owners) < 2:
            return Verdict(False, "no owner field or a single owner — not co-mingled")
        return Verdict(True, "one user's list carries multiple owners", finding=_finding(
            hyp, title=f"excessive_data_exposure — {obj} list leaks all users' records",
            observed=f"userA received {len(records)} {obj} record(s) owned by {len(owners)} distinct "
                     f"users at {url} (guest denied — private data)",
            proof={"oracle": "owner_comingling", "list_url": url, "distinct_owners": len(owners),
                   "record_count": len(records), "guest_status": (guest or {}).get("status"),
                   "poc": hyp.request_sequence}))

    # ---- Oracle 1: invariant assertion (price / mass-assignment) ------

    def _verify_assertion(self, hyp: Hypothesis, result: TestResult) -> Verdict:
        a = hyp.meta.get("assertion") or {}
        field = a.get("field")
        data = self._assertion_data(hyp, result)
        if data is None or field is None:
            return Verdict(False, "no data/field to assert on")
        observed = _dotted(data, field)

        if "expected_value" in a:                         # price-tamper style
            expected, tampered = a.get("expected_value"), a.get("tampered_value")
            if observed == tampered and observed != expected:
                return Verdict(True, "server used client-supplied value", finding=_finding(
                    hyp, title=f"{hyp.bug_class} — {hyp.description}",
                    observed=f"{field}={observed!r} (client value) instead of server value {expected!r}",
                    proof={"oracle": "invariant_assertion", "field": field, "observed": observed,
                           "expected_server_value": expected, "poc": hyp.request_sequence}))
            return Verdict(False, f"{field}={observed!r} matches server value — invariant holds")

        if "equals" in a:                                 # reflected privileged field
            if observed == a["equals"]:
                return Verdict(True, "privileged field was accepted", finding=_finding(
                    hyp, title=f"{hyp.bug_class} — {hyp.description}",
                    observed=f"{field}={observed!r} took effect (should be rejected)",
                    proof={"oracle": "invariant_assertion", "field": field, "observed": observed,
                           "poc": hyp.request_sequence}))
            return Verdict(False, f"{field}={observed!r} — privileged field not accepted")

        return Verdict(False, "unrecognized assertion shape")

    def _assertion_data(self, hyp: Hypothesis, result: TestResult) -> Any:
        if hyp.meta.get("state_probe"):
            return (result.state_after or {}).get("json")
        return (result.responses.get("final") or {}).get("json")

    # ---- Oracle 3: state-delta judge (workflow bypass) ----------------

    def _verify_state_delta(self, hyp: Hypothesis, result: TestResult) -> Verdict:
        if self.judge_llm is None:
            return Verdict(False, "state-delta oracle needs an LLM backend")
        after = (result.state_after or {}).get("json")
        before = (result.state_before or {}).get("json")
        if after is None:
            return Verdict(False, "no post-action state to judge")
        rule = hyp.meta.get("invariant_rule", "")
        v = self.judge_llm.judge(_JUDGE_SYS, _state_payload(hyp, result), tag="judge")
        if not v.get("verdict"):
            return Verdict(False, f"judge: invariant holds ({v.get('why', '')})")
        return Verdict(True, "state-delta judge flags violation", finding=_finding(
            hyp, title=f"{hyp.bug_class} — {hyp.description}",
            observed=f"invariant '{rule}' broken; state after action: {after}",
            proof={"oracle": "state_delta_judge", "invariant": rule, "before": before,
                   "after": after, "judge": v, "poc": hyp.request_sequence}))


# ---- helpers -----------------------------------------------------------

def _finding(hyp: Hypothesis, *, title: str, observed: str, proof: dict) -> Finding:
    return Finding(
        title=title, invariant_id=hyp.invariant_id, bug_class=hyp.bug_class,
        severity=_SEVERITY.get(hyp.bug_class, Severity.MEDIUM),
        expected=hyp.expected_safe, observed=observed, proof=proof,
        remediation=_REMEDIATION.get(hyp.bug_class, ""),
    )


def _state_payload(hyp: Hypothesis, result: TestResult) -> str:
    return json.dumps({
        "invariant": hyp.meta.get("invariant_rule", ""),
        "before": (result.state_before or {}).get("json"),
        "after": (result.state_after or {}).get("json"),
        "action": hyp.description,
    }, default=str)


def _readonly(hyp: Hypothesis) -> bool:
    seq = hyp.request_sequence or []
    return bool(seq) and all(s.get("method", "GET").upper() == "GET" for s in seq)


def _dotted(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _records(payload: Any, list_path: str | None) -> list[dict]:
    """Extract the list of record dicts from a list response (unwrapping data/list_path)."""
    data = payload
    if isinstance(data, dict):
        if list_path and isinstance(data.get(list_path), list):
            data = data[list_path]
        else:
            arrays = [v for v in data.values() if isinstance(v, list)]
            data = arrays[0] if arrays else []
    return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []


def _looks_html(body: str) -> bool:
    """A SPA shell / HTML page, not a JSON API response."""
    t = (body or "")[:400].lstrip().lower()
    return t.startswith(("<!doctype html", "<html")) or "<head" in t or "<body" in t


def _nontrivial(snap: dict[str, Any]) -> bool:
    body = (snap.get("body") or "").strip()
    return len(body) > _MIN_BODY_LEN and body not in ("{}", "[]", "null")


def _similarity(a: dict[str, Any], b: dict[str, Any]) -> float:
    if a.get("json") is not None and a.get("json") == b.get("json"):
        return 1.0
    ta, tb = (a.get("body") or "")[:5000], (b.get("body") or "")[:5000]
    if not ta or not tb:
        return 0.0
    return SequenceMatcher(None, ta, tb).ratio()
