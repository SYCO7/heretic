"""Multi-session manager — KEY infrastructure (M1).

Business-logic bugs are RELATIONAL: they exist between users (userA reads
userB's order) or across roles. A single session finds almost nothing. This
module authenticates every role from accounts.yaml, harvests the object ids each
role OWNS (so ownership is known, not guessed), and replays the SAME item
request as owner / attacker / guest — the raw signal the differential Oracle
turns into proof (see docs/03-ORACLE.md).

M1 uses httpx for API targets. Browser (Playwright) crawling for JS-heavy apps
is deferred to M2.
"""
from __future__ import annotations

import contextlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import Config, ObjectSpec
from .http import RoleClient, join
from .models import Hypothesis, TestResult


@dataclass
class SiteObservation:
    """Raw material for the LLM intent model: what endpoints returned, per role."""
    endpoints: list[dict[str, Any]] = field(default_factory=list)

    def record(self, method: str, path: str, role: str, resp: httpx.Response) -> None:
        self.endpoints.append({
            "method": method, "path": path, "role": role,
            "status": resp.status_code, "sample": resp.text[:1500],
        })


def _find_id(obj: Any, hints: tuple[str, ...]) -> Any:
    """Recursively find an int-valued field whose name contains a hint (e.g. basket `bid`)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, int) and not isinstance(v, bool) and any(h in k.lower() for h in hints):
                return v
            found = _find_id(v, hints)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for x in obj:
            found = _find_id(x, hints)
            if found is not None:
                return found
    return None


def _short_err(e: Exception) -> str:
    resp = getattr(e, "response", None)
    if resp is not None:
        return f"HTTP {resp.status_code}"
    return f"{type(e).__name__}: {e}"[:80]


def _dotted(obj: Any, path: str | None) -> Any:
    """Walk a dotted path through nested dicts. Returns None if any hop misses."""
    if path is None:
        return obj
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _list_items(payload: Any, spec: ObjectSpec) -> list[Any]:
    data = _dotted(payload, spec.list_path) if spec.list_path else payload
    if isinstance(data, dict):                          # unwrap {key: [...]} envelope
        arrays = [v for v in data.values() if isinstance(v, list)]
        if arrays:
            data = arrays[0]
    return data if isinstance(data, list) else []


def _extract_ids(payload: Any, spec: ObjectSpec) -> set[str]:
    """Pull owned object ids out of a list-endpoint response."""
    ids: set[str] = set()
    for item in _list_items(payload, spec):
        val = _dotted(item, spec.id_field) if isinstance(item, dict) else item
        if val is not None:
            ids.add(str(val))
    return ids


def _extract_owned_ids(payload: Any, spec: ObjectSpec) -> dict[str | None, set[str]]:
    """{owner_value: {ids}} using each record's owner field. `None` = no owner field, so
    the fetching role is treated as the owner. Turns a leaky list into true ownership."""
    from .exposure import owner_of
    out: dict[str | None, set[str]] = {}
    for item in _list_items(payload, spec):
        if not isinstance(item, dict):
            continue
        val = _dotted(item, spec.id_field)
        if val is None:
            continue
        out.setdefault(owner_of(item), set()).add(str(val))
    return out


class SessionManager:
    def __init__(self, cfg: Config, transport: httpx.BaseTransport | None = None) -> None:
        self.cfg = cfg
        self.transport = transport
        self.clients: dict[str, RoleClient] = {}
        self.login_errors: list[tuple[str, str]] = []
        self.login_json: dict[str, Any] = {}            # per-role parsed login response
        self.identities: dict[str, set[str]] = {}       # per-role identity values (for owner matching)

    # ---- Phase 1: authenticate every identity -------------------------

    def login_all(self) -> None:
        for role in self.cfg.accounts.roles:
            headers: dict[str, str] = {}
            if role.creds:                                 # remember identity values for owner matching
                self.identities[role.name] = {str(v) for v in role.creds.values() if v is not None}
            if role.token:                                 # pre-obtained token (OTP/MFA/SSO) — no login
                headers = self._auth_header(role.token)
            elif role.creds and self.cfg.accounts.login:
                try:
                    token, body = self._login(role.creds)
                    headers = self._auth_header(token)
                    self.login_json[role.name] = body      # keep the login JSON (for id harvest)
                except Exception as e:                     # login failed — skip, don't crash
                    self.login_errors.append((role.name, _short_err(e)))
                    continue
            self.clients[role.name] = RoleClient(self.cfg, role.name, headers, self.transport)
        # guaranteed unauthenticated baseline for the public-resource FP check
        if "guest" not in self.clients:
            self.clients["guest"] = RoleClient(self.cfg, "guest", {}, self.transport)

    def _login(self, creds: dict[str, Any]) -> tuple[str, Any]:
        """Returns (token, parsed-login-body). The body feeds login-response id harvest.
        Handles CSRF-guarded logins (pre-fetch + replay), form-encoded bodies, and
        session-cookie auth — driven entirely by the LoginSpec that detection produced.
        `tmp` keeps one httpx client so the CSRF-seed cookies persist into the login POST."""
        login = self.cfg.accounts.login
        assert login is not None
        tmp = RoleClient(self.cfg, "_login", {}, self.transport)
        headers: dict[str, str] = {}
        send: dict[str, Any] = dict(creds)
        if login.csrf is not None:                       # defeat a CSRF-guarded login
            from .login_detect import extract_csrf
            seed = tmp.request("GET", login.csrf.fetch_url)
            token = extract_csrf(seed, login.csrf.source)
            if token:
                if login.csrf.header:
                    headers[login.csrf.header] = token
                if login.csrf.field:
                    send[login.csrf.field] = token
        if login.content_type == "form":                 # application/x-www-form-urlencoded
            resp = tmp.request(login.method, login.url, data=send, headers=headers or None)
        else:
            resp = tmp.request(login.method, login.url, json=send, headers=headers or None)
        resp.raise_for_status()
        body: Any = None
        with contextlib.suppress(ValueError):
            body = resp.json()
        if login.token_field.startswith("cookie:"):
            return resp.cookies.get(login.token_field.split(":", 1)[1], ""), body
        token = _dotted(body, login.token_field)
        if token is None:
            raise ValueError(f"login token field '{login.token_field}' not in response")
        return str(token), body

    def harvest_login_ids(self, login_objects: list) -> dict[str, dict[str, set[str]]]:
        """{object_name: {role: {owned id}}} pulled from each role's login response —
        the owned id the app itself hands the user (e.g. Juice Shop's basket `bid`)."""
        owned: dict[str, dict[str, set[str]]] = {}
        for spec in login_objects:
            per_role: dict[str, set[str]] = {}
            for role_name, body in self.login_json.items():
                val = _dotted(body, spec.id_from)
                if val is not None:
                    per_role[role_name] = {str(val)}
            owned[spec.name] = per_role
        return owned

    def _auth_header(self, token: str) -> dict[str, str]:
        login = self.cfg.accounts.login
        tmpl = login.auth_header if login else "Authorization: Bearer {token}"  # token-only roles
        raw = tmpl.format(token=token)
        if ": " in raw:
            name, val = raw.split(": ", 1)
            return {name: val}
        return {"Authorization": raw}

    def roles(self) -> list[str]:
        return list(self.clients)

    def get_as(self, role: str, url: str) -> httpx.Response:
        return self.clients[role].get(url)

    def abs(self, url: str) -> str:
        return join(self.cfg.url, url)

    def role_auth(self, role: str) -> tuple[dict[str, str], str | None]:
        """(auth headers, bearer token) for a role — for the headless-browser capture."""
        client = self.clients.get(role)
        if client is None:
            return {}, None
        headers = {k: v for k, v in client.client.headers.items()
                   if k.lower() in ("authorization", "cookie") or k.lower().startswith("x-")}
        auth = headers.get("Authorization") or headers.get("authorization", "")
        token = auth.split(" ", 1)[1] if " " in auth else (auth or None)
        return headers, token

    # ---- Phase 1b: harvest owned ids per role -------------------------

    def harvest_ids(self, objects: list[ObjectSpec]) -> dict[str, dict[str, set[str]]]:
        """Returns {object_name: {role: {owned ids}}}. Only authenticated roles
        harvest — an id seen in a role's own list is OWNED by that role."""
        owned: dict[str, dict[str, set[str]]] = {}
        for spec in objects:
            per_role: dict[str, set[str]] = {}
            for role, client in self.clients.items():
                if role == "guest":
                    continue
                try:
                    resp = client.get(spec.list_url)
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                try:
                    ids = _extract_ids(resp.json(), spec)
                except ValueError:
                    ids = set()
                if ids:
                    per_role[role] = ids
            owned[spec.name] = per_role
        return owned

    # ---- Phase 1 (combined): harvest ids + observe traffic ------------

    def _role_for_identity(self, owner: str | None) -> str | None:
        if owner is None:
            return None
        return next((r for r, ids in self.identities.items() if owner in ids), None)

    def recon(self, objects: list[ObjectSpec]) -> tuple[dict[str, dict[str, set[str]]], SiteObservation]:
        """One pass: harvest owned ids (for BOLA) and record endpoint samples
        (raw material for the LLM intent model)."""
        owned: dict[str, dict[str, set[str]]] = {}
        obs = SiteObservation()
        for spec in objects:
            per_role: dict[str, set[str]] = {}
            for role, client in self.clients.items():
                if role == "guest":
                    continue
                try:
                    resp = client.get(spec.list_url)
                except httpx.HTTPError:
                    continue
                obs.record("GET", spec.list_url, role, resp)
                if resp.status_code == 200:
                    try:
                        by_owner = _extract_owned_ids(resp.json(), spec)
                    except ValueError:
                        by_owner = {}
                    for owner, ids in by_owner.items():
                        # owner field maps a record to its true owner even from a leaky list;
                        # records with no owner field are attributed to the fetching role.
                        target = self._role_for_identity(owner) or (role if owner is None else None)
                        if target:
                            per_role.setdefault(target, set()).update(ids)
            owned[spec.name] = per_role
            # one authenticated item sample (helps the model understand the shape)
            for role, ids in per_role.items():
                url = spec.item_url.format(id=sorted(ids)[0])
                with contextlib.suppress(httpx.HTTPError):
                    obs.record("GET", url, role, self.get_as(role, url))
                break
        return owned, obs

    # ---- Phase 4: execute a hypothesis --------------------------------

    def execute(self, hyp: Hypothesis) -> TestResult:
        if hyp.bug_class == "bola":
            return self._execute_bola(hyp)
        if hyp.bug_class == "race_condition":
            return self._execute_race(hyp)
        if hyp.bug_class == "excessive_data_exposure":
            return self._execute_exposure(hyp)
        if hyp.bug_class == "bfla":
            return self._execute_bfla(hyp)
        if hyp.invariant_id == "MASS:registration":
            return self._execute_massassign(hyp)
        if hyp.invariant_id == "PRICE:negative_quantity":
            return self._execute_pricetamper(hyp)
        if hyp.invariant_id == "WORKFLOW:finalize_without_prereq":
            return self._execute_workflow(hyp)
        if hyp.meta.get("coupon"):
            return self._execute_coupon(hyp)
        return self._execute_sequence(hyp)

    def _execute_coupon(self, hyp: Hypothesis) -> TestResult:
        """Redeem the same coupon code `reps` times in series and count how many succeeded.
        A success is `success_status` (and, if given, a truthy `success_field`)."""
        m = hyp.meta
        role = m["as"] if m["as"] in self.clients else next(
            (r for r in self.clients if r != "guest"), "guest")
        snaps: list[dict[str, Any]] = []
        success = 0
        for _ in range(m["reps"]):
            snap = self._send(role, m["method"], m["url"], m.get("body"))
            ok = snap["status"] == m["success_status"]
            if ok and m.get("success_field"):
                ok = bool(_dotted(snap.get("json"), m["success_field"]))
            success += 1 if ok else 0
            snaps.append(snap)
        return TestResult(hypothesis=hyp, responses={
            "results": snaps, "success_count": success,
            "reps": m["reps"], "max_uses": m["max_uses"]})

    def _execute_workflow(self, hyp: Hypothesis) -> TestResult:
        """Try to finalize an order without paying (checkout returns a confirmation), or to set
        a client-controlled workflow state on an order create endpoint."""
        from .workflow import STATE_FIELDS, order_confirmation, reflects_state

        role = next((r for r in self.clients if r != "guest"), "guest")
        bid = _find_id(self.login_json.get(role), ("bid", "basket", "cart", "order")) or 1
        attempts: list[dict] = []

        # 1) finalize without payment — a checkout endpoint that returns an order confirmation
        for tmpl in hyp.meta["checkout_paths"]:
            path = tmpl.replace("{bid}", str(bid))
            snap = self._send(role, "POST", path, {})
            conf = order_confirmation(snap.get("json")) if snap["status"] in (200, 201) else None
            attempts.append({"path": path, "status": snap["status"], "kind": "unpaid_checkout"})
            if conf:
                return TestResult(hyp, responses={"hit": {"kind": "unpaid_checkout", "path": path,
                                                          "field": conf[0], "value": conf[1]}, "attempts": attempts})

        # 2) client-controlled workflow state on an order create endpoint
        for path in hyp.meta["create_paths"]:
            for fld, value in STATE_FIELDS:
                snap = self._send(role, "POST", path, {fld: value})
                hit = snap["status"] in (200, 201) and reflects_state(snap.get("json"), fld, value)
                attempts.append({"path": path, "status": snap["status"], "kind": "state_injection"})
                if hit:
                    return TestResult(hyp, responses={"hit": {"kind": "state_injection", "path": path,
                                                              "field": fld, "value": value}, "attempts": attempts})
        return TestResult(hyp, responses={"hit": None, "attempts": attempts})

    def _execute_pricetamper(self, hyp: Hypothesis) -> TestResult:
        """POST a negative-quantity line item to each candidate endpoint; confirm if reflected."""
        from .pricetamper import bodies, reflects_negative_quantity

        role = next((r for r in self.clients if r != "guest"), "guest")
        basket_id = _find_id(self.login_json.get(role), ("bid", "basket", "cart")) or 1
        attempts: list[dict] = []
        for path in hyp.meta["paths"]:
            for body in bodies(basket_id, 1):
                snap = self._send(role, "POST", path, body)
                neg = reflects_negative_quantity(snap.get("json")) if snap["status"] in (200, 201) else None
                attempts.append({"path": path, "status": snap["status"], "reflected": bool(neg)})
                if neg:
                    return TestResult(hyp, responses={
                        "hit": {"path": path, "field": neg[0], "value": neg[1], "body": body},
                        "attempts": attempts})
        return TestResult(hyp, responses={"hit": None, "attempts": attempts})

    def _execute_massassign(self, hyp: Hypothesis) -> TestResult:
        """For each registration endpoint: learn a working body, then inject privileged
        fields (unique identity each time) and check whether the response reflects them."""
        from .massassign import PRIV_FIELDS, body_shapes, creds, reflects

        role = "guest" if "guest" in self.clients else next(iter(self.clients), None)
        attempts: list[dict] = []
        n = 0
        for path in hyp.meta["register_paths"]:
            email, user, pw = creds(n)
            n += 1
            working = next((s for s in body_shapes(email, user, pw)
                            if self._send(role, "POST", path, s)["status"] in (200, 201)), None)
            if working is None:
                continue                                    # not a working registration endpoint
            for fld, value in PRIV_FIELDS:
                email, user, pw = creds(n)
                n += 1
                body = {k: {"email": email, "username": user, "password": pw,
                            "passwordRepeat": pw}.get(k, v) for k, v in working.items()}
                body[fld] = value
                snap = self._send(role, "POST", path, body)
                hit = snap["status"] in (200, 201) and reflects(snap.get("json"), fld, value)
                attempts.append({"path": path, "field": fld, "value": value,
                                 "status": snap["status"], "reflected": bool(hit)})
                if hit:
                    return TestResult(hyp, responses={"hit": {"path": path, "field": fld, "value": value},
                                                      "attempts": attempts})
        return TestResult(hyp, responses={"hit": None, "attempts": attempts})

    def _execute_bfla(self, hyp: Hypothesis) -> TestResult:
        """Fetch an admin-marked endpoint as userA, admin, and guest — the Oracle diffs access."""
        url = hyp.meta["path"]
        responses = {role: self._snap(role, url)
                     for role in ("userA", "admin", "guest") if role in self.clients}
        return TestResult(hypothesis=hyp, responses=responses)

    def _execute_exposure(self, hyp: Hypothesis) -> TestResult:
        """Fetch the list as userA, userB, and guest — the Oracle inspects owner fields."""
        url = hyp.meta["list_url"]
        responses: dict[str, Any] = {
            role: self._snap(role, url) for role in ("userA", "userB", "guest") if role in self.clients
        }
        return TestResult(hypothesis=hyp, responses=responses)

    def _execute_race(self, hyp: Hypothesis) -> TestResult:
        """Fire N identical requests concurrently and count how many succeeded."""
        m = hyp.meta
        n, role = m["parallel"], m["as"]

        def fire(_: int) -> dict[str, Any]:
            return self._send(role, m["method"], m["url"], m.get("body"))

        with ThreadPoolExecutor(max_workers=max(n, 1)) as ex:
            snaps = list(ex.map(fire, range(n)))

        success = 0
        for s in snaps:
            ok = s["status"] == m["success_status"]
            if ok and m.get("success_field"):
                ok = bool(_dotted(s.get("json"), m["success_field"]))
            success += 1 if ok else 0
        return TestResult(
            hypothesis=hyp,
            responses={"results": snaps, "success_count": success,
                       "parallel": n, "expect_max": m["expect_max_success"]},
        )

    def _execute_bola(self, hyp: Hypothesis) -> TestResult:
        """Fetch the target item as owner, attacker (twice, for reproducibility),
        and guest. The Oracle diffs these to confirm or drop."""
        url = hyp.meta["item_url"]
        owner = hyp.meta["owner_role"]
        attacker = hyp.meta["attacker_role"]
        responses: dict[str, Any] = {
            "owner": self._snap(owner, url),
            "attacker": self._snap(attacker, url),
            "attacker_rerun": self._snap(attacker, url),   # reproducibility check
        }
        if "guest" in self.clients:
            responses["guest"] = self._snap("guest", url)
        return TestResult(hypothesis=hyp, responses=responses)

    def _execute_sequence(self, hyp: Hypothesis) -> TestResult:
        """Replay an ordered request sequence (with body mutations) and snapshot
        state before/after via an optional probe. Used by price/mass/workflow."""
        probe = hyp.meta.get("state_probe")
        before = self._probe(probe) if probe else {}
        seq: list[dict[str, Any]] = []
        for step in hyp.request_sequence:
            role = step.get("as") or next(iter(self.clients))
            seq.append(self._send(role, step.get("method", "GET"), step["url"], step.get("body")))
        after = self._probe(probe) if probe else {}
        return TestResult(
            hypothesis=hyp,
            responses={"seq": seq, "final": seq[-1] if seq else {}},
            state_before=before, state_after=after,
        )

    def _send(self, role: str, method: str, url: str, body: Any = None) -> dict[str, Any]:
        try:
            r = self.clients[role].request(method, url, json=body)
        except httpx.HTTPError as e:
            return {"status": -1, "body": f"<error: {e}>", "json": None}
        try:
            body_json = r.json()
        except Exception:
            body_json = None
        return {"status": r.status_code, "body": r.text, "json": body_json}

    def _probe(self, probe: dict[str, Any]) -> dict[str, Any]:
        return self._send(probe.get("as", "guest"), "GET", probe["url"])

    def _snap(self, role: str, url: str) -> dict[str, Any]:
        return self._send(role, "GET", url)

    def close(self) -> None:
        for c in self.clients.values():
            c.close()
